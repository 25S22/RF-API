#!/usr/bin/env python3
"""
rf_ioc_enricher.py - Recorded Future IOC enrichment for threat hunting (multi-sheet)
====================================================================================

What it does
------------
1. Reads EVERY sheet of the input workbook (.xlsx / .xlsm; .csv / .tsv / .txt are
   treated as a single sheet). Every cell is scanned for IOCs, so a sheet can hold
   IPs, domains, URLs, hashes, CVEs - mixed or not, one or several per cell.
   Defanged indicators such as hxxp://evil[.]com or 1[.]2[.]3[.]4 are re-fanged.
2. Enriches the unique IOCs in two fast phases:
      Phase 1  BULK risk lookup - one POST to /soar/v3/enrichment per 1,000 IOCs
               (risk score, level, triggered rules + evidence).
      Phase 2  DEEP enrichment via the Connect API (location, ASN, intel card,
               threat lists ...) for the IOCs you care about
               (DEEP_ENRICH = "risky" | "all" | "none").
3. Writes ONE output workbook:
      * the SAME sheets, in the same order, with the original cells and formatting,
        and the enrichment columns written NEXT TO each column that holds IOCs
        (ENRICH_PLACEMENT = "adjacent" or "end"),
      * a final "Summary" sheet.
   Plus a sidecar  <output>_raw.jsonl  with the untouched API responses.

Requirements:  pip install requests openpyxl      (tkinter ships with Python)

Usage
-----
    1. Edit the USER CONFIGURATION block just below the imports, then run:
           python rf_ioc_enricher.py
    2. Or override on the command line:
           python rf_ioc_enricher.py -i iocs.xlsx -o D:\\hunt\\out -y
    3. Or use the pop-up configuration window:
           python rf_ioc_enricher.py --gui        (or set USE_GUI = True)

    Central lookup for use from your own code:
           from rf_ioc_enricher import RFClient, central_lookup
           client = RFClient("<token>")
           row, raw = central_lookup(client, "8.8.8.8")       # type auto-detected
           row, raw = central_lookup(client, "CVE-2021-44228")

Notes
-----
* The token is only held in memory. It is never printed, logged or saved.
* Cell values written to the workbook are sanitised against formula injection
  (RF text fields can contain attacker-influenced strings).
* IOC values are only sent to api.recordedfuture.com (or your proxy).
* The input workbook is read with cached values (formulas become their last
  calculated values). Charts, images and conditional formatting are not carried
  over to the output copy; cell values, fonts, fills, borders, number formats,
  column widths, merged cells, freeze panes and filters are.
"""
from __future__ import annotations

import argparse
import csv
import getpass
import ipaddress
import json
import os
import queue
import re
import sys
import threading
import time
from collections import Counter, OrderedDict
from concurrent.futures import ThreadPoolExecutor, as_completed
from copy import copy
from dataclasses import dataclass, field
from datetime import datetime, timezone
from urllib.parse import quote

try:
    import requests
    from requests.adapters import HTTPAdapter
except ImportError:  # pragma: no cover
    sys.exit("Missing dependency. Run:  pip install requests openpyxl")

try:
    from openpyxl import Workbook, load_workbook
    from openpyxl.styles import Alignment, Font, PatternFill
    from openpyxl.utils import column_index_from_string, get_column_letter
    from openpyxl.utils.cell import coordinate_from_string
    try:
        from openpyxl.cell.cell import ILLEGAL_CHARACTERS_RE
    except Exception:  # pragma: no cover
        ILLEGAL_CHARACTERS_RE = re.compile(r"[\000-\010\013\014\016-\037]")
except ImportError:  # pragma: no cover
    sys.exit("Missing dependency. Run:  pip install requests openpyxl")

try:
    import tkinter as tk
    from tkinter import filedialog, messagebox, scrolledtext, ttk
    HAVE_TK = True
except Exception:  # pragma: no cover
    HAVE_TK = False

# =========================================================================== #
#                         USER CONFIGURATION  (edit me)                        #
# =========================================================================== #
# Recorded Future API token. Leave "" to read it from the RF_API_TOKEN
# environment variable (safer), or you will be prompted with hidden input.
API_TOKEN = ""

# Input workbook. EVERY sheet is processed. Sheets may freely MIX IPs, domains,
# URLs, file hashes (MD5/SHA1/SHA256) and CVEs - every cell is scanned and each
# indicator is routed to the right RF endpoint automatically.
# Windows example:  r"C:\Hunts\iocs.xlsx"
INPUT_FILE = "iocs.xlsx"

# Folder where the result is written (created if missing). "" = same folder as input.
OUTPUT_FOLDER = "rf_output"

# --- Output layout --------------------------------------------------------------
# Where the enrichment columns go on each sheet:
#   "adjacent" = inserted right after each column that contains IOCs (other
#                original columns are shifted right to make room)
#   "end"      = appended after the last original column (original columns never move)
ENRICH_PLACEMENT = "adjacent"

# Is row 1 of each sheet a header row?
#   "auto" = yes, unless row 1 itself contains IOCs (then the sheet is treated as
#            headerless and a header row is inserted on top of the output sheet)
#   True / False = force it for every sheet
HEADER_ROW = "auto"

# Enrichment columns written next to the IOC columns (full detail for every IOC
# is also kept in the *_raw.jsonl file). Use "all" to write every column RF returned.
# Columns with no data on a given sheet are left out of that sheet automatically.
INLINE_COLUMNS = [
    "IOC", "IOC_Type", "RF_Status", "RF_Risk_Score", "RF_Risk_Level",
    "RF_Rules_Triggered", "RF_Most_Critical_Rule", "RF_Risk_Rules", "RF_Risk_Evidence",
    "RF_Country", "RF_City", "RF_ASN", "RF_Organization",
    "RF_First_Seen", "RF_Last_Seen", "RF_Threat_Lists", "RF_IntelCard", "RF_Error",
]

# Also add a flat "All_Enriched" sheet (one row per unique IOC, every column) before Summary.
ADD_ALL_ENRICHED_SHEET = False

# Any IOC whose RF risk score is GREATER THAN this value is listed in the Summary's
# "flagged" table and (with DEEP_ENRICH = "risky") gets deep enrichment.
RISK_SCORE_THRESHOLD = 0

# --- Speed -------------------------------------------------------------------
# Phase 1 is always a BULK lookup (up to 1000 IOCs per API call).
# Phase 2 adds the full Connect-API detail one IOC at a time, in parallel:
#     "risky" = only IOCs with score > RISK_SCORE_THRESHOLD   (fast, recommended)
#     "all"   = every IOC                                     (slower)
#     "none"  = skip phase 2                                  (fastest)
DEEP_ENRICH = "risky"
# Phase 2 has no bulk endpoint at Recorded Future (one request per IOC), so to save
# API calls you can limit it further:
DEEP_MIN_SCORE = None           # None = use RISK_SCORE_THRESHOLD; e.g. 65 = deep-enrich only Malicious+
DEEP_MAX_IOCS = 0               # 0 = no cap; e.g. 200 = deep-enrich at most the 200 highest-scoring IOCs
BATCH_SIZE = 1000               # IOCs per bulk call (RF maximum is 1000)
WORKERS = 4                     # parallel requests for phase 2 / multiple batches
TIMEOUT = 60                    # seconds per HTTP request

# --- Network / TLS -------------------------------------------------------------
# Keep certificate verification ON. If you are behind a corporate proxy that
# inspects TLS (the most common reason for "SSL / certificate verify failed"),
# point CA_BUNDLE_PATH at your company's root CA in PEM format, e.g.
#     CA_BUNDLE_PATH = r"C:\certs\corp-root-ca.pem"
# Leave "" to use Python's default trusted CAs.
VERIFY_SSL = True               # False disables all checks - avoid; use CA_BUNDLE_PATH
CA_BUNDLE_PATH = ""
PROXY = ""                      # e.g. "http://proxy.corp:8080" (or user:pass@host:port)

# --- Behaviour -------------------------------------------------------------------
SKIP_PRIVATE_IPS = True         # don't send RFC1918 / loopback / reserved IPs to RF
ASK_CONFIRMATION = True         # show the IOC count and ask before using API quota
USE_GUI = False                 # True = show the pop-up configuration window instead

# --------------------------------------------------------------------------- #
# Constants
# --------------------------------------------------------------------------- #
RF_BASE = "https://api.recordedfuture.com/v2"                     # Connect API (deep enrichment)
SOAR_URL = "https://api.recordedfuture.com/soar/v3/enrichment"    # bulk risk enrichment
SOAR_KEY = {"ip": "ip", "domain": "domain", "url": "url", "hash": "hash", "cve": "vulnerability"}
TYPE_TO_KIND = {"IpAddress": "ip", "InternetDomainName": "domain", "URL": "url",
                "Hash": "hash", "CyberVulnerability": "cve"}
USER_AGENT = "ThreatHunt-RF-Enricher/1.1"
CELL_LIMIT = 32000  # Excel hard limit is 32,767 chars per cell
SUMMARY_FLAG_CAP = 1000   # max flagged IOCs listed on the Summary sheet

ENDPOINT = {"ip": "ip", "domain": "domain", "url": "url",
            "hash": "hash", "cve": "vulnerability"}
TYPE_LABEL = {"ip": "IP", "domain": "Domain", "url": "URL",
              "hash": "Hash", "cve": "CVE"}
LABEL_TO_KIND = {v: k for k, v in TYPE_LABEL.items()}

# Used only if runtime discovery of valid fields (GET /v2/<type>/fields) fails.
_CORE = ["entity", "risk", "timestamps", "sightings", "intelCard", "analystNotes",
         "counts", "metrics", "links", "relatedEntities", "threatLists",
         "enterpriseLists"]
FALLBACK_FIELDS = {
    "ip": _CORE + ["location"],
    "domain": list(_CORE),
    "url": list(_CORE),
    "hash": _CORE + ["fileHashes", "hashAlgorithm"],
    "cve": ["entity", "risk", "timestamps", "sightings", "intelCard", "analystNotes",
            "counts", "metrics", "links", "relatedEntities", "cvss", "cvssv3", "cpe",
            "nvdDescription"],
}
MINIMAL_FIELDS = ["entity", "risk", "timestamps"]

RISK_LEVELS = ["Very Malicious", "Malicious", "Suspicious", "Unusual",
               "No Threats Found", "No Risk Data", "Not in Recorded Future",
               "Lookup Error"]
SKIPPED_LEVEL = "Skipped (private/reserved)"

PRIORITY_COLS = [
    "IOC", "IOC_Type", "RF_Risk_Level", "RF_Risk_Score", "RF_Criticality_Label",
    "RF_Rules_Triggered", "RF_Most_Critical_Rule", "RF_Risk_Rules", "RF_Status", "RF_Error",
    "RF_Country", "RF_City", "RF_Continent", "RF_ASN", "RF_Organization",
    "RF_CIDR", "RF_First_Seen", "RF_Last_Seen", "RF_Threat_Lists",
    "RF_Enterprise_Lists", "RF_IntelCard", "RF_AI_Insights", "RF_Risk_Evidence",
    "Source_Occurrences", "Source_Locations", "RF_Lookup_UTC", "RF_Deep_Enrichment",
]


class AuthError(RuntimeError):
    pass


class RFFatalError(RuntimeError):
    """Problem that makes every further request pointless (TLS, proxy, entitlement)."""


# --------------------------------------------------------------------------- #
# IOC extraction
# --------------------------------------------------------------------------- #
URL_RE = re.compile(r"(?i)\b(?:https?|ftp)://[^\s<>\"'`]+")
CVE_RE = re.compile(r"(?i)(?<![\w-])CVE-\d{4}-\d{4,}(?![\w-])")
HASH_RE = re.compile(r"(?<![A-Fa-f0-9])(?:[A-Fa-f0-9]{64}|[A-Fa-f0-9]{40}|[A-Fa-f0-9]{32})(?![A-Fa-f0-9])")
IPV4_RE = re.compile(
    r"(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?!\d|\.\d)")
IPV6_RE = re.compile(r"(?<![\w:.])(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}(?![\w:])")
DOMAIN_RE = re.compile(
    r"(?i)(?<![\w.-])((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24})(?![\w-])")

# Things that look like domains but are usually file names
NOT_TLDS = {
    "exe", "dll", "txt", "csv", "xlsx", "xls", "xlsm", "doc", "docx", "pdf", "png",
    "jpg", "jpeg", "gif", "bmp", "log", "json", "xml", "html", "htm", "js", "ps1",
    "bat", "cmd", "vbs", "tmp", "dat", "ini", "cfg", "conf", "yml", "yaml", "rar",
    "gz", "tar", "sys", "msi", "lnk", "md", "rtf", "ppt", "pptx", "bin", "jar",
    "class", "php", "asp", "aspx", "css", "svg", "ico", "evtx", "pcap", "pcapng",
    "sql", "db", "bak", "iso", "img", "dmp", "reg", "scr", "ocx", "so", "cpp",
}


def refang(s: str) -> str:
    """Undo common IOC defanging so regexes can see the real indicator."""
    s = re.sub(r"(?i)\bhxxp(s?)://", r"http\1://", s)
    s = re.sub(r"(?i)\bh\*\*p(s?)://", r"http\1://", s)
    s = re.sub(r"(?i)\bfxp://", "ftp://", s)
    s = re.sub(r"(?i)[\[\(\{]\s*(?:\.|dot)\s*[\]\)\}]", ".", s)
    s = re.sub(r"(?i)[\[\(\{]\s*(?:@|at)\s*[\]\)\}]", "@", s)
    s = s.replace("[:]", ":").replace("[://]", "://").replace("[/]", "/")
    return s


def extract_iocs(text: str):
    """Return list of (kind, value, skip_reason_or_None) found in a text blob."""
    out = []
    t = refang(text)

    for m in URL_RE.finditer(t):
        u = m.group(0).rstrip(".,;:!?)]}>'\"")
        if len(u) > 8:
            out.append(("url", u, None))
    t = URL_RE.sub(" ", t)          # don't re-detect the domain/IP inside a URL

    for m in CVE_RE.finditer(t):
        out.append(("cve", m.group(0).upper(), None))
    for m in HASH_RE.finditer(t):
        out.append(("hash", m.group(0).lower(), None))

    for m in IPV4_RE.finditer(t):
        ip = ipaddress.ip_address(m.group(0))
        out.append(("ip", str(ip), None if ip.is_global else "private/reserved address"))
    for m in IPV6_RE.finditer(t):
        cand = m.group(0)
        if len(cand) < 4:
            continue
        try:
            ip = ipaddress.IPv6Address(cand)
        except ValueError:
            continue
        out.append(("ip", str(ip), None if ip.is_global else "private/reserved address"))

    t = IPV4_RE.sub(" ", t)
    for m in DOMAIN_RE.finditer(t):
        d = m.group(1).lower().rstrip(".")
        if d.rsplit(".", 1)[-1] in NOT_TLDS:
            continue
        out.append(("domain", d, None))
    return out


# --------------------------------------------------------------------------- #
# Input loading + scanning (all sheets)
# --------------------------------------------------------------------------- #
def load_input_workbook(path: str):
    """Return an openpyxl Workbook. Excel files keep all their sheets; csv/tsv/txt become one sheet."""
    ext = os.path.splitext(path)[1].lower()
    if ext in (".xlsx", ".xlsm"):
        return load_workbook(path, data_only=True)
    if ext not in (".csv", ".tsv", ".txt", ".log", ".list", ".ioc", ""):
        raise ValueError(f"Unsupported input type '{ext}'. Use .xlsx, .csv or .txt "
                         "(save legacy .xls files as .xlsx first).")
    wb = Workbook()
    ws = wb.active
    ws.title = "Sheet1"

    def put(r, c, val):
        cell = ws.cell(row=r, column=c)
        cell.value = ILLEGAL_CHARACTERS_RE.sub("", val)
        cell.data_type = "s"

    if ext in (".csv", ".tsv"):
        csv.field_size_limit(min(sys.maxsize, 2**31 - 1))
        with open(path, newline="", encoding="utf-8-sig", errors="replace") as f:
            sample = f.read(65536)
            f.seek(0)
            try:
                dialect = csv.Sniffer().sniff(sample, delimiters=",;\t|")
            except csv.Error:
                dialect = csv.excel_tab if ext == ".tsv" else csv.excel
            for r, row in enumerate(csv.reader(f, dialect), 1):
                for c, val in enumerate(row, 1):
                    if val.strip():
                        put(r, c, val)
    else:
        with open(path, encoding="utf-8-sig", errors="replace") as f:
            for n, line in enumerate(f, 1):
                if line.strip():
                    put(n, 1, line.rstrip("\r\n"))
    return wb


def sheet_has_header(ws, mode) -> bool:
    if mode is True or mode is False:
        return mode
    row1 = [c for c in next(ws.iter_rows(min_row=1, max_row=1), ())
            if c.value is not None and str(c.value).strip()]
    if not row1:
        return True
    hits = {c.column: extract_iocs(str(c.value)) for c in row1}
    if any(k != "domain" for h in hits.values() for k, _, _ in h):
        return False                      # IP / hash / URL / CVE in row 1 -> it is data
    domain_cols = [col for col, h in hits.items() if h]
    if not domain_cols:
        return True                       # plain labels only
    if len(domain_cols) < len(row1):
        return True                       # labels like "Source.IP" next to plain labels like "Notes"
    # every cell in row 1 looks like a bare domain: a header only if row 2 below it holds other IOC types
    for c in next(ws.iter_rows(min_row=2, max_row=2), ()):
        if c.column in domain_cols and c.value is not None and \
                any(k != "domain" for k, _, _ in extract_iocs(str(c.value))):
            return True
    return False


@dataclass
class Scan:
    wb: object
    iocs: list          # unique IOCs: {"kind","value","count","locs"}
    skipped: list       # unique private/reserved IPs that will not be sent to RF
    cell_map: dict      # {sheet: {(row, col): [(kind, value, skip_reason_or_None), ...]}}
    ioc_cols: dict      # {sheet: {col_index, ...}}  columns that contain IOCs
    header: dict        # {sheet: bool}  row 1 is a header row


def scan_input(path: str, skip_private: bool, header_mode, log) -> Scan:
    wb = load_input_workbook(path)
    occ: "OrderedDict[tuple, list]" = OrderedDict()       # key -> [count, [locs]]
    skipped: "OrderedDict[tuple, list]" = OrderedDict()   # key -> [reason, count, [locs]]
    cell_map, ioc_cols, header = {}, {}, {}
    cells = 0
    for ws in wb.worksheets:
        has_header = sheet_has_header(ws, header_mode)
        header[ws.title] = has_header
        cmap = cell_map[ws.title] = {}
        cols = ioc_cols[ws.title] = set()
        for row in ws.iter_rows():
            for cell in row:
                val = cell.value
                if val is None:
                    continue
                text = str(val)
                if not text.strip():
                    continue
                if has_header and cell.row == 1:
                    continue
                cells += 1
                found = extract_iocs(text)
                if not found:
                    continue
                loc = f"{ws.title}!{cell.coordinate}"
                entries, seen = [], set()
                for kind, v, reason in found:
                    if (kind, v) in seen:
                        continue
                    seen.add((kind, v))
                    why = reason if (reason and skip_private) else None
                    entries.append((kind, v, why))
                    if why:
                        rec = skipped.setdefault((kind, v), [why, 0, []])
                        rec[1] += 1
                        if len(rec[2]) < 5 and loc not in rec[2]:
                            rec[2].append(loc)
                    else:
                        rec = occ.setdefault((kind, v), [0, []])
                        rec[0] += 1
                        if len(rec[1]) < 10 and loc not in rec[1]:
                            rec[1].append(loc)
                cmap[(cell.row, cell.column)] = entries
                cols.add(cell.column)
        note = ("  [row 1 = header]" if has_header else
                "  [row 1 is data -> no header; a header row will be added on top. "
                "Set HEADER_ROW = True if row 1 is really a header]")
        log(f"  sheet '{ws.title}': {len(cmap)} cell(s) with IOCs in "
            f"{len(cols)} column(s){note}")
    log(f"Scanned {cells:,} non-empty cells across {len(wb.worksheets)} sheet(s).")
    iocs = [{"kind": k[0], "value": k[1], "count": v[0], "locs": v[1]} for k, v in occ.items()]
    skipped_list = [{"kind": k[0], "value": k[1], "reason": v[0], "count": v[1], "locs": v[2]}
                    for k, v in skipped.items()]
    return Scan(wb, iocs, skipped_list, cell_map, ioc_cols, header)


# --------------------------------------------------------------------------- #
# Recorded Future client
# --------------------------------------------------------------------------- #
def _parse_field_list(payload):
    if isinstance(payload, dict):
        payload = payload.get("data", payload)
    names = []
    if isinstance(payload, list):
        for x in payload:
            if isinstance(x, str):
                names.append(x)
            elif isinstance(x, dict) and (x.get("name") or x.get("field")):
                names.append(x.get("name") or x.get("field"))
    elif isinstance(payload, dict):
        names = list(payload.keys())
    names = sorted({n for n in names if isinstance(n, str) and re.fullmatch(r"[A-Za-z0-9_]+", n)})
    return names if ("entity" in names or "risk" in names) else []


def _net_hint(e):
    n = type(e).__name__
    if isinstance(e, requests.exceptions.SSLError):
        return (f"{n}: TLS certificate verification failed - typically a corporate SSL-inspection proxy. "
                "FIX: set CA_BUNDLE_PATH to your company root CA (.pem), or `pip install pip-system-certs` "
                f"to use the OS trust store. Details: {str(e)[:200]}")
    if isinstance(e, requests.exceptions.ProxyError):
        return f"{n}: proxy problem - set PROXY in the config block (http://host:port). Details: {str(e)[:200]}"
    return (f"{n}: cannot reach api.recordedfuture.com:443 - check VPN/firewall, set PROXY, or raise TIMEOUT. "
            f"Details: {str(e)[:200]}")


def _norm(kind, v):
    v = str(v).strip().lower()
    if kind == "ip":
        try:
            return str(ipaddress.ip_address(v))
        except ValueError:
            return v
    if kind == "url":
        return v.rstrip("/")
    if kind == "domain":
        return v.rstrip(".")
    return v


class RFClient:
    def __init__(self, token, timeout=60, verify=True, proxy="", workers=4, log=print):
        self.timeout, self.workers, self.log = timeout, max(1, workers), log
        self.s = requests.Session()
        adapter = HTTPAdapter(pool_connections=self.workers, pool_maxsize=self.workers * 2)
        self.s.mount("https://", adapter)
        self.s.headers.update({"X-RFToken": token, "X-RF-User-Agent": USER_AGENT, "Accept": "application/json"})
        if proxy:
            self.s.proxies = {"http": proxy, "https": proxy}
        self.s.verify = verify                 # True | False | path to CA bundle
        if verify is False:
            try:
                import urllib3
                urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            except Exception:
                pass
        self._lock = threading.Lock()
        self._tiers, self._good_tier = {}, {}
        self.deep_blocked = set()
        self.stats = Counter()          # bulk_calls / deep_calls actually sent to RF
        self.warnings = []
        self.auth_failed = threading.Event()

    # -- low level --------------------------------------------------------- #
    def _request(self, method, url, **kw):
        last = None
        for attempt in range(1, 6):
            if self.auth_failed.is_set():
                raise AuthError("Authentication failed")
            try:
                r = self.s.request(method, url, timeout=self.timeout, **kw)
            except (requests.exceptions.SSLError, requests.exceptions.ProxyError) as e:
                raise RFFatalError(_net_hint(e))            # not transient: fail fast
            except requests.RequestException as e:
                last = _net_hint(e)
                if attempt >= 3:
                    raise RFFatalError(last)
                time.sleep(2 * attempt)
                continue
            if r.status_code == 429:
                try:
                    wait = float(r.headers.get("Retry-After", ""))
                except ValueError:
                    wait = min(2 ** attempt * 2, 60)
                last = "HTTP 429 (rate limited)"
                time.sleep(wait)
                continue
            if r.status_code >= 500:
                last = f"HTTP {r.status_code}"
                time.sleep(min(2 ** attempt, 10))
                continue
            return r
        raise RFFatalError(f"RF API kept failing ({last})")

    def preflight(self):
        """Prove TLS + network path works before spending any API quota."""
        r = self._request("GET", "https://api.recordedfuture.com/")
        return r.status_code

    # -- PHASE 1: bulk ------------------------------------------------------ #
    def bulk_enrich(self, items, batch_size=1000, log=None):
        """items: [(kind, value)]. Returns {(kind, value): (status, payload)}; status OK|NOT_FOUND|ERROR."""
        log = log or self.log
        batch_size = max(1, min(int(batch_size), 1000))
        chunks = [items[i:i + batch_size] for i in range(0, len(items), batch_size)]
        out = {}
        with ThreadPoolExecutor(max_workers=min(len(chunks), self.workers) or 1) as ex:
            for n, part in enumerate(ex.map(self._bulk_chunk, chunks), 1):
                out.update(part)
                log(f"  bulk batch {n}/{len(chunks)} done ({len(out)}/{len(items)} IOCs)")
        return out

    def _bulk_chunk(self, chunk):
        body = {}
        for kind, val in chunk:
            body.setdefault(SOAR_KEY[kind], []).append(val)
        with self._lock:
            self.stats["bulk_calls"] += 1
        r = self._request("POST", SOAR_URL, json=body, params={"metadata": "false"})
        if r.status_code == 200:
            return self._match(chunk, r.json())
        if r.status_code == 401:
            self.auth_failed.set()
            raise AuthError("HTTP 401 - invalid or expired API token")
        if r.status_code == 403:
            raise RFFatalError("HTTP 403 - this token is not entitled to the SOAR enrichment API "
                               f"(ask your RF admin). Response: {r.text[:200]}")
        if r.status_code in (400, 422) and len(chunk) > 1:      # isolate the bad IOC(s)
            mid = len(chunk) // 2
            res = self._bulk_chunk(chunk[:mid])
            res.update(self._bulk_chunk(chunk[mid:]))
            return res
        msg = f"HTTP {r.status_code}: {r.text[:200].strip()}"
        return {k: ("ERROR", msg) for k in chunk}

    def _match(self, chunk, body):
        data = body.get("data", body) if isinstance(body, dict) else body
        results = data.get("results") if isinstance(data, dict) else data
        idx = {(k, _norm(k, v)): (k, v) for k, v in chunk}
        out, unmatched = {}, []
        for res in results or []:
            if not isinstance(res, dict):
                continue
            ent = res.get("entity") if isinstance(res.get("entity"), dict) else {}
            name = str(ent.get("name") or "")
            guess = TYPE_TO_KIND.get(ent.get("type"))
            order = ([guess] if guess else []) + [k for k in SOAR_KEY if k != guess]
            for k in order:
                key = idx.get((k, _norm(k, name)))
                if key:
                    out[key] = ("OK", res)
                    break
            else:
                unmatched.append(name)
        if unmatched:
            with self._lock:
                self.warnings.append(f"{len(unmatched)} RF result(s) could not be matched to your input, "
                                     f"e.g. '{unmatched[0][:80]}'")
        for key in idx.values():
            out.setdefault(key, ("NOT_FOUND", None))
        return out

    # -- PHASE 2: Connect API (deep) -------------------------------------- #
    def _field_tiers(self, kind):
        with self._lock:
            if kind in self._tiers:
                return self._tiers[kind]
        discovered = []
        try:
            r = self._request("GET", f"{RF_BASE}/{ENDPOINT[kind]}/fields")
            if r.status_code == 200:
                discovered = _parse_field_list(r.json())
            elif r.status_code == 401:
                self.auth_failed.set()
        except AuthError:
            raise
        except Exception:
            pass
        tiers = ([discovered] if discovered else []) + [FALLBACK_FIELDS[kind], MINIMAL_FIELDS]
        with self._lock:
            if kind in self._tiers:             # another thread got here first
                return self._tiers[kind]
            self._tiers[kind] = tiers
        self.log(f"[{TYPE_LABEL[kind]}] deep enrichment: requesting "
                 f"{len(tiers[0])} RF fields" + ("" if discovered else " (built-in set)"))
        return tiers

    def lookup(self, kind, value):
        """Connect API single-entity lookup. Returns (status, data, error)."""
        if kind in self.deep_blocked:
            return "ERROR", None, "HTTP 403 - no Connect API entitlement for this IOC type (skipped)"
        ident = quote(value, safe="") if kind == "url" else value
        url = f"{RF_BASE}/{ENDPOINT[kind]}/{ident}"
        tiers = self._field_tiers(kind)
        with self._lock:
            self.stats["deep_calls"] += 1
        err = ""
        for i in range(self._good_tier.get(kind, 0), len(tiers)):
            r = self._request("GET", url, params={"fields": ",".join(tiers[i])})
            if r.status_code == 200:
                self._good_tier[kind] = i
                body = r.json()
                return "OK", (body.get("data", body) if isinstance(body, dict) else body), None
            if r.status_code == 404:
                return "NOT_FOUND", None, None
            if r.status_code == 401:
                self.auth_failed.set()
                raise AuthError("HTTP 401 - invalid or expired API token")
            err = f"HTTP {r.status_code}: {r.text[:200].strip()}"
            if r.status_code in (400, 403) and i < len(tiers) - 1:
                continue
            if r.status_code == 403:
                with self._lock:
                    if kind not in self.deep_blocked:
                        self.deep_blocked.add(kind)
                        self.log(f"[{TYPE_LABEL[kind]}] Connect API returned 403 - deep enrichment "
                                 "not available for this type with your token; skipping the rest.")
            break
        return "ERROR", None, err


# --------------------------------------------------------------------------- #
# Flattening RF responses into spreadsheet columns
# --------------------------------------------------------------------------- #
def risk_level(score):
    try:
        s = int(score)
    except (TypeError, ValueError):
        return "No Risk Data"
    if s >= 90:
        return "Very Malicious"
    if s >= 65:
        return "Malicious"
    if s >= 25:
        return "Suspicious"
    if s >= 5:
        return "Unusual"
    return "No Threats Found"


def _j(v):
    s = json.dumps(v, ensure_ascii=False, separators=(",", ":"), default=str)
    return s if len(s) <= CELL_LIMIT else s[:CELL_LIMIT - 15] + "...[truncated]"


def _join(vals, sep="; "):
    return sep.join(str(v) for v in vals)[:CELL_LIMIT]


def _names(items):
    out = []
    for it in items or []:
        if isinstance(it, dict):
            for k in ("name", "title", "id"):
                if it.get(k):
                    out.append(str(it[k]))
                    break
        elif it is not None:
            out.append(str(it))
    return out


def _collect_entities(node, out):
    """Recursively harvest {id,name,type} entities (MITRE IDs, malware, actors...)."""
    if isinstance(node, dict):
        t, n = node.get("type"), node.get("name")
        if isinstance(t, str) and isinstance(n, str) and "id" in node:
            out.setdefault(t, set()).add(n)
        for v in node.values():
            _collect_entities(v, out)
    elif isinstance(node, list):
        for v in node:
            _collect_entities(v, out)


def flatten(data: dict) -> dict:
    row, handled = {}, set()

    def take(k):
        handled.add(k)
        return data.get(k)

    ent = take("entity")
    if isinstance(ent, dict):
        row["RF_Entity_ID"] = ent.get("id")
        row["RF_Entity_Name"] = ent.get("name")
        row["RF_Entity_Type"] = ent.get("type")
        row["RF_Entity_Description"] = ent.get("description")

    risk = take("risk")
    if isinstance(risk, dict):
        row["RF_Risk_Score"] = risk.get("score")
        row["RF_Criticality"] = risk.get("criticality")
        row["RF_Criticality_Label"] = risk.get("criticalityLabel")
        row["RF_Rules_Triggered"] = risk.get("riskString")
        row["RF_Rule_Count"] = risk.get("rules")
        ev = [e for e in (risk.get("evidenceDetails") or []) if isinstance(e, dict)]
        row["RF_Risk_Rules"] = _join(e.get("rule", "") for e in ev)
        row["RF_Risk_Evidence"] = _join(
            (f"[{e.get('criticalityLabel') or e.get('criticality')}] {e.get('rule')}: "
             f"{e.get('evidenceString')} (first: {e.get('timestamp')})" for e in ev), " | ")
    row["RF_Risk_Level"] = risk_level(row.get("RF_Risk_Score")) if isinstance(risk, dict) else "No Risk Data"

    ts = take("timestamps")
    if isinstance(ts, dict):
        row["RF_First_Seen"] = ts.get("firstSeen")
        row["RF_Last_Seen"] = ts.get("lastSeen")

    loc = take("location")
    if isinstance(loc, dict):
        inner = loc.get("location") if isinstance(loc.get("location"), dict) else loc
        row["RF_Country"] = inner.get("country")
        row["RF_City"] = inner.get("city")
        row["RF_Continent"] = inner.get("continent")
        row["RF_ASN"] = loc.get("asn")
        row["RF_Organization"] = loc.get("organization")
        cidr = loc.get("cidr")
        if isinstance(cidr, dict):
            row["RF_CIDR"] = cidr.get("name") or cidr.get("id")
            row["RF_CIDR_Score"] = cidr.get("score")
        elif cidr:
            row["RF_CIDR"] = cidr

    sg = take("sightings")
    if isinstance(sg, list):
        sights = sorted((s for s in sg if isinstance(s, dict)),
                        key=lambda s: str(s.get("published") or ""), reverse=True)
        row["RF_Sightings_Returned"] = len(sights)
        if sights:
            fmt = lambda s: (f"{s.get('published', '')} | {s.get('source', '')} | "
                             f"{s.get('title', '')} | {s.get('url', '')}")
            row["RF_Latest_Sighting"] = fmt(sights[0])
            row["RF_Recent_Sightings"] = _join((fmt(s) for s in sights[:5]), " || ")
            row["RF_Sighting_Sources"] = "; ".join(
                f"{k} ({v})" for k, v in Counter(s.get("source") for s in sights if s.get("source")).most_common(8))
            row["RF_Sighting_Types"] = "; ".join(
                f"{k} ({v})" for k, v in Counter(s.get("type") for s in sights if s.get("type")).most_common(8))

    for key, col in (("threatLists", "RF_Threat_Lists"), ("enterpriseLists", "RF_Enterprise_Lists")):
        v = take(key)
        if isinstance(v, list):
            row[col] = _join(_names(v))

    if "intelCard" in data:
        row["RF_IntelCard"] = take("intelCard")

    an = take("analystNotes")
    if isinstance(an, list):
        row["RF_Analyst_Notes_Count"] = len(an)
        row["RF_Analyst_Notes"] = _join(_names(an)[:15])

    ai = take("aiInsights")
    if isinstance(ai, dict):
        row["RF_AI_Insights"] = ai.get("text") or ai.get("comment") or _j(ai)
    elif ai:
        row["RF_AI_Insights"] = str(ai)

    mt = take("metrics")
    if isinstance(mt, list):
        row["RF_Metrics"] = _join(f"{m.get('type')}={m.get('value')}" if isinstance(m, dict) else m for m in mt)

    cn = take("counts")
    if cn is not None:
        row["RF_Counts"] = _j(cn)

    rel = take("relatedEntities")
    if isinstance(rel, list):
        for grp in rel:
            if not isinstance(grp, dict):
                continue
            gname = str(grp.get("type", "Other")).replace("Related", "") or "Other"
            vals = []
            for e in grp.get("entities") or []:
                en = e.get("entity") if isinstance(e, dict) else None
                if isinstance(en, dict):
                    vals.append(f"{en.get('name') or en.get('id')} ({e.get('count', '?')})")
            if vals:
                row[f"RF_Related_{gname}"] = _join(vals[:25])

    lk = take("links")
    if lk:
        found = {}
        _collect_entities(lk, found)
        for t, names in sorted(found.items()):
            row[f"RF_Links_{t}"] = _join(sorted(names)[:40])

    if "fileHashes" in data:
        row["RF_File_Hashes"] = _join(take("fileHashes") or [])
    if "hashAlgorithm" in data:
        row["RF_Hash_Algorithm"] = take("hashAlgorithm")
    if "cpe" in data:
        row["RF_CPE"] = _join(take("cpe") or [])
    if "nvdDescription" in data:
        row["RF_NVD_Description"] = take("nvdDescription")
    for k in ("cvss", "cvssv3", "cvssv3_1"):
        if isinstance(data.get(k), dict):
            v = take(k)
            row[f"RF_{k.upper()}_Score"] = v.get("score")
            row[f"RF_{k.upper()}_Details"] = _j(v)

    # Everything else RF returned (dnsPortCert, scanner, riskyCIDRIPs, ...) as compact JSON
    for k, v in data.items():
        if k in handled or k in row:
            continue
        if isinstance(v, (dict, list)):
            row[f"RF_{k}"] = _j(v)
        else:
            row[f"RF_{k}"] = v
    return row


def flatten_soar(res: dict) -> dict:
    """Flatten one result from POST /soar/v3/enrichment into RF_* columns."""
    row = {}
    ent = res.get("entity")
    if isinstance(ent, dict):
        row["RF_Entity_ID"], row["RF_Entity_Name"] = ent.get("id"), ent.get("name")
        row["RF_Entity_Type"], row["RF_Entity_Description"] = ent.get("type"), ent.get("description")
    risk = res.get("risk") if isinstance(res.get("risk"), dict) else {}
    score = risk.get("score")
    row["RF_Risk_Score"] = score
    row["RF_Risk_Level"] = risk_level(score)
    row["RF_Criticality"] = risk.get("level")
    rule = risk.get("rule") if isinstance(risk.get("rule"), dict) else {}
    cnt, mx = rule.get("count"), rule.get("maxCount")
    if cnt is not None:
        row["RF_Rules_Triggered"] = f"{cnt}/{mx}" if mx is not None else str(cnt)
    row["RF_Most_Critical_Rule"] = rule.get("mostCritical")

    ev = rule.get("evidence")
    pairs = list(ev.items()) if isinstance(ev, dict) else [(None, v) for v in ev] if isinstance(ev, list) else []
    names, lines = [], []
    for k, v in pairs:
        if isinstance(v, dict):
            nm = v.get("rule") or k or ""
            names.append(str(nm))
            lines.append(f"[{v.get('level', '?')}] {nm}: {v.get('description') or v.get('evidenceString') or ''} "
                         f"(count={v.get('count', '?')}, {v.get('timestamp', '')})")
    if not names and isinstance(rule.get("summary"), list):
        names = [str(x) for x in rule["summary"]]
    row["RF_Risk_Rules"] = _join(names)
    row["RF_Risk_Evidence"] = _join(lines, " | ")

    ctx = risk.get("context")
    if ctx is not None:
        row["RF_Risk_Context"] = _j(ctx)
        if isinstance(ctx, dict):
            for k, v in ctx.items():
                if isinstance(v, dict) and "score" in v:
                    row[f"RF_Context_{k}_Score"] = v["score"]
    for k, v in risk.items():
        if k not in ("score", "level", "rule", "context"):
            row[f"RF_Risk_{k}"] = _j(v) if isinstance(v, (dict, list)) else v
    for k, v in res.items():
        if k not in ("entity", "risk"):
            row[f"RF_{k}"] = _j(v) if isinstance(v, (dict, list)) else v
    return row


# --------------------------------------------------------------------------- #
# Central lookup + orchestration
# --------------------------------------------------------------------------- #
@dataclass
class Config:
    token: str
    input_path: str
    output_path: str
    workers: int = 4
    timeout: int = 60
    skip_private: bool = True
    verify_ssl: bool = True
    proxy: str = ""
    risk_threshold: int = 0
    ca_bundle: str = ""
    deep_enrich: str = "risky"
    batch_size: int = 1000
    deep_min_score: object = None
    deep_max: int = 0
    placement: str = "adjacent"
    header_row: object = "auto"
    inline_columns: object = field(default_factory=lambda: INLINE_COLUMNS)
    all_sheet: bool = False


def _verify_setting(cfg: Config):
    if not cfg.verify_ssl:
        return False
    if cfg.ca_bundle:
        if not os.path.isfile(cfg.ca_bundle):
            raise RFFatalError(f"CA_BUNDLE_PATH file not found: {cfg.ca_bundle}")
        return cfg.ca_bundle
    return True


def make_client(cfg: Config, log=print) -> RFClient:
    return RFClient(cfg.token, cfg.timeout, _verify_setting(cfg), cfg.proxy, cfg.workers, log)


def classify_ioc(value: str):
    """Auto-detect the type of ONE indicator. Returns (kind, normalised_value) or (None, value)."""
    v = refang(str(value).strip())
    try:
        return "ip", str(ipaddress.ip_address(v))
    except ValueError:
        pass
    if CVE_RE.fullmatch(v):
        return "cve", v.upper()
    if HASH_RE.fullmatch(v):
        return "hash", v.lower()
    if URL_RE.fullmatch(v):
        return "url", v
    if DOMAIN_RE.fullmatch(v):
        return "domain", v.lower().rstrip(".")
    return None, v


def _assemble(kind, value, count, locs, status, payload):
    row = {
        "IOC": value,
        "IOC_Type": TYPE_LABEL[kind],
        "Source_Occurrences": count,
        "Source_Locations": "; ".join(locs) + (" ..." if count > len(locs) else ""),
        "RF_Lookup_UTC": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
    }
    raw = {"ioc": value, "type": kind, "status": status, "error": None, "soar": None, "connect": None}
    if status == "OK" and isinstance(payload, dict):
        row["RF_Status"] = "Enriched"
        row.update(flatten_soar(payload))
        raw["soar"] = payload
    elif status == "NOT_FOUND":
        row["RF_Status"] = "Not found in RF"
        row["RF_Risk_Level"] = "Not in Recorded Future"
    else:
        row["RF_Status"] = "Error"
        row["RF_Risk_Level"] = "Lookup Error"
        row["RF_Error"] = str(payload)
        raw["error"] = str(payload)
    return row, raw


def _merge_deep(row, raw, res):
    status, data, err = res
    if status == "OK" and isinstance(data, dict):
        d = flatten(data)
        if "RF_Risk_Score" not in d:
            d.pop("RF_Risk_Level", None)
        row.update({k: v for k, v in d.items() if v not in (None, "")})
        row["RF_Deep_Enrichment"] = "Done"
        raw["connect"] = data
    elif status == "NOT_FOUND":
        row["RF_Deep_Enrichment"] = "Not found in Connect API"
    else:
        row["RF_Deep_Enrichment"] = f"Failed: {err}"


def central_lookup(client: RFClient, value: str, kind: str = None, count: int = 1, locs=None, deep: bool = True):
    """
    Single-indicator entry point for your own code. Detects the type (unless `kind`
    is given), does the bulk-API risk lookup, optionally the deep Connect lookup,
    and returns (flat_row_dict, raw_record).
    """
    if kind is None:
        kind, value = classify_ioc(value)
        if kind is None:
            return ({"IOC": value, "IOC_Type": "Unknown", "RF_Status": "Unsupported IOC",
                     "RF_Risk_Level": "Lookup Error", "RF_Error": "Could not classify indicator"}, None)
    status, payload = client.bulk_enrich([(kind, value)], 1, lambda m: None)[(kind, value)]
    row, raw = _assemble(kind, value, count, locs or [], status, payload)
    if deep and status == "OK":
        _merge_deep(row, raw, client.lookup(kind, value))
    return row, raw


def is_risky(row, threshold):
    s_ = row.get("RF_Risk_Score")
    return isinstance(s_, (int, float)) and s_ > threshold


def enrich(cfg: Config, iocs, log, progress, cancel: threading.Event):
    client = make_client(cfg, log)
    total = len(iocs)

    log("Checking network / TLS path to api.recordedfuture.com ...")
    code = client.preflight()
    log(f"  reachable (HTTP {code}).")

    # ---------------- Phase 1: bulk ----------------
    log(f"Phase 1/2 - bulk risk lookup: {total} unique IOCs in batches of {min(cfg.batch_size, 1000)} ...")
    t0 = time.time()
    results = client.bulk_enrich([(i["kind"], i["value"]) for i in iocs], cfg.batch_size, log)
    log(f"  bulk lookup finished in {time.time() - t0:.1f}s")
    for w in client.warnings:
        log("  WARNING: " + w)
    progress(total, total)

    rows, raws, by_key = [], [], {}
    for it in iocs:
        key = (it["kind"], it["value"])
        status, payload = results.get(key, ("ERROR", "no response from RF"))
        row, raw = _assemble(it["kind"], it["value"], it["count"], it["locs"], status, payload)
        rows.append(row)
        raws.append(raw)
        by_key[key] = (row, raw)

    # ---------------- Phase 2: deep ----------------
    policy = str(cfg.deep_enrich).lower()
    deep_thr = cfg.risk_threshold if cfg.deep_min_score is None else cfg.deep_min_score
    if policy == "all":
        cand = [k for k, (r, _) in by_key.items() if r["RF_Status"] == "Enriched"]
    elif policy == "risky":
        cand = [k for k, (r, _) in by_key.items() if r["RF_Status"] == "Enriched" and is_risky(r, deep_thr)]
    else:
        cand = []
    # highest risk first; optionally cap the number of one-by-one deep lookups (saves API quota)
    cand.sort(key=lambda k: -(by_key[k][0].get("RF_Risk_Score") or 0))
    capped = 0
    if cfg.deep_max and len(cand) > cfg.deep_max:
        capped = len(cand) - cfg.deep_max
        cand_skipped_by_cap = set(cand[cfg.deep_max:])
        cand = cand[:cfg.deep_max]
    else:
        cand_skipped_by_cap = set()
    cand_set = set(cand)
    for k, (r, _) in by_key.items():
        if k in cand_set:
            continue
        if k in cand_skipped_by_cap:
            r["RF_Deep_Enrichment"] = f"Skipped (over DEEP_MAX_IOCS={cfg.deep_max} cap)"
        elif policy == "none":
            r["RF_Deep_Enrichment"] = "Skipped (deep enrichment off)"
        elif policy == "risky":
            r["RF_Deep_Enrichment"] = f"Skipped (score <= {deep_thr})"
        else:
            r["RF_Deep_Enrichment"] = "Skipped"
    if capped:
        log(f"  deep enrichment capped at {cfg.deep_max}; {capped} lower-risk IOC(s) get bulk data only.")

    if cand and not cancel.is_set():
        log(f"Phase 2/2 - deep Connect-API enrichment for {len(cand)} IOC(s) (policy: {policy}) ...")

        def deep(key):
            if cancel.is_set() or client.auth_failed.is_set():
                return key, None
            try:
                return key, client.lookup(*key)
            except AuthError:
                return key, None
            except RFFatalError as e:
                return key, ("ERROR", None, str(e)[:250])

        done = 0
        with ThreadPoolExecutor(max_workers=max(1, cfg.workers)) as ex:
            for fut in as_completed([ex.submit(deep, k) for k in cand]):
                key, res = fut.result()
                done += 1
                progress(done, len(cand))
                if res is not None:
                    _merge_deep(*by_key[key], res)
                if done % 10 == 0 or done == len(cand):
                    log(f"  {done}/{len(cand)} deep lookups")
    elif not cand:
        log("Phase 2/2 - nothing to deep-enrich.")

    log(f"API calls used: {client.stats['bulk_calls']} bulk call(s) covering {total} IOC(s) "
        f"+ {client.stats['deep_calls']} deep lookup(s).")
    if client.auth_failed.is_set():
        raise AuthError("Authentication failed (HTTP 401). Check that the API token is valid and active.")
    rows.sort(key=lambda r: (not isinstance(r.get("RF_Risk_Score"), (int, float)), -(r.get("RF_Risk_Score") or 0)))
    return rows, raws


# --------------------------------------------------------------------------- #
# Output: same sheets + enrichment next to the IOC columns + Summary
# --------------------------------------------------------------------------- #
FONT = "Arial"
HDR_FILL = PatternFill("solid", start_color="1F3864")
HDR_FONT = Font(name=FONT, bold=True, color="FFFFFF", size=10)
BODY_FONT = Font(name=FONT, size=10)
BOLD_FONT = Font(name=FONT, bold=True, size=10)


def _order_columns(rows, drop_empty=False):
    seen = OrderedDict()
    for r in rows:
        for k, v in r.items():
            if drop_empty and (v is None or v == ""):
                continue
            seen.setdefault(k, None)
    for must in ("IOC", "IOC_Type"):
        seen.setdefault(must, None)
    front = [c for c in PRIORITY_COLS if c in seen]
    return front + [c for c in seen if c not in front]


def _xl_clean(v):
    if isinstance(v, str):
        return ILLEGAL_CHARACTERS_RE.sub("", v)[:CELL_LIMIT]
    if isinstance(v, (dict, list)):
        return _j(v)
    return v


def _score_fill(score):
    if score is None:
        return None
    for limit, colour in ((90, "F8696B"), (65, "F4B183"), (25, "FFE699"), (5, "DDEBF7")):
        if score >= limit:
            return PatternFill("solid", start_color=colour)
    return PatternFill("solid", start_color="C6E0B4")


def _hdr(name):
    return name if name.startswith("RF_") else "RF_" + name


def _unique_title(wb, base):
    if base not in wb.sheetnames:
        return base
    name, n = ("RF_" + base)[:31], 2
    while name in wb.sheetnames:
        name = f"{('RF_' + base)[:27]}_{n}"
        n += 1
    return name


def plan_layout(ioc_cols, max_col, n_inline, placement):
    """Return (colmap {src_col: out_col}, blocks {src_ioc_col: first_enrichment_col}, total_cols)."""
    colmap, blocks = {}, {}
    if placement == "end":
        for c in range(1, max_col + 1):
            colmap[c] = c
        cur = max_col + 1
        for c in sorted(ioc_cols):
            blocks[c] = cur
            cur += n_inline
    else:
        cur = 1
        for c in range(1, max_col + 1):
            colmap[c] = cur
            cur += 1
            if c in ioc_cols:
                blocks[c] = cur
                cur += n_inline
    return colmap, blocks, cur - 1


def _sheet_inline_columns(setting, cmap, lookup):
    keys = {(k, v) for entries in cmap.values() for k, v, _ in entries}
    srows = [lookup[k] for k in keys if k in lookup]
    if isinstance(setting, (list, tuple)):
        wanted = list(setting)
    else:
        wanted = [c for c in _order_columns(srows, drop_empty=True)
                  if c not in ("Source_Occurrences", "Source_Locations", "RF_Lookup_UTC")]
        if "RF_Status" not in wanted:
            wanted.append("RF_Status")
    keep = {"IOC", "IOC_Type", "RF_Status"}
    return [c for c in wanted if c in keep or any(r.get(c) not in (None, "") for r in srows)]


def _inline_value(entries, lookup, col):
    """Value of enrichment column `col` for one source cell (which may hold several IOCs)."""
    parts = []
    for kind, val, why in entries:
        row = lookup.get((kind, val))
        if row is None:       # private/reserved address that was not sent to RF
            row = {"IOC": val, "IOC_Type": TYPE_LABEL[kind],
                   "RF_Status": f"Skipped ({why})" if why else "Not looked up",
                   "RF_Risk_Level": "Skipped" if why else "Not looked up"}
        parts.append((val, row.get(col)))
    if len(parts) == 1:
        return parts[0][1]
    if col == "IOC":
        return "\n".join(str(v) for _, v in parts if v)
    lines = [f"{val}: {v}" for val, v in parts if v not in (None, "")]
    return "\n".join(lines) or None


def _write_sheet(out_wb, ws, cfg, scan, lookup):
    """Copy one source sheet and write enrichment columns next to its IOC columns."""
    title = ws.title
    cmap = scan.cell_map.get(title, {})
    cols = sorted(scan.ioc_cols.get(title, ()))
    has_header = scan.header.get(title, True)
    shift = 1 if (cols and not has_header) else 0
    max_col, max_row = max(ws.max_column or 1, 1), max(ws.max_row or 1, 1)
    inline = _sheet_inline_columns(cfg.inline_columns, cmap, lookup) if cols else []
    colmap, blocks, total_cols = plan_layout(set(cols), max_col, len(inline), cfg.placement)

    new = out_wb.create_sheet(title)
    new.sheet_state = ws.sheet_state
    if ws.sheet_properties.tabColor is not None:
        new.sheet_properties.tabColor = copy(ws.sheet_properties.tabColor)

    # ---- 1. copy original cells + styles ---------------------------------- #
    for row in ws.iter_rows():
        for c in row:
            if c.value is None and not c.has_style:
                continue
            nc = new.cell(row=c.row + shift, column=colmap[c.column])
            if c.value is not None:
                nc.value = c.value
                if isinstance(c.value, str):
                    nc.data_type = "s"           # never let Excel treat original text as a formula
            if c.has_style:
                nc.font, nc.fill, nc.border = copy(c.font), copy(c.fill), copy(c.border)
                nc.alignment, nc.number_format = copy(c.alignment), c.number_format

    # ---- 2. dimensions, merges, panes, filter ------------------------------ #
    for key, dim in ws.column_dimensions.items():
        lo = dim.min or column_index_from_string(key)
        hi = min(dim.max or lo, max_col)
        for idx in range(lo, hi + 1):
            if idx in colmap and dim.width:
                nd = new.column_dimensions[get_column_letter(colmap[idx])]
                nd.width, nd.hidden = dim.width, dim.hidden
    for r_idx, dim in ws.row_dimensions.items():
        if dim.height:
            new.row_dimensions[r_idx + shift].height = dim.height
    for mr in list(ws.merged_cells.ranges):
        if cfg.placement != "end" and any(mr.min_col <= c < mr.max_col for c in blocks):
            continue                              # merge would swallow an enrichment block
        new.merge_cells(start_row=mr.min_row + shift, start_column=colmap[mr.min_col],
                        end_row=mr.max_row + shift, end_column=colmap[mr.max_col])
    if ws.freeze_panes:
        col_letter, row_i = coordinate_from_string(ws.freeze_panes)
        ci = column_index_from_string(col_letter)
        new_ci = colmap.get(ci, ci + total_cols - max_col)
        new.freeze_panes = f"{get_column_letter(new_ci)}{row_i + shift}"
    if ws.auto_filter.ref:
        new.auto_filter.ref = f"A1:{get_column_letter(total_cols)}{max_row + shift}"

    stats = {"sheet": title, "columns": ", ".join(get_column_letter(c) for c in cols) or "-",
             "cells": len(cmap), "unique": 0, "flagged": 0, "max": None, "no_data": 0, "skipped": 0}
    if not cols:
        return stats

    # ---- 3. headers --------------------------------------------------------- #
    widths = {}
    if shift:                                    # headerless sheet: label the original columns
        for c in range(1, max_col + 1):
            cell = new.cell(row=1, column=colmap[c], value=f"Column {get_column_letter(c)}")
            cell.font, cell.fill = BOLD_FONT, PatternFill("solid", start_color="D9D9D9")
    for c in cols:
        src = (str(ws.cell(row=1, column=c).value or "").strip() if has_header else "")
        src = src or f"Column {get_column_letter(c)}"
        suffix = f" [{src}]" if len(cols) > 1 else ""
        for j, name in enumerate(inline):
            text = _hdr(name) + suffix
            cell = new.cell(row=1, column=blocks[c] + j, value=text)
            cell.font, cell.fill = HDR_FONT, HDR_FILL
            widths[blocks[c] + j] = len(text)

    # ---- 4. enrichment values ---------------------------------------------- #
    for (r, c), entries in cmap.items():
        scores = [lookup[(k, v)].get("RF_Risk_Score") for k, v, _ in entries if (k, v) in lookup]
        scores = [s for s in scores if isinstance(s, (int, float))]
        fill = _score_fill(max(scores)) if scores else None
        for j, name in enumerate(inline):
            v = _xl_clean(_inline_value(entries, lookup, name))
            if v is None or v == "":
                continue
            col = blocks[c] + j
            cell = new.cell(row=r + shift, column=col, value=v)
            cell.font = BODY_FONT
            if isinstance(v, str):
                cell.data_type = "s"
                if "\n" in v:
                    cell.alignment = Alignment(wrap_text=True, vertical="top")
            if fill and name in ("RF_Risk_Score", "RF_Risk_Level"):
                cell.fill = fill
            ln = max(len(x) for x in str(v).split("\n"))
            widths[col] = max(widths.get(col, 0), ln)
    for col, w in widths.items():
        new.column_dimensions[get_column_letter(col)].width = max(12, min(60, w + 2))

    # ---- 5. stats for the Summary -------------------------------------------- #
    keys = {(k, v) for entries in cmap.values() for k, v, _ in entries}
    srows = [lookup[k] for k in keys if k in lookup]
    sc = [r_["RF_Risk_Score"] for r_ in srows if isinstance(r_.get("RF_Risk_Score"), (int, float))]
    stats.update(unique=len(keys), flagged=sum(1 for r_ in srows if is_risky(r_, cfg.risk_threshold)),
                 max=max(sc) if sc else None,
                 no_data=sum(1 for r_ in srows if r_.get("RF_Status") != "Enriched"),
                 skipped=sum(1 for k in keys if k not in lookup))
    return stats


def _add_flat_sheet(wb, title, cols, rows):
    ws = wb.create_sheet(title)
    for ci, name in enumerate(cols, 1):
        c = ws.cell(row=1, column=ci, value=name)
        c.font, c.fill = HDR_FONT, HDR_FILL
    for ri, r in enumerate(rows, 2):
        for ci, name in enumerate(cols, 1):
            v = _xl_clean(r.get(name))
            c = ws.cell(row=ri, column=ci, value=v)
            c.font = BODY_FONT
            if isinstance(v, str):
                c.data_type = "s"
        score = r.get("RF_Risk_Score")
        f = _score_fill(score) if isinstance(score, (int, float)) else None
        if f:
            for name in ("RF_Risk_Score", "RF_Risk_Level"):
                if name in cols:
                    ws.cell(row=ri, column=cols.index(name) + 1).fill = f
    for ci, name in enumerate(cols, 1):
        longest = max([len(str(name))] + [len(str(r.get(name, ""))) for r in rows[:200]])
        ws.column_dimensions[get_column_letter(ci)].width = max(10, min(60, longest + 2))
    ws.freeze_panes = "C2"
    ws.auto_filter.ref = ws.dimensions
    return ws


def _write_summary(wb, cfg, rows, skipped, stats):
    sm = wb.create_sheet(_unique_title(wb, "Summary"))
    sm.sheet_properties.tabColor = "1F3864"
    sec = Font(name=FONT, bold=True, size=11)

    def put(r, c, v, font=BODY_FONT, fill=None):
        cell = sm.cell(row=r, column=c, value=_xl_clean(v))
        cell.font = font
        if isinstance(cell.value, str):
            cell.data_type = "s"
        if fill:
            cell.fill = fill
        return cell

    def header(r, labels):
        for i, lab in enumerate(labels, 1):
            put(r, i, lab, HDR_FONT, HDR_FILL)

    thr = cfg.risk_threshold
    put(1, 1, "Recorded Future enrichment summary", Font(name=FONT, bold=True, size=14))
    put(2, 1, f"Source: {os.path.basename(cfg.input_path)}   |   Generated (UTC): "
              f"{datetime.now(timezone.utc):%Y-%m-%d %H:%M}   |   "
              "Risk bands: >=90 Very Malicious, 65-89 Malicious, 25-64 Suspicious, 5-24 Unusual, <5 No Threats",
        Font(name=FONT, italic=True, size=9))
    put(3, 1, f"Attention threshold: risk score > {thr}   |   counts below are UNIQUE IOCs "
              "(an IOC that appears on several sheets is counted once)", Font(name=FONT, italic=True, size=9))

    # ---- 1. risk level x type ------------------------------------------------ #
    types = list(TYPE_LABEL.values())
    levels = list(RISK_LEVELS) + ([SKIPPED_LEVEL] if skipped else [])
    cnt = Counter((r.get("RF_Risk_Level") or "No Risk Data", r["IOC_Type"]) for r in rows)
    for s_ in skipped:
        cnt[(SKIPPED_LEVEL, TYPE_LABEL[s_["kind"]])] += 1
    r = 5
    put(r, 1, "1. Unique IOCs by risk level and type", sec)
    r += 1
    header(r, ["Risk level"] + types + ["Total"])
    r += 1
    first = r
    for lvl in levels:
        put(r, 1, lvl)
        tot = 0
        for i, t in enumerate(types, 2):
            v = cnt.get((lvl, t), 0)
            tot += v
            put(r, i, v)
        put(r, len(types) + 2, tot)
        r += 1
    put(r, 1, "Total", BOLD_FONT)
    for i in range(2, len(types) + 3):
        put(r, i, sum(sm.cell(row=x, column=i).value for x in range(first, r)), BOLD_FONT)
    r += 1
    red = Font(name=FONT, bold=True, size=10, color="C00000")
    put(r, 1, f"Flagged (score > {thr})", red)
    for i, t in enumerate(types, 2):
        put(r, i, sum(1 for x in rows if x["IOC_Type"] == t and is_risky(x, thr)), red)
    put(r, len(types) + 2, sum(1 for x in rows if is_risky(x, thr)), red)
    r += 2

    # ---- 2. per sheet ------------------------------------------------------- #
    put(r, 1, "2. Results by sheet", sec)
    r += 1
    header(r, ["Sheet", "IOC columns", "Cells with IOCs", "Unique IOCs", f"Flagged (> {thr})",
               "Highest score", "Not found / errors", "Skipped (private)"])
    r += 1
    for s_ in stats:
        for i, key in enumerate(("sheet", "columns", "cells", "unique", "flagged", "max", "no_data", "skipped"), 1):
            put(r, i, s_[key] if s_[key] is not None else "-")
        r += 1
    r += 1

    # ---- 3. flagged IOCs ----------------------------------------------------- #
    flagged = sorted((x for x in rows if is_risky(x, thr)), key=lambda x: -x["RF_Risk_Score"])
    put(r, 1, f"3. Flagged IOCs (score > {thr}), highest first", sec)
    r += 1
    if not flagged:
        put(r, 1, f"No IOC had a risk score > {thr}.")
        r += 1
    else:
        header(r, ["IOC", "Type", "Score", "Risk level", "Rules triggered", "Occurrences",
                   "Most critical rule", "Where found (sheet!cell)"])
        r += 1
        for x in flagged[:SUMMARY_FLAG_CAP]:
            vals = [x["IOC"], x["IOC_Type"], x["RF_Risk_Score"], x.get("RF_Risk_Level"),
                    x.get("RF_Rules_Triggered"), x.get("Source_Occurrences"),
                    x.get("RF_Most_Critical_Rule"), x.get("Source_Locations")]
            for i, v in enumerate(vals, 1):
                cell = put(r, i, v if v is not None else "")
                if i in (3, 4):
                    f = _score_fill(x["RF_Risk_Score"])
                    if f:
                        cell.fill = f
            r += 1
        if len(flagged) > SUMMARY_FLAG_CAP:
            put(r, 1, f"... {len(flagged) - SUMMARY_FLAG_CAP} more flagged IOCs not listed here "
                      "- see the enrichment columns on the data sheets.", Font(name=FONT, italic=True, size=9))
    for col, w in zip("ABCDEFGH", (40, 16, 16, 18, 18, 18, 42, 50)):
        sm.column_dimensions[col].width = w
    return sm


def make_output_path(folder, input_path):
    stem = os.path.splitext(os.path.basename(input_path))[0]
    folder = folder or os.path.dirname(os.path.abspath(input_path))
    return os.path.join(folder, f"{stem}_RF_enriched_{datetime.now():%Y%m%d_%H%M%S}.xlsx")


def default_output_path(input_path):
    return make_output_path(OUTPUT_FOLDER, input_path)


def write_output(cfg: Config, scan: Scan, rows, raws, log):
    out = cfg.output_path
    base, ext = os.path.splitext(out)
    if ext.lower() != ".xlsx":
        out = base + ".xlsx"
        cfg.output_path = out
    os.makedirs(os.path.dirname(os.path.abspath(out)), exist_ok=True)

    lookup = {(LABEL_TO_KIND[r["IOC_Type"]], r["IOC"]): r for r in rows}
    out_wb = Workbook()
    out_wb.remove(out_wb.active)
    stats = []
    for ws in scan.wb.worksheets:
        stats.append(_write_sheet(out_wb, ws, cfg, scan, lookup))
        log(f"  wrote sheet '{ws.title}'")
    if cfg.all_sheet:
        _add_flat_sheet(out_wb, _unique_title(out_wb, "All_Enriched"), _order_columns(rows), rows)
    _write_summary(out_wb, cfg, rows, scan.skipped, stats)

    for i, s in enumerate(out_wb.worksheets):          # open on the first visible sheet only
        s.sheet_view.tabSelected = False
    for i, s in enumerate(out_wb.worksheets):
        if s.sheet_state == "visible":
            out_wb.active = i
            s.sheet_view.tabSelected = True
            break
    out_wb.save(out)

    raw_path = os.path.splitext(out)[0] + "_raw.jsonl"
    with open(raw_path, "w", encoding="utf-8") as f:
        for rec in raws:
            f.write(json.dumps(rec, ensure_ascii=False, default=str) + "\n")
    log(f"Wrote enriched workbook : {out}")
    log(f"Wrote raw RF responses  : {raw_path}")
    return out


def summarize_iocs(iocs, skipped):
    c = Counter(TYPE_LABEL[i["kind"]] for i in iocs)
    s = ", ".join(f"{v} {k}" for k, v in c.items()) or "none"
    return f"{len(iocs)} unique IOCs ({s})" + (f"; {len(skipped)} private/reserved IPs skipped" if skipped else "")


def _make_cfg(token, inp, out, **over):
    base = dict(workers=WORKERS, timeout=TIMEOUT, skip_private=SKIP_PRIVATE_IPS, verify_ssl=VERIFY_SSL,
                proxy=PROXY, risk_threshold=RISK_SCORE_THRESHOLD, ca_bundle=CA_BUNDLE_PATH,
                deep_enrich=DEEP_ENRICH, batch_size=BATCH_SIZE, deep_min_score=DEEP_MIN_SCORE,
                deep_max=DEEP_MAX_IOCS, placement=ENRICH_PLACEMENT,
                header_row=HEADER_ROW, inline_columns=INLINE_COLUMNS, all_sheet=ADD_ALL_ENRICHED_SHEET)
    base.update(over)
    return Config(token=token, input_path=inp, output_path=out, **base)


# --------------------------------------------------------------------------- #
# GUI
# --------------------------------------------------------------------------- #
if HAVE_TK:
    class App(tk.Tk):
        def __init__(self):
            super().__init__()
            self.title("Recorded Future IOC Enrichment - Threat Hunting")
            self.geometry("860x680")
            self.minsize(760, 600)
            self.q = queue.Queue()
            self.cancel = threading.Event()
            self.worker = None
            self._confirm_evt = threading.Event()
            self._confirm_ok = False

            self.v_token = tk.StringVar(value=API_TOKEN or os.environ.get("RF_API_TOKEN", ""))
            self.v_show = tk.BooleanVar(value=False)
            self.v_in = tk.StringVar(value=INPUT_FILE if os.path.isfile(INPUT_FILE) else "")
            self.v_out = tk.StringVar(value=default_output_path(INPUT_FILE) if os.path.isfile(INPUT_FILE) else "")
            self.v_workers = tk.IntVar(value=WORKERS)
            self.v_timeout = tk.IntVar(value=TIMEOUT)
            self.v_ca = tk.StringVar(value=CA_BUNDLE_PATH)
            self.v_priv = tk.BooleanVar(value=SKIP_PRIVATE_IPS)
            self.v_ssl = tk.BooleanVar(value=VERIFY_SSL)
            self.v_proxy = tk.StringVar(value=PROXY or os.environ.get("HTTPS_PROXY", ""))
            self._build()
            self.after(100, self._poll)

        def _build(self):
            pad = {"padx": 8, "pady": 5}
            box = ttk.LabelFrame(self, text=" Configuration ")
            box.pack(fill="x", padx=12, pady=(12, 6))
            box.columnconfigure(1, weight=1)

            ttk.Label(box, text="RF API token").grid(row=0, column=0, sticky="w", **pad)
            self.e_token = ttk.Entry(box, textvariable=self.v_token, show="\u2022")
            self.e_token.grid(row=0, column=1, sticky="ew", **pad)
            ttk.Checkbutton(box, text="Show", variable=self.v_show,
                            command=lambda: self.e_token.config(show="" if self.v_show.get() else "\u2022")
                            ).grid(row=0, column=2, **pad)

            ttk.Label(box, text="Input file").grid(row=1, column=0, sticky="w", **pad)
            ttk.Entry(box, textvariable=self.v_in).grid(row=1, column=1, sticky="ew", **pad)
            ttk.Button(box, text="Browse\u2026", command=self._pick_in).grid(row=1, column=2, **pad)

            ttk.Label(box, text="Output file").grid(row=2, column=0, sticky="w", **pad)
            ttk.Entry(box, textvariable=self.v_out).grid(row=2, column=1, sticky="ew", **pad)
            ttk.Button(box, text="Browse\u2026", command=self._pick_out).grid(row=2, column=2, **pad)

            ttk.Label(box, text="Proxy (optional)").grid(row=3, column=0, sticky="w", **pad)
            ttk.Entry(box, textvariable=self.v_proxy).grid(row=3, column=1, sticky="ew", **pad)
            ttk.Label(box, text="http://host:port", foreground="#777").grid(row=3, column=2, sticky="w", **pad)

            ttk.Label(box, text="CA bundle (optional)").grid(row=4, column=0, sticky="w", **pad)
            ttk.Entry(box, textvariable=self.v_ca).grid(row=4, column=1, sticky="ew", **pad)
            ttk.Button(box, text="Browse\u2026", command=self._pick_ca).grid(row=4, column=2, **pad)

            opt = ttk.Frame(box)
            opt.grid(row=5, column=0, columnspan=3, sticky="w", padx=8, pady=(2, 8))
            ttk.Label(opt, text="Parallel requests").pack(side="left")
            ttk.Spinbox(opt, from_=1, to=10, width=4, textvariable=self.v_workers).pack(side="left", padx=(4, 14))
            ttk.Label(opt, text="Timeout (s)").pack(side="left")
            ttk.Spinbox(opt, from_=5, to=120, width=5, textvariable=self.v_timeout).pack(side="left", padx=(4, 14))
            ttk.Checkbutton(opt, text="Skip private/reserved IPs", variable=self.v_priv).pack(side="left", padx=6)
            ttk.Checkbutton(opt, text="Verify SSL", variable=self.v_ssl).pack(side="left", padx=6)

            btns = ttk.Frame(self)
            btns.pack(fill="x", padx=12, pady=4)
            self.b_start = ttk.Button(btns, text="Start enrichment", command=self._start)
            self.b_start.pack(side="left")
            self.b_cancel = ttk.Button(btns, text="Cancel", command=self.cancel.set, state="disabled")
            self.b_cancel.pack(side="left", padx=8)
            ttk.Button(btns, text="Quit", command=self.destroy).pack(side="right")

            self.pb = ttk.Progressbar(self, mode="determinate")
            self.pb.pack(fill="x", padx=12, pady=(6, 2))
            self.lbl = ttk.Label(self, text="Idle")
            self.lbl.pack(anchor="w", padx=12)

            self.log_box = scrolledtext.ScrolledText(self, height=16, state="disabled", font=("Consolas", 9))
            self.log_box.pack(fill="both", expand=True, padx=12, pady=(4, 12))

        # -- helpers ------------------------------------------------------- #
        def _pick_in(self):
            p = filedialog.askopenfilename(
                title="Select IOC file",
                filetypes=[("IOC files", "*.xlsx *.xlsm *.csv *.tsv *.txt"), ("All files", "*.*")])
            if p:
                self.v_in.set(p)
                if not self.v_out.get():
                    self.v_out.set(default_output_path(p))

        def _pick_ca(self):
            p = filedialog.askopenfilename(title="Select CA bundle / root certificate",
                                           filetypes=[("Certificates", "*.pem *.crt *.cer"), ("All files", "*.*")])
            if p:
                self.v_ca.set(p)

        def _pick_out(self):
            p = filedialog.asksaveasfilename(
                title="Save enriched workbook as", defaultextension=".xlsx",
                filetypes=[("Excel workbook", "*.xlsx")])
            if p:
                self.v_out.set(p)

        def _log(self, msg):
            self.q.put(("log", msg))

        def _append(self, msg):
            self.log_box.config(state="normal")
            self.log_box.insert("end", f"[{datetime.now():%H:%M:%S}] {msg}\n")
            self.log_box.see("end")
            self.log_box.config(state="disabled")

        def _poll(self):
            try:
                while True:
                    kind, *rest = self.q.get_nowait()
                    if kind == "log":
                        self._append(rest[0])
                    elif kind == "progress":
                        done, total = rest
                        self.pb.config(maximum=max(total, 1), value=done)
                        self.lbl.config(text=f"{done} / {total} IOCs processed")
                    elif kind == "confirm":
                        self._confirm_ok = messagebox.askyesno(
                            "Confirm enrichment",
                            f"Found {rest[0]}.\n\nEach IOC counts as an API lookup against your "
                            "Recorded Future quota. Continue?")
                        self._confirm_evt.set()
                    elif kind == "error":
                        self._append("ERROR: " + rest[0])
                        messagebox.showerror("Error", rest[0])
                        self._finish()
                    elif kind == "done":
                        messagebox.showinfo("Finished", rest[0])
                        self._finish()
            except queue.Empty:
                pass
            self.after(100, self._poll)

        def _finish(self):
            self.b_start.config(state="normal")
            self.b_cancel.config(state="disabled")
            self.lbl.config(text="Idle")

        def _start(self):
            token, inp, out = self.v_token.get().strip(), self.v_in.get().strip(), self.v_out.get().strip()
            if not token:
                return messagebox.showwarning("Missing token", "Please enter your Recorded Future API token.")
            if not inp or not os.path.isfile(inp):
                return messagebox.showwarning("Missing input", "Please select a valid input file.")
            if not out:
                out = default_output_path(inp)
                self.v_out.set(out)
            cfg = _make_cfg(token, inp, out,
                            workers=int(self.v_workers.get()), timeout=int(self.v_timeout.get()),
                            skip_private=self.v_priv.get(), verify_ssl=self.v_ssl.get(),
                            proxy=self.v_proxy.get().strip(), ca_bundle=self.v_ca.get().strip())
            self.cancel.clear()
            self._confirm_evt.clear()
            self.b_start.config(state="disabled")
            self.b_cancel.config(state="normal")
            self.pb.config(value=0)
            self.worker = threading.Thread(target=self._run, args=(cfg,), daemon=True)
            self.worker.start()

        def _run(self, cfg: Config):
            try:
                self._log(f"Reading {cfg.input_path} ...")
                scan = scan_input(cfg.input_path, cfg.skip_private, cfg.header_row, self._log)
                if not scan.iocs:
                    self.q.put(("error", "No IOCs were found in the input file."))
                    return
                summary = summarize_iocs(scan.iocs, scan.skipped)
                self._log("Found " + summary)
                self.q.put(("confirm", summary))
                self._confirm_evt.wait()
                if not self._confirm_ok:
                    self._log("Cancelled by user before any API calls were made.")
                    self.q.put(("done", "Cancelled - no lookups were performed."))
                    return
                rows, raws = enrich(cfg, scan.iocs, self._log,
                                    lambda d, t: self.q.put(("progress", d, t)), self.cancel)
                out = write_output(cfg, scan, rows, raws, self._log)
                note = " (partial - cancelled)" if self.cancel.is_set() else ""
                self.q.put(("done", f"Enriched {len(rows)} of {len(scan.iocs)} unique IOCs{note}.\n\nSaved to:\n{out}"))
            except Exception as e:
                self.q.put(("error", f"{type(e).__name__}: {e}"))


# --------------------------------------------------------------------------- #
# Headless run (uses the USER CONFIGURATION block) + entry point
# --------------------------------------------------------------------------- #
def run_headless(args):
    token = (API_TOKEN or os.environ.get("RF_API_TOKEN", "")).strip()
    if not token:
        token = getpass.getpass("Recorded Future API token (hidden): ").strip()
    inp = (args.input or INPUT_FILE or "").strip().strip('"')
    if not token:
        sys.exit("No API token supplied. Set API_TOKEN in the config block or RF_API_TOKEN in the environment.")
    if not inp or not os.path.isfile(inp):
        sys.exit(f"Input file not found: '{inp}'.  Edit INPUT_FILE in the config block, pass -i, or use --gui.")
    folder = args.output_folder if args.output_folder is not None else OUTPUT_FOLDER
    cfg = _make_cfg(token, inp, make_output_path(folder, inp))
    log = lambda m: print(m, flush=True)

    log(f"Reading {cfg.input_path} ...")
    scan = scan_input(cfg.input_path, cfg.skip_private, cfg.header_row, log)
    if not scan.iocs:
        sys.exit("No IOCs found in the input file.")
    log("Found " + summarize_iocs(scan.iocs, scan.skipped))
    if ASK_CONFIRMATION and not args.yes:
        if input("Each unique IOC uses an RF API lookup. Proceed? [y/N] ").strip().lower() != "y":
            sys.exit("Aborted - no lookups were made.")
    rows, raws = enrich(cfg, scan.iocs, log, lambda d, t: None, threading.Event())
    write_output(cfg, scan, rows, raws, log)
    flagged = sum(1 for r in rows if is_risky(r, cfg.risk_threshold))
    log(f"Done. {len(rows)} unique IOCs enriched, {flagged} with risk score > {cfg.risk_threshold}.")


def main():
    ap = argparse.ArgumentParser(description="Enrich mixed IOCs in every sheet of a workbook with Recorded Future. "
                                             "Settings come from the USER CONFIGURATION block at the top of this file.")
    ap.add_argument("--gui", action="store_true", help="show the pop-up configuration window")
    ap.add_argument("-i", "--input", help="override INPUT_FILE")
    ap.add_argument("-o", "--output-folder", help="override OUTPUT_FOLDER")
    ap.add_argument("-y", "--yes", action="store_true", help="skip the confirmation prompt")
    args = ap.parse_args()

    if (args.gui or USE_GUI) and HAVE_TK:
        try:
            App().mainloop()
            return
        except tk.TclError:
            print("No display available - continuing in headless mode.")
    try:
        run_headless(args)
    except (AuthError, RFFatalError) as e:
        sys.exit(f"\nERROR: {e}")


if __name__ == "__main__":
    main()

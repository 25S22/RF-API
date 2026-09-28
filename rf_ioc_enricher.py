"""
rf_ioc_enricher.py - Recorded Future IOC enrichment for threat hunting
======================================================================

What it does
------------
1. Opens a small configuration window asking for:
      * Recorded Future API token (masked, never written to disk or logs)
      * Input file  (.xlsx / .xlsm / .csv / .tsv / .txt)
      * Output file (.xlsx or .csv)
2. Extracts every IOC it can find in the input (every cell of every sheet for
   Excel, every field for CSV, every line for TXT). Defanged indicators such as
   hxxp://evil[.]com or 1[.]2[.]3[.]4 are re-fanged automatically.
      IPv4 / IPv6, domains, URLs, MD5 / SHA1 / SHA256, CVE IDs
3. Enriches each unique IOC through the Recorded Future Connect API (v2),
   requesting ALL enrichment fields the API exposes for that entity type
   (discovered at runtime via GET /v2/<type>/fields, with safe fallbacks).
4. Writes an enriched workbook (Enriched / Summary / Skipped sheets) or CSV,
   plus a sidecar  <output>_raw.jsonl  containing the untouched API responses
   so nothing RF returns is ever lost.

Requirements:  pip install requests openpyxl      (tkinter ships with Python)

Usage
-----
    1. Edit the USER CONFIGURATION block just below the imports
       (API_TOKEN, INPUT_FILE, OUTPUT_FOLDER ...), then run:
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

Security notes
--------------
* The token is only held in memory. It is never printed, logged or saved.
* Cell values written to CSV/XLSX are sanitised against spreadsheet formula
  injection (RF text fields can contain attacker-influenced strings).
* IOC values are only sent to api.recordedfuture.com (or your proxy).
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
from dataclasses import dataclass
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
    from openpyxl.utils import get_column_letter
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

# Input file: .xlsx / .xlsm / .csv / .tsv / .txt
# It may freely MIX IPs, domains, URLs, file hashes (MD5/SHA1/SHA256) and CVEs -
# every cell / line is scanned and each indicator is routed to the right RF
# endpoint automatically.  Windows example:  r"C:\Hunts\iocs.xlsx"
INPUT_FILE = "iocs.xlsx"

# Folder where results are written (created if missing). "" = same folder as input.
OUTPUT_FOLDER = "rf_output"
OUTPUT_FORMAT = "xlsx"          # "xlsx" (multi-sheet) or "csv" (one file per sheet)

# Any IOC whose RF risk score is GREATER THAN this value is copied into its own
# attention sheet: Risk_IPs, Risk_Domains, Risk_Hashes, Risk_URLs, Risk_CVEs.
RISK_SCORE_THRESHOLD = 0

# Behaviour
SKIP_PRIVATE_IPS = True         # don't send RFC1918 / loopback / reserved IPs to RF
ASK_CONFIRMATION = True         # show the IOC count and ask before using API quota
WORKERS = 4                     # parallel requests (RF rate-limits; keep <= 5-10)
TIMEOUT = 30                    # seconds per HTTP request
VERIFY_SSL = True               # set False only if a corporate proxy breaks TLS
PROXY = ""                      # e.g. "http://proxy.corp:8080"
USE_GUI = False                 # True = show the pop-up configuration window instead

# --------------------------------------------------------------------------- #
# Constants
# --------------------------------------------------------------------------- #
RF_BASE = "https://api.recordedfuture.com/v2"
USER_AGENT = "ThreatHunt-RF-Enricher/1.0"
CELL_LIMIT = 32000  # Excel hard limit is 32,767 chars per cell

ENDPOINT = {"ip": "ip", "domain": "domain", "url": "url",
            "hash": "hash", "cve": "vulnerability"}
TYPE_LABEL = {"ip": "IP", "domain": "Domain", "url": "URL",
              "hash": "Hash", "cve": "CVE"}

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

PRIORITY_COLS = [
    "IOC", "IOC_Type", "RF_Risk_Level", "RF_Risk_Score", "RF_Criticality_Label",
    "RF_Rules_Triggered", "RF_Risk_Rules", "RF_Status", "RF_Error",
    "RF_Country", "RF_City", "RF_Continent", "RF_ASN", "RF_Organization",
    "RF_CIDR", "RF_First_Seen", "RF_Last_Seen", "RF_Threat_Lists",
    "RF_Enterprise_Lists", "RF_IntelCard", "RF_AI_Insights", "RF_Risk_Evidence",
    "Source_Occurrences", "Source_Locations", "RF_Lookup_UTC",
]


class AuthError(RuntimeError):
    pass


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


def iter_cells(path: str):
    """Yield (location, text) for every non-empty cell / field / line."""
    ext = os.path.splitext(path)[1].lower()
    if ext in (".xlsx", ".xlsm"):
        wb = load_workbook(path, read_only=True, data_only=True)
        try:
            for ws in wb.worksheets:
                for r, row in enumerate(ws.iter_rows(values_only=True), 1):
                    for c, val in enumerate(row, 1):
                        if val is not None and str(val).strip():
                            yield f"{ws.title}!{get_column_letter(c)}{r}", str(val)
        finally:
            wb.close()
    elif ext in (".csv", ".tsv"):
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
                        yield f"{get_column_letter(c)}{r}", val
    elif ext in (".txt", ".log", ".list", ".ioc", ""):
        with open(path, encoding="utf-8-sig", errors="replace") as f:
            for n, line in enumerate(f, 1):
                if line.strip():
                    yield f"line {n}", line
    else:
        raise ValueError(f"Unsupported input type '{ext}'. Use .xlsx, .csv or .txt "
                         "(save legacy .xls files as .xlsx first).")


def collect_iocs(path: str, skip_private: bool, log):
    """Scan the file; return (iocs, skipped). iocs is a list of dicts."""
    occ: "OrderedDict[tuple, list]" = OrderedDict()   # key -> [count, [locs]]
    skipped: "OrderedDict[tuple, list]" = OrderedDict()
    cells = 0
    for loc, text in iter_cells(path):
        cells += 1
        for kind, val, reason in extract_iocs(text):
            key = (kind, val)
            if reason and skip_private:
                rec = skipped.setdefault(key, [reason, 0, []])
                rec[1] += 1
                if len(rec[2]) < 5:
                    rec[2].append(loc)
                continue
            rec = occ.setdefault(key, [0, []])
            rec[0] += 1
            if len(rec[1]) < 10 and loc not in rec[1]:
                rec[1].append(loc)
    log(f"Scanned {cells:,} non-empty cells/lines.")
    iocs = [{"kind": k[0], "value": k[1], "count": v[0], "locs": v[1]}
            for k, v in occ.items()]
    skipped_list = [{"kind": k[0], "value": k[1], "reason": v[0], "count": v[1], "locs": v[2]}
                    for k, v in skipped.items()]
    return iocs, skipped_list


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


class RFClient:
    def __init__(self, token, timeout=30, verify=True, proxy="", workers=4, log=print):
        self.timeout = timeout
        self.log = log
        self.s = requests.Session()
        adapter = HTTPAdapter(pool_connections=workers, pool_maxsize=workers * 2)
        self.s.mount("https://", adapter)
        self.s.headers.update({"X-RFToken": token, "X-RF-User-Agent": USER_AGENT,
                               "Accept": "application/json"})
        if proxy:
            self.s.proxies = {"http": proxy, "https": proxy}
        self.s.verify = verify
        if not verify:
            try:
                import urllib3
                urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            except Exception:
                pass
        self._lock = threading.Lock()
        self._tiers = {}            # kind -> list of field lists (most -> least)
        self._good_tier = {}        # kind -> index of tier that last worked
        self.auth_failed = threading.Event()

    # -- low level --------------------------------------------------------- #
    def _request(self, url, params=None):
        last = None
        for attempt in range(1, 6):
            if self.auth_failed.is_set():
                raise AuthError("Authentication failed")
            try:
                r = self.s.get(url, params=params, timeout=self.timeout)
            except requests.RequestException as e:
                last = e
                time.sleep(min(2 ** attempt, 20))
                continue
            if r.status_code == 429:
                try:
                    wait = float(r.headers.get("Retry-After", ""))
                except ValueError:
                    wait = min(2 ** attempt * 2, 60)
                time.sleep(wait)
                last = "HTTP 429 (rate limited)"
                continue
            if r.status_code >= 500:
                last = f"HTTP {r.status_code}"
                time.sleep(min(2 ** attempt, 20))
                continue
            return r
        raise RuntimeError(f"Request failed after retries: {last}")

    # -- field discovery --------------------------------------------------- #
    def _field_tiers(self, kind):
        with self._lock:
            if kind in self._tiers:
                return self._tiers[kind]
        discovered = []
        try:
            r = self._request(f"{RF_BASE}/{ENDPOINT[kind]}/fields")
            if r.status_code == 200:
                discovered = _parse_field_list(r.json())
            elif r.status_code == 401:
                self.auth_failed.set()
        except AuthError:
            raise
        except Exception:
            pass
        tiers = []
        if discovered:
            tiers.append(discovered)
            self.log(f"[{TYPE_LABEL[kind]}] requesting all {len(discovered)} RF fields.")
        else:
            self.log(f"[{TYPE_LABEL[kind]}] field discovery unavailable, using built-in field set.")
        tiers += [FALLBACK_FIELDS[kind], MINIMAL_FIELDS]
        with self._lock:
            self._tiers[kind] = tiers
        return tiers

    # -- public ------------------------------------------------------------ #
    def lookup(self, kind, value):
        """Return (status, data, error). status: OK | NOT_FOUND | ERROR"""
        ident = quote(value, safe="") if kind == "url" else value
        url = f"{RF_BASE}/{ENDPOINT[kind]}/{ident}"
        tiers = self._field_tiers(kind)
        start = self._good_tier.get(kind, 0)
        err = ""
        for i in range(start, len(tiers)):
            r = self._request(url, {"fields": ",".join(tiers[i])})
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
                continue        # try a smaller field set
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


# --------------------------------------------------------------------------- #
# Central lookup + orchestration
# --------------------------------------------------------------------------- #
@dataclass
class Config:
    token: str
    input_path: str
    output_path: str
    workers: int = 4
    timeout: int = 30
    skip_private: bool = True
    verify_ssl: bool = True
    proxy: str = ""
    risk_threshold: int = 0


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


def central_lookup(client: "RFClient", value: str, kind: str = None, count: int = 1, locs=None):
    """
    THE single entry point for enrichment. Give it any indicator; it detects the
    type (unless `kind` is supplied), routes it to the matching Recorded Future
    endpoint (ip / domain / url / hash / vulnerability), and returns
    (flat_row_dict, raw_record).  Raises AuthError on a 401.
    """
    locs = locs or []
    if kind is None:
        kind, value = classify_ioc(value)
        if kind is None:
            return ({"IOC": value, "IOC_Type": "Unknown", "RF_Status": "Unsupported IOC",
                     "RF_Risk_Level": "Lookup Error", "RF_Error": "Could not classify indicator"}, None)
    row = {
        "IOC": value,
        "IOC_Type": TYPE_LABEL[kind],
        "Source_Occurrences": count,
        "Source_Locations": "; ".join(locs) + (" ..." if count > len(locs) else ""),
        "RF_Lookup_UTC": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
    }
    try:
        status, data, err = client.lookup(kind, value)
    except AuthError:
        raise
    except Exception as e:                       # network etc.
        status, data, err = "ERROR", None, str(e)[:300]

    row["RF_Status"] = {"OK": "Enriched", "NOT_FOUND": "Not found in RF", "ERROR": "Error"}[status]
    if status == "OK" and isinstance(data, dict):
        row.update(flatten(data))
    elif status == "NOT_FOUND":
        row["RF_Risk_Level"] = "Not in Recorded Future"
    else:
        row["RF_Risk_Level"] = "Lookup Error"
        row["RF_Error"] = err
    raw = {"ioc": value, "type": kind, "status": status, "error": err, "data": data}
    return row, raw


def enrich(cfg: Config, iocs, log, progress, cancel: threading.Event):
    client = RFClient(cfg.token, cfg.timeout, cfg.verify_ssl, cfg.proxy, cfg.workers, log)
    rows, raws = [], []
    total = len(iocs)

    def work(item):
        if cancel.is_set() or client.auth_failed.is_set():
            return None
        try:
            return central_lookup(client, item["value"], item["kind"], item["count"], item["locs"])
        except AuthError:
            return None

    done = 0
    with ThreadPoolExecutor(max_workers=max(1, cfg.workers)) as ex:
        for fut in as_completed([ex.submit(work, it) for it in iocs]):
            res = fut.result()
            done += 1
            progress(done, total)
            if res is not None:
                rows.append(res[0])
                raws.append(res[1])
            if done % 10 == 0 or done == total:
                log(f"  {done}/{total} looked up")

    if client.auth_failed.is_set():
        raise AuthError("Authentication failed (HTTP 401). Check that the API token is valid and active.")
    rows.sort(key=lambda r: (not isinstance(r.get("RF_Risk_Score"), (int, float)), -(r.get("RF_Risk_Score") or 0)))
    return rows, [r for r in raws if r]


# --------------------------------------------------------------------------- #
# Output
# --------------------------------------------------------------------------- #
RISK_SHEETS = OrderedDict([("ip", "Risk_IPs"), ("domain", "Risk_Domains"), ("hash", "Risk_Hashes"),
                           ("url", "Risk_URLs"), ("cve", "Risk_CVEs")])


def is_risky(row, threshold):
    s_ = row.get("RF_Risk_Score")
    return isinstance(s_, (int, float)) and s_ > threshold


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


def _csv_safe(v):
    if isinstance(v, str) and v and v[0] in "=+-@\t\r":
        return "'" + v
    return v


def _xl_clean(v):
    if isinstance(v, str):
        return ILLEGAL_CHARACTERS_RE.sub("", v)[:CELL_LIMIT]
    if isinstance(v, (dict, list)):
        return _j(v)
    return v


def _write_csv(path, cols, rows):
    with open(path, "w", newline="", encoding="utf-8-sig") as f:
        w = csv.DictWriter(f, fieldnames=cols, extrasaction="ignore")
        w.writeheader()
        for r in rows:
            w.writerow({k: _csv_safe(_xl_clean(v)) for k, v in r.items()})


def write_output(cfg: Config, rows, raws, skipped, log):
    out = cfg.output_path
    os.makedirs(os.path.dirname(os.path.abspath(out)), exist_ok=True)
    base, ext = os.path.splitext(out)
    ext = ext.lower()
    risky = {k: [r for r in rows if r.get("IOC_Type") == TYPE_LABEL[k] and is_risky(r, cfg.risk_threshold)]
             for k in RISK_SHEETS}

    if ext == ".csv":
        _write_csv(out, _order_columns(rows), rows)
        for k, rs in risky.items():
            if rs:
                p = f"{base}_{RISK_SHEETS[k].lower()}.csv"
                _write_csv(p, _order_columns(rs, True), rs)
                log(f"Wrote attention file    : {p}  ({len(rs)} rows)")
    else:
        if ext not in (".xlsx", ".xlsm"):
            out = base + ".xlsx"
            cfg.output_path = out
        _write_xlsx(cfg, out, rows, risky, skipped)
        for k, rs in risky.items():
            if rs:
                log(f"  sheet {RISK_SHEETS[k]:<13}: {len(rs)} IOC(s) with score > {cfg.risk_threshold}")

    raw_path = os.path.splitext(out)[0] + "_raw.jsonl"
    with open(raw_path, "w", encoding="utf-8") as f:
        for rec in raws:
            f.write(json.dumps(rec, ensure_ascii=False, default=str) + "\n")
    log(f"Wrote enriched output   : {out}")
    log(f"Wrote raw RF responses  : {raw_path}")
    if not any(risky.values()):
        log(f"No IOC had a risk score > {cfg.risk_threshold}, so no Risk_* sheets were created.")
    return out


FONT = "Arial"
HDR_FILL = PatternFill("solid", start_color="1F3864")
HDR_FONT = Font(name=FONT, bold=True, color="FFFFFF", size=10)
BODY_FONT = Font(name=FONT, size=10)


def _score_fill(score):
    if score is None:
        return None
    for limit, colour in ((90, "F8696B"), (65, "F4B183"), (25, "FFE699"), (5, "DDEBF7")):
        if score >= limit:
            return PatternFill("solid", start_color=colour)
    return PatternFill("solid", start_color="C6E0B4")


def _add_sheet(wb, title, cols, rows, tab=None):
    ws = wb.create_sheet(title)
    if tab:
        ws.sheet_properties.tabColor = tab
    for ci, name in enumerate(cols, 1):
        c = ws.cell(row=1, column=ci, value=name)
        c.font, c.fill = HDR_FONT, HDR_FILL
    for ri, r in enumerate(rows, 2):
        for ci, name in enumerate(cols, 1):
            v = _xl_clean(r.get(name))
            c = ws.cell(row=ri, column=ci, value=v)
            c.font = BODY_FONT
            if isinstance(v, str):
                c.data_type = "s"           # never let Excel treat RF text as a formula
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


def _write_xlsx(cfg, out, rows, risky, skipped):
    wb = Workbook()
    sm = wb.active
    sm.title = "Summary"
    all_cols = _order_columns(rows)

    # Attention sheets first (one per IOC type), then the full table
    for kind, title in RISK_SHEETS.items():
        if risky[kind]:
            _add_sheet(wb, title, _order_columns(risky[kind], drop_empty=True), risky[kind], tab="C00000")
    _add_sheet(wb, "All_Enriched", all_cols, rows)

    if skipped:
        sk = wb.create_sheet("Skipped")
        for ci, h in enumerate(["IOC", "IOC_Type", "Reason", "Occurrences", "Example_Locations"], 1):
            c = sk.cell(row=1, column=ci, value=h)
            c.font, c.fill = HDR_FONT, HDR_FILL
        for ri, s_ in enumerate(skipped, 2):
            vals = [s_["value"], TYPE_LABEL[s_["kind"]], s_["reason"], s_["count"], "; ".join(s_["locs"])]
            for ci, v in enumerate(vals, 1):
                c = sk.cell(row=ri, column=ci, value=_xl_clean(v))
                c.font = BODY_FONT
                if isinstance(v, str):
                    c.data_type = "s"
        for ci, w in enumerate([45, 12, 28, 13, 50], 1):
            sk.column_dimensions[get_column_letter(ci)].width = w

    # ---- Summary: live COUNTIFS formulas over All_Enriched ---------------
    sm["A1"] = "Recorded Future enrichment summary"
    sm["A1"].font = Font(name=FONT, bold=True, size=14)
    sm["A2"] = (f"Source: {os.path.basename(cfg.input_path)}   |   Generated (UTC): "
                f"{datetime.now(timezone.utc):%Y-%m-%d %H:%M}   |   "
                "Risk bands: >=90 Very Malicious, 65-89 Malicious, 25-64 Suspicious, 5-24 Unusual, <5 No Threats")
    sm["A2"].font = Font(name=FONT, italic=True, size=9)
    sm["A3"] = "Attention threshold (score >)"
    sm["A3"].font = Font(name=FONT, bold=True, size=10)
    sm["B3"] = cfg.risk_threshold                       # editable input (blue)
    sm["B3"].font = Font(name=FONT, size=10, color="0000FF")
    sm["C3"] = "Set in RISK_SCORE_THRESHOLD; the Risk_* sheets list IOCs above it. Editing this cell re-counts row 'Flagged'."
    sm["C3"].font = Font(name=FONT, italic=True, size=9)

    types = list(TYPE_LABEL.values())
    hr = 5
    sm.cell(row=hr, column=1, value="Risk level")
    for i, t in enumerate(types, 2):
        sm.cell(row=hr, column=i, value=t)
    sm.cell(row=hr, column=len(types) + 2, value="Total")
    for c in range(1, len(types) + 3):
        cell = sm.cell(row=hr, column=c)
        cell.font, cell.fill = HDR_FONT, HDR_FILL
    tcol = get_column_letter(all_cols.index("IOC_Type") + 1)
    lcol = get_column_letter(all_cols.index("RF_Risk_Level") + 1) if "RF_Risk_Level" in all_cols else None
    scol = get_column_letter(all_cols.index("RF_Risk_Score") + 1) if "RF_Risk_Score" in all_cols else None
    last = get_column_letter(len(types) + 1)
    first_lvl = hr + 1
    for ri, lvl in enumerate(RISK_LEVELS, first_lvl):
        sm.cell(row=ri, column=1, value=lvl).font = BODY_FONT
        for ci in range(2, len(types) + 2):
            L = get_column_letter(ci)
            f = (f"=COUNTIFS(All_Enriched!${tcol}:${tcol},{L}${hr},All_Enriched!${lcol}:${lcol},$A{ri})"
                 if lcol else 0)
            sm.cell(row=ri, column=ci, value=f).font = BODY_FONT
        sm.cell(row=ri, column=len(types) + 2, value=f"=SUM(B{ri}:{last}{ri})").font = BODY_FONT
    tr = first_lvl + len(RISK_LEVELS)
    sm.cell(row=tr, column=1, value="Total").font = Font(name=FONT, bold=True, size=10)
    for ci in range(2, len(types) + 3):
        L = get_column_letter(ci)
        sm.cell(row=tr, column=ci, value=f"=SUM({L}{first_lvl}:{L}{tr - 1})").font = Font(name=FONT, bold=True, size=10)
    fr = tr + 1
    sm.cell(row=fr, column=1, value="Flagged (score > threshold)").font = Font(name=FONT, bold=True, size=10, color="C00000")
    for ci in range(2, len(types) + 2):
        L = get_column_letter(ci)
        f = (f'=COUNTIFS(All_Enriched!${tcol}:${tcol},{L}${hr},All_Enriched!${scol}:${scol},">"&$B$3)'
             if scol else 0)
        sm.cell(row=fr, column=ci, value=f).font = Font(name=FONT, bold=True, size=10, color="C00000")
    sm.cell(row=fr, column=len(types) + 2, value=f"=SUM(B{fr}:{last}{fr})").font = Font(name=FONT, bold=True, size=10, color="C00000")
    sm.column_dimensions["A"].width = 30
    for ci in range(2, len(types) + 3):
        sm.column_dimensions[get_column_letter(ci)].width = 12
    wb.save(out)


# --------------------------------------------------------------------------- #
# Shared pipeline (used by both GUI and CLI)
# --------------------------------------------------------------------------- #
def make_output_path(folder, input_path, fmt="xlsx"):
    stem = os.path.splitext(os.path.basename(input_path))[0]
    fmt = "csv" if str(fmt).lower() == "csv" else "xlsx"
    folder = folder or os.path.dirname(os.path.abspath(input_path))
    return os.path.join(folder, f"{stem}_RF_enriched_{datetime.now():%Y%m%d_%H%M%S}.{fmt}")


def default_output_path(input_path):
    return make_output_path(OUTPUT_FOLDER, input_path, OUTPUT_FORMAT)


def summarize_iocs(iocs, skipped):
    c = Counter(TYPE_LABEL[i["kind"]] for i in iocs)
    s = ", ".join(f"{v} {k}" for k, v in c.items()) or "none"
    return f"{len(iocs)} unique IOCs ({s})" + (f"; {len(skipped)} private/reserved IPs skipped" if skipped else "")


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

            opt = ttk.Frame(box)
            opt.grid(row=4, column=0, columnspan=3, sticky="w", padx=8, pady=(2, 8))
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

        def _pick_out(self):
            p = filedialog.asksaveasfilename(
                title="Save enriched output as", defaultextension=".xlsx",
                filetypes=[("Excel workbook", "*.xlsx"), ("CSV", "*.csv")])
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
            cfg = Config(token=token, input_path=inp, output_path=out,
                         workers=int(self.v_workers.get()), timeout=int(self.v_timeout.get()),
                         skip_private=self.v_priv.get(), verify_ssl=self.v_ssl.get(),
                         proxy=self.v_proxy.get().strip(),
                         risk_threshold=RISK_SCORE_THRESHOLD)
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
                iocs, skipped = collect_iocs(cfg.input_path, cfg.skip_private, self._log)
                if not iocs:
                    self.q.put(("error", "No IOCs were found in the input file."))
                    return
                summary = summarize_iocs(iocs, skipped)
                self._log("Found " + summary)
                self.q.put(("confirm", summary))
                self._confirm_evt.wait()
                if not self._confirm_ok:
                    self._log("Cancelled by user before any API calls were made.")
                    self.q.put(("done", "Cancelled - no lookups were performed."))
                    return
                rows, raws = enrich(cfg, iocs, self._log,
                                    lambda d, t: self.q.put(("progress", d, t)), self.cancel)
                out = write_output(cfg, rows, raws, skipped, self._log)
                note = " (partial - cancelled)" if self.cancel.is_set() else ""
                self.q.put(("done", f"Enriched {len(rows)} of {len(iocs)} IOCs{note}.\n\nSaved to:\n{out}"))
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
    cfg = Config(token=token, input_path=inp, output_path=make_output_path(folder, inp, OUTPUT_FORMAT),
                 workers=WORKERS, timeout=TIMEOUT, skip_private=SKIP_PRIVATE_IPS,
                 verify_ssl=VERIFY_SSL, proxy=PROXY, risk_threshold=RISK_SCORE_THRESHOLD)
    log = lambda m: print(m, flush=True)

    log(f"Reading {cfg.input_path} ...")
    iocs, skipped = collect_iocs(cfg.input_path, cfg.skip_private, log)
    if not iocs:
        sys.exit("No IOCs found in the input file.")
    log("Found " + summarize_iocs(iocs, skipped))
    if ASK_CONFIRMATION and not args.yes:
        if input("Each IOC uses an RF API lookup. Proceed? [y/N] ").strip().lower() != "y":
            sys.exit("Aborted - no lookups were made.")
    rows, raws = enrich(cfg, iocs, log, lambda d, t: None, threading.Event())
    write_output(cfg, rows, raws, skipped, log)
    flagged = sum(1 for r in rows if is_risky(r, cfg.risk_threshold))
    log(f"Done. {len(rows)} enriched, {flagged} with risk score > {cfg.risk_threshold}.")


def main():
    ap = argparse.ArgumentParser(description="Enrich mixed IOCs with Recorded Future. "
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
    run_headless(args)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
vt_enrich.py - Quota-safe VirusTotal (API v3) enrichment: XLSX/TXT in -> XLSX out.

Design goals (in priority order)
  1. NEVER waste a call:
       * lookups only (GET) - nothing is ever uploaded or submitted for scanning
       * each unique indicator is queried at most once (de-duplicated + normalised)
       * invalid values / private IPs / file names are rejected locally, no call
       * every answer is written to an on-disk cache IMMEDIATELY, so a crash,
         Ctrl+C or re-run never repeats a call (cache is shared between input files)
       * HTTP 404 ("not in VT") is cached too - it is an answer, and it cost a call
       * no hidden retries: urllib3 retries are off, every attempt is counted
  2. NEVER break the rate limits:
       * sliding window (default 4 calls / 61 s) AND an even gap between calls
       * limiter state survives restarts (a re-run 5 s later still waits correctly)
       * persistent daily (UTC) and monthly (UTC) counters; the run stops cleanly
         when the local budget is exhausted
       * HTTP 429 -> cool-down + limited retries, then a clean stop (no hammering)
  3. Always produce the XLSX, even when stopped early (unfinished rows = PENDING).

Usage
  Easiest: fill in API_KEY, INPUT_FILE (and SSL_CERT_PATH if you need one) in the
  USER CONFIGURATION block below, then run:   python vt_enrich.py
  Or use command-line options (they override the block):
  export VT_API_KEY=xxxxxxxx
  python vt_enrich.py -i indicators.txt  -o results.xlsx
  python vt_enrich.py -i indicators.xlsx -o results.xlsx --column A
  python vt_enrich.py -i indicators.txt --dry-run        # plan only, zero calls

Input   : .txt (one indicator per line, '#' comments allowed) or .xlsx/.xlsm
          (all cells of all sheets, or --sheet / --column to narrow it down).
          Supported: IPv4/IPv6, domains, URLs (with http/https/ftp scheme),
          MD5 / SHA-1 / SHA-256. Defanged input (hxxp://, example[.]com) is fixed.
Requires: Python 3.9+, `pip install requests openpyxl`
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import ipaddress
import json
import logging
import os
import re
import sys
import time
from collections import OrderedDict, deque
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable, Optional
from urllib.parse import quote, urlsplit, urlunsplit

import requests
from openpyxl import Workbook, load_workbook
from openpyxl.cell.cell import ILLEGAL_CHARACTERS_RE
from openpyxl.formatting.rule import FormulaRule
from openpyxl.styles import Alignment, Font, PatternFill
from openpyxl.utils import column_index_from_string, get_column_letter

# =============================================================================
#  USER CONFIGURATION  -  edit these values, then just run:  python vt_enrich.py
#  (command-line options such as -i / -o / --api-key / --ca-bundle override them)
# =============================================================================
API_KEY = ""          # your VirusTotal API key, e.g. "0123abcd..."  (falls back to env VT_API_KEY)
INPUT_FILE = r""      # .txt or .xlsx, e.g. r"C:\iocs\indicators.xlsx" or "/home/me/iocs.txt"
OUTPUT_FILE = r""     # optional; empty = <input name>_vt_enriched.xlsx next to the input
SSL_CERT_PATH = r""   # optional CA bundle (.pem/.crt) or folder, e.g. your company proxy's
                      # root certificate; empty = Python's default trusted certificates
# =============================================================================

log = logging.getLogger("vt_enrich")

VT_BASE = "https://www.virustotal.com/api/v3"
ENDPOINTS = {"ip": "ip_addresses", "domain": "domains", "file": "files", "url": "urls"}
GUI_PATHS = {"ip": "ip-address", "domain": "domain", "file": "file", "url": "url"}
TS_FMT = "%Y-%m-%dT%H:%M:%SZ"

# ----------------------------------------------------------------------------
# Input normalisation / classification
# ----------------------------------------------------------------------------

HASH_RE = re.compile(r"^(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})$", re.I)
HASH_PREFIX_RE = re.compile(r"^(?:md5|sha-?1|sha-?256)\s*[:=]\s*([a-f0-9]{32,64})$", re.I)
IPV4_PORT_RE = re.compile(r"^(\d{1,3}(?:\.\d{1,3}){3}):\d{1,5}$")
IPV6_PORT_RE = re.compile(r"^\[([0-9a-f:.]+)\]:\d{1,5}$", re.I)
DOMAIN_PORT_RE = re.compile(r"^([^\s:/@]+\.[^\s:/@]+):\d{1,5}$")
CIDR_RE = re.compile(r"^[0-9a-f:.]+/\d{1,3}$", re.I)
DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?\.)+"
    r"(?:[a-z]{2,63}|xn--[a-z0-9-]{1,59})$",
    re.I,
)
SCHEME_RE = re.compile(r"^[a-z][a-z0-9+.\-]*://", re.I)
ZERO_WIDTH_RE = re.compile("[\u200b\u200c\u200d\u2060\ufeff]")
ODD_SPACE_RE = re.compile("[\u00a0\u202f\u2007\u2009]")
SPLIT_RE = re.compile(r"[\s,;|]+")
# Extensions that are NOT real TLDs: such "domains" are almost surely file names.
FILE_EXT_DENY = {
    "exe", "dll", "txt", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "pdf", "jpg",
    "jpeg", "png", "gif", "bat", "log", "tmp", "csv", "json", "xml", "htm", "html",
    "msi", "scr", "vbs", "lnk", "iso", "bin", "dat", "cfg", "ini",
}


def refang(s: str) -> str:
    s = ZERO_WIDTH_RE.sub("", s)
    s = ODD_SPACE_RE.sub(" ", s)
    s = s.strip().strip("\"'<>").strip()
    s = re.sub(r"^hxxp", "http", s, flags=re.I)
    s = re.sub(r"^fxp", "ftp", s, flags=re.I)
    for old, new in (("[://]", "://"), ("[:]", ":"), ("[.]", "."), ("(.)", "."),
                     ("{.}", "."), ("[dot]", "."), ("(dot)", ".")):
        s = re.sub(re.escape(old), new, s, flags=re.I)
    return s.strip()


def normalize_url(v: str) -> str:
    """Lower-case scheme + host, punycode the host. Path/query/fragment untouched.
    (VirusTotal canonicalises server-side; this only stops us paying twice for
    HTTP://Example.com/x and http://example.com/x.)"""
    try:
        p = urlsplit(v)
        userinfo, at, hostport = p.netloc.rpartition("@")
        m = re.match(r"^(\[[^\]]+\]|[^:]*)(:\d*)?$", hostport)
        if not m:
            return v
        host, port = m.group(1), m.group(2) or ""
        if not host.startswith("["):
            try:
                host = host.encode("idna").decode("ascii")
            except UnicodeError:
                pass
        netloc = f"{userinfo}{at}{host.lower()}{port}"
        return urlunsplit((p.scheme.lower(), netloc, p.path, p.query, p.fragment))
    except ValueError:
        return v


def classify(raw: str, include_private: bool = False):
    """Return (kind, normalised_value, reason).  kind is None => do not query."""
    v = refang(raw)
    if not v:
        return None, "", "empty value"
    m = HASH_PREFIX_RE.match(v)  # sha256:abcd..., MD5=abcd...
    if m:
        v = m.group(1)
    if HASH_RE.match(v):
        return "file", v.lower(), ""

    m = IPV4_PORT_RE.match(v) or IPV6_PORT_RE.match(v)  # 1.2.3.4:443, [::1]:80
    if m:
        v = m.group(1)
    cand = v[1:-1] if v.startswith("[") and v.endswith("]") else v
    try:
        ip = ipaddress.ip_address(cand)
    except ValueError:
        ip = None
    if ip is not None:
        if not include_private and (not ip.is_global or ip.is_multicast):
            return None, v, "non-public IP address (not queried; use --include-private)"
        return "ip", ip.compressed, ""

    if SCHEME_RE.match(v):
        scheme = v.split("://", 1)[0].lower()
        if scheme not in ("http", "https", "ftp"):
            return None, v, f"unsupported URL scheme '{scheme}'"
        if re.search(r"\s", v):
            return None, v, "URL contains whitespace"
        try:
            host = urlsplit(v).hostname
        except ValueError:
            host = None
        if not host:
            return None, v, "URL has no host"
        return "url", normalize_url(v), ""

    if "@" in v:
        return None, v, "email address / credentials - not supported (query the domain instead)"
    if CIDR_RE.match(v):
        return None, v, "CIDR range - VirusTotal looks up single IP addresses"
    if "/" in v:
        return None, v, "path without scheme - add http:// or https:// so the URL is exact"

    m = DOMAIN_PORT_RE.match(v)  # example.com:8443
    if m:
        v = m.group(1)
    d = v.rstrip(".").lower()
    if not d.isascii():  # internationalised domain -> punycode
        try:
            d = d.encode("idna").decode("ascii")
        except UnicodeError:
            return None, v, "invalid internationalised domain name"
    if DOMAIN_RE.match(d):
        if d.rsplit(".", 1)[1] in FILE_EXT_DENY:
            return None, v, "looks like a file name, not a domain"
        return "domain", d, ""
    return None, v, "not a recognised IP, domain, URL or file hash"


@dataclass
class Entry:
    kind: str
    value: str
    source: str
    raw: str = ""
    count: int = 1

    @property
    def key(self) -> str:
        return f"{self.kind}:{self.value}"


def read_inputs(path: Path, sheet: Optional[str], columns: Optional[str]):
    """Yield (raw_text, source_location) for every non-empty candidate."""
    if not path.is_file():
        raise SystemExit(f"Input file not found: {path}")
    ext = path.suffix.lower()
    out = []
    if ext in (".xlsx", ".xlsm", ".xltx", ".xltm"):
        wanted = None
        if columns:
            try:
                wanted = {column_index_from_string(c.strip().upper())
                          for c in columns.split(",") if c.strip()}
            except ValueError:
                raise SystemExit(f"--column must be letters such as A or A,C (got '{columns}')")
        wb = load_workbook(path, read_only=True, data_only=True)
        try:
            names = [sheet] if sheet else list(wb.sheetnames)
            for name in names:
                if name not in wb.sheetnames:
                    raise SystemExit(f"Sheet '{name}' not found. Available: {wb.sheetnames}")
                ws = wb[name]
                try:
                    ws.reset_dimensions()  # some writers store a wrong used-range
                except AttributeError:
                    pass
                for r, row in enumerate(ws.iter_rows(values_only=True), start=1):
                    for c, val in enumerate(row, start=1):
                        if val is None or (wanted and c not in wanted):
                            continue
                        s = str(val).strip()
                        if s:
                            out.append((s, f"{name}!{get_column_letter(c)}{r}"))
        finally:
            wb.close()
    elif ext == ".xls":
        raise SystemExit("Legacy .xls is not supported - save it as .xlsx first.")
    else:
        with open(path, encoding="utf-8-sig", errors="replace") as fh:
            for n, line in enumerate(fh, start=1):
                s = re.sub(r"\s+#.*$", "", line.strip())  # inline ' # comment'
                if s and not s.startswith("#"):
                    out.append((s, f"line {n}"))
    return out


def build_entries(items, include_private: bool):
    entries: "OrderedDict[str, Entry]" = OrderedDict()
    skipped = []

    def register(piece, source, result):
        kind, value, reason = result
        if kind is None:
            skipped.append((source, piece, reason))
            return
        e = Entry(kind, value, source, raw=piece)
        if e.key in entries:
            entries[e.key].count += 1
        else:
            entries[e.key] = e

    for raw, source in items:
        whole = classify(raw, include_private)
        if whole[0] is None:
            # A cell/line may hold several indicators ("1.1.1.1, 8.8.8.8" or one per
            # line inside a cell). Split only if that yields at least one valid one.
            parts = [p for p in SPLIT_RE.split(refang(raw)) if p]
            if len(parts) > 1:
                results = [(p, classify(p, include_private)) for p in parts]
                if any(r[0] for _, r in results):
                    for p, r in results:
                        if r[0] is None:
                            r = (None, r[1], "part of a multi-value cell; " + r[2])
                        register(p, source, r)
                    continue
        register(raw, source, whole)
    return list(entries.values()), skipped


# ----------------------------------------------------------------------------
# Persistent cache (JSON lines; later lines win)
# ----------------------------------------------------------------------------

def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Cache:
    def __init__(self, path: Path):
        self.path = path
        self.data: dict = {}
        path.parent.mkdir(parents=True, exist_ok=True)
        bad = 0
        if path.exists():
            with open(path, encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        rec = json.loads(line)
                        self.data[rec["key"]] = rec
                    except (ValueError, KeyError, TypeError):
                        bad += 1  # e.g. a half-written last line after a crash
        if bad:
            log.warning("Cache: ignored %d unreadable line(s) in %s", bad, path)

    def put(self, rec: dict) -> None:
        self.data[rec["key"]] = rec
        with open(self.path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
            fh.flush()
            os.fsync(fh.fileno())

    def fresh(self, key: str, max_age_days: float, now: datetime) -> Optional[dict]:
        rec = self.data.get(key)
        if rec is None:
            return None
        if max_age_days <= 0:
            return rec
        try:
            t = datetime.strptime(rec["queried_at"], TS_FMT).replace(tzinfo=timezone.utc)
        except (KeyError, ValueError):
            return None
        return rec if now - t <= timedelta(days=max_age_days) else None


# ----------------------------------------------------------------------------
# Rate limiter + persistent quota counters
# ----------------------------------------------------------------------------

class RateLimiter:
    """Sliding window (max_calls per window) plus an even minimum gap.

    Timestamps are taken when a response (or error) COMPLETES, i.e. never earlier
    than the moment the server received the request, so the spacing seen by the
    server is always >= the spacing enforced here.
    """

    def __init__(self, per_minute: int = 4, margin: float = 1.0,
                 clock: Callable[[], float] = time.monotonic,
                 sleep: Callable[[float], None] = time.sleep):
        self.max_calls = max(1, per_minute)
        self.window = 60.0 + margin
        self.min_gap = self.window / self.max_calls
        self.clock, self.sleep = clock, sleep
        self._stamps: deque = deque(maxlen=self.max_calls)

    def seed(self, ages_seconds) -> None:
        """Pre-load calls made by a previous run (age = seconds ago)."""
        now = self.clock()
        for age in sorted(ages_seconds, reverse=True):
            if 0 <= age < self.window:
                self._stamps.append(now - age)

    def wait(self) -> None:
        while True:
            now = self.clock()
            need = 0.0
            if self._stamps:
                need = max(need, self._stamps[-1] + self.min_gap - now)
            if len(self._stamps) == self.max_calls:
                need = max(need, self._stamps[0] + self.window - now)
            if need <= 0:
                return
            log.debug("rate limit: sleeping %.1fs", need)
            self.sleep(need)

    def record(self) -> None:
        self._stamps.append(self.clock())


class QuotaTracker:
    """Daily/monthly (UTC) call counters persisted per API key, plus the recent
    call timestamps that seed the rate limiter on the next start."""

    def __init__(self, path: Path, key_fp: str, daily_limit: int, monthly_limit: int,
                 keep_stamps: int = 10):
        self.path, self.fp = path, key_fp
        self.daily_limit, self.monthly_limit = daily_limit, monthly_limit
        self.keep = keep_stamps
        path.parent.mkdir(parents=True, exist_ok=True)
        try:
            self.all = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(self.all, dict):
                self.all = {}
        except (OSError, ValueError):
            self.all = {}
        self.s = self.all.setdefault(
            key_fp, {"day": "", "day_count": 0, "month": "", "month_count": 0, "recent_calls": []})
        self._roll()

    def _roll(self) -> None:
        today = utcnow().strftime("%Y-%m-%d")
        if self.s.get("day") != today:
            self.s["day"], self.s["day_count"] = today, 0
        if self.s.get("month") != today[:7]:
            self.s["month"], self.s["month_count"] = today[:7], 0

    def _save(self) -> None:
        tmp = self.path.with_suffix(self.path.suffix + ".tmp")
        tmp.write_text(json.dumps(self.all, indent=1), encoding="utf-8")
        os.replace(tmp, self.path)

    @property
    def day_used(self) -> int:
        self._roll()
        return self.s["day_count"]

    @property
    def month_used(self) -> int:
        self._roll()
        return self.s["month_count"]

    def remaining(self) -> float:
        self._roll()
        rem = float("inf")
        if self.daily_limit > 0:
            rem = min(rem, self.daily_limit - self.s["day_count"])
        if self.monthly_limit > 0:
            rem = min(rem, self.monthly_limit - self.s["month_count"])
        return rem

    def recent_ages(self):
        now = time.time()
        return [max(0.0, now - t) for t in self.s.get("recent_calls", [])]

    def consume(self) -> None:
        """Called BEFORE a request is sent: a call that dies mid-flight still counts."""
        self._roll()
        self.s["day_count"] += 1
        self.s["month_count"] += 1
        self._save()

    def refund(self) -> None:
        """Undo consume() for a call that never reached VirusTotal (TLS handshake failed)."""
        self._roll()
        self.s["day_count"] = max(0, self.s["day_count"] - 1)
        self.s["month_count"] = max(0, self.s["month_count"] - 1)
        self._save()

    def stamp(self) -> None:
        self.s["recent_calls"] = (self.s.get("recent_calls", []) + [time.time()])[-self.keep:]
        self._save()

    def sync_from_server(self, daily, monthly) -> None:
        """daily / monthly = (allowed, used) from VirusTotal, or None."""
        self._roll()
        for name, pair, count_key, attr in (
                ("daily", daily, "day_count", "daily_limit"),
                ("monthly", monthly, "month_count", "monthly_limit")):
            if not pair:
                continue
            allowed, used = pair
            self.s[count_key] = max(self.s[count_key], used)
            if allowed < 10 ** 8:  # huge numbers mean "unlimited" (premium)
                cur = getattr(self, attr)
                setattr(self, attr, allowed if cur <= 0 else min(cur, allowed))
            log.info("Server quota (%s): %s/%s used", name, used, allowed)
        self._save()


# ----------------------------------------------------------------------------
# VirusTotal client
# ----------------------------------------------------------------------------

class AbortRun(Exception):
    """Unrecoverable (bad key / forbidden): stop immediately."""


class QuotaExhausted(Exception):
    """Local budget used up, or VirusTotal keeps answering 429."""


def _first(d: dict, *path):
    for p in path:
        if not isinstance(d, dict):
            return None
        d = d.get(p)
    return d


def extract_fields(kind: str, obj: dict) -> dict:
    a = obj.get("attributes") or {}
    st = a.get("last_analysis_stats") or {}
    cats = a.get("categories")
    cat_txt = ", ".join(sorted({str(v) for v in cats.values()})) if isinstance(cats, dict) else ""
    f = {
        "malicious": st.get("malicious"), "suspicious": st.get("suspicious"),
        "harmless": st.get("harmless"), "undetected": st.get("undetected"),
        "timeout": st.get("timeout"),
        "reputation": a.get("reputation"),
        "last_analysis_date": a.get("last_analysis_date"),
        "tags": ", ".join(str(t) for t in (a.get("tags") or [])),
        "votes_harmless": _first(a, "total_votes", "harmless"),
        "votes_malicious": _first(a, "total_votes", "malicious"),
    }
    if kind == "ip":
        f.update(country=a.get("country"), as_owner=a.get("as_owner"), asn=a.get("asn"),
                 network=a.get("network"))
    elif kind == "domain":
        f.update(registrar=a.get("registrar"), creation_date=a.get("creation_date"),
                 categories=cat_txt)
    elif kind == "file":
        ptc = a.get("popular_threat_classification") or {}
        pcat = ptc.get("popular_threat_category") or []
        f.update(meaningful_name=a.get("meaningful_name"), type_description=a.get("type_description"),
                 size=a.get("size"), md5=a.get("md5"), sha1=a.get("sha1"), sha256=a.get("sha256"),
                 threat_label=ptc.get("suggested_threat_label"),
                 threat_categories=", ".join(str(x.get("value")) for x in pcat[:3] if isinstance(x, dict)),
                 first_submission_date=a.get("first_submission_date"),
                 times_submitted=a.get("times_submitted"))
    elif kind == "url":
        tn = a.get("threat_names") or []
        f.update(title=a.get("title"), last_final_url=a.get("last_final_url"),
                 last_http_response_code=a.get("last_http_response_code"),
                 first_submission_date=a.get("first_submission_date"),
                 times_submitted=a.get("times_submitted"), categories=cat_txt,
                 threat_label=", ".join(str(t) for t in tn))
    return f


class VTClient:
    def __init__(self, api_key: str, limiter: RateLimiter, quota: QuotaTracker,
                 session=None, max_attempts: int = 3, max_429_retries: int = 2,
                 cooldown: float = 65.0, sleep: Callable[[float], None] = time.sleep,
                 verify=True):
        self.key = api_key
        self.limiter, self.quota = limiter, quota
        self.session = session or requests.Session()  # default adapter: 0 hidden retries
        # True, or a path to a CA bundle / certificate folder. It is ALSO passed on every
        # request: `requests` lets the REQUESTS_CA_BUNDLE / CURL_CA_BUNDLE environment
        # variables override session.verify, which would silently ignore SSL_CERT_PATH.
        self.verify = verify
        self.session.verify = verify
        self.session.headers.update({"x-apikey": api_key, "accept": "application/json",
                                     "user-agent": "vt-enrich/1.0"})
        self.max_attempts, self.max_429_retries = max_attempts, max_429_retries
        self.cooldown, self.sleep = cooldown, sleep
        self.calls = 0
        self.call_cap = 0  # hard cap on calls for this run (incl. retries); 0 = none

    # -- helpers ------------------------------------------------------------
    def _redact(self, text: str) -> str:
        return text.replace(self.key, "***")

    @staticmethod
    def _error_message(resp) -> str:
        try:
            return str(resp.json()["error"]["message"])[:200]
        except Exception:
            return (getattr(resp, "text", "") or "")[:200]

    def _send(self, url: str):
        if self.quota.remaining() <= 0:
            raise QuotaExhausted("local quota budget reached")
        if self.call_cap and self.calls >= self.call_cap:
            raise QuotaExhausted("--max-calls reached")
        self.limiter.wait()
        self.quota.consume()
        self.calls += 1
        try:
            return self.session.get(url, timeout=(10, 30), verify=self.verify), None
        except requests.exceptions.SSLError as ex:
            if "CERTIFICATE_VERIFY_FAILED" in str(ex):
                self.quota.refund()  # handshake failed: nothing reached VirusTotal
                raise AbortRun(
                    "TLS certificate verification failed (typical behind a company proxy). "
                    "Set SSL_CERT_PATH at the top of the script (or --ca-bundle) to your "
                    "organisation's root certificate (.pem/.crt). Detail: "
                    + self._redact(str(ex))[-220:])
            return None, self._redact(f"{type(ex).__name__}: {ex}")
        except requests.RequestException as ex:
            return None, self._redact(f"{type(ex).__name__}: {ex}")
        except OSError as ex:  # e.g. requests: "Could not find a suitable TLS CA certificate bundle"
            self.quota.refund()
            raise AbortRun(f"TLS/CA configuration problem: {self._redact(str(ex))}")
        finally:
            self.limiter.record()
            self.quota.stamp()

    @staticmethod
    def _rec(kind, value, status, http, fields=None, vt_id=None, note="", transient=False):
        return {"key": f"{kind}:{value}", "kind": kind, "value": value, "status": status,
                "http": http, "queried_at": utcnow().strftime(TS_FMT), "vt_id": vt_id,
                "fields": fields or {}, "note": note, "transient": transient}

    # -- public -------------------------------------------------------------
    def lookup(self, kind: str, value: str) -> dict:
        ident = (base64.urlsafe_b64encode(value.encode()).decode().rstrip("=")
                 if kind == "url" else value)
        url = f"{VT_BASE}/{ENDPOINTS[kind]}/{quote(ident, safe=':')}"
        attempts = rl_retries = 0
        while True:
            resp, err = self._send(url)
            if resp is None:
                attempts += 1
                if attempts >= self.max_attempts:
                    return self._rec(kind, value, "ERROR", None, transient=True,
                                     note=f"network error after {attempts} attempts: {err}")
                log.warning("network error (%s) - retrying", err)
                continue
            code = resp.status_code
            if code == 200:
                try:
                    obj = resp.json()["data"]
                    return self._rec(kind, value, "OK", 200, extract_fields(kind, obj),
                                     vt_id=obj.get("id"))
                except (ValueError, KeyError, TypeError, AttributeError):
                    attempts += 1
                    if attempts >= self.max_attempts:
                        return self._rec(kind, value, "ERROR", 200, transient=True,
                                         note="unparseable response from VirusTotal")
                    continue
            if code == 404:
                return self._rec(kind, value, "NOT_FOUND", 404,
                                 note="Not present in VirusTotal (nothing was submitted)")
            if code == 400:
                return self._rec(kind, value, "ERROR", 400,
                                 note=f"Bad request: {self._error_message(resp)}")
            if code in (401, 403):
                raise AbortRun(f"HTTP {code}: {self._error_message(resp)} - check the API key/account")
            if code == 429:
                rl_retries += 1
                try:
                    ra = float(resp.headers.get("Retry-After", ""))
                except (ValueError, TypeError, AttributeError):
                    ra = 0.0
                if rl_retries > self.max_429_retries or ra > 300:
                    raise QuotaExhausted(
                        f"VirusTotal keeps returning 429 ({self._error_message(resp)})")
                wait = max(self.cooldown, ra + 1)
                log.warning("HTTP 429 - cooling down %.0fs (retry %d/%d)",
                            wait, rl_retries, self.max_429_retries)
                self.sleep(wait)
                continue
            if 500 <= code < 600:
                attempts += 1
                if attempts >= self.max_attempts:
                    return self._rec(kind, value, "ERROR", code, transient=True,
                                     note=f"VirusTotal server error HTTP {code}")
                continue
            return self._rec(kind, value, "ERROR", code, transient=True,
                             note=f"Unexpected HTTP {code}: {self._error_message(resp)}")

    def fetch_quota(self):
        """Optional: ask VT for the key's real quota (costs 1 counted call)."""
        resp, err = self._send(f"{VT_BASE}/users/{quote(self.key, safe='')}/overall_quotas")
        if resp is None or resp.status_code != 200:
            log.warning("Could not read server quota (%s)",
                        err or f"HTTP {resp.status_code}")
            return None, None
        try:
            data = resp.json()["data"]
        except Exception:
            log.warning("Quota response not understood")
            return None, None

        def pick(block):
            if not isinstance(block, dict):
                return None
            cands = [c for c in ([block] + [block.get(k) for k in ("user", "group")])
                     if isinstance(c, dict) and isinstance(c.get("allowed"), (int, float))
                     and isinstance(c.get("used"), (int, float))]
            if not cands:
                return None
            c = min(cands, key=lambda c: c["allowed"] - c["used"])
            return int(c["allowed"]), int(c["used"])
        return pick(data.get("api_requests_daily")), pick(data.get("api_requests_monthly"))


# ----------------------------------------------------------------------------
# XLSX output
# ----------------------------------------------------------------------------

FONT = "Arial"
# (header, key, width)   key None => formula column handled explicitly
COLUMNS = [
    ("Indicator", "indicator", 36), ("Type", "kind", 8), ("Status", "status", 12),
    ("Verdict", "verdict", 17),
    ("Malicious", "malicious", 10), ("Suspicious", "suspicious", 11), ("Harmless", "harmless", 10),
    ("Undetected", "undetected", 11), ("Timeout", "timeout", 9), ("Engines Total", "total", 13),
    ("Reputation", "reputation", 11), ("Last Analysis (UTC)", "last_analysis_date", 20),
    ("VT Link", "vt_link", 9),
    ("Tags", "tags", 28), ("Votes Harmless", "votes_harmless", 10), ("Votes Malicious", "votes_malicious", 10),
    ("Country", "country", 9), ("AS Owner", "as_owner", 26), ("ASN", "asn", 10), ("Network", "network", 20),
    ("Registrar", "registrar", 24), ("Domain Created (UTC)", "creation_date", 20),
    ("Categories", "categories", 28),
    ("File Name", "meaningful_name", 28), ("File Type", "type_description", 20),
    ("File Size (bytes)", "size", 14),
    ("Threat Label", "threat_label", 28), ("Threat Categories", "threat_categories", 24),
    ("MD5", "md5", 34), ("SHA1", "sha1", 42), ("SHA256", "sha256", 66),
    ("First Submission (UTC)", "first_submission_date", 20), ("Times Submitted", "times_submitted", 10),
    ("URL Title", "title", 28), ("Final URL", "last_final_url", 34), ("HTTP Code", "last_http_response_code", 9),
    ("Note", "note", 44), ("Queried At (UTC)", "queried_at", 20),
    ("Original Input", "raw", 30), ("Source", "source", 16), ("Occurrences", "count", 11),
]
EPOCH_KEYS = {"last_analysis_date", "creation_date", "first_submission_date"}
DT_FMT = "yyyy-mm-dd hh:mm:ss"


def _clean(v):
    if isinstance(v, str):
        v = ILLEGAL_CHARACTERS_RE.sub("", v)
        if len(v) > 32000:
            v = v[:32000]
    return v


def _put(ws, row, col, value, fmt=None, bold=False, color=None, formula=False):
    """Write a cell. formula=True is ONLY for formulas generated by this script;
    every other string is data (VT responses, user input) and is never executable."""
    c = ws.cell(row=row, column=col)
    v = _clean(value)
    c.value = v
    # openpyxl turns any string starting with '=' into a FORMULA; VT-supplied text
    # (file names, titles, tags) must never be executable, so force plain text.
    if not formula and isinstance(v, str) and v.startswith("="):
        c.data_type = "s"
    c.font = Font(name=FONT, size=10, bold=bold, color=color)
    if fmt:
        c.number_format = fmt
    return c


def _to_dt(v):
    if isinstance(v, (int, float)) and not isinstance(v, bool) and 0 < v < 4_102_444_800:
        return datetime.fromtimestamp(v, timezone.utc).replace(tzinfo=None)
    return None


def write_xlsx(path: Path, entries, skipped, records, pending_reason, run_info,
               mal_thr: int, sus_thr: int) -> Path:
    wb = Workbook()
    ws = wb.active
    ws.title = "Results"
    L = {key: get_column_letter(i) for i, (_, key, _) in enumerate(COLUMNS, start=1)}
    n = len(entries)
    last = max(n + 1, 2)

    for i, (head, _, width) in enumerate(COLUMNS, start=1):
        c = _put(ws, 1, i, head, bold=True, color="FFFFFF")
        c.fill = PatternFill("solid", start_color="1F3864", end_color="1F3864")
        c.alignment = Alignment(horizontal="center", vertical="center", wrap_text=True)
        ws.column_dimensions[get_column_letter(i)].width = width
    ws.row_dimensions[1].height = 30

    for r, e in enumerate(entries, start=2):
        rec = records.get(e.key)
        f = (rec or {}).get("fields", {})
        status = rec["status"] if rec else "PENDING"
        note = rec["note"] if rec else f"Not queried: {pending_reason or 'run incomplete'} - re-run to continue"
        if rec and rec.get("transient"):
            note += " (transient - not cached, will be retried on next run)"
        base = {"indicator": e.value, "kind": e.kind, "status": status, "note": note,
                "queried_at": rec["queried_at"] if rec else None,
                "source": e.source, "count": e.count, "raw": e.raw}
        for ci, (_, key, _) in enumerate(COLUMNS, start=1):
            if key == "verdict":
                _put(ws, r, ci,
                     f'=IF(${L["status"]}{r}="NOT_FOUND","NOT IN VT",IF(${L["status"]}{r}<>"OK","",'
                     f'IF(${L["total"]}{r}=0,"NO DATA",'
                     f'IF(${L["malicious"]}{r}>=Summary!$B$4,"MALICIOUS",'
                     f'IF(${L["malicious"]}{r}+${L["suspicious"]}{r}>=Summary!$B$5,"SUSPICIOUS","NO DETECTIONS")))))',
                     formula=True)
            elif key == "total":
                _put(ws, r, ci, f'=IF(${L["status"]}{r}="OK",SUM(${L["malicious"]}{r}:${L["undetected"]}{r}),"")',
                     formula=True)
                # NB: columns Malicious..Undetected are adjacent; Timeout (after them) is excluded.
            elif key == "vt_link":
                c = _put(ws, r, ci, None)
                if status == "OK":
                    ident = rec.get("vt_id") if e.kind == "url" else (f.get("sha256") or e.value)
                    if ident:
                        c.value = "Open"
                        c.hyperlink = f"https://www.virustotal.com/gui/{GUI_PATHS[e.kind]}/{ident}"
                        c.font = Font(name=FONT, size=10, color="0563C1", underline="single")
            elif key in base:
                if key == "queried_at" and base[key]:
                    _put(ws, r, ci, datetime.strptime(base[key], TS_FMT), DT_FMT)
                else:
                    _put(ws, r, ci, base[key])
            else:
                v = f.get(key)
                if key in EPOCH_KEYS:
                    dt = _to_dt(v)
                    _put(ws, r, ci, dt, DT_FMT if dt else None)
                else:
                    _put(ws, r, ci, v)

    ws.freeze_panes = "B2"
    ws.auto_filter.ref = f"A1:{get_column_letter(len(COLUMNS))}{last}"
    vr = f'{L["verdict"]}2:{L["verdict"]}{last}'
    for text, colour in (("MALICIOUS", "F8B4B4"), ("SUSPICIOUS", "FCD9A8"),
                         ("NO DETECTIONS", "C6EFCE")):
        fill = PatternFill(start_color=colour, end_color=colour, bgColor=colour, fill_type="solid")
        ws.conditional_formatting.add(
            vr, FormulaRule(formula=[f'${L["verdict"]}2="{text}"'], fill=fill))

    # ---- Skipped -----------------------------------------------------------
    sk = wb.create_sheet("Skipped")
    for i, (h, w) in enumerate((("Source", 16), ("Raw value", 50), ("Reason not queried", 70)), start=1):
        c = _put(sk, 1, i, h, bold=True, color="FFFFFF")
        c.fill = PatternFill("solid", start_color="1F3864", end_color="1F3864")
        sk.column_dimensions[get_column_letter(i)].width = w
    for r, (src, raw, why) in enumerate(skipped, start=2):
        _put(sk, r, 1, src)
        _put(sk, r, 2, raw)
        _put(sk, r, 3, why)
    sk.freeze_panes = "A2"
    sk_last = max(len(skipped) + 1, 2)

    # ---- Summary -----------------------------------------------------------
    sm = wb.create_sheet("Summary", 0)
    sm.column_dimensions["A"].width = 52
    sm.column_dimensions["B"].width = 44
    _put(sm, 1, 1, "VirusTotal enrichment summary", bold=True).font = Font(name=FONT, size=14, bold=True)
    _put(sm, 3, 1, "Verdict thresholds (editable inputs - Results!Verdict recalculates)", bold=True)
    _put(sm, 4, 1, "MALICIOUS if 'Malicious' engines >=")
    _put(sm, 4, 2, mal_thr, color="0000FF").fill = PatternFill("solid", start_color="FFFF00", end_color="FFFF00")
    _put(sm, 5, 1, "SUSPICIOUS if Malicious + Suspicious >=")
    _put(sm, 5, 2, sus_thr, color="0000FF").fill = PatternFill("solid", start_color="FFFF00", end_color="FFFF00")
    _put(sm, 6, 1, "Assumption: default thresholds (5 / 1) are this script's own choice, set via "
                   "--malicious-threshold / --suspicious-threshold; they are NOT a VirusTotal verdict. "
                   "'Engines Total' = Malicious + Suspicious + Harmless + Undetected (Timeout excluded).")
    sm["A6"].alignment = Alignment(wrap_text=True, vertical="top")
    sm.merge_cells("A6:B6")
    sm.row_dimensions[6].height = 54

    R = f"Results!{{col}}2:{{col}}{last}"
    rows = [("Counts", None), ("Unique indicators", f"=COUNTA({R.format(col=L['indicator'])})")]
    for s in ("OK", "NOT_FOUND", "ERROR", "PENDING"):
        rows.append((f"Status: {s}", f'=COUNTIF({R.format(col=L["status"])},"{s}")'))
    rows.append(("Verdicts", None))
    for v in ("MALICIOUS", "SUSPICIOUS", "NO DETECTIONS", "NO DATA", "NOT IN VT"):
        rows.append((f"Verdict: {v}", f'=COUNTIF({R.format(col=L["verdict"])},"{v}")'))
    rows.append(("Skipped inputs (not queried)", f"=COUNTA(Skipped!A2:A{sk_last})"))
    r = 8
    for label, formula in rows:
        if formula is None:
            r += 1 if label == "Verdicts" else 0
            _put(sm, r, 1, label, bold=True)
        else:
            _put(sm, r, 1, label)
            _put(sm, r, 2, formula, formula=True)
        r += 1
    r += 1
    _put(sm, r, 1, "Run information (static values written by the script)", bold=True)
    for k, v in run_info.items():
        r += 1
        _put(sm, r, 1, k)
        _put(sm, r, 2, v)

    out = path
    try:
        wb.save(out)
    except PermissionError:  # typically: file open in Excel on Windows
        out = path.with_name(f"{path.stem}_{utcnow().strftime('%H%M%S')}{path.suffix}")
        log.warning("'%s' is locked (open in Excel?) - saving as '%s'", path, out)
        wb.save(out)
    return out


# ----------------------------------------------------------------------------
# CLI
# ----------------------------------------------------------------------------

def parse_args(argv=None):
    home = Path.home() / ".vt_enrich"
    p = argparse.ArgumentParser(
        description="Quota-safe VirusTotal enrichment (lookups only). XLSX/TXT in, XLSX out.")
    p.add_argument("-i", "--input", type=Path, default=Path(INPUT_FILE) if INPUT_FILE else None,
                   help="default: INPUT_FILE at the top of this script")
    p.add_argument("-o", "--output", type=Path, default=Path(OUTPUT_FILE) if OUTPUT_FILE else None,
                   help="default: OUTPUT_FILE in this script, else <input>_vt_enriched.xlsx")
    p.add_argument("--ca-bundle", default=SSL_CERT_PATH or None,
                   help="CA bundle file/folder used to verify VirusTotal's TLS certificate "
                        "(default: SSL_CERT_PATH in this script)")
    p.add_argument("--sheet", help="XLSX input: only this sheet")
    p.add_argument("--column", help="XLSX input: only these columns, e.g. A or A,C")
    p.add_argument("--api-key", help="default: API_KEY in this script, else env VT_API_KEY")
    p.add_argument("--per-minute", type=int, default=4, help="calls per minute (free: 4)")
    p.add_argument("--daily-limit", type=int, default=500,
                   help="local daily (UTC) call budget; 0 = no local cap (free: 500)")
    p.add_argument("--monthly-limit", type=int, default=15500,
                   help="local monthly (UTC) call budget; 0 = no local cap (free: ~15,500)")
    p.add_argument("--safety-margin", type=float, default=1.0,
                   help="extra seconds added to the 60 s window (default 1.0)")
    p.add_argument("--max-calls", type=int, default=0, help="cap on calls in this run; 0 = none")
    p.add_argument("--cache-max-age-days", type=float, default=7,
                   help="cached answers older than this are re-queried; 0 = never expire")
    p.add_argument("--check-quota", action="store_true",
                   help="read the key's real quota from VT first (costs 1 counted call)")
    p.add_argument("--include-private", action="store_true",
                   help="also query private/reserved IPs (normally skipped, no value)")
    p.add_argument("--malicious-threshold", type=int, default=5)
    p.add_argument("--suspicious-threshold", type=int, default=1)
    p.add_argument("--cache", type=Path, default=home / "vt_cache.jsonl")
    p.add_argument("--state", type=Path, default=home / "vt_quota_state.json")
    p.add_argument("--dry-run", action="store_true", help="show the plan, make ZERO API calls")
    p.add_argument("-v", "--verbose", action="store_true")
    return p.parse_args(argv)


def run(args, session=None, clock=time.monotonic, sleep=time.sleep) -> int:
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(asctime)s %(levelname)-7s %(message)s", datefmt="%H:%M:%S")
    logging.getLogger("urllib3").setLevel(logging.WARNING)  # its DEBUG lines print URL paths
    api_key = (args.api_key or API_KEY or os.environ.get("VT_API_KEY", "")).strip()
    if not api_key and not args.dry_run:
        log.error("No API key. Set API_KEY at the top of the script (or env VT_API_KEY / --api-key).")
        return 2
    if not args.input:
        log.error("No input file. Set INPUT_FILE at the top of the script (or use -i).")
        return 2
    verify = True
    if args.ca_bundle:
        ca = Path(str(args.ca_bundle).strip().strip('"')).expanduser()
        if not ca.exists():
            log.error("SSL certificate path not found: %s (check SSL_CERT_PATH / --ca-bundle)", ca)
            return 2
        verify = str(ca)
        log.info("TLS verification uses: %s", verify)
    elif not args.dry_run:
        for var in ("REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE"):
            env_ca = os.environ.get(var)
            if env_ca:  # `requests` honours this when SSL_CERT_PATH is empty
                if not Path(env_ca).exists():
                    log.error("Environment variable %s points to '%s' which does not exist. "
                              "Fix/unset it, or set SSL_CERT_PATH at the top of the script.", var, env_ca)
                    return 2
                log.info("TLS verification uses %s=%s", var, env_ca)
                break
    output = args.output or args.input.with_name(args.input.stem + "_vt_enriched.xlsx")

    items = read_inputs(args.input, args.sheet, args.column)
    entries, skipped = build_entries(items, args.include_private)
    cache = Cache(args.cache)
    now = utcnow()
    records = {}
    stale = {}
    todo = []
    for e in entries:
        rec = cache.fresh(e.key, args.cache_max_age_days, now)
        if rec is not None:
            records[e.key] = rec
        else:
            todo.append(e)
            if e.key in cache.data:  # expired answer: better than a blank row if refresh doesn't happen
                stale[e.key] = cache.data[e.key]

    key_fp = hashlib.sha256(api_key.encode()).hexdigest()[:12] if api_key else "no-key"
    quota = QuotaTracker(args.state, key_fp, args.daily_limit, args.monthly_limit)
    limiter = RateLimiter(args.per_minute, args.safety_margin, clock=clock, sleep=sleep)
    limiter.seed(quota.recent_ages())
    client = None
    if api_key and not args.dry_run:
        client = VTClient(api_key, limiter, quota, session=session, sleep=sleep, verify=verify)
        client.call_cap = args.max_calls if args.max_calls > 0 else 0
        if args.check_quota:
            d, m = client.fetch_quota()
            quota.sync_from_server(d, m)

    budget = quota.remaining()
    if args.max_calls > 0:
        budget = min(budget, args.max_calls)
    n_calls = int(min(len(todo), budget))
    eta_min = n_calls * limiter.min_gap / 60

    log.info("Input: %d value(s) -> %d unique queryable, %d skipped (see 'Skipped' sheet)",
             len(items), len(entries), len(skipped))
    log.info("Cache: %d answered already (0 calls), %d need a call", len(records), len(todo))
    log.info("Quota (local): today %d/%s used, month %d/%s used",
             quota.day_used, args.daily_limit or "inf", quota.month_used, args.monthly_limit or "inf")
    log.info("This run: up to %d call(s), spacing >= %.2fs, ETA ~%.1f min", n_calls, limiter.min_gap, eta_min)
    if n_calls < len(todo):
        log.warning("%d indicator(s) will stay PENDING (budget) - re-run later to continue",
                    len(todo) - n_calls)
    if args.dry_run:
        log.info("Dry run: no API calls were made and no output was written.")
        return 0

    pending_reason = ""
    exit_code = 0
    done_this_run = 0
    try:
        for idx, e in enumerate(todo, start=1):
            if args.max_calls > 0 and client.calls >= args.max_calls:
                pending_reason = "--max-calls reached"
                break
            if quota.remaining() <= 0:
                pending_reason = "local daily/monthly quota budget reached"
                break
            rec = client.lookup(e.kind, e.value)
            records[e.key] = rec
            if not rec.get("transient"):
                cache.put(rec)
            done_this_run += 1
            f = rec["fields"]
            tot = sum((f.get(k) or 0) for k in ("malicious", "suspicious", "harmless", "undetected"))
            log.info("[%d/%d] %-6s %-45.45s %s%s", idx, len(todo), e.kind, e.value, rec["status"],
                     f" mal={f.get('malicious')}/{tot}" if rec["status"] == "OK" else "")
    except QuotaExhausted as ex:
        pending_reason = f"quota: {ex}"
        if "max-calls" in str(ex) or "local quota" in str(ex):
            log.warning("Stopping: %s.", ex)
        else:
            log.error("Stopping: %s. If this is the daily limit it resets at 00:00 UTC "
                      "(check https://www.virustotal.com/gui/my-apikey).", ex)
        exit_code = 1
    except AbortRun as ex:
        pending_reason = f"aborted: {ex}"
        log.error("Aborting: %s", ex)
        exit_code = 2
    except KeyboardInterrupt:
        pending_reason = "interrupted by user"
        log.warning("Interrupted - saving what has been collected so far.")
        exit_code = 130

    still_pending = [e for e in entries if e.key not in records]
    out_records = dict(records)
    for e in still_pending:
        if e.key in stale:
            old = dict(stale[e.key])
            old["note"] = (f"STALE data from {old.get('queried_at')}; refresh pending "
                           f"({pending_reason or 'run incomplete'}). {old.get('note', '')}").strip()
            out_records[e.key] = old
    if still_pending and exit_code == 0:
        exit_code = 1
    run_info = {
        "Generated (UTC)": utcnow().strftime("%Y-%m-%d %H:%M:%S"),
        "Input file": str(args.input),
        "Unique indicators": len(entries),
        "Answered from cache (no call)": len(entries) - len(todo),
        "Lookups completed this run": done_this_run,
        "API calls made this run (incl. retries)": client.calls if client else 0,
        "Local quota used today (UTC)": f"{quota.day_used} / {args.daily_limit or 'unlimited'}",
        "Local quota used this month (UTC)": f"{quota.month_used} / {args.monthly_limit or 'unlimited'}",
        "Still pending": len(still_pending),
    }
    written = write_xlsx(output, entries, skipped, out_records, pending_reason, run_info,
                         args.malicious_threshold, args.suspicious_threshold)
    log.info("Wrote %s  (calls this run: %d, pending: %d)", written,
             client.calls if client else 0, len(still_pending))
    return exit_code


def main(argv=None) -> int:
    return run(parse_args(argv))


if __name__ == "__main__":
    sys.exit(main())

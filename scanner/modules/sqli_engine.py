"""
SQL injection detection engine.

Works on normalised InjectionPoint objects. Each unique point is tested
once (GET or POST). Three techniques: error-based, boolean-based,
time-based blind.

Points are tested CONCURRENTLY with a thread pool: the work is almost
entirely spent waiting on network I/O (especially the 5s time-based
probes), so threads waiting in parallel give a big speed-up without
loading the CPU -- suitable even for a very weak processor. The browser
work (XSS) is kept separate and serial, since that IS CPU/RAM heavy.
"""

import time
import threading
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from . import scan_log

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                  "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
}

ERROR_SIGNATURES = [
    "sql syntax", "mysql_fetch", "you have an error in your sql syntax",
    "unclosed quotation mark", "sqlite3.operationalerror", "ora-01756",
    "warning: mysql", "postgresql", "sqlstate", "psql:", "syntax error at or near",
    "sqlite error", "odbc", "quoted string not properly terminated",
]

BOOLEAN_PAIRS = [
    ("' OR '1'='1", "' OR '1'='2"),
    ("1 OR 1=1", "1 OR 1=2"),
    ("' AND '1'='1", "' AND '1'='2"),
]

TIME_PAYLOADS = [
    "1' AND SLEEP({s})-- ",
    "1'; WAITFOR DELAY '0:0:{s}'-- ",
    "1 OR SLEEP({s})",
    "1' || pg_sleep({s})-- ",
]

DELAY_SECONDS = 5
SIMILARITY_THRESHOLD = 0.95
DEFAULT_WORKERS = 6

REMEDIATION = (
    "Use parameterised queries (prepared statements) instead of building "
    "SQL by concatenating user input. Pass request values as bound "
    "parameters so the database treats them as data, not code."
)

# One requests.Session per thread (Session isn't guaranteed thread-safe to
# share). Threads are reused by the pool, so this keeps connection reuse.
_thread_local = threading.local()


def _session():
    s = getattr(_thread_local, "session", None)
    if s is None:
        s = requests.Session()
        s.headers.update(HEADERS)
        _thread_local.session = s
    return s


def _similar(a, b):
    if not a and not b:
        return 1.0
    longer = max(len(a), len(b))
    return min(len(a), len(b)) / longer if longer else 1.0


def _send(point, value):
    sess = _session()
    if point.location == "query":
        parts = urlparse(point.url)
        params = parse_qs(parts.query)
        params.update(point.other_fields)
        params[point.field] = value
        url = urlunparse(parts._replace(query=urlencode(params, doseq=True)))
        return sess.get(url, timeout=25)
    elif point.location == "body":
        data = dict(point.other_fields)
        data[point.field] = value
        return sess.post(point.url, data=data, timeout=25)
    elif point.location == "header":
        return sess.get(point.url, headers={point.field: value}, timeout=25)
    elif point.location == "cookie":
        return sess.get(point.url, cookies={point.field: value}, timeout=25)
    else:
        raise ValueError(f"Unknown injection location: {point.location}")


def _finding(point, technique, evidence):
    return {
        "type": "SQL Injection",
        "severity": "high",
        "injection_point": {"kind": point.kind_label(), "name": point.field,
                            "url": point.url, "method": point.method},
        "technique": technique,
        "evidence": evidence,
        "remediation": REMEDIATION,
    }


def _test_point(point):
    label = repr(point)
    scan_log.transient(f"SQLi: {label}")

    # 1. Error-based
    try:
        text = _send(point, "'").text.lower()
        for sig in ERROR_SIGNATURES:
            if sig in text:
                return _finding(point, "error-based", f"Database error surfaced: '{sig}'")
    except requests.exceptions.RequestException:
        pass

    try:
        baseline = _send(point, "1").text
    except requests.exceptions.RequestException:
        baseline = None

    # 2. Boolean-based
    for true_cond, false_cond in BOOLEAN_PAIRS:
        try:
            r_true = _send(point, true_cond).text
            r_false = _send(point, false_cond).text
        except requests.exceptions.RequestException:
            continue
        if baseline is not None:
            if (_similar(r_true, baseline) >= SIMILARITY_THRESHOLD
                    and _similar(r_false, baseline) < SIMILARITY_THRESHOLD):
                return _finding(point, "boolean-based",
                                "TRUE condition matches the normal page; FALSE differs")
        if _similar(r_true, r_false) < 0.8:
            return _finding(point, "boolean-based",
                            "Response differs between TRUE and FALSE conditions")

    # 3. Time-based blind (only reached if the fast techniques found nothing)
    for template in TIME_PAYLOADS:
        payload = template.format(s=DELAY_SECONDS)
        try:
            start = time.time()
            _send(point, payload)
            elapsed = time.time() - start
        except requests.exceptions.RequestException:
            continue
        if elapsed >= DELAY_SECONDS:
            return _finding(point, "time-based blind",
                            f"Response delayed {elapsed:.1f}s (>= {DELAY_SECONDS}s)")

    return None


def scan(points, workers=DEFAULT_WORKERS):
    """Test all points concurrently. `workers` caps simultaneous requests."""
    findings = []
    if not points:
        return findings

    with ThreadPoolExecutor(max_workers=workers) as pool:
        future_to_point = {pool.submit(_test_point, p): p for p in points}
        for future in as_completed(future_to_point):
            point = future_to_point[future]
            try:
                result = future.result()
            except Exception:
                result = None
            if result:
                scan_log.add_finding("SQL Injection",
                    f"SQLi ({result['technique']}) at {point!r}")
                findings.append(result)
    return findings
"""
Vulnerable JavaScript dependency detection.

Many sites load JS libraries (jQuery, Angular, etc.) whose older versions
have publicly known vulnerabilities. This engine looks at the <script src>
URLs the crawler found, tries to identify the library and its version
(from the filename or, if needed, from the file's contents), and compares
that version against a small built-in database of known-vulnerable ranges.

This is NOT DOM analysis: it only reads script names/contents and compares
versions, which is why it is feasible here (unlike true client-side
vulnerability detection). The database is intentionally small and citable;
a real tool would use a full feed such as OSV or Retire.js.
"""

import re
import requests

from . import scan_log

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                  "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
}

# library -> list of (max_vulnerable_version, note). A detected version <=
# max_vulnerable_version is flagged. Small, illustrative, and documentable.
KNOWN_VULNERABLE = {
    "jquery": [("3.4.1", "XSS via jQuery.htmlPrefilter and others; upgrade to >= 3.5.0")],
    "angular": [("1.8.2", "Multiple client-side template / sandbox issues in AngularJS 1.x; unsupported, migrate")],
    "bootstrap": [("3.4.1", "XSS in data-target / tooltip; upgrade to >= 4.3.1")],
    "lodash": [("4.17.20", "Prototype pollution; upgrade to >= 4.17.21")],
    "moment": [("2.29.1", "Path traversal / ReDoS; upgrade to >= 2.29.2")],
    "vue": [("2.6.14", "Older Vue 2.x; check advisories, consider upgrade")],
}

# filename patterns: library-1.2.3.js  /  library.min.js?ver=1.2.3
NAME_RE = re.compile(
    r"(?P<lib>jquery|angular|bootstrap|lodash|moment|vue)[.-]?"
    r"(?P<ver>\d+\.\d+\.\d+)", re.IGNORECASE)

REMEDIATION_TMPL = (
    "The page loads {lib} {ver}, which has known vulnerabilities. {note}. "
    "Keep front-end dependencies updated and remove unused ones."
)


def _version_tuple(v):
    return tuple(int(x) for x in v.split("."))


def _is_vulnerable(lib, ver):
    lib = lib.lower()
    if lib not in KNOWN_VULNERABLE:
        return None
    for max_vuln, note in KNOWN_VULNERABLE[lib]:
        try:
            if _version_tuple(ver) <= _version_tuple(max_vuln):
                return note
        except ValueError:
            continue
    return None


def _identify(src, fetch=True):
    """Return (lib, version) from the URL, or by peeking into the file."""
    m = NAME_RE.search(src)
    if m:
        return m.group("lib").lower(), m.group("ver")
    if fetch:
        try:
            head = requests.get(src, headers=HEADERS, timeout=15).text[:2000]
        except requests.exceptions.RequestException:
            return None, None
        # many libs announce themselves in a top comment: "jQuery v3.4.1"
        m2 = re.search(r"(jquery|angular|bootstrap|lodash|moment|vue)"
                       r"[^\d]{0,20}(\d+\.\d+\.\d+)", head, re.IGNORECASE)
        if m2:
            return m2.group(1).lower(), m2.group(2)
    return None, None


def _finding(lib, ver, note, script_url):
    return {
        "type": "Vulnerable JS dependency",
        "severity": "medium",
        "injection_point": {"kind": "script", "name": f"{lib} {ver}",
                            "url": script_url, "method": "get"},
        "technique": "version compared against known-vulnerable list",
        "evidence": f"Loads {lib} {ver} (known-vulnerable). {note}",
        "remediation": REMEDIATION_TMPL.format(lib=lib, ver=ver, note=note),
    }


def scan(scripts):
    """scripts: dict {script_src_url: set(pages)} from the crawler."""
    findings = []
    seen = set()
    for src in (scripts or {}):
        scan_log.transient(f"JS deps: {src}")
        lib, ver = _identify(src)
        if not lib or not ver:
            continue
        key = (lib, ver)
        if key in seen:
            continue
        seen.add(key)
        note = _is_vulnerable(lib, ver)
        if note:
            findings.append(_finding(lib, ver, note, src))
            scan_log.add_finding("Vulnerable JS dependency",
                                 f"{lib} {ver} at {src}")
    return findings
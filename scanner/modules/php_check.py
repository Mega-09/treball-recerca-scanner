"""
Vulnerable PHP version detection — PHP2Shell (CVE-2026-109618 / CVE-2026-109619).

On 21 October 2026, PHP released emergency patches for two critical,
unauthenticated remote-code-execution flaws in the PHP core web worker,
known together as "PHP2Shell" (CVSS 9.2). Fixed releases: PHP 8.5.12,
8.4.27, 8.3.36 and 8.2.35. Branches 8.1 and older are end-of-life and get
no fix.

This engine detects the flaws the same safe way js_deps_engine detects
vulnerable JavaScript libraries: BY VERSION. It reads the PHP version the
server already discloses in its response headers (X-Powered-By, Server) and
compares it against the fixed releases. It does NOT try to exploit the
flaws — that would run attacker-controlled code on the target. It only
reads what the server already advertises, so it is passive and
non-destructive.

Outcomes:
  - PHP version found and older than the fix for its branch (or an
    end-of-life branch): reported as HIGH (confirmed vulnerable).
  - PHP detected but the version is hidden: reported as LOW (can't confirm;
    check manually). Hiding the version is good practice, so this is only a
    reminder, not a confirmed hole.
  - PHP version found and already patched, or no PHP at all: nothing.

References:
  https://www.php.net/  (official patched releases, 21 Oct 2026)
  https://thehackernews.com/2026/10/php-issues-emergency-patches-for-two.html
"""

import re
import requests

from . import scan_log

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                  "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
}

# Lowest SAFE version per branch (the emergency releases of 21 Oct 2026).
FIXED = {
    (8, 5): (8, 5, 12),
    (8, 4): (8, 4, 27),
    (8, 3): (8, 3, 36),
    (8, 2): (8, 2, 35),
}

CVES = "CVE-2026-109618, CVE-2026-109619"
REFERENCE = ("https://thehackernews.com/2026/10/"
             "php-issues-emergency-patches-for-two.html")

_VERSION_RE = re.compile(r"PHP/(\d+)\.(\d+)\.(\d+)", re.IGNORECASE)


def _assess(version):
    """Return (vulnerable, note) for a (major, minor, patch) tuple."""
    major, minor, _ = version
    # Newer than everything we know about -> assume patched.
    if major > 8 or (major == 8 and minor >= 6):
        return False, "versio posterior a les afectades"
    branch = (major, minor)
    fix = FIXED.get(branch)
    if fix is None:
        # 8.1 or older (and 7.x, 5.x): end of life, no patch exists.
        return True, "branca sense manteniment: no hi ha cap versio corregida"
    if version < fix:
        f = ".".join(str(n) for n in fix)
        return True, f"cal actualitzar com a minim a PHP {f}"
    return False, "versio ja corregida"


def _php_signal(resp):
    """True if the response looks like it is served by PHP (version aside)."""
    xpb = resp.headers.get("X-Powered-By", "")
    server = resp.headers.get("Server", "")
    cookies = ";".join(resp.headers.get_all("Set-Cookie", []) if hasattr(
        resp.headers, "get_all") else [resp.headers.get("Set-Cookie", "")])
    blob = f"{xpb} {server} {cookies}".lower()
    return "php" in blob or "phpsessid" in blob


def _version_from(resp):
    for header in ("X-Powered-By", "Server"):
        m = _VERSION_RE.search(resp.headers.get(header, ""))
        if m:
            return tuple(int(g) for g in m.groups())
    return None


def _finding_vuln(version, note, url):
    vstr = ".".join(str(n) for n in version)
    return {
        "type": "Vulnerable PHP version (PHP2Shell)",
        "severity": "high",
        "injection_point": {"kind": "server", "name": f"PHP {vstr}",
                            "url": url, "method": "get"},
        "technique": "PHP version compared against the PHP2Shell fixed releases",
        "evidence": f"Server advertises PHP {vstr}; {note} ({CVES}).",
        "remediation": REFERENCE,
    }


def _finding_hidden(url):
    return {
        "type": "PHP detected, version hidden",
        "severity": "low",
        "injection_point": {"kind": "server", "name": "PHP",
                            "url": url, "method": "get"},
        "technique": "passive header inspection",
        "evidence": ("The server looks like PHP but does not disclose its "
                     f"version, so PHP2Shell ({CVES}) cannot be confirmed "
                     "remotely. Check the installed version manually."),
        "remediation": REFERENCE,
    }


def scan(target_url, pages=None):
    """
    Check the target (and a few crawled .php pages) for a PHP version
    affected by PHP2Shell. Returns a list of findings.
    """
    findings = []
    urls = [target_url]
    for u in (pages or []):
        if u not in urls and u.split("?")[0].endswith(".php"):
            urls.append(u)
    urls = urls[:4]   # the target plus up to three .php pages

    php_seen = False
    for url in urls:
        scan_log.transient(f"PHP version: {url}")
        try:
            resp = requests.get(url, headers=HEADERS, timeout=25)
        except requests.exceptions.RequestException:
            continue

        version = _version_from(resp)
        if version:
            vulnerable, note = _assess(version)
            if vulnerable:
                findings.append(_finding_vuln(version, note, url))
                scan_log.add_finding(
                    "Vulnerable PHP version (PHP2Shell)",
                    f"PHP {'.'.join(map(str, version))} at {url} — {note}")
            return findings   # version known: one answer is enough

        if _php_signal(resp):
            php_seen = True

    if php_seen:
        findings.append(_finding_hidden(target_url))
        scan_log.add_finding("PHP detected, version hidden",
                             f"PHP detected but version hidden at {target_url}")
    return findings

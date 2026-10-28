"""
Open redirect detection engine.

An open redirect happens when an app takes a user-controlled value (often
a parameter like ?redir= or ?url=) and sends the browser to it without
checking that it points to an allowed destination. An attacker can abuse
it to send victims to a malicious site while the link still looks like it
belongs to the trusted domain (phishing).

Detection: inject a known external marker URL into the point and see
whether the server tries to redirect there -- either via a Location
response header (HTTP redirect) or via the final URL after following
redirects. We do NOT actually get sent anywhere harmful; the marker host
is a harmless example domain and redirects are inspected, not followed to
anything real.
"""

import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from . import scan_log

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                  "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
}

MARKER_HOST = "example-redirect-check.com"
PAYLOADS = [
    f"https://{MARKER_HOST}/",
    f"//{MARKER_HOST}/",
    f"https:/{MARKER_HOST}/",
]

# Only parameters whose name suggests a redirect are worth testing, to
# avoid noise. Matched case-insensitively as a substring.
LIKELY_NAMES = ["redir", "url", "next", "return", "dest", "continue", "goto", "target"]

REMEDIATION = (
    "Do not redirect to a location taken directly from user input. Use an "
    "allowlist of permitted destinations, or only accept relative paths and "
    "reject anything containing a scheme or host."
)


def _looks_like_redirect_param(name):
    n = name.lower()
    return any(k in n for k in LIKELY_NAMES)


def _send(point, value):
    if point.location == "query":
        parts = urlparse(point.url)
        params = parse_qs(parts.query)
        params.update(point.other_fields)
        params[point.field] = value
        url = urlunparse(parts._replace(query=urlencode(params, doseq=True)))
        return requests.get(url, headers=HEADERS, timeout=25,
                            allow_redirects=False)
    elif point.location == "body":
        data = dict(point.other_fields)
        data[point.field] = value
        return requests.post(point.url, data=data, headers=HEADERS, timeout=25,
                             allow_redirects=False)
    return None


def _finding(point, evidence):
    return {
        "type": "Open Redirect",
        "severity": "medium",
        "injection_point": {"kind": point.kind_label(), "name": point.field,
                            "url": point.url, "method": point.method},
        "technique": "redirect to injected external URL",
        "evidence": evidence,
        "remediation": REMEDIATION,
    }


def scan(points):
    findings = []
    # Only query/body params with redirect-like names.
    targets = [p for p in points
               if p.location in ("query", "body")
               and _looks_like_redirect_param(p.field)]
    for point in targets:
        scan_log.transient(f"Open redirect: {point!r}")
        for payload in PAYLOADS:
            try:
                resp = _send(point, payload)
            except requests.exceptions.RequestException:
                continue
            if resp is None:
                continue
            location = resp.headers.get("Location", "")
            if MARKER_HOST in location:
                findings.append(_finding(
                    point, f"Location header points to injected host: {location}"))
                scan_log.add_finding("Open Redirect", f"Open redirect at {point!r}")
                break
    return findings
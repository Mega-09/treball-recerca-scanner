"""
HTTP header (response) injection detection engine.

If an application puts user input into a response header (for example, a
Location header built from a parameter, or a Set-Cookie value) without
stripping line breaks, an attacker can inject a newline (CR/LF) followed
by a header of their own -- "HTTP response splitting". This can be used
to set malicious cookies, poison caches, or facilitate other attacks.

Detection: inject a payload containing a CR/LF and a unique marker header,
then check whether that marker header appears in the response's headers.
If it does, the app copied our line break into the response verbatim.
"""

import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from . import scan_log

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                  "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
}

MARKER_HEADER = "X-Injected-Check"
MARKER_VALUE = "hdr_probe_5c1d"
# CR/LF variants that break out of a header value.
PAYLOADS = [
    f"test\r\n{MARKER_HEADER}: {MARKER_VALUE}",
    f"test\n{MARKER_HEADER}: {MARKER_VALUE}",
    f"test\r\n\r\n{MARKER_HEADER}: {MARKER_VALUE}",
]

REMEDIATION = (
    "Never place raw user input into response headers. Strip or reject "
    "carriage-return and line-feed characters (CR/LF) from any value that "
    "ends up in a header, and prefer framework APIs that do this for you."
)


def _send(point, value):
    if point.location == "query":
        parts = urlparse(point.url)
        params = parse_qs(parts.query)
        params.update(point.other_fields)
        params[point.field] = value
        url = urlunparse(parts._replace(query=urlencode(params, doseq=True)))
        return requests.get(url, headers=HEADERS, timeout=25, allow_redirects=False)
    elif point.location == "body":
        data = dict(point.other_fields)
        data[point.field] = value
        return requests.post(point.url, data=data, headers=HEADERS, timeout=25,
                             allow_redirects=False)
    return None


def _finding(point):
    return {
        "type": "HTTP Header Injection",
        "severity": "medium",
        "injection_point": {"kind": point.kind_label(), "name": point.field,
                            "url": point.url, "method": point.method},
        "technique": "CR/LF injected header reflected in response",
        "evidence": f"Injected header '{MARKER_HEADER}' appeared in the response",
        "remediation": REMEDIATION,
    }


def scan(points):
    findings = []
    targets = [p for p in points if p.location in ("query", "body")]
    for point in targets:
        scan_log.transient(f"Header injection: {point!r}")
        for payload in PAYLOADS:
            try:
                resp = _send(point, payload)
            except requests.exceptions.RequestException:
                continue
            if resp is None:
                continue
            # requests normalises header names; compare case-insensitively
            present = {k.lower() for k in resp.headers.keys()}
            if MARKER_HEADER.lower() in present:
                findings.append(_finding(point))
                scan_log.add_finding("HTTP Header Injection",
                                     f"Header injection at {point!r}")
                break
    return findings
"""
Security headers check.

Passive: loads a URL and reports which recommended security headers are
missing. Each missing header becomes a low/medium finding.
"""

import requests
from . import scan_log

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                  "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
}

RECOMMENDED = {
    "content-security-policy": (
        "medium",
        "Add a Content-Security-Policy header to restrict which sources of "
        "scripts, styles and other resources the browser will load. Strong "
        "second line of defence against XSS.",
    ),
    "x-frame-options": (
        "low",
        "Add X-Frame-Options: DENY (or a frame-ancestors CSP directive) to "
        "prevent the page being embedded in a frame elsewhere (clickjacking).",
    ),
    "x-content-type-options": (
        "low",
        "Add X-Content-Type-Options: nosniff so the browser does not MIME-"
        "sniff the content type of a response.",
    ),
    "strict-transport-security": (
        "medium",
        "Add Strict-Transport-Security so browsers only ever connect over "
        "HTTPS, preventing downgrade attacks.",
    ),
    "referrer-policy": (
        "low",
        "Add a Referrer-Policy header to control how much referrer "
        "information is sent to other sites.",
    ),
}


def check_security_headers(url):
    findings = []
    scan_log.transient(f"Headers: fetching {url}")
    try:
        resp = requests.get(url, headers=HEADERS, timeout=25)
    except requests.exceptions.RequestException:
        return findings

    present = {k.lower() for k in resp.headers.keys()}
    for header, (severity, remediation) in RECOMMENDED.items():
        if header not in present:
            scan_log.add_finding("Missing security header", f"Missing header: {header} [{severity}]")
            findings.append({
                "type": "Missing security header",
                "severity": severity,
                "injection_point": {"kind": "response header", "name": header,
                                    "url": url, "method": "get"},
                "technique": "passive header inspection",
                "evidence": f"Response does not set the '{header}' header",
                "remediation": remediation,
            })
    return findings
"""
Reflected-surface reporting (informational).

This is NOT a vulnerability test on its own: it reports, for each injection
point, whether a value the user sends is echoed back in the response and, if
so, whether the application ESCAPES it or returns it raw.

Why it is useful:
  - A value reflected *escaped* is the application doing the right thing; it
    is reported as evidence that the output encoding works there.
  - A value reflected *raw* (unescaped) is the surface on which reflected
    XSS lives. The XSS engine confirms whether it actually executes; this
    pass flags the surface even when execution could not be confirmed, so a
    human knows where to look.

It is kept separate from the findings list on purpose: a reflected surface
is not, by itself, a confirmed vulnerability, so it must not change the
vulnerability count. The scanner stores these results under
`report["reflected_surfaces"]`.

Technique: send a uniquely marked value wrapped in markup
(`zz<b>TOKEN</b>zz`) and inspect the raw response text:
  - `<b>TOKEN</b>` present  -> reflected RAW (unescaped surface)
  - the TOKEN present but the tag escaped/stripped -> reflected ESCAPED
  - neither -> not reflected

Lightweight (plain HTTP, no browser), so it is cheap to run.
"""

import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from . import scan_log

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                  "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
}

TOKEN = "rflchk8d2a"
PROBE = f"zz<b>{TOKEN}</b>zz"
RAW_SIGNATURE = f"<b>{TOKEN}</b>"


def _send(point, value):
    if point.location == "query":
        parts = urlparse(point.url)
        params = parse_qs(parts.query)
        params.update(point.other_fields)
        params[point.field] = value
        url = urlunparse(parts._replace(query=urlencode(params, doseq=True)))
        return requests.get(url, headers=HEADERS, timeout=25)
    elif point.location == "body":
        data = dict(point.other_fields)
        data[point.field] = value
        return requests.post(point.url, data=data, headers=HEADERS, timeout=25)
    return None


def _entry(point, escaped):
    return {
        "injection_point": {"kind": point.kind_label(), "name": point.field,
                            "url": point.url, "method": point.method},
        "escaped": escaped,
        "evidence": ("Input reflected ESCAPED (output encoding works here)"
                     if escaped else
                     "Input reflected RAW (unescaped) — potential XSS surface"),
    }


def scan(points):
    """Return a list of reflected-surface entries (not vulnerability findings)."""
    results = []
    targets = [p for p in points if p.location in ("query", "body")]
    for point in targets:
        scan_log.transient(f"Reflection: {point!r}")
        try:
            resp = _send(point, PROBE)
        except requests.exceptions.RequestException:
            continue
        if resp is None:
            continue
        body = resp.text
        if RAW_SIGNATURE in body:
            results.append(_entry(point, escaped=False))
            scan_log.logger.info(f"[REFLECT] RAW at {point!r}")
        elif TOKEN in body:
            results.append(_entry(point, escaped=True))
            scan_log.logger.info(f"[REFLECT] escaped at {point!r}")
    return results

"""
Reflected XSS detection engine (browser-based).

Works on normalised InjectionPoint objects. Loads the injected input in a
real Chromium (Playwright) and checks whether the payload EXECUTED in the
DOM (marker or dialog), not just whether it was echoed back.

Runs SERIAL: one Playwright, one Chromium, one page. This is stable and
safe on weak hardware. (The Playwright *sync* API cannot be shared across
threads; true parallel XSS would need multiprocessing -- a possible future
optimisation, not needed while XSS has no long per-point waits like the
SQLi time-based probes do.)
"""

from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from playwright.sync_api import sync_playwright

from . import scan_log

MARKER = "xss_probe_9f3a"
REFLECT_MARKER = "xreflchk_7b2c"

XSS_PAYLOADS = [
    # HTML context
    f"<script>window.{MARKER}=1</script>",
    f"\"><script>window.{MARKER}=1</script>",
    f"'><script>window.{MARKER}=1</script>",
    f"<img src=x onerror=window.{MARKER}=1>",
    f"\"><img src=x onerror=window.{MARKER}=1>",
    f"'><img src=x onerror=window.{MARKER}=1>",
    f"<svg onload=window.{MARKER}=1>",
    f"\"><svg onload=window.{MARKER}=1>",
    # HTML attribute context
    f"\" onmouseover=window.{MARKER}=1 x=\"",
    f"\" autofocus onfocus=window.{MARKER}=1 x=\"",
    # JavaScript string context (break out of quotes)
    f"'-window.{MARKER}=1-'",
    f"'+window.{MARKER}=1+'",
    f"';window.{MARKER}=1;'",
    f"\"-window.{MARKER}=1-\"",
    f"\";window.{MARKER}=1;\"",
    # break out of the whole <script> element
    f"</script><script>window.{MARKER}=1</script>",
    f"'</script><script>window.{MARKER}=1</script>",
]

REMEDIATION = (
    "Escape or encode all user-controlled data before inserting it into "
    "HTML output (context-aware output encoding), and set a Content-Security-"
    "Policy header. Prefer frameworks that auto-escape by default."
)


def _get_url(point, value):
    parts = urlparse(point.url)
    params = parse_qs(parts.query)
    params.update(point.other_fields)
    params[point.field] = value
    return urlunparse(parts._replace(query=urlencode(params, doseq=True)))


def _load(page, point, value):
    if point.location == "query":
        page.goto(_get_url(point, value), timeout=20000, wait_until="networkidle")
    else:
        data = dict(point.other_fields)
        data[point.field] = value
        body = urlencode(data)
        page.goto("about:blank")
        page.evaluate(
            """async ([url, body]) => {
                const r = await fetch(url, {method:'POST',
                    headers:{'Content-Type':'application/x-www-form-urlencoded'},
                    body: body});
                const html = await r.text();
                document.open(); document.write(html); document.close();
            }""",
            [point.url, body],
        )
        page.wait_for_timeout(300)


def _make_finding(point, payload):
    return {
        "type": "Reflected XSS",
        "severity": "high",
        "injection_point": {"kind": "URL parameter" if point.location == "query"
                            else "form field", "name": point.field,
                            "url": point.url, "method": point.method},
        "technique": "payload executed in DOM",
        "evidence": f"Payload executed in the browser: {payload}",
        "remediation": REMEDIATION,
    }


def _test_point(page, dialog_fired, point):
    label = repr(point)
    hit = None
    reflected = False
    try:
        _load(page, point, REFLECT_MARKER)
        reflected = REFLECT_MARKER in page.content()
    except Exception:
        reflected = False

    for payload in XSS_PAYLOADS:
        dialog_fired["v"] = False
        scan_log.transient(f"XSS: {label}")
        try:
            _load(page, point, payload)
            executed = page.evaluate(f"() => window.{MARKER} === 1")
        except Exception:
            continue
        if executed or dialog_fired["v"]:
            hit = payload
            break
    return (_make_finding(point, hit) if hit else None), reflected


def scan(points, browser_workers=1):
    """
    browser_workers is accepted for interface compatibility but XSS runs
    serial (see module docstring). It is intentionally ignored.
    """
    findings = []
    if not points:
        return findings

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context()
        page = context.new_page()
        dialog_fired = {"v": False}
        page.on("dialog", lambda d: (dialog_fired.update(v=True), d.dismiss()))

        for point in points:
            with scan_log.Timer() as t:
                finding, reflected = _test_point(page, dialog_fired, point)
            if finding:
                scan_log.add_finding("Reflected XSS",
                    f"Reflected XSS at {point!r}  [{t.elapsed:.1f}s]")
                findings.append(finding)
            elif reflected:
                scan_log.logger.info(f"[XSS-DIAG] {point!r}: reflected but not executed")

        browser.close()
    return findings
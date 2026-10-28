"""
Injection point normalisation and de-duplication.

Turns the crawler's raw findings into a list of UNIQUE injection points.
A point is identified by (method, base_url_without_query, field, location).

Locations supported:
    "query"  -> a URL query parameter          (GET)
    "body"   -> a form field                    (POST)
    "header" -> an HTTP request header          (e.g. User-Agent, Referer)
    "cookie" -> a request cookie                (e.g. TrackingId, session)

Header and cookie points are generated once per unique page, since those
values do not depend on a particular form. Each InjectionPoint is
self-contained: it carries everything an engine needs to test it.
"""

from urllib.parse import urlparse, urlunparse, parse_qs

# Header/cookie names commonly reflected into back-end queries. Tested on
# every unique page discovered by the crawler.
CANDIDATE_HEADERS = ["User-Agent", "Referer", "X-Forwarded-For"]
CANDIDATE_COOKIES = ["TrackingId", "session", "sid"]


class InjectionPoint:
    def __init__(self, method, url, field, location, other_fields=None):
        self.method = method            # "get" or "post"
        self.url = url                  # request URL
        self.field = field              # parameter / field / header / cookie name
        self.location = location        # "query" | "body" | "header" | "cookie"
        self.other_fields = other_fields or {}

    def base_key(self):
        base = urlunparse(urlparse(self.url)._replace(query=""))
        # For header/cookie points, the base page (not the exact query) is
        # what matters, so different query values collapse to one point.
        return (self.method, base, self.field, self.location)

    def __repr__(self):
        labels = {"query": "URL param", "body": "form field",
                  "header": "HTTP header", "cookie": "cookie"}
        loc = labels.get(self.location, self.location)
        return f"{loc} '{self.field}' [{self.method.upper()}] @ {self.url}"

    def kind_label(self):
        return {"query": "URL parameter", "body": "form field",
                "header": "HTTP header", "cookie": "cookie"}.get(
                    self.location, self.location)


def build_points(url_params, forms, pages=None, include_headers=True):
    """
    Return a de-duplicated list of InjectionPoint objects.

    url_params : list of (page_url, param_name)
    forms      : list of (page_url, form_dict)
    pages      : iterable of unique page URLs (for header/cookie points)
    include_headers : also generate header + cookie points per page
    """
    points = {}

    for page_url, param in url_params:
        p = InjectionPoint("get", page_url, param, "query")
        points.setdefault(p.base_key(), p)

    for _, form in forms:
        method = form["method"]
        location = "query" if method == "get" else "body"
        for field in form["fields"]:
            others = {f: "1" for f in form["fields"] if f != field}
            p = InjectionPoint(method, form["action"], field, location, others)
            points.setdefault(p.base_key(), p)

    if include_headers and pages:
        for page_url in pages:
            for h in CANDIDATE_HEADERS:
                p = InjectionPoint("get", page_url, h, "header")
                points.setdefault(p.base_key(), p)
            for c in CANDIDATE_COOKIES:
                p = InjectionPoint("get", page_url, c, "cookie")
                points.setdefault(p.base_key(), p)

    return list(points.values())
"""
Browser-based crawler (Playwright / Chromium).

Unlike a plain requests-based crawler, this one loads each page in a real
Chromium browser, lets the JavaScript run, and only then reads the DOM.
That means it can discover links, forms and parameters that only appear
after client-side code executes -- which a requests-only crawler misses.

Output (all target-independent, discovered at runtime):
  - self.pages       : set of visited URLs
  - self.forms       : list of (page_url, form_dict)
  - self.url_params  : list of (page_url, param_name)
  - self.links       : set of in-scope links (useful for reflected-param tests)

Run standalone to see what it finds on a target:
    python browser_crawler.py https://ginandjuice.shop
"""

import sys
from urllib.parse import urljoin, urlparse, parse_qs

from playwright.sync_api import sync_playwright


class BrowserCrawler:
    def __init__(self, start_url, max_pages=40, max_depth=2, headless=True):
        self.start_url = start_url.rstrip("/")
        self.domain = urlparse(start_url).netloc
        self.max_pages = max_pages
        self.max_depth = max_depth
        self.headless = headless

        self.pages = set()
        self.forms = []
        self.url_params = []
        self.links = set()
        self.scripts = {}   # script src URL -> set of pages that load it
        self._queue = [(self.start_url, 0)]

    def same_domain(self, url):
        return urlparse(url).netloc == self.domain

    def _extract_scripts(self, page, url):
        for tag in page.query_selector_all("script[src]"):
            src = tag.get_attribute("src")
            if not src:
                continue
            absolute = urljoin(url, src)
            self.scripts.setdefault(absolute, set()).add(url)

    def _extract_forms(self, page, url):
        forms = page.query_selector_all("form")
        for form in forms:
            action = form.get_attribute("action")
            method = (form.get_attribute("method") or "get").lower()
            fields = []
            for inp in form.query_selector_all("input, textarea, select"):
                name = inp.get_attribute("name")
                if name:
                    fields.append(name)
            if fields:
                self.forms.append((url, {
                    "action": urljoin(url, action) if action else url,
                    "method": method,
                    "fields": fields,
                }))

    def _add_url_params(self, url):
        """Record every query parameter of `url` as an injection point."""
        query = urlparse(url).query
        for param_name in parse_qs(query):
            entry = (url, param_name)
            if entry not in self.url_params:
                self.url_params.append(entry)

    def _extract_links_and_params(self, page, url):
        anchors = page.query_selector_all("a[href]")
        for a in anchors:
            href = a.get_attribute("href")
            if not href:
                continue
            absolute = urljoin(url, href).split("#")[0]
            if not self.same_domain(absolute):
                continue
            self.links.add(absolute)
            self._add_url_params(absolute)

    def crawl(self):
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=self.headless)
            context = browser.new_context()
            page = context.new_page()

            while self._queue and len(self.pages) < self.max_pages:
                url, depth = self._queue.pop(0)
                if url in self.pages or depth > self.max_depth:
                    continue
                try:
                    page.goto(url, timeout=20000, wait_until="networkidle")
                except Exception:
                    continue

                self.pages.add(url)
                self._add_url_params(url)   # the visited URL's own params count
                self._extract_forms(page, url)
                self._extract_links_and_params(page, url)
                self._extract_scripts(page, url)

                for link in list(self.links):
                    if link not in self.pages and all(link != q[0] for q in self._queue):
                        self._queue.append((link, depth + 1))

            browser.close()


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "https://ginandjuice.shop"
    crawler = BrowserCrawler(target)
    crawler.crawl()

    print(f"Pages visited: {len(crawler.pages)}")
    print(f"Forms found: {len(crawler.forms)}")
    print(f"URL parameters found: {len(crawler.url_params)}\n")
    for page_url, param in crawler.url_params:
        print(f"  param '{param}' at {page_url}")
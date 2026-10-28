"""
Demo vulnerable site: COMPANY "Tècnics Vallès SL" (port 5003).
Realistic corporate/industrial look. Photos, fonts, icons, CSS and JS are
all served locally from ./static, so the site works with no Internet access
(photo credits: static/img/CREDITS.md).

Vulnerabilities (toggle in CONFIG, False=vulnerable):
  - open_redirect : ?next= after applying redirects anywhere (phishing)
  - header_inj    : ?ref= copied into a response header with CR/LF

RUN LOCALLY ONLY. Never expose unprotected.
    pip install flask ; python app.py     # http://127.0.0.1:5003/
"""
import html as H
from flask import Flask, request, redirect, make_response, render_template_string
from markupsafe import Markup

app = Flask(__name__)
CONFIG = {"redirect_fixed": False, "headerinj_fixed": False}


def ic(name):
    """Inline reference to an icon of the local SVG sprite."""
    return f'<svg class="i" aria-hidden="true"><use href="/static/icons.svg#{name}"/></svg>'

def photo(name, alt=""):
    """Local photo (static/img)."""
    return f'<img src="/static/img/{name}.jpg" alt="{H.escape(alt)}" loading="lazy">'


LOGO = """<span class="mark">{{ic('gear')}}</span><span>Tècnics <span class="accent">Vallès</span><small>Serveis industrials</small></span>"""

BASE = """<!doctype html><html lang="ca"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{title}} · Tècnics Vallès</title>
<link rel="icon" href="/static/favicon.svg">
<link rel="stylesheet" href="/static/style.css"></head><body>
<div class="topbar"><div class="wrap"><div class="left">
  <span>{{ic('pin')}} Pol. Ind. Can Roqueta · Sabadell</span>
  <span>{{ic('mail')}} info@tecnicsvalles.example</span></div>
  <span>Urgències 24 h: <b>93 555 01 05</b></span></div></div>
<header class="site"><div class="wrap head">
  <a class="logo" href="/">""" + LOGO + """</a>
  <button class="menu-toggle" aria-label="Menú">☰</button>
  <nav><a href="/"{% if active == 'home' %} class="on"{% endif %}>Inici</a>
    <a href="/services"{% if active == 'services' %} class="on"{% endif %}>Serveis</a>
    <a href="/about"{% if active == 'about' %} class="on"{% endif %}>Qui som</a>
    <a class="cta" href="/careers">Treballa amb nosaltres</a></nav>
</div></header>
{{body|safe}}
<footer class="site"><div class="wrap foot-grid">
  <div><a class="logo" href="/">""" + LOGO + """</a>
    <p>Manteniment industrial, enginyeria i instal·lacions per a la indústria del Vallès des de 2005.</p></div>
  <div><h4>Empresa</h4><ul>
    <li><a href="/services">Serveis</a></li><li><a href="/about">Qui som</a></li>
    <li><a href="/careers">Treballa amb nosaltres</a></li></ul></div>
  <div><h4>Contacte</h4><ul>
    <li>{{ic('pin')}} Pol. Ind. Can Roqueta, nau 12 · Sabadell</li><li>{{ic('phone')}} 93 555 01 05</li>
    <li>{{ic('mail')}} info@tecnicsvalles.example</li><li>{{ic('clock')}} Dl–Dv 7–18 h · Urgències 24 h</li></ul></div>
</div><div class="legal"><div class="wrap"><span>© 2026 Tècnics Vallès SL · Serveis industrials des de 2005</span>
  <span>Demo acadèmica (TR) · Conté vulnerabilitats intencionades amb finalitat educativa.</span></div></div></footer>
<script src="/static/app.js"></script></body></html>"""

def render(title, body, active=None):
    return render_template_string(BASE, title=title, body=body, active=active,
                                  ic=lambda n: Markup(ic(n)))

def pagehero(eyebrow, title, sub, img="nau"):
    return (f'<section class="pagehero">{photo(img)}<div class="wrap"><span class="eyebrow">{eyebrow}</span>'
            f'<h1>{title}</h1><p>{sub}</p></div></section>')

def card(num, ph, title, text):
    return f"""<div class="card reveal"><div class="ph">{photo(ph, title)}</div>
      <div class="body"><span class="num">{num}</span><h4>{title}</h4><p>{text}</p></div></div>"""

CTA_BAND = f"""<section class="band"><div class="wrap">
      <div><h2>Tens una avaria o un projecte?</h2><p>Truca'ns al 93 555 01 05. Servei d'urgència les 24 hores.</p></div>
      <a class="btn btn-dark" href="/services">Veure els serveis {ic('arrow')}</a></div></section>"""


@app.route("/")
def home():
    body = f"""<section class="hero">{photo('hero')}
      <div class="wrap"><span class="eyebrow">Manteniment · Enginyeria · Instal·lacions</span>
      <h1>Solucions tècniques per a la <span class="accent">teva indústria</span></h1>
      <p>Manteniment industrial i enginyeria amb més de 15 anys d'experiència al Vallès.</p>
      <div class="cta-row"><a class="btn" href="/services">Descobreix els nostres serveis {ic('arrow')}</a>
        <a class="btn btn-outline" href="/about">Qui som</a></div></div>
      <div class="hero-strip"><div class="wrap">
        <div>{ic('alert')} Servei d'urgència 24 h, 365 dies</div>
        <div>{ic('shield')} Tècnics certificats i assegurats</div>
        <div>{ic('pin')} Cobertura a tot el Vallès</div></div></div></section>
      <section class="section"><div class="wrap">
        <div class="sec-head"><div><span class="eyebrow">Serveis</span>
          <h2>Què <span class="accent">oferim</span></h2></div>
          <p>Un equip complet al servei de la teva empresa</p></div>
        <div class="grid3">
          {card('01', 'soldadura', 'Manteniment industrial', 'Preventiu i correctiu per mantenir la teva producció en marxa.')}
          {card('02', 'planols', 'Enginyeria', 'Projectes a mida, des del disseny fins a la posada en marxa.')}
          {card('03', 'quadre-electric', 'Instal·lacions', 'Elèctriques i mecàniques, amb totes les garanties.')}
        </div>
      </div></section>
      <div class="stats"><div class="wrap">
        <div class="stat"><div class="n" data-count="15">15<span>+</span></div><div class="l">Anys d'experiència</div></div>
        <div class="stat"><div class="n" data-count="100">100<span>+</span></div><div class="l">Empreses ateses</div></div>
        <div class="stat"><div class="n" data-count="25">25</div><div class="l">Professionals</div></div>
        <div class="stat"><div class="n" data-count="24">24<span>h</span></div><div class="l">Servei d'urgència</div></div>
      </div></div>
      <section class="section alt"><div class="wrap">
        <div class="sec-head"><div><span class="eyebrow">Com treballem</span>
          <h2>Un mètode <span class="accent">clar</span></h2></div>
          <p>Del primer diagnòstic al seguiment, sempre amb un tècnic de referència.</p></div>
        <div class="steps">
          <div class="step"><b>01</b><h4>Diagnòstic</h4><p>Visitem la planta i avaluem l'estat de les instal·lacions.</p></div>
          <div class="step"><b>02</b><h4>Proposta</h4><p>Pla d'actuació i pressupost tancat, sense sorpreses.</p></div>
          <div class="step"><b>03</b><h4>Execució</h4><p>Intervenim minimitzant les aturades de producció.</p></div>
          <div class="step"><b>04</b><h4>Seguiment</h4><p>Manteniment preventiu i informes periòdics.</p></div>
        </div></div></section>""" + CTA_BAND
    return render("Inici", body, "home")


@app.route("/services")
def services():
    body = pagehero("Serveis", 'Serveis <span class="accent">complets</span>',
                    "Tot el que la teva planta necessita, amb un únic interlocutor.", "engranatges") + f"""
      <section class="section"><div class="wrap"><div class="grid3">
        {card('01', 'soldadura', 'Manteniment preventiu i correctiu', 'Plans de manteniment i reparació d’avaries per evitar aturades.')}
        {card('02', 'planols', "Projectes d'enginyeria industrial", 'Disseny, càlcul i direcció de projectes a mida.')}
        {card('03', 'quadre-electric', 'Instal·lacions elèctriques i mecàniques', 'Quadres, línies, canonades i maquinària, amb legalització inclosa.')}
        {card('04', 'canonades', 'Assessorament i auditoria tècnica', 'Auditories d’eficiència i de seguretat de les instal·lacions.')}
        {card('05', 'eines', "Servei d'urgència 24 hores", 'Un tècnic a la teva planta en menys de dues hores.')}
        {card('06', 'maquinaria', 'Reparació de maquinària', 'Revisió i posada a punt d’equips i línies de producció.')}
      </div></div></section>
      <section class="section alt"><div class="wrap split">
      <div class="photo">{photo('planta', 'Planta industrial')}</div>
      <div><span class="eyebrow">Tot en un</span><h2>Un sol equip per a tota la <span class="accent">planta</span></h2>
      <ul class="list">
        <li>{ic('wrench')} Manteniment preventiu i correctiu</li>
        <li>{ic('ruler')} Projectes d'enginyeria industrial</li>
        <li>{ic('bolt')} Instal·lacions elèctriques i mecàniques</li>
        <li>{ic('clipboard')} Assessorament i auditoria tècnica</li>
        <li>{ic('alert')} Servei d'urgència 24 hores</li>
      </ul>
      <a class="btn" href="/careers">Treballa amb nosaltres {ic('arrow')}</a></div>
    </div></section>""" + CTA_BAND
    return render("Serveis", body, "services")


@app.route("/about")
def about():
    body = pagehero("Empresa", 'Qui <span class="accent">som</span>',
                    "Una empresa familiar al servei de la indústria del Vallès.", "planta") + f"""
      <section class="section"><div class="wrap split">
      <div><span class="eyebrow">Des de 2005</span><h2>Proximitat i <span class="accent">ofici</span></h2>
      <p>Tècnics Vallès SL és una empresa familiar fundada el 2005,
      especialitzada en serveis industrials al Vallès. El nostre equip de 25 professionals
      dona servei a més de 100 empreses de la comarca, amb un compromís ferm amb la qualitat
      i la proximitat.</p>
      <p>Creiem en les relacions de confiança
      a llarg termini amb els nostres clients.</p>
      <a class="btn" href="/services">Els nostres serveis {ic('arrow')}</a></div>
      <div class="photo">{photo('oficines', 'Seu de Tècnics Vallès')}</div>
    </div></section>
    <section class="section alt"><div class="wrap">
      <div class="sec-head"><div><span class="eyebrow">Valors</span><h2>El que ens <span class="accent">defineix</span></h2></div></div>
      <div class="grid3 values">
        <div class="card reveal"><div class="body"><span class="ic">{ic('shield')}</span><h4>Seguretat</h4><p>Treballem amb protocols estrictes de prevenció de riscos a cada intervenció.</p></div></div>
        <div class="card reveal"><div class="body"><span class="ic">{ic('users')}</span><h4>Proximitat</h4><p>Un tècnic de referència que coneix la teva planta i respon quan cal.</p></div></div>
        <div class="card reveal"><div class="body"><span class="ic">{ic('gear')}</span><h4>Qualitat</h4><p>Feina ben feta i documentada, amb garantia per escrit.</p></div></div>
      </div></div></section>""" + CTA_BAND
    return render("Qui som", body, "about")


@app.route("/careers")
def careers():
    body = pagehero("Feina", 'Treballa amb <span class="accent">nosaltres</span>',
                    "Busquem talent tècnic per créixer junts", "soldadura") + f"""
      <section class="section"><div class="wrap"><div class="jobs">
      <div class="jobcard"><div><h3>Tècnic/a de manteniment industrial</h3>
        <div class="tags"><span>Jornada completa</span><span>Vallès Occidental</span><span>Incorporació immediata</span></div></div>
        <a href="/apply?next=/thanks" class="btn">Presenta la candidatura {ic('arrow')}</a></div>
      <div class="jobcard"><div><h3>Enginyer/a de projectes</h3>
        <div class="tags"><span>Jornada completa</span><span>Vallès Occidental</span><span>Experiència mínima 2 anys</span></div></div>
        <a href="/apply?next=/thanks" class="btn">Presenta la candidatura {ic('arrow')}</a></div>
      </div>
      <p class="tracklink">
        <a href="/track?ref=web">Segueix l'estat de la teva sol·licitud {ic('arrow')}</a></p>
      </div></section>"""
    return render("Feina", body, "careers")


@app.route("/apply")
def apply():
    nxt = request.args.get("next", "/thanks")
    if CONFIG["redirect_fixed"]:
        if nxt.startswith("/") and not nxt.startswith("//"):
            return redirect(nxt)
        return redirect("/thanks")
    return redirect(nxt)


@app.route("/thanks")
def thanks():
    body = f"""<section class="section alt"><div class="wrap"><div class="statuscard">
      <span class="ic">{ic('check')}</span>
      <h2>Gràcies per la teva <span class="accent">candidatura</span></h2>
      <p>Hem rebut la teva sol·licitud. Ens posarem en contacte ben aviat.</p>
      <a class="btn" href="/">Torna a l'inici</a></div></div></section>"""
    return render("Gràcies", body)


@app.route("/track")
def track():
    ref = request.args.get("ref", "web")
    body = f"""<section class="section alt"><div class="wrap"><div class="statuscard">
      <span class="eyebrow">Seguiment de la sol·licitud</span>
      <div class="timeline"><div class="done">Rebuda</div><div class="done">En revisió</div><div>Entrevista</div><div>Resolució</div></div>
      <p class="ok">La teva candidatura està en revisió</p>
      <p>T'avisarem per correu de qualsevol novetat.</p>
      <p class="origin">Origen: {H.escape(ref)}</p></div></div></section>"""
    resp = make_response(render("Seguiment", body))
    if CONFIG["headerinj_fixed"]:
        ref = ref.replace("\r", "").replace("\n", "")
    resp.headers["X-Ref"] = ref
    return resp


if __name__ == "__main__":
    import os
    if os.environ.get("TR_SECURE"):
        for _k in CONFIG: CONFIG[_k] = True   # secure mode: apply every fix
    port = int(os.environ.get("PORT", 5003))
    print(f"Empresa 'Tècnics Vallès SL': http://0.0.0.0:{port}/")
    app.run(host="0.0.0.0", port=port)
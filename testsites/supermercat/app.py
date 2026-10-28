"""
Demo vulnerable site: SUPERMARKET "Ca l'Andreu" (port 5001).
Realistic online-grocery look. Photos, fonts, icons, CSS and JS are all
served locally from ./static, so the site works with no Internet access
(photo credits: static/img/CREDITS.md).

Vulnerabilities (toggle in CONFIG, False=vulnerable):
  - sqli_search   : SQLi via search box (?q=)
  - sqli_category : SQLi via catalog category (?cat=)
  - xss_reviews   : reflected XSS in reviews (?comment=)

RUN LOCALLY ONLY. Never expose unprotected.
    pip install flask ; python app.py     # http://127.0.0.1:5001/
"""
import sqlite3, html as H
from flask import (Flask, request, redirect, session,
                   render_template_string, url_for)
from markupsafe import Markup

app = Flask(__name__)
app.secret_key = "demo-only"
CONFIG = {"sqli_search_fixed": False, "sqli_category_fixed": False,
          "xss_reviews_fixed": False}
DB = "supermercat.db"

CATEGORIES = ["Forn", "Làctics", "Fruita i verdura", "Carn i peix", "Rebost", "Begudes"]
# Local photo (static/img/<file>.jpg) and sales format for each product.
PHOTO = {
 "Pa de pagès":"pa","Croissant de mantega":"croissant",
 "Llet sencera 1L":"llet","Iogurt natural x4":"iogurt",
 "Formatge manxec curat":"formatge","Tomàquets de penjar":"tomaquet",
 "Plàtans de Canàries":"platan","Pollastre sencer":"pollastre",
 "Salmó fresc":"salmo","Arròs bomba 1kg":"arros",
 "Oli d'oliva verge extra":"oli","Aigua mineral 6x1.5L":"aigua"}
UNIT = {
 "Pa de pagès":"Peça de 500 g","Croissant de mantega":"Unitat",
 "Llet sencera 1L":"Ampolla d'1 L","Iogurt natural x4":"Pack de 4 × 125 g",
 "Formatge manxec curat":"Tall de 250 g","Tomàquets de penjar":"Safata de 500 g",
 "Plàtans de Canàries":"Manat d'1 kg aprox.","Pollastre sencer":"Peça d'1,4 kg aprox.",
 "Salmó fresc":"Safata de 300 g","Arròs bomba 1kg":"Paquet d'1 kg",
 "Oli d'oliva verge extra":"Ampolla de 750 ml","Aigua mineral 6x1.5L":"Pack de 6 × 1,5 L"}
CATPHOTO = {"Forn":"pa","Làctics":"llet","Fruita i verdura":"tomaquet",
 "Carn i peix":"salmo","Rebost":"oli","Begudes":"aigua"}


def init_db():
    c = sqlite3.connect(DB)
    c.executescript("""
      DROP TABLE IF EXISTS products; DROP TABLE IF EXISTS users; DROP TABLE IF EXISTS reviews;
      CREATE TABLE products(id INTEGER PRIMARY KEY, name TEXT, category TEXT, price REAL, description TEXT);
      CREATE TABLE users(id INTEGER PRIMARY KEY, username TEXT, password TEXT, is_admin INTEGER DEFAULT 0);
      CREATE TABLE reviews(id INTEGER PRIMARY KEY, product_id INTEGER, author TEXT, comment TEXT);
      INSERT INTO products(name,category,price,description) VALUES
        ('Pa de pagès','Forn',1.20,'Pa artesà de massa mare, cuit al forn de llenya.'),
        ('Croissant de mantega','Forn',1.10,'Cruixent i fullat, recepta tradicional.'),
        ('Llet sencera 1L','Làctics',0.95,'Llet fresca pasteuritzada del dia.'),
        ('Iogurt natural x4','Làctics',1.75,'Iogurts cremosos sense sucre afegit.'),
        ('Formatge manxec curat','Làctics',4.50,'Curat 6 mesos, sabor intens.'),
        ('Tomàquets de penjar','Fruita i verdura',1.80,'Ideals per a pa amb tomàquet.'),
        ('Plàtans de Canàries','Fruita i verdura',1.40,'Dolços i madurs al punt.'),
        ('Pollastre sencer','Carn i peix',5.20,'Pollastre de corral criat en llibertat.'),
        ('Salmó fresc','Carn i peix',9.90,'Tallat del dia, ideal al forn.'),
        ('Arròs bomba 1kg','Rebost',1.60,'Varietat ideal per a paella.'),
        ('Oli d''oliva verge extra','Rebost',6.90,'Primera pressió en fred.'),
        ('Aigua mineral 6x1.5L','Begudes',2.10,'D''origen natural.');
      INSERT INTO users(username,password,is_admin) VALUES ('admin','Sup3rM3rc4t!',1),('joana','1234',0);
      INSERT INTO reviews(product_id,author,comment) VALUES
        (1,'Marc','Boníssim, com el de tota la vida'),
        (5,'Laia','El meu formatge preferit, molt recomanable');
    """)
    c.commit(); c.close()

def db():
    conn = sqlite3.connect(DB); conn.row_factory = sqlite3.Row; return conn


def ic(name):
    """Inline reference to an icon of the local SVG sprite."""
    return f'<svg class="i" aria-hidden="true"><use href="/static/icons.svg#{name}"/></svg>'

def eur(x):
    return f"{x:.2f}".replace(".", ",") + " €"

def img(p):
    """Local product photo (static/img)."""
    f = PHOTO.get(p["name"], "botiga")
    return f'<img src="/static/img/{f}.jpg" alt="{H.escape(p["name"])}" loading="lazy">'

STARS = '<span class="stars">' + ic("star") * 5 + '</span>'


BASE = """<!doctype html><html lang="ca"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{title}} · Ca l'Andreu</title>
<link rel="icon" href="/static/favicon.svg">
<link rel="stylesheet" href="/static/style.css"></head><body>
<div class="topbar"><div class="wrap"><div class="perks">
  <span>{{ic('truck')}} Enviament gratuït a partir de 40 €</span>
  <span>{{ic('clock')}} Recollida a la botiga en 2 h</span>
  <span>{{ic('leaf')}} Producte fresc del barri cada dia</span></div>
  <span>{{ic('phone')}} 93 555 01 72</span></div></div>
<header class="site"><div class="wrap head">
  <a class="logo" href="/"><span class="mark">{{ic('basket')}}</span><span>Ca l'<em>Andreu</em></span></a>
  <form class="searchbar" action="/search" method="get">{{ic('search')}}
    <input name="q" placeholder="Cerca pa, llet, fruita…" aria-label="Cerca productes">
    <button>Cerca</button></form>
  <nav class="actions">
    {% if user %}<a href="/account">{{ic('user')}}<span class="lbl">{{user}}</span></a>
    {% if is_admin %}<a href="/admin">{{ic('settings')}}<span class="lbl">Admin</span></a>{% endif %}
    <a href="/logout">{{ic('logout')}}<span class="lbl">Surt</span></a>
    {% else %}<a href="/login">{{ic('user')}}<span class="lbl">Entra</span></a>{% endif %}
    <a class="cartlink" href="/cart">{{ic('cart')}}<span class="lbl">Cistella</span>{% if cart_n %}<span class="badge">{{cart_n}}</span>{% endif %}</a>
  </nav></div>
  <div class="cats"><div class="wrap">
    {% for c in categories %}<a href="/catalog?cat={{c}}"{% if c == active %} class="on"{% endif %}>{{c}}</a>{% endfor %}
  </div></div>
</header>
<main><div class="wrap">{{body|safe}}</div></main>
<div id="toast" class="toast">{{ic('check')}} Producte afegit a la cistella</div>
<footer class="site"><div class="wrap foot-grid">
  <div><a class="logo" href="/"><span class="mark">{{ic('basket')}}</span><span>Ca l'<em>Andreu</em></span></a>
    <p>Supermercat de barri des de 1972. Producte fresc i de proximitat, amb el tracte de sempre.</p></div>
  <div><h4>Seccions</h4><ul>
    {% for c in categories %}<li><a href="/catalog?cat={{c}}">{{c}}</a></li>{% endfor %}</ul></div>
  <div><h4>El teu compte</h4><ul>
    <li><a href="/login">Accés clients</a></li><li><a href="/cart">La teva cistella</a></li></ul></div>
  <div><h4>Contacte</h4><ul>
    <li>{{ic('pin')}} Carrer Major, 14 · Sabadell</li><li>{{ic('phone')}} 93 555 01 72</li>
    <li>{{ic('mail')}} hola@calandreu.example</li><li>{{ic('clock')}} Dl–Ds · 8.30–21 h</li></ul></div>
</div><div class="legal"><div class="wrap"><span>© 2026 Ca l'Andreu · Supermercat de barri des de 1972</span>
  <span>Demo acadèmica (TR) · Aquest lloc conté vulnerabilitats intencionades amb finalitat educativa.</span></div></div></footer>
<script src="/static/app.js"></script>
</body></html>"""

def render(title, body, active=None):
    return render_template_string(
        BASE, title=title, body=body, user=session.get("user"),
        is_admin=session.get("is_admin"), active=active, ic=lambda n: Markup(ic(n)),
        cart_n=sum(session.get("cart", {}).values()), categories=CATEGORIES)

def card(p):
    return f"""<a class="card reveal" href="/product?id={p['id']}"><div class="ph">{img(p)}</div><div class="body">
      <div class="cat">{H.escape(p['category'])}</div>
      <div class="name">{H.escape(p['name'])}</div>
      <div class="unit">{H.escape(UNIT.get(p['name'], ''))}</div>
      <div class="foot"><span class="price">{eur(p['price'])}</span>
      <span class="go">Veure {ic('arrow')}</span></div></div></a>"""

def pagehead(eyebrow, title, sub=""):
    return (f'<div class="pagehead"><span class="eyebrow">{eyebrow}</span><h1>{title}</h1>'
            + (f"<p>{sub}</p>" if sub else "") + "</div>")


@app.route("/")
def home():
    conn = db(); prods = conn.execute("SELECT * FROM products LIMIT 8").fetchall(); conn.close()
    grid = "".join(card(p) for p in prods)
    tiles = "".join(f'<a class="tile" href="/catalog?cat={c}"><img src="/static/img/{CATPHOTO[c]}.jpg" alt="" loading="lazy">'
                    f'<span>{c}</span></a>' for c in CATEGORIES)
    body = f"""<section class="hero">
        <div class="slide on"><img src="/static/img/hero-mercat.jpg" alt="">
          <div class="txt"><span class="eyebrow">Supermercat de barri des de 1972</span>
          <h1>La compra de sempre, ara en línia</h1>
          <p>Producte fresc del barri, a casa teva en poques hores.</p>
          <a class="btn btn-lg" href="/catalog?cat=Fruita i verdura">Comença la compra {ic('arrow')}</a></div></div>
        <div class="slide"><img src="/static/img/hero-verdura.jpg" alt="">
          <div class="txt"><span class="eyebrow">De temporada</span>
          <h1>Fruita i verdura de proximitat</h1>
          <p>Del pagès a la teva taula, cada matí.</p>
          <a class="btn btn-lg" href="/catalog?cat=Fruita i verdura">Veure la secció {ic('arrow')}</a></div></div>
        <div class="slide"><img src="/static/img/hero-forn.jpg" alt="">
          <div class="txt"><span class="eyebrow">Forn propi</span>
          <h1>Pa de massa mare, acabat de fer</h1>
          <p>Enviament gratuït a partir de 40 € de compra.</p>
          <a class="btn btn-lg" href="/catalog?cat=Forn">Descobreix el forn {ic('arrow')}</a></div></div>
        <div class="dots"><button class="dot on" aria-label="Diapositiva 1"></button><button class="dot" aria-label="Diapositiva 2"></button><button class="dot" aria-label="Diapositiva 3"></button></div>
      </section>
      <div class="perks-row">
        <div class="perk"><span class="ic">{ic('truck')}</span><div><b>Enviament en 24 h</b><small>Gratuït a partir de 40 €</small></div></div>
        <div class="perk"><span class="ic">{ic('clock')}</span><div><b>Recollida en 2 h</b><small>A la botiga del carrer Major</small></div></div>
        <div class="perk"><span class="ic">{ic('leaf')}</span><div><b>Producte de proximitat</b><small>Pagesos i productors locals</small></div></div>
        <div class="perk"><span class="ic">{ic('shield')}</span><div><b>Frescor garantida</b><small>O et tornem els diners</small></div></div>
      </div>
      <section class="section"><div class="section-head"><h2 class="section-title">Compra per seccions</h2></div>
        <div class="tiles">{tiles}</div></section>
      <section class="section"><div class="section-head"><h2 class="section-title">Els més venuts</h2>
        <p>Els preferits dels nostres clients aquesta setmana</p></div>
        <div class="grid">{grid}</div></section>
      <section class="section story"><img src="/static/img/botiga.jpg" alt="Interior de la botiga" loading="lazy">
        <div class="txt"><span class="eyebrow">La nostra història</span>
          <h2>Tres generacions darrere el taulell</h2>
          <p>L'Andreu va obrir la botiga el 1972 amb una idea senzilla: bon producte i tracte de veí. Avui hi afegim la comoditat de comprar des de casa.</p>
          <div class="nums"><div><b>1972</b><span>Any de fundació</span></div><div><b>40+</b><span>Productors locals</span></div><div><b>2 h</b><span>Recollida a la botiga</span></div></div>
        </div></section>"""
    return render("Inici", body)


@app.route("/catalog")
def catalog():
    cat = request.args.get("cat", "")
    conn = db()
    if CONFIG["sqli_category_fixed"]:
        prods = conn.execute("SELECT * FROM products WHERE category=?", (cat,)).fetchall()
    else:
        prods = conn.execute(f"SELECT * FROM products WHERE category='{cat}'").fetchall()
    conn.close()
    grid = "".join(card(p) for p in prods)
    body = (f"""<div class="crumbs"><a href="/">Inici</a><span>/</span><b>{H.escape(cat)}</b></div>"""
            + pagehead("Secció", H.escape(cat), f"{len(prods)} {'producte' if len(prods) == 1 else 'productes'}")
            + (f'<div class="grid">{grid}</div>' if prods else
               '<p class="muted">No hi ha productes en aquesta categoria.</p>'))
    return render(cat or "Catàleg", body, active=cat)


@app.route("/search")
def search():
    q = request.args.get("q", "")
    conn = db()
    if CONFIG["sqli_search_fixed"]:
        prods = conn.execute("SELECT * FROM products WHERE name LIKE ?", (f"%{q}%",)).fetchall()
    else:
        prods = conn.execute(f"SELECT * FROM products WHERE name LIKE '%{q}%'").fetchall()
    conn.close()
    grid = "".join(card(p) for p in prods)
    body = (pagehead("Cerca", f"Resultats per «{H.escape(q)}»", f"{len(prods)} {'producte trobat' if len(prods) == 1 else 'productes trobats'}")
            + f'<div class="grid">{grid}</div>'
            if prods else
            f"""<div class="empty"><span class="ic">{ic('search')}</span>
              <h1>Cap resultat per «{H.escape(q)}»</h1>
              <p>Prova amb una altra paraula o explora les nostres seccions.</p>
              <a class="btn" href="/">Torna a l'inici</a></div>""")
    return render("Cerca", body)


@app.route("/product")
def product():
    pid = request.args.get("id", "1")
    conn = db()
    p = conn.execute("SELECT * FROM products WHERE id=?", (pid,)).fetchone()
    revs = conn.execute("SELECT * FROM reviews WHERE product_id=?", (pid,)).fetchall()
    conn.close()
    if not p:
        return render("No trobat", f"""<div class="empty"><span class="ic">{ic('search')}</span>
          <h1>Producte no trobat</h1><p>Pot ser que ja no estigui disponible.</p>
          <a class="btn" href="/">Torna a l'inici</a></div>""")
    rev = "".join(f'<div class="review"><span class="avatar">{H.escape(r["author"][:1])}</span>'
                  f'<div><b>{H.escape(r["author"])}</b>{STARS}<p>{H.escape(r["comment"])}</p></div></div>'
                  for r in revs) or '<p class="muted">Encara no hi ha ressenyes. Sigues el primer a opinar!</p>'
    body = f"""<div class="crumbs"><a href="/">Inici</a><span>/</span>
        <a href="/catalog?cat={p['category']}">{H.escape(p['category'])}</a><span>/</span><b>{H.escape(p['name'])}</b></div>
      <div class="product">
        <div class="photo">{img(p)}</div>
        <div><span class="cat">{H.escape(p['category'])}</span>
          <h1>{H.escape(p['name'])}</h1>
          <div class="rating">{STARS}<span>{len(revs)} {'ressenya' if len(revs) == 1 else 'ressenyes'} · {H.escape(UNIT.get(p['name'], ''))}</span></div>
          <p class="desc">{H.escape(p['description'])}</p>
          <div class="price">{eur(p['price'])}<small>IVA inclòs</small></div>
          <div class="buy"><a class="btn btn-lg" href="/cart/add?id={p['id']}">{ic('cart')} Afegeix a la cistella</a></div>
          <ul class="facts">
            <li>{ic('truck')} Enviament a domicili en 24 h · gratuït a partir de 40 €</li>
            <li>{ic('clock')} Recollida a la botiga en 2 hores</li>
            <li>{ic('shield')} Frescor garantida o et tornem els diners</li></ul>
        </div></div>
      <section class="section"><div class="section-head"><h2 class="section-title">Ressenyes dels clients</h2>
        <a class="btn btn-ghost"
         href="/reviews?product={p['id']}&comment=Escriu la teva opinió">Escriu una ressenya</a></div>{rev}</section>"""
    return render(p['name'], body, active=p['category'])


@app.route("/reviews")
def reviews():
    comment = request.args.get("comment", ""); pid = request.args.get("product", "")
    shown = H.escape(comment) if CONFIG["xss_reviews_fixed"] else comment
    body = pagehead("Ressenyes", "La teva ressenya", "Així es veurà la teva opinió abans de publicar-la.") + f"""
      <div class="alert alert-info">Previsualització: {shown}</div>
      <a class="btn" href="/product?id={H.escape(pid)}">Torna al producte</a>"""
    return render("Ressenya", body)


@app.route("/cart/add")
def cart_add():
    pid = request.args.get("id"); cart = session.get("cart", {})
    cart[pid] = cart.get(pid, 0) + 1; session["cart"] = cart
    return redirect(url_for("cart") + "#added")


@app.route("/cart")
def cart():
    cart = session.get("cart", {})
    if not cart:
        return render("Cistella", f"""<div class="empty"><span class="ic">{ic('cart')}</span>
          <h1>La cistella és buida</h1><p>Afegeix-hi productes i els trobaràs aquí.</p>
          <a class="btn" href="/">Ves a comprar</a></div>""")
    conn = db(); rows = ""; total = 0; units = 0
    for pid, n in cart.items():
        p = conn.execute("SELECT * FROM products WHERE id=?", (pid,)).fetchone()
        if p:
            sub = p["price"]*n; total += sub; units += n
            rows += (f'<tr><td><a class="item" href="/product?id={p["id"]}">{img(p)}{H.escape(p["name"])}</a></td>'
                     f'<td class="num">{eur(p["price"])}</td><td class="num">{n}</td><td class="num"><b>{eur(sub)}</b></td></tr>')
    conn.close()
    ship = 0 if total >= 40 else 3.90
    body = pagehead("Cistella", "La teva cistella", f"{units} {'article' if units == 1 else 'articles'}") + f"""
      <div class="checkout"><div class="panel">
      <table><thead><tr><th>Producte</th><th class="num">Preu</th><th class="num">Unitats</th><th class="num">Subtotal</th></tr></thead>
      <tbody>{rows}</tbody></table></div>
      <div class="panel summary"><h3>Resum de la comanda</h3>
        <div class="row"><span>Subtotal</span><span>{eur(total)}</span></div>
        <div class="row"><span>Enviament</span><span>{'Gratuït' if not ship else eur(ship)}</span></div>
        <div class="row total"><span>Total</span><span>{eur(total + ship)}</span></div>
        <a class="btn btn-block btn-lg" href="#">Finalitza la compra</a>
        <span class="secure">{ic('lock')} Pagament segur</span></div></div>"""
    return render("Cistella", body)


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        u = request.form.get("user", ""); pw = request.form.get("password", "")
        conn = db(); row = conn.execute("SELECT * FROM users WHERE username=? AND password=?", (u, pw)).fetchone(); conn.close()
        if row:
            session["user"] = row["username"]; session["is_admin"] = bool(row["is_admin"])
            return redirect(url_for("home"))
        return render("Entra", _form('<div class="alert">Credencials incorrectes</div>'))
    return render("Entra", _form())

def _form(alert=""):
    return f"""<form class="auth" method="post">
        <h1>Accedeix al teu compte</h1><p>Consulta les teves comandes i compra més de pressa.</p>{alert}
        <label class="field"><span>Usuari</span><input name="user" autocomplete="username"></label>
        <label class="field"><span>Contrasenya</span><input name="password" type="password" autocomplete="current-password"></label>
        <button class="btn btn-block btn-lg">Entra</button>
        <p class="hint">Compte de prova: <b>joana</b> / <b>1234</b></p></form>"""


@app.route("/account")
def account():
    if not session.get("user"): return redirect(url_for("login"))
    return render("Compte", pagehead("El meu compte", f'Hola, {H.escape(session["user"])}',
        "Benvingut/da a la teva àrea personal de Ca l'Andreu.") + f"""
      <div class="perks-row">
        <div class="perk"><span class="ic">{ic('cart')}</span><div><b>La teva cistella</b><small><a href="/cart">Continua la compra</a></small></div></div>
        <div class="perk"><span class="ic">{ic('truck')}</span><div><b>Comandes</b><small>Encara no has fet cap comanda</small></div></div>
        <div class="perk"><span class="ic">{ic('pin')}</span><div><b>Adreça d'entrega</b><small>Carrer Major, 14 · Sabadell</small></div></div>
        <div class="perk"><span class="ic">{ic('shield')}</span><div><b>Compte verificat</b><small>Client des de 2024</small></div></div>
      </div>""")


@app.route("/admin")
def admin():
    if not session.get("is_admin"):
        return render("Admin", f"""<div class="empty"><span class="ic">{ic('lock')}</span>
          <h1>Accés restringit</h1><p>Aquesta secció és només per a administradors.</p>
          <a class="btn" href="/">Torna a l'inici</a></div>""")
    conn = db(); prods = conn.execute("SELECT * FROM products").fetchall(); conn.close()
    rows = "".join(f'<tr><td>{p["id"]}</td><td><span class="item">{img(p)}{H.escape(p["name"])}</span></td>'
                   f'<td>{H.escape(p["category"])}</td><td class="num">{eur(p["price"])}</td></tr>' for p in prods)
    body = pagehead("Administració", "Panell d'administració", f"{len(prods)} productes al catàleg") + f"""
      <div class="panel"><table><thead><tr><th>ID</th><th>Producte</th><th>Categoria</th><th class="num">Preu</th></tr></thead><tbody>{rows}</tbody></table></div>"""
    return render("Admin", body)


@app.route("/logout")
def logout():
    session.clear(); return redirect(url_for("home"))


if __name__ == "__main__":
    import os
    if os.environ.get("TR_SECURE"):
        for _k in CONFIG: CONFIG[_k] = True   # secure mode: apply every fix
    port = int(os.environ.get("PORT", 5001))
    init_db(); print(f"Supermercat 'Ca l'Andreu': http://0.0.0.0:{port}/")
    app.run(host="0.0.0.0", port=port)
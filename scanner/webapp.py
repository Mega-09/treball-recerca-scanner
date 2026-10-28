"""
Web interface for the vulnerability scanner.

Flask app: enter a URL, run the scanner, stream progress live (SSE), and
show findings with contextual summaries and expandable detail (steps +
code fix + reference). The page markup lives below; its CSS, JS, icons and
fonts are served locally from ./static. Features:
  - Language selector for the solutions (Catalan / English), switchable
    without re-scanning (every finding carries all languages).
  - Download the raw scan.log (English).
  - Download a full report (findings + solutions) as JSON.

SECURITY: the scanner's ALLOWED_HOSTS still applies. For public use, add
authentication and rate limiting (see the TR).

    pip install flask ; python webapp.py     # http://127.0.0.1:8080/
"""
import json
import os
import queue
import threading

from flask import Flask, request, Response, render_template_string, jsonify

import scanner
from modules import scan_log
from modules import attack_demo
import html as _H

app = Flask(__name__)
LAST = {"report": None}   # keep the most recent report for downloads

PAGE = r"""<!doctype html><html lang="ca"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Escàner de vulnerabilitats web</title>
<link rel="icon" href="/static/favicon.svg">
<link rel="stylesheet" href="/static/app.css"></head><body>
{% macro ic(n) %}<svg class="i" aria-hidden="true"><use href="/static/icons.svg#{{n}}"/></svg>{% endmacro %}
<div class="nav"><div class="wrap">
  <a class="brand" href="/"><span class="mark">{{ic('shield')}}</span>
    <span>Escàner de vulnerabilitats web<small>Treball de recerca</small></span></a>
  <span class="navlinks"><a class="navlink" href="/attack">{{ic('alert')}} Mode atacant</a>
  <span class="pill">{{ic('lock')}} Només objectius autoritzats</span></span></div></div>
<div class="wrap">
  <header class="hero"><h1>Analitza la seguretat d'un <span>lloc web</span></h1>
  <p>Introdueix una adreça i comprova si té vulnerabilitats conegudes: injecció SQL, XSS,
  redireccions obertes, capçaleres de seguretat i més.</p></header>

  <section class="card scan">
    <div class="scanbox">
      <div class="inputwrap">{{ic('globe')}}
        <input id="url" placeholder="https://exemple.com" value="https://ginandjuice.shop" spellcheck="false" autocomplete="off" aria-label="Adreça a escanejar"></div>
      <button class="go" id="go">{{ic('play')}} Escaneja</button>
    </div>
    <div class="quick">Objectius de prova:
      <button data-url="https://ginandjuice.shop">Gin &amp; Juice Shop</button>
      <button data-url="http://127.0.0.1:5001">Supermercat</button>
      <button data-url="http://127.0.0.1:5002">Clínica</button>
      <button data-url="http://127.0.0.1:5003">Empresa</button>
    </div>
    <div class="opts">
      <div><span class="lbl">Nivell d'escaneig</span>
        <div class="levels">
          <label><input type="radio" name="level" value="basic"><span><b>Bàsic</b><small>Ràpid · capçaleres i dependències</small></span></label>
          <label><input type="radio" name="level" value="standard" checked><span><b>Estàndard</b><small>Equilibrat · afegeix SQLi i redireccions</small></span></label>
          <label><input type="radio" name="level" value="complete"><span><b>Complet</b><small>A fons · totes les proves</small></span></label>
        </div></div>
      <div><label class="lbl" for="lang">Idioma de les solucions</label>
        <select id="lang"><option value="ca">Català</option><option value="en">English</option></select></div>
    </div>
  </section>

  <section class="card progress section" id="progress">
    <div class="prog-top"><div class="phase"><span class="dotlive"></span><span id="phase">A punt per escanejar</span></div>
      <div class="meta"><span>{{ic('clock')}} <span id="timer">0 s</span></span>
        <span>Trobades: <b id="count">0</b></span></div></div>
    <div class="bar"><i id="bar"></i></div>
    <div class="steps" id="steps"></div>
  </section>

  <section class="card console section">
    <div class="console-head"><i></i><i></i><i></i><span>scan.log — progrés en directe</span></div>
    <div class="console-body" id="console"><div class="ph">La consola mostrarà el progrés en directe…</div></div>
  </section>

  <section id="resultsbox" class="hidden">
    <div class="results-head"><h2>Resultats de l'escaneig</h2>
      <div class="dls"><a class="dl disabled" id="dllog" href="#">{{ic('download')}} Log (anglès)</a>
        <a class="dl disabled" id="dlrep" href="#">{{ic('file')}} Informe JSON</a></div></div>
    <div id="scorecard"></div>
    <div class="summary">
      <button class="stat on" data-f="all"><b id="n-all">0</b><span>Totes</span></button>
      <button class="stat high" data-f="high"><b id="n-high">0</b><span>Alta</span></button>
      <button class="stat medium" data-f="medium"><b id="n-medium">0</b><span>Mitjana</span></button>
      <button class="stat low" data-f="low"><b id="n-low">0</b><span>Baixa</span></button>
    </div>
    <div class="facts" id="facts"></div>
    <div id="results"></div>
    <div id="reflected"></div>
  </section>
</div>
<footer><div class="wrap"><span>Escàner de vulnerabilitats web · Treball de recerca</span>
  <span>Fes servir aquesta eina només contra llocs propis o amb autorització expressa.</span></div></footer>
<script src="/static/app.js"></script></body></html>"""


@app.route("/")
def index():
    return render_template_string(PAGE)


@app.route("/scan")
def scan_stream():
    url = request.args.get("url", "").strip()
    level = request.args.get("level", "complete")
    tests = scanner.LEVELS.get(level, None)

    def generate():
        q = queue.Queue()
        scan_log.add_sink(lambda kind, text: q.put((kind, text)))

        def run():
            try:
                report = scanner.scan(url, tests=tests)
                LAST["report"] = report
                q.put(("_report", report))
            except scanner.TargetNotAllowed as e:
                q.put(("_fail", str(e)))
            except Exception as e:
                q.put(("_fail", f"{type(e).__name__}: {e}"))
            finally:
                scan_log.clear_sinks()
                q.put(("_end", None))

        threading.Thread(target=run, daemon=True).start()

        def sse(event, data):
            return f"event: {event}\ndata: {data}\n\n"

        while True:
            kind, payload = q.get()
            if kind == "_end":
                break
            elif kind == "_fail":
                yield sse("fail", payload)
            elif kind == "_report":
                for f in payload["findings"]:
                    yield sse("result", json.dumps(f, ensure_ascii=False))
                yield sse("done", json.dumps({"count": len(payload["findings"]),
                    "elapsed": payload.get("elapsed_seconds"), "level": level,
                    "target": payload.get("target"), "pages": payload.get("pages_scanned"),
                    "forms": payload.get("forms_found"), "points": payload.get("injection_points"),
                    "reflected": payload.get("reflected_surfaces", []),
                    "score": payload.get("security_score")},
                    ensure_ascii=False))
            else:
                yield sse(kind, payload)

    return Response(generate(), mimetype="text/event-stream")


@app.route("/download/log")
def download_log():
    # scan.log is written next to the scanner package (cwd when run)
    path = "scan.log"
    if not os.path.exists(path):
        return "No log available yet.", 404
    with open(path, encoding="utf-8") as f:
        data = f.read()
    return Response(data, mimetype="text/plain",
                    headers={"Content-Disposition": "attachment; filename=scan.log"})


@app.route("/download/report")
def download_report():
    if not LAST["report"]:
        return "No report available yet.", 404
    data = json.dumps(LAST["report"], ensure_ascii=False, indent=2)
    return Response(data, mimetype="application/json",
                    headers={"Content-Disposition": "attachment; filename=report.json"})


# --- "Attacker's-eye view": impact demo on the authorised demo sites -------
# Each site is run twice: the vulnerable instance and the one with the
# scanner's fixes applied, side by side.
ATTACK_SITES = [
    ("clinica",     "Clínica Salut Sant Jordi",
     "http://127.0.0.1:5002", "http://127.0.0.1:5012"),
    ("supermercat", "Supermercat Ca l'Andreu",
     "http://127.0.0.1:5001", "http://127.0.0.1:5011"),
    ("empresa",     "Tècnics Vallès SL",
     "http://127.0.0.1:5003", "http://127.0.0.1:5013"),
]

ATTACK_PAGE = r"""<!doctype html><html lang="ca"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Mode atacant · Escàner de vulnerabilitats web</title>
<link rel="icon" href="/static/favicon.svg">
<link rel="stylesheet" href="/static/app.css">
<style>
.atk-hero{padding:28px 0 8px}
.atk-hero h1{font-size:1.9rem;margin:.2rem 0;letter-spacing:-.02em}
.atk-hero .lead{max-width:64ch;color:var(--muted);font-size:1.05rem}
.atk-note{display:flex;gap:.6rem;align-items:flex-start;margin:16px 0 4px;padding:12px 14px;
  border:1px solid #4a3a12;background:rgba(255,176,32,.08);color:#ffce7a;border-radius:12px;font-size:.9rem}
.atk-note .i{flex:0 0 auto;width:18px;height:18px;margin-top:1px;color:var(--medium)}
.atk{margin:22px 0;border:1px solid var(--line);border-radius:16px;overflow:hidden;background:var(--panel)}
.atk-top{padding:16px 18px;border-bottom:1px solid var(--line)}
.atk-top .tag{font-size:.74rem;text-transform:uppercase;letter-spacing:.06em;color:var(--high);font-weight:700}
.atk-top h2{margin:.2rem 0 .3rem;font-size:1.25rem;color:var(--text)}
.atk-top p{margin:0;color:var(--muted)}
.atk-steps{margin:0;padding:14px 18px;list-style:none;border-bottom:1px solid var(--line);background:var(--panel-2)}
.atk-steps li{margin:0 0 10px;padding-left:2px}
.atk-steps li:last-child{margin-bottom:0}
.atk-steps b{display:block;font-size:.92rem;color:var(--text)}
.atk-steps code{display:inline-block;margin:3px 0;padding:2px 7px;border-radius:7px;background:#05080f;color:#8fb6ff;
  font-family:var(--mono);font-size:.78rem;word-break:break-all;border:1px solid var(--line)}
.atk-steps .n{display:block;color:var(--muted);font-size:.84rem}
.atk-cols{display:grid;grid-template-columns:1fr 1fr;gap:0}
.atk-col{padding:16px 18px}
.atk-col+.atk-col{border-left:1px solid var(--line)}
.atk-col h3{display:flex;align-items:center;gap:.45rem;margin:0 0 4px;font-size:1rem}
.atk-col h3 .i{width:18px;height:18px}
.atk-col .sub{margin:0 0 12px;font-size:.84rem;color:var(--muted)}
.col-vuln h3{color:var(--high)}
.col-safe h3{color:var(--ok)}
.leak{width:100%;border-collapse:collapse;font-size:.86rem}
.leak th{text-align:left;font-size:.72rem;text-transform:uppercase;letter-spacing:.04em;color:#ff9a9a;
  border-bottom:2px solid rgba(255,93,93,.4);padding:6px 8px}
.leak td{padding:6px 8px;border-bottom:1px solid rgba(255,93,93,.15);font-family:var(--mono);
  font-size:.82rem;color:#ffb4b4;word-break:break-word}
.leak tr:nth-child(even) td{background:rgba(255,93,93,.06)}
.leak .danger{color:var(--high);font-weight:700}
.safe-box{display:flex;gap:.7rem;align-items:flex-start;padding:14px;border:1px solid rgba(61,220,151,.35);
  background:rgba(61,220,151,.08);border-radius:12px;color:#8ef0c4}
.safe-box .i{flex:0 0 auto;width:22px;height:22px;margin-top:1px;color:var(--ok)}
.safe-box b{display:block;color:var(--ok)}
.atk-impact{padding:14px 18px;background:rgba(255,93,93,.1);color:#ffb4b4;font-size:.92rem;display:flex;gap:.6rem;align-items:flex-start;border-top:1px solid rgba(255,93,93,.2)}
.atk-impact .i{flex:0 0 auto;width:20px;height:20px;margin-top:1px;color:var(--high)}
.atk-impact.safe{background:rgba(61,220,151,.08);color:#8ef0c4;border-top-color:rgba(61,220,151,.2)}
.atk-impact.safe .i{color:var(--ok)}
.atk-impact b{color:inherit}
.atk-foot{margin:30px 0 50px;text-align:center}
@media(max-width:720px){.atk-cols{grid-template-columns:1fr}.atk-col+.atk-col{border-left:0;border-top:1px solid var(--line)}}
</style></head><body>
{% macro ic(n) %}<svg class="i" aria-hidden="true"><use href="/static/icons.svg#{{n}}"/></svg>{% endmacro %}
<div class="nav"><div class="wrap">
  <a class="brand" href="/"><span class="mark">{{ic('shield')}}</span>
    <span>Escàner de vulnerabilitats web<small>Mode atacant</small></span></a>
  <span class="navlinks"><a class="navlink" href="/">{{ic('arrow')}} Torna a l'escàner</a>
  <span class="pill">{{ic('lock')}} Només llocs de prova propis</span></span></div></div>
<div class="wrap">
  <header class="atk-hero"><h1>Què veu un atacant <span style="color:#b91c1c">de veritat</span></h1>
  <p class="lead">L'escàner marca una vulnerabilitat amb una etiqueta («alta», «mitjana»). Aquí
  executem l'atac fins al final contra els nostres llocs de prova per ensenyar què vol dir
  això de debò: les dades que s'enduu un atacant. A la dreta, el mateix atac contra la versió
  amb les correccions que proposa l'escàner.</p></header>
  <div class="atk-note">{{ic('alert')}}<span>Aquesta demostració sí que explota les vulnerabilitats,
  a diferència de l'escàner. Per això només s'executa contra els llocs de prova locals creats per
  al treball (127.0.0.1), mai contra webs de tercers.</span></div>

  {{ blocks|safe }}

  <div class="atk-foot"><a class="go" href="/">{{ic('play')}} Executa l'escàner</a></div>
</div>
<footer><div class="wrap"><span>Escàner de vulnerabilitats web · Treball de recerca</span>
  <span>Demostració d'impacte només contra llocs de prova propis.</span></div></footer>
</body></html>"""


def _leak_table(res):
    cols = res["leak"]["columns"]
    rows = res["leak"]["rows"]
    if not cols or not rows:
        return "<p class='sub'>Sense dades.</p>"
    head = "".join(f"<th>{_H.escape(c)}</th>" for c in cols)
    body = ""
    for r in rows:
        tds = "".join(f"<td>{_H.escape(str(v))}</td>" for v in r)
        body += f"<tr>{tds}</tr>"
    return f"<table class='leak'><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table>"


def _ic(n):
    return (f'<svg class="i" aria-hidden="true">'
            f'<use href="/static/icons.svg#{n}"/></svg>')


def _attack_block(label, vuln, safe):
    story = _H.escape(vuln.get("story", ""))
    tag = _H.escape(vuln.get("title", ""))
    steps = ""
    for s in vuln.get("steps", []):
        steps += (f"<li><b>{_H.escape(s['label'])}</b>"
                  f"<code>{_H.escape(s['detail'])}</code>"
                  f"<span class='n'>{_H.escape(s['note'])}</span></li>")

    n_leaked = len(vuln["leak"]["rows"])
    vuln_side = (f"<h3>{_ic('alert')} Lloc vulnerable</h3>"
                 f"<p class='sub'>Dades obtingudes per l'atacant: "
                 f"<span class='danger'>{n_leaked}</span></p>"
                 f"{_leak_table(vuln)}")

    if safe and safe.get("blocked"):
        safe_body = (f"<div class='safe-box'>{_ic('shield')}<span>"
                     f"<b>Atac bloquejat.</b> Amb les correccions aplicades, "
                     f"l'atac no obté cap dada (0 files).</span></div>")
    else:
        safe_body = _leak_table(safe) if safe else "<p class='sub'>No disponible.</p>"
    safe_side = (f"<h3>{_ic('check')} Amb les correccions</h3>"
                 f"<p class='sub'>Mateix atac, versió corregida.</p>{safe_body}")

    impact_v = _H.escape(vuln.get("impact", ""))
    impact_s = _H.escape(safe.get("impact", "")) if safe else ""
    return f"""<section class="atk">
      <div class="atk-top"><span class="tag">{tag}</span>
        <h2>{_H.escape(label)}</h2><p>{story}</p></div>
      <ol class="atk-steps">{steps}</ol>
      <div class="atk-cols">
        <div class="atk-col col-vuln">{vuln_side}</div>
        <div class="atk-col col-safe">{safe_side}</div>
      </div>
      <div class="atk-impact">{_ic('alert')}<span><b>Conseqüència real:</b> {impact_v}</span></div>
      <div class="atk-impact safe">{_ic('check')}<span><b>Un cop corregit:</b> {impact_s}</span></div>
    </section>"""


@app.route("/attack")
def attack_view():
    blocks = ""
    for key, label, vuln_url, safe_url in ATTACK_SITES:
        try:
            vuln = attack_demo.run(vuln_url)
            safe = attack_demo.run(safe_url)
        except attack_demo.TargetNotAllowed as e:
            blocks += f"<section class='atk'><div class='atk-top'><p>{_H.escape(str(e))}</p></div></section>"
            continue
        if not vuln:
            blocks += (f"<section class='atk'><div class='atk-top'><h2>{_H.escape(label)}</h2>"
                       f"<p>El lloc de prova no respon (engega'l amb el seu port). "
                       f"Objectiu: {_H.escape(vuln_url)}</p></div></section>")
            continue
        blocks += _attack_block(label, vuln, safe)
    return render_template_string(ATTACK_PAGE, blocks=blocks)


if __name__ == "__main__":
    print("Scanner web UI: http://0.0.0.0:8080/")
    app.run(host="0.0.0.0", port=8080, threaded=True)
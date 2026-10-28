// Escàner de vulnerabilitats web — lògica de la interfície
const $ = id => document.getElementById(id);
const cons = $('console'), results = $('results'), count = $('count'), phase = $('phase'),
      go = $('go'), langSel = $('lang'), dllog = $('dllog'), dlrep = $('dlrep'),
      progress = $('progress'), bar = $('bar'), steps = $('steps'), timer = $('timer'),
      resultsBox = $('resultsbox'), facts = $('facts');

// Fases de cada nivell (mateix ordre en què les executa scanner.py)
const PHASES = [
  ['crawl', 'Crawl', 'Rastreig'], ['sqli', 'SQL injection', 'Injecció SQL'],
  ['xss', 'Reflected XSS', 'XSS reflectit'], ['headers', 'Security headers', 'Capçaleres'],
  ['redirect', 'Open redirect', 'Redirecció oberta'], ['headerinj', 'HTTP header injection', 'Injecció de capçaleres'],
  ['xxe', 'XXE', 'XXE'], ['jsdeps', 'Vulnerable JS dependencies', 'Dependències JS'],
  ['php', 'PHP version', 'PHP (PHP2Shell)'], ['reflect', 'Reflected surfaces', 'Superfícies reflectides'],
];
const LEVELS = {
  basic: ['crawl', 'headers', 'jsdeps', 'php'],
  standard: ['crawl', 'sqli', 'headers', 'redirect', 'headerinj', 'jsdeps', 'php'],
  complete: PHASES.map(p => p[0]),
};
const T = {
  ca: { what: 'Què vol dir', how: 'Com corregir-ho', ref: 'Referència', bad: 'Codi vulnerable', good: 'Codi corregit',
        tech: 'Tècnica de detecció', ev: 'Evidència', none: "No s'han trobat vulnerabilitats de les que comprova l'eina." },
  en: { what: 'What it means', how: 'How to fix it', ref: 'Reference', bad: 'Vulnerable code', good: 'Fixed code',
        tech: 'Detection technique', ev: 'Evidence', none: 'No vulnerabilities found among those this tool checks.' },
};

let nFound = 0, findings = [], liveEl = null, filter = 'all', active = [], tick = null, t0 = 0, reflectedList = [], lastScore = null;

const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const icon = n => `<svg class="i" aria-hidden="true"><use href="/static/icons.svg#${n}"/></svg>`;
const level = () => document.querySelector('input[name=level]:checked').value;

function line(cls, txt) {
  const d = document.createElement('div'); d.className = cls; d.textContent = txt;
  cons.appendChild(d); cons.scrollTop = cons.scrollHeight;
}
function live(txt) {
  if (!liveEl) { liveEl = document.createElement('div'); liveEl.className = 'live'; cons.appendChild(liveEl); }
  liveEl.textContent = '… ' + txt; cons.scrollTop = cons.scrollHeight;
}

function drawSteps() {
  steps.innerHTML = active.map(k => `<span class="step" data-k="${k}">${esc(PHASES.find(p => p[0] === k)[2])}</span>`).join('');
}
function setPhase(title) {
  const p = PHASES.find(p => title.startsWith(p[1]));
  phase.textContent = p ? p[2] : title;
  if (!p) return;
  const idx = active.indexOf(p[0]);
  steps.querySelectorAll('.step').forEach((el, i) => {
    el.classList.toggle('done', i < idx); el.classList.toggle('active', i === idx);
  });
  bar.style.width = Math.max(4, idx / active.length * 100) + '%';
}
function state(s) { progress.classList.remove('running', 'finished', 'failed'); if (s) progress.classList.add(s); }
function stopTimer() { clearInterval(tick); tick = null; }

function setFilter(f) { filter = f; rerender(); }

function rerender() {
  const lang = langSel.value, L = T[lang];
  const n = s => findings.filter(f => (f.severity || 'low').toLowerCase() === s).length;
  $('n-all').textContent = findings.length; $('n-high').textContent = n('high');
  $('n-medium').textContent = n('medium'); $('n-low').textContent = n('low');
  document.querySelectorAll('.stat').forEach(b => b.classList.toggle('on', b.dataset.f === filter));
  results.innerHTML = '';
  if (!findings.length) {
    results.innerHTML = `<div class="empty">${icon('check')}<div>${esc(L.none)}</div></div>`;
    return;
  }
  const order = { high: 0, medium: 1, low: 2 };
  findings
    .map(f => ({ f, sev: (f.severity || 'low').toLowerCase() }))
    .filter(x => filter === 'all' || x.sev === filter)
    .sort((a, b) => (order[a.sev] ?? 3) - (order[b.sev] ?? 3))
    .forEach(({ f, sev }) => {
      const rem = (f.remediation_all && f.remediation_all[lang]) || f.remediation || {};
      const p = f.injection_point || {};
      const stepsHtml = (rem.steps || []).map(s => '<li>' + esc(s) + '</li>').join('');
      const bad = rem.bad_example ? `<div><h4>${L.bad}</h4><pre class="bad">${esc(rem.bad_example)}</pre></div>` : '';
      const good = rem.good_example ? `<div><h4>${L.good}</h4><pre class="good">${esc(rem.good_example)}</pre></div>` : '';
      const ref = /^https?:\/\//.test(rem.reference || '')
        ? `<h4>${L.ref}</h4><a class="ref" href="${esc(rem.reference)}" target="_blank" rel="noopener noreferrer">${icon('link')}${esc(rem.reference)}</a>` : '';
      const el = document.createElement('div'); el.className = 'finding';
      el.innerHTML = `<button class="head" aria-expanded="false">
        <span class="sev ${esc(sev)}">${esc(sev)}</span>
        <span class="main"><div class="title">${esc(f.type)}</div>
        <div class="where">${esc(p.kind)} <em>${esc(p.name)}</em> · ${esc((p.method || '').toUpperCase())} ${esc(p.url)}</div></span>
        <span class="chev">${icon('chevron')}</span></button>
        <div class="detail"><h4>${L.what}</h4><p>${esc(rem.summary || f.evidence || '')}</p>
        <div class="kv"><div><span>${L.tech}</span>${esc(f.technique || '—')}</div><div><span>${L.ev}</span>${esc(typeof f.evidence === 'string' ? f.evidence : '—')}</div></div>
        <h4>${L.how}</h4><ol>${stepsHtml}</ol><div class="code">${bad}${good}</div>${ref}</div>`;
      el.querySelector('.head').addEventListener('click', e => {
        const open = el.classList.toggle('open'); e.currentTarget.setAttribute('aria-expanded', open);
      });
      results.appendChild(el);
    });
}

function renderScore(sc) {
  lastScore = sc;
  const box = $('scorecard');
  if (!sc) { box.innerHTML = ''; return; }
  const RL = { ca: { h: 'Puntuació de seguretat', of: 'de 100', grade: 'Nota',
                     expl: 'Es parteix de 100 punts i es resta per cada troballa segons la gravetat (alta −25, mitjana −10, baixa −4; superfície crua −2).' },
               en: { h: 'Security score', of: 'of 100', grade: 'Grade',
                     expl: 'Starts at 100 and subtracts per finding by severity (high −25, medium −10, low −4; raw surface −2).' } }[langSel.value];
  const g = (sc.grade || 'F').toLowerCase();
  box.innerHTML = `<div class="scorecard grade-${esc(g)}">
    <div class="sc-num"><b>${esc(sc.score)}</b><span>${esc(RL.of)}</span></div>
    <div class="sc-mid"><div class="sc-h">${esc(RL.h)}</div><div class="sc-bar"><i style="width:${Math.max(2, +sc.score)}%"></i></div>
      <div class="sc-expl">${esc(RL.expl)}</div></div>
    <div class="sc-grade"><b>${esc(sc.grade)}</b><span>${esc(sc.label || '')}</span></div></div>`;
}

function renderReflected(list) {
  reflectedList = list;
  const box = $('reflected');
  const RL = { ca: { h: 'Superfícies reflectides', sub: "On l'entrada de l'usuari torna a la resposta. No són vulnerabilitats confirmades: una reflexió escapada és bon senyal; una de crua és on pot viure l'XSS.", raw: 'Crua', esc: 'Escapada', none: "Cap entrada reflectida a la resposta." },
             en: { h: 'Reflected surfaces', sub: 'Where user input is echoed back. Not confirmed vulnerabilities: an escaped reflection is a good sign; a raw one is where XSS can live.', raw: 'Raw', esc: 'Escaped', none: 'No input reflected in the response.' } }[langSel.value];
  if (!list.length) { box.innerHTML = ''; return; }
  const row = r => {
    const p = r.injection_point || {};
    const raw = !r.escaped;
    return `<div class="refl ${raw ? 'raw' : 'esc'}">
      <span class="rtag ${raw ? 'raw' : 'esc'}">${raw ? esc(RL.raw) : esc(RL.esc)}</span>
      <span class="rwhere">${esc(p.kind)} <em>${esc(p.name)}</em> · ${esc((p.method || '').toUpperCase())} ${esc(p.url)}</span></div>`;
  };
  box.innerHTML = `<div class="refl-head"><h3>${esc(RL.h)} <span class="rcount">${list.length}</span></h3>
    <p>${esc(RL.sub)}</p></div>${list.map(row).join('')}`;
}

function finish() { go.disabled = false; stopTimer(); }

function startScan() {
  const url = $('url').value.trim(); if (!url) { $('url').focus(); return; }
  cons.innerHTML = ''; results.innerHTML = ''; $('reflected').innerHTML = ''; $('scorecard').innerHTML = ''; nFound = 0; findings = []; reflectedList = []; count.textContent = '0'; liveEl = null; filter = 'all';
  go.disabled = true; phase.textContent = 'Iniciant…'; state('running'); bar.style.width = '2%';
  resultsBox.classList.add('hidden');
  dllog.classList.add('disabled'); dlrep.classList.add('disabled');
  const lvl = level(); active = LEVELS[lvl]; drawSteps();
  t0 = Date.now(); stopTimer(); timer.textContent = '0 s';
  tick = setInterval(() => { timer.textContent = Math.round((Date.now() - t0) / 1000) + ' s'; }, 1000);

  const es = new EventSource('/scan?url=' + encodeURIComponent(url) + '&level=' + lvl);
  es.addEventListener('title', e => { liveEl = null; line('t', '▶ ' + e.data); setPhase(e.data); });
  es.addEventListener('info', e => { liveEl = null; line('i-line', e.data); });
  es.addEventListener('transient', e => live(e.data));
  es.addEventListener('finding', e => { liveEl = null; nFound++; count.textContent = nFound; line('f', '⚠ ' + e.data); });
  es.addEventListener('result', e => { findings.push(JSON.parse(e.data)); });
  es.addEventListener('done', e => {
    const r = JSON.parse(e.data);
    if (liveEl) { liveEl.remove(); liveEl = null; }
    phase.textContent = 'Escaneig completat'; state('finished'); bar.style.width = '100%';
    steps.querySelectorAll('.step').forEach(el => { el.classList.remove('active'); el.classList.add('done'); });
    if (r.elapsed) timer.textContent = r.elapsed + ' s';
    count.textContent = findings.length;
    facts.innerHTML = [['Objectiu', r.target || url], ['Pàgines', r.pages], ['Formularis', r.forms],
      ['Punts d\'injecció', r.points], ['Durada', r.elapsed != null ? r.elapsed + ' s' : null], ['Nivell', r.level]]
      .filter(x => x[1] != null).map(x => `<span>${x[0]}: <b>${esc(x[1])}</b></span>`).join('');
    renderScore(r.score);
    resultsBox.classList.remove('hidden'); rerender(); renderReflected(r.reflected || []);
    resultsBox.scrollIntoView({ behavior: 'smooth', block: 'start' });
    dllog.href = '/download/log'; dllog.classList.remove('disabled');
    dlrep.href = '/download/report'; dlrep.classList.remove('disabled');
    finish(); es.close();
  });
  es.addEventListener('fail', e => { line('f', 'ERROR: ' + e.data); phase.textContent = 'Error'; state('failed'); finish(); es.close(); });
  es.onerror = () => {
    if (es.readyState === EventSource.CLOSED || !go.disabled) return;
    line('f', 'ERROR: s\'ha perdut la connexió amb el servidor'); phase.textContent = 'Error'; state('failed'); finish(); es.close();
  };
}

go.addEventListener('click', startScan);
$('url').addEventListener('keydown', e => { if (e.key === 'Enter' && !go.disabled) startScan(); });
langSel.addEventListener('change', () => { if (!resultsBox.classList.contains('hidden')) { renderScore(lastScore); rerender(); renderReflected(reflectedList); } });
document.querySelectorAll('.quick button').forEach(b => b.addEventListener('click', () => { $('url').value = b.dataset.url; $('url').focus(); }));
document.querySelectorAll('.stat').forEach(b => b.addEventListener('click', () => setFilter(b.dataset.f)));

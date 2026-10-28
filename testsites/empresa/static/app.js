// Tècnics Vallès — millores d'interfície (sense dependències)
document.documentElement.classList.add('js');

const io = new IntersectionObserver(es => es.forEach(e => {
  if (e.isIntersecting) { e.target.classList.add('in'); io.unobserve(e.target); }
}), { threshold: .1 });
document.querySelectorAll('.reveal').forEach((el, i) => {
  el.style.transitionDelay = (i % 3 * 70) + 'ms'; io.observe(el);
});

// Comptadors animats de les xifres
const fmt = n => n.toLocaleString('ca');
const counters = new IntersectionObserver(es => es.forEach(e => {
  if (!e.isIntersecting) return;
  counters.unobserve(e.target);
  const el = e.target, end = +el.dataset.count, t0 = performance.now();
  const step = t => {
    const p = Math.min((t - t0) / 1100, 1);
    el.firstChild.textContent = fmt(Math.round(end * (1 - Math.pow(1 - p, 3))));
    if (p < 1) requestAnimationFrame(step);
  };
  requestAnimationFrame(step);
}), { threshold: .4 });
document.querySelectorAll('[data-count]').forEach(el => counters.observe(el));

// Menú en pantalles petites
const toggle = document.querySelector('.menu-toggle');
if (toggle) toggle.addEventListener('click', () => document.querySelector('header.site nav').classList.toggle('open'));

// Ca l'Andreu — petites millores d'interfície (sense dependències)
document.documentElement.classList.add('js');

// Aparició suau de les targetes en entrar a la pantalla
const io = new IntersectionObserver(es => es.forEach(e => {
  if (e.isIntersecting) { e.target.classList.add('in'); io.unobserve(e.target); }
}), { threshold: .08 });
document.querySelectorAll('.reveal').forEach((el, i) => {
  el.style.transitionDelay = (i % 4 * 50) + 'ms'; io.observe(el);
});

// Carrusel de la portada
const slides = [...document.querySelectorAll('.slide')];
const dots = [...document.querySelectorAll('.dot')];
if (slides.length) {
  let cur = 0, timer;
  const show = n => {
    cur = (n + slides.length) % slides.length;
    slides.forEach((s, i) => s.classList.toggle('on', i === cur));
    dots.forEach((d, i) => d.classList.toggle('on', i === cur));
  };
  const play = () => { timer = setInterval(() => show(cur + 1), 6000); };
  dots.forEach((d, i) => d.addEventListener('click', () => { clearInterval(timer); show(i); play(); }));
  play();
}

// Avís en afegir un producte a la cistella
if (location.hash === '#added') {
  const t = document.getElementById('toast');
  if (t) { t.classList.add('show'); setTimeout(() => t.classList.remove('show'), 2600); }
  history.replaceState(null, '', location.pathname);
}

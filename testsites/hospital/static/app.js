// Salut Sant Jordi — millores d'interfície (sense dependències)
document.documentElement.classList.add('js');

const io = new IntersectionObserver(es => es.forEach(e => {
  if (e.isIntersecting) { e.target.classList.add('in'); io.unobserve(e.target); }
}), { threshold: .1 });
document.querySelectorAll('.reveal').forEach((el, i) => {
  el.classList.add('d' + (i % 4)); io.observe(el);
});

// Menú en pantalles petites
const toggle = document.querySelector('.menu-toggle');
if (toggle) toggle.addEventListener('click', () => document.querySelector('header.site nav').classList.toggle('open'));

// Formulari de cita (demostració: no envia dades)
const form = document.getElementById('cita');
if (form) form.addEventListener('submit', e => {
  e.preventDefault();
  form.classList.add('sent');
});

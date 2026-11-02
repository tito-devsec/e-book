if ('serviceWorker' in navigator) navigator.serviceWorker.register('sw.js');
const book = document.getElementById('book'), pages = window.BOOK.pages;
const els = pages.map((p, i) => {
  const d = document.createElement('div'); d.className = 'page';
  d.innerHTML = '<h2></h2><p></p><div class="n"></div><div class="shade"></div>';
  d.children[0].textContent = p.h; d.children[1].textContent = p.t; d.children[2].textContent = (i + 1);
  book.appendChild(d); return d;
});
let cur = 0; // index of top unflipped page
function layout() {
  els.forEach((e, i) => {
    e.style.transition = 'transform .5s ease';
    e.style.transform = i < cur ? 'rotateY(-180deg)' : 'rotateY(0)';
    e.style.zIndex = i < cur ? i : els.length - i;
    e.style.visibility = (i < cur - 1) ? 'hidden' : 'visible';
    e.querySelector('.shade').style.opacity = 0;
  });
  try { localStorage.setItem('page', cur); } catch (e) {}
}
try { cur = Math.min(+localStorage.getItem('page') || 0, els.length - 1); } catch (e) {}
let startX = null, dir = 0, w = 1;
function setAngle(a) { // a: 0..180 progress of flip
  const el = dir > 0 ? els[cur] : els[cur - 1];
  el.style.transition = 'none';
  el.style.visibility = 'visible';
  el.style.transform = 'rotateY(' + (dir > 0 ? -a : -180 + a) + 'deg)';
  el.querySelector('.shade').style.opacity = Math.sin(a * Math.PI / 180);
  return el;
}
book.addEventListener('pointerdown', e => { startX = e.clientX; dir = 0; w = book.offsetWidth; book.setPointerCapture(e.pointerId); });
book.addEventListener('pointermove', e => {
  if (startX === null) return;
  const dx = e.clientX - startX;
  if (!dir) { if (Math.abs(dx) < 6) return; dir = dx < 0 ? 1 : -1; if ((dir > 0 && cur >= els.length - 1) || (dir < 0 && cur <= 0)) { dir = 0; startX = null; return; } }
  setAngle(Math.min(180, Math.abs(dx) / w * 180));
});
function end(e) {
  if (startX === null) return;
  const dx = e.clientX - startX; startX = null;
  if (dir && Math.abs(dx) > w * 0.2) cur += dir;
  dir = 0; layout();
}
book.addEventListener('pointerup', end); book.addEventListener('pointercancel', end);
addEventListener('keydown', e => {
  if (e.key === 'ArrowRight' && cur < els.length - 1) { cur++; layout(); }
  if (e.key === 'ArrowLeft' && cur > 0) { cur--; layout(); }
});
layout();

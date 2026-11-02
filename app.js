let deferred = null, target = 'reader.html';
const $ = id => document.getElementById(id);
if ('serviceWorker' in navigator) navigator.serviceWorker.register('sw.js');
addEventListener('beforeinstallprompt', e => { e.preventDefault(); deferred = e; });
const standalone = matchMedia('(display-mode: standalone)').matches || navigator.standalone;
if (standalone) location.replace('reader.html?source=pwa');
function openModal() {
  const ios = /iphone|ipad|ipod/i.test(navigator.userAgent);
  const s = $('steps');
  if (!deferred) {
    s.style.display = 'block';
    s.textContent = ios ? 'Tap the Share button, then "Add to Home Screen".'
      : 'Open your browser menu and choose "Install app" or "Add to Home screen".';
    $('install').style.display = 'none';
  }
  $('modal').classList.add('open');
}
$('read').onclick = () => { target = 'reader.html'; openModal(); };
$('dl').onclick = () => { target = null; openModal(); };
$('continue').onclick = () => { $('modal').classList.remove('open'); if (target) location.href = target; };
$('install').onclick = async () => {
  if (!deferred) return;
  deferred.prompt(); await deferred.userChoice; deferred = null;
  $('modal').classList.remove('open'); if (target) location.href = target;
};

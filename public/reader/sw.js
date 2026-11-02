// Reader service worker.
//
// Caches ONLY the public application shell (HTML shell, scripts, styles, icons) so the
// installed app opens instantly. It never caches API responses, book content, covers,
// invitation pages, or anything carrying customer data. Reading always requires the
// server to authorize the current session, device and license.
const VERSION = 'reader-shell-v4';
const SHELL = [
  '/app',
  '/static/shared/base.css',
  '/static/reader/reader.css',
  '/static/reader/app.js',
  '/static/vendor/page-flip.js',
  '/static/uicons/regular/rounded.css',
  '/static/uicons/brands/all.css',
  '/manifest.webmanifest',
  '/assets/icon-192.png',
  '/assets/icon-512.png',
];

self.addEventListener('install', (event) => {
  event.waitUntil(caches.open(VERSION).then((c) => c.addAll(SHELL)).then(() => self.skipWaiting()));
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys()
      .then((keys) => Promise.all(keys.filter((k) => k !== VERSION).map((k) => caches.delete(k))))
      .then(() => self.clients.claim()),
  );
});

function isProtected(url) {
  return url.pathname.startsWith('/api/')
    || url.pathname.startsWith('/access/')
    || url.pathname.startsWith('/media/')
    || url.pathname.startsWith('/admin');
}

self.addEventListener('fetch', (event) => {
  const req = event.request;
  const url = new URL(req.url);
  if (req.method !== 'GET' || url.origin !== self.location.origin) return;

  // Protected routes: straight to the network, never stored.
  if (isProtected(url)) {
    event.respondWith(fetch(req, { cache: 'no-store' }));
    return;
  }

  // Navigations: network first; offline falls back to the cached shell, which then
  // tells the reader to reconnect (no offline reading of protected content).
  if (req.mode === 'navigate') {
    event.respondWith(fetch(req).catch(() => caches.match('/app')));
    return;
  }

  // Static shell assets: cache first, refreshed in the background.
  if (SHELL.includes(url.pathname) || url.pathname.startsWith('/static/') || url.pathname.startsWith('/assets/')) {
    event.respondWith(
      caches.open(VERSION).then(async (cache) => {
        const hit = await cache.match(req);
        const network = fetch(req).then((res) => {
          if (res.ok && res.type === 'basic') cache.put(req, res.clone());
          return res;
        }).catch(() => hit);
        return hit || network;
      }),
    );
  }
});

self.addEventListener('message', (event) => {
  if (event.data === 'clear-caches') {
    event.waitUntil(caches.keys().then((keys) => Promise.all(keys.map((k) => caches.delete(k)))));
  }
});

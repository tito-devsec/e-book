// Private reader PWA.
// - Device identity: a non-extractable ECDSA P-256 key generated in this browser (WebCrypto),
//   stored in IndexedDB. Every reader API request is signed with it. This is an additional
//   authorization signal, not a hardware-backed identity.
// - Book content is fetched one chapter/page at a time, kept in memory only, and never
//   written to the service worker cache, localStorage or IndexedDB.

// ===========================================================================
// DOM helpers (text is always set via textContent; no untrusted innerHTML)
// ===========================================================================
function h(tag, attrs = {}, ...children) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === undefined || v === null || v === false) continue;
    if (k === 'class') el.className = v;
    else if (k.startsWith('on') && typeof v === 'function') el.addEventListener(k.slice(2), v);
    else if (k === 'text') el.textContent = v;
    else el.setAttribute(k, v === true ? '' : v);
  }
  for (const c of children.flat(Infinity)) {
    if (c === null || c === undefined || c === false) continue;
    el.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return el;
}
const root = document.getElementById('root');
function mount(...nodes) { cleanupView(); root.replaceChildren(...nodes); }
let viewCleanup = [];
function onCleanup(fn) { viewCleanup.push(fn); }
function cleanupView() { for (const fn of viewCleanup.splice(0)) { try { fn(); } catch { /* ignore */ } } }

// ===========================================================================
// Device key (IndexedDB)
// ===========================================================================
const DB_NAME = 'private-reader';
function idb() {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, 1);
    req.onupgradeneeded = () => req.result.createObjectStore('keys');
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}
async function idbGet(key) {
  const db = await idb();
  return new Promise((resolve, reject) => {
    const r = db.transaction('keys').objectStore('keys').get(key);
    r.onsuccess = () => resolve(r.result); r.onerror = () => reject(r.error);
  });
}
async function idbPut(key, value) {
  const db = await idb();
  return new Promise((resolve, reject) => {
    const t = db.transaction('keys', 'readwrite'); t.objectStore('keys').put(value, key);
    t.oncomplete = () => resolve(); t.onerror = () => reject(t.error);
  });
}
async function idbDelete(key) {
  const db = await idb();
  return new Promise((resolve) => {
    const t = db.transaction('keys', 'readwrite'); t.objectStore('keys').delete(key);
    t.oncomplete = () => resolve(); t.onerror = () => resolve();
  });
}

let deviceKey = null;
async function getDeviceKey(create = false) {
  if (deviceKey) return deviceKey;
  try { deviceKey = await idbGet('device'); } catch { deviceKey = null; }
  if (!deviceKey && create) {
    const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign', 'verify']);
    const jwk = await crypto.subtle.exportKey('jwk', pair.publicKey);
    deviceKey = { privateKey: pair.privateKey, publicJwk: { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y } };
    await idbPut('device', deviceKey);
  }
  return deviceKey;
}
async function forgetDevice() {
  deviceKey = null;
  await idbDelete('device');
}

// ===========================================================================
// API client
// ===========================================================================
class ApiError extends Error {
  constructor(status, data) { super(data?.message || `Request failed (${status})`); this.status = status; this.code = data?.code; this.data = data; }
}
let csrf = null;
const b64url = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const hex = (buf) => [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, '0')).join('');

async function api(method, url, body, { signed = false, raw = false } = {}) {
  const headers = {};
  let payload;
  if (body !== undefined) { payload = JSON.stringify(body); headers['content-type'] = 'application/json'; }
  if (csrf && method !== 'GET') headers['x-csrf-token'] = csrf;
  if (signed) {
    const key = await getDeviceKey(false);
    if (!key) throw new ApiError(403, { code: 'DEVICE_REVOKED', message: 'This browser is not registered' });
    const ts = Date.now();
    const nonce = b64url(crypto.getRandomValues(new Uint8Array(16)));
    const bodyHash = hex(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(payload || '')));
    const msg = `${method}\n${url}\n${ts}\n${nonce}\n${bodyHash}`;
    const sig = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, key.privateKey, new TextEncoder().encode(msg));
    Object.assign(headers, { 'x-sig-ts': String(ts), 'x-sig-nonce': nonce, 'x-sig': b64url(sig) });
  }
  let res;
  try {
    res = await fetch(url, { method, headers, body: payload, credentials: 'same-origin', cache: 'no-store' });
  } catch {
    throw new ApiError(0, { code: 'OFFLINE', message: 'You appear to be offline. Connect to the internet to continue.' });
  }
  if (raw && res.ok) return res;
  const ct = res.headers.get('content-type') || '';
  const data = ct.includes('json') ? await res.json().catch(() => ({})) : {};
  if (!res.ok) throw new ApiError(res.status, data);
  return data;
}

/** Central handling of authorization failures: clear state and route appropriately. */
async function handleAuthError(err) {
  if (!(err instanceof ApiError)) return false;
  if (['DEVICE_REVOKED', 'ACCOUNT_SUSPENDED'].includes(err.code)) {
    await clearSensitiveState({ forgetKey: err.code === 'DEVICE_REVOKED' });
    go(`/denied?reason=${err.code === 'DEVICE_REVOKED' ? 'device' : 'suspended'}`, true);
    return true;
  }
  if (err.status === 401) {
    await clearSensitiveState({ forgetKey: false });
    go(`/login?reason=${err.code === 'SESSION_EXPIRED' ? 'expired' : 'signin'}`, true);
    return true;
  }
  if (err.status === 404) { go('/denied', true); return true; }
  return false;
}

async function clearSensitiveState({ forgetKey }) {
  csrf = null;
  try { sessionStorage.clear(); } catch { /* ignore */ }
  if (forgetKey) await forgetDevice();
  if (navigator.serviceWorker?.controller) navigator.serviceWorker.controller.postMessage('clear-caches');
}

// ===========================================================================
// Router
// ===========================================================================
function go(path, replace = false) {
  if (replace) history.replaceState({}, '', path); else history.pushState({}, '', path);
  route();
}
addEventListener('popstate', () => route());
document.addEventListener('click', (e) => {
  const a = e.target.closest('a[data-nav]');
  if (a && !e.metaKey && !e.ctrlKey) { e.preventDefault(); go(a.getAttribute('href')); }
});

function route() {
  const { pathname, search } = location;
  const q = new URLSearchParams(search);
  let m;
  if (pathname === '/') return viewHome();
  if ((m = pathname.match(/^\/access\/([^/]+)$/))) return viewInvitation(m[1]);
  if (pathname === '/login') return viewLogin(q.get('reason'));
  if (pathname === '/app') return viewLauncher();
  if (pathname === '/library') return viewLibrary();
  if ((m = pathname.match(/^\/book\/([0-9a-f-]{36})$/))) return viewBook(m[1]);
  if ((m = pathname.match(/^\/read\/([0-9a-f-]{36})$/))) return viewReader(m[1]);
  if (pathname === '/install') return viewInstallGuide();
  return viewDenied(q.get('reason'));
}

const isStandalone = () => matchMedia('(display-mode: standalone)').matches || navigator.standalone === true;

// ===========================================================================
// Install (PWA)
// ===========================================================================
let installPrompt = null;
addEventListener('beforeinstallprompt', (e) => { e.preventDefault(); installPrompt = e; });
addEventListener('appinstalled', () => { installPrompt = null; });

function platform() {
  const ua = navigator.userAgent;
  if (/iPhone|iPad|iPod/.test(ua) || (navigator.platform === 'MacIntel' && navigator.maxTouchPoints > 1)) return 'ios';
  if (/Android/.test(ua)) return 'android';
  if (/Macintosh/.test(ua) && /Safari/.test(ua) && !/Chrome|Edg/.test(ua)) return 'mac-safari';
  if (/Firefox/.test(ua)) return 'firefox';
  return 'desktop';
}

function installSteps() {
  switch (platform()) {
    case 'ios': return ['Tap the Share button (the square with an arrow) in Safari.', 'Scroll down and tap “Add to Home Screen”.', 'Tap “Add”. Open “My Books” from your home screen and sign in with your WhatsApp number.'];
    case 'android': return ['Open your browser menu (⋮).', 'Tap “Install app” or “Add to Home screen”.', 'Open “My Books” from your home screen.'];
    case 'mac-safari': return ['In Safari, open the File menu.', 'Choose “Add to Dock”.', 'Open “My Books” from your Dock.'];
    case 'firefox': return ['Firefox on desktop cannot install web apps.', 'Open this page in Chrome, Edge or Safari to install, or keep reading here in your browser.'];
    default: return ['Click the install icon at the right of the address bar, or open the browser menu.', 'Choose “Install My Books”.', 'Open “My Books” from your desktop or app list.'];
  }
}

function showInstallModal({ coverUrl, onContinue }) {
  const close = () => modal.remove();
  const steps = h('ol', { class: 'steps' }, installSteps().map((s) => h('li', { text: s })));
  const installBtn = installPrompt ? h('button', {
    class: 'btn btn-primary btn-block',
    onclick: async () => {
      const p = installPrompt; installPrompt = null;
      p.prompt();
      const choice = await p.userChoice.catch(() => ({ outcome: 'dismissed' }));
      close();
      if (choice.outcome === 'accepted') toast('Installed. Open “My Books” from your home screen or app list.');
      if (onContinue) onContinue();
    },
  }, 'Install Reader') : null;
  const modal = h('div', { class: 'modal', role: 'dialog', 'aria-modal': 'true', 'aria-labelledby': 'install-title' },
    h('div', { class: 'panel' },
      coverUrl ? h('img', { src: coverUrl, alt: '' }) : null,
      h('h1', { id: 'install-title', text: 'Get it on your device' }),
      h('p', { class: 'muted', text: 'Install the private reader so your book opens straight from your home screen. No file is downloaded: your book stays protected inside the app.' }),
      installBtn || steps,
      h('div', { class: 'stack' },
        onContinue ? h('button', { class: installBtn ? 'btn btn-block' : 'btn btn-primary btn-block', onclick: () => { close(); onContinue(); } }, 'Continue reading in browser') : null,
        h('button', { class: 'btn-link', onclick: close }, 'Not now'))));
  modal.addEventListener('click', (e) => { if (e.target === modal) close(); });
  modal.addEventListener('keydown', (e) => { if (e.key === 'Escape') close(); });
  document.body.append(modal);
  modal.querySelector('button')?.focus();
}

function toast(text) {
  const t = h('div', { class: 'notice', role: 'status', text });
  Object.assign(t.style, { position: 'fixed', left: '50%', bottom: '24px', transform: 'translateX(-50%)', zIndex: 200, maxWidth: '90vw' });
  document.body.append(t);
  setTimeout(() => t.remove(), 4500);
}

// ===========================================================================
// Shared bits
// ===========================================================================
function screen(...children) { return h('main', { class: 'screen' }, h('div', { class: 'panel' }, ...children)); }
function errorLine() { return h('p', { class: 'error-text', role: 'alert' }); }
function setBusy(btn, busy, label) { btn.disabled = busy; if (label) btn.textContent = busy ? 'Please wait…' : label; }

const blobUrls = new Set();
async function coverFor(bookId) {
  try {
    const res = await api('GET', `/api/reader/books/${bookId}/cover`, undefined, { signed: true, raw: true });
    const url = URL.createObjectURL(await res.blob());
    blobUrls.add(url);
    return url;
  } catch { return null; }
}
function revokeBlobs() { for (const u of blobUrls) URL.revokeObjectURL(u); blobUrls.clear(); }

async function loadSession() {
  try {
    const s = await api('GET', '/api/auth/session');
    csrf = s.csrf;
    return s;
  } catch (err) {
    if (err.status === 401 || err.status === 403) return { authenticated: false, code: err.code };
    throw err;
  }
}

function otpForm({ onSubmit, onResend, label = 'Verify and continue' }) {
  const input = h('input', { class: 'otp-input', type: 'text', inputmode: 'numeric', autocomplete: 'one-time-code', pattern: '[0-9]*', maxlength: '6', 'aria-label': '6-digit code', required: true });
  const err = errorLine();
  const btn = h('button', { class: 'btn btn-primary btn-block', type: 'submit' }, label);
  const form = h('form', { class: 'stack', novalidate: true },
    h('div', { class: 'field' }, h('label', { text: 'Enter the 6-digit code we sent on WhatsApp' }), input),
    err, btn,
    onResend ? h('button', { type: 'button', class: 'btn-link', onclick: onResend }, 'Send a new code') : null);
  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    err.textContent = '';
    const code = input.value.replace(/\D/g, '');
    if (code.length !== 6) { err.textContent = 'Enter the 6 digits from the message.'; return; }
    setBusy(btn, true, label);
    try { await onSubmit(code); } catch (ex) { err.textContent = ex.message; } finally { setBusy(btn, false, label); }
  });
  setTimeout(() => input.focus(), 50);
  return form;
}

// ===========================================================================
// Invitation activation  (/access/:token)
// ===========================================================================
async function viewInvitation(tokenInPath) {
  // Move the token out of the address bar and history immediately; keep it only for this tab.
  let token = tokenInPath;
  if (tokenInPath === '_') token = sessionStorage.getItem('invite') || '';
  else { sessionStorage.setItem('invite', tokenInPath); history.replaceState({}, '', '/access/_'); }

  if (!token) return viewDenied('invite');
  let info;
  try { info = await api('POST', '/api/access/validate-invitation', { token }); } catch (err) { return mount(screen(h('h1', { text: 'Something went wrong' }), h('p', { class: 'muted', text: err.message }))); }

  const messages = {
    CONSUMED: ['THIS INVITATION HAS ALREADY BEEN ACTIVATED.', 'This private reading invitation belongs to an existing customer and cannot be used again.', 'If you believe this is an error, please contact the book owner.'],
    EXPIRED: ['This invitation has expired', 'Private invitations are only valid for a limited time.', 'Please contact the book owner for a new invitation.'],
    REVOKED: ['This invitation is no longer valid', 'It was replaced or cancelled by the book owner.', 'Please use the most recent invitation you received, or contact the book owner.'],
    INVALID: ['Invitation not found', 'This link is not a valid private reading invitation.', 'Please check that you opened the complete link from your WhatsApp message.'],
  };
  if (info.state !== 'VALID') {
    sessionStorage.removeItem('invite');
    const [title, line1, line2] = messages[info.state] || messages.INVALID;
    return mount(h('main', { class: 'screen denied' }, h('div', { class: 'panel' },
      h('div', { class: 'lock', 'aria-hidden': 'true', text: '🔒' }),
      h('h1', { text: title }), h('p', { text: line1 }), h('p', { class: 'muted', text: line2 }),
      h('div', { class: 'stack' }, h('a', { class: 'btn btn-block', href: '/login', 'data-nav': true }, 'I already activated — sign in')))));
  }

  const err = errorLine();
  const phone = h('input', { type: 'tel', autocomplete: 'tel', inputmode: 'tel', placeholder: '+254 7XX XXX XXX', required: true, id: 'phone' });
  const btn = h('button', { class: 'btn btn-primary btn-block', type: 'submit' }, 'Send my code');
  const body = h('div');
  let challengeId = null;

  const askPhone = h('form', { class: 'stack', novalidate: true },
    h('div', { class: 'field' },
      h('label', { for: 'phone', text: 'Your WhatsApp number' }), phone,
      h('span', { class: 'hint', text: `This invitation is registered to the number ending ${info.phoneHint.slice(-3)}. We will send a code there.` })),
    err, btn);

  const sendCode = async () => {
    const r = await api('POST', '/api/access/request-otp', { token, phone: phone.value });
    challengeId = r.challengeId;
  };
  askPhone.addEventListener('submit', async (e) => {
    e.preventDefault(); err.textContent = '';
    setBusy(btn, true, 'Send my code');
    try {
      await sendCode();
      body.replaceChildren(otpForm({
        label: 'Activate my book',
        onSubmit: async (code) => {
          const key = await getDeviceKey(true);
          const r = await api('POST', '/api/access/activate', { token, challengeId, code, deviceKey: key.publicJwk });
          csrf = r.csrf;
          sessionStorage.removeItem('invite');
          go(`/book/${r.bookId}`, true);
        },
        onResend: async () => { try { await sendCode(); toast('A new code is on its way.'); } catch (ex) { toast(ex.message); } },
      }));
    } catch (ex) { err.textContent = ex.message; } finally { setBusy(btn, false, 'Send my code'); }
  });
  body.append(askPhone);

  mount(screen(
    info.book.hasCover ? h('img', { class: 'cover-sm', src: `/media/covers/${info.book.id}`, alt: '' }) : null,
    h('p', { class: 'hint', text: 'Private reading invitation' }),
    h('h1', { text: info.book.title }),
    h('p', { class: 'muted', text: `by ${info.book.author}` }),
    h('p', { text: 'Your payment has been verified. Confirm your WhatsApp number to activate your personal reading access on this device.' }),
    body,
  ));
}

// ===========================================================================
// Sign in again  (/login)
// ===========================================================================
function viewLogin(reason) {
  const err = errorLine();
  const phone = h('input', { type: 'tel', autocomplete: 'tel', inputmode: 'tel', placeholder: '+254 7XX XXX XXX', id: 'phone', required: true });
  const btn = h('button', { class: 'btn btn-primary btn-block', type: 'submit' }, 'Send my code');
  const body = h('div');
  let challengeId = null;
  const send = async () => { challengeId = (await api('POST', '/api/auth/request-otp', { phone: phone.value })).challengeId; };

  const form = h('form', { class: 'stack', novalidate: true },
    h('div', { class: 'field' }, h('label', { for: 'phone', text: 'WhatsApp number used for your purchase' }), phone), err, btn);
  form.addEventListener('submit', async (e) => {
    e.preventDefault(); err.textContent = '';
    setBusy(btn, true, 'Send my code');
    try {
      await send();
      body.replaceChildren(
        h('p', { class: 'hint', text: 'If this number has book access, a code is on its way on WhatsApp.' }),
        otpForm({
          onSubmit: async (code) => {
            const key = await getDeviceKey(true);
            try {
              const r = await api('POST', '/api/auth/verify-otp', { challengeId, code, deviceKey: key.publicJwk });
              csrf = r.csrf;
              go('/app', true);
            } catch (ex) {
              if (ex.code === 'DEVICE_LIMIT') return body.replaceChildren(replacePrompt(ex.data));
              throw ex;
            }
          },
          onResend: async () => { try { await send(); toast('A new code is on its way.'); } catch (ex) { toast(ex.message); } },
        }));
    } catch (ex) { err.textContent = ex.message; } finally { setBusy(btn, false, 'Send my code'); }
  });
  body.append(form);

  const lead = { expired: 'Your reading session has ended. Confirm your number to continue reading — no new purchase or invitation is needed.' }[reason]
    || 'Confirm your WhatsApp number to open your books on this device.';
  mount(screen(
    h('div', { class: 'lock', 'aria-hidden': 'true', text: '🔑' }),
    h('h1', { text: 'Sign in to your books' }),
    h('p', { class: 'muted', text: lead }),
    body,
    h('p', { class: 'hint', text: 'First time? Open the private invitation link you received on WhatsApp.' }),
  ));
}

function replacePrompt({ grantToken, mode }) {
  const err = errorLine();
  const btn = h('button', { class: 'btn btn-primary btn-block' }, mode === 'ADMIN_APPROVAL' ? 'Request access on this device' : 'Use this device instead');
  btn.addEventListener('click', async () => {
    setBusy(btn, true);
    try {
      const r = await api('POST', '/api/access/replace-device', { grantToken });
      if (r.status === 'PENDING_APPROVAL') {
        btn.replaceWith(h('div', { class: 'notice', text: 'Your request was sent to the book owner. Once approved, sign in again on this device.' }));
        return;
      }
      csrf = r.csrf;
      go('/app', true);
    } catch (ex) { err.textContent = ex.message; setBusy(btn, false, 'Try again'); }
  });
  return h('div', { class: 'stack' },
    h('div', { class: 'notice', text: 'Your book is registered to another device or browser.' }),
    h('p', { text: mode === 'ADMIN_APPROVAL'
      ? 'Moving your access to this device needs approval from the book owner.'
      : 'Continuing here moves your access to this device. The other device will stop showing the book. If you just installed the app on this same phone, choose this option.' }),
    err, btn, h('a', { class: 'btn btn-block', href: '/login', 'data-nav': true }, 'Cancel'));
}

// ===========================================================================
// Launcher  (/app — PWA start URL)
// ===========================================================================
async function viewLauncher() {
  let s;
  try { s = await loadSession(); } catch (err) { return viewOffline(err); }
  if (!s.authenticated) {
    if (['DEVICE_REVOKED', 'ACCOUNT_SUSPENDED'].includes(s.code)) return handleAuthError(new ApiError(403, { code: s.code }));
    return go('/login', true);
  }
  if (s.books.length === 1) return go(isStandalone() ? `/read/${s.books[0].id}` : `/book/${s.books[0].id}`, true);
  return go('/library', true);
}

function viewOffline(err) {
  mount(screen(h('h1', { text: 'You are offline' }),
    h('p', { class: 'muted', text: err?.message || 'Connect to the internet to open your books. Reading requires an online check that your access is still active.' }),
    h('button', { class: 'btn btn-primary btn-block', onclick: () => route() }, 'Try again')));
}

// ===========================================================================
// Library  (/library)
// ===========================================================================
async function viewLibrary() {
  let lib;
  try { lib = await api('GET', '/api/reader/library', undefined, { signed: true }); } catch (err) {
    if (err.status === 401) return viewDenied('signin');
    if (await handleAuthError(err)) return; return viewOffline(err);
  }
  const shelf = h('div', { class: 'shelf' });
  for (const b of lib.books) {
    const img = h('div', { class: 'ph' });
    shelf.append(h('a', { href: `/read/${b.id}`, 'data-nav': true }, img,
      h('div', { class: 't', text: b.title }), h('div', { class: 'hint', text: b.author }),
      h('div', { class: 'bar', 'aria-label': `${Math.round(b.progress)}% read` }, Object.assign(h('i'), { style: `width:${b.progress}%` }))));
    if (b.hasCover) coverFor(b.id).then((u) => u && img.replaceWith(h('img', { src: u, alt: '' })));
  }
  // Inline style attributes are blocked by CSP; set widths through the CSSOM instead.
  shelf.querySelectorAll('.bar > i').forEach((i, n) => { i.removeAttribute('style'); i.style.width = `${lib.books[n].progress}%`; });
  mount(h('main', { class: 'lib' },
    h('div', { class: 'lib-head' }, h('h1', { text: 'My books' }), h('button', { class: 'btn btn-small', onclick: logout }, 'Sign out')),
    lib.books.length ? shelf : h('p', { class: 'muted', text: 'There are no active books on this device.' })));
  onCleanup(revokeBlobs);
}

async function logout() {
  try { await api('POST', '/api/auth/logout'); } catch { /* ignore */ }
  await clearSensitiveState({ forgetKey: false });
  go('/login', true);
}

// ===========================================================================
// Book preparation page  (/book/:id)
// ===========================================================================
/** The download page layout (cover, "Download <title>", DOWNLOAD BOOK, START READING). */
function downloadPage({ book, coverImg, chips = [], topRight = null, onDownload, onStart, disabled = false }) {
  return h('div', {},
    h('div', { class: 'prep-top' },
      h('div', { class: 'prep-bar' }, h('span', { class: 'who', text: book.author }), h('span', {}, topRight)),
      h('div', { class: 'prep' },
        h('div', { class: 'prep-cover' }, coverImg),
        h('div', {},
          h('h1', { text: `Download ${book.title}` }),
          chips.length ? h('div', { class: 'chips' }, chips) : null,
          h('button', { class: 'btn btn-primary', disabled, onclick: onDownload }, 'DOWNLOAD BOOK'),
          h('div', {}, h('button', { class: 'btn-link start', disabled, onclick: onStart }, 'START READING')),
          h('p', { class: 'author', text: `by ${book.author}` }),
          h('p', { class: 'desc', text: (book.description || book.subtitle || '').replace(/\s+/g, ' ').trim() })))));
}

async function viewBook(bookId, { session } = {}) {
  let info; let s = session;
  try {
    s ??= await loadSession();
    if (!s.authenticated) return viewDenied(s.code === 'DEVICE_REVOKED' ? 'device' : 'signin');
    info = await api('GET', `/api/reader/books/${bookId}`, undefined, { signed: true });
  } catch (err) { if (await handleAuthError(err)) return; return viewOffline(err); }
  if (isStandalone()) return go(`/read/${bookId}`, true);

  const coverImg = h('img', { alt: `${info.book.title} cover` });
  coverFor(bookId).then((u) => { if (u) coverImg.src = u; });
  const ready = info.preparation === 'READY';
  const read = () => go(`/read/${bookId}`);

  mount(downloadPage({
    book: info.book, coverImg, disabled: !ready,
    chips: [h('span', { class: ready ? 'chip' : 'chip wait', text: ready ? 'Ready to read' : 'Preparing your book…' }),
      h('span', { class: 'chip', text: 'Access active on this device' })],
    topRight: s.books.length > 1 ? h('a', { href: '/library', 'data-nav': true }, 'My books') : h('button', { class: 'btn-link', onclick: logout }, 'Sign out'),
    onDownload: () => showInstallModal({ coverUrl: coverImg.src }),
    onStart: () => showInstallModal({ coverUrl: coverImg.src, onContinue: read }),
  }));
  onCleanup(revokeBlobs);
}

// ===========================================================================
// Home  (/ on the reader's own host or port): the book download page
// ===========================================================================
async function viewHome() {
  if (isStandalone()) return go('/app', true);
  let s;
  try { s = await loadSession(); } catch (err) { return viewOffline(err); }
  if (s.authenticated && s.books.length === 1) return viewBook(s.books[0].id, { session: s });
  if (s.authenticated && s.books.length > 1) return go('/library', true);

  // Visitor without access on this device: show the book, explain how access works.
  let info;
  try { info = await api('GET', '/api/public/book'); } catch (err) { return viewOffline(err); }
  if (!info.book) return mount(screen(h('h1', { text: 'Coming soon' }), h('p', { class: 'muted', text: 'The book will be available here shortly.' })));
  const coverImg = h('img', { alt: `${info.book.title} cover` });
  if (info.book.hasCover) coverImg.src = `/media/covers/${info.book.id}`;
  const needAccess = () => {
    const close = () => m.remove();
    const m = h('div', { class: 'modal', role: 'dialog', 'aria-modal': 'true', 'aria-labelledby': 'access-title' },
      h('div', { class: 'panel' },
        info.book.hasCover ? h('img', { src: `/media/covers/${info.book.id}`, alt: '' }) : null,
        h('h1', { id: 'access-title', text: 'Get it on your device' }),
        h('p', { class: 'muted', text: 'This book is private to its buyers. Your copy opens in the protected reader on your own device.' }),
        h('div', { class: 'stack' },
          h('a', { class: 'btn btn-primary btn-block', href: '/login', 'data-nav': true, onclick: close }, 'I bought it — sign in with WhatsApp'),
          h('p', { class: 'hint', text: 'First time? Open the private invitation link you received on WhatsApp after paying.' }),
          info.orderUrl ? h('a', { class: 'btn btn-block', href: info.orderUrl, target: '_blank', rel: 'noopener noreferrer' }, 'Buy this book on WhatsApp') : null,
          h('button', { class: 'btn-link', onclick: close }, 'Not now'))));
    m.addEventListener('click', (e) => { if (e.target === m) close(); });
    document.body.append(m);
    m.querySelector('a, button')?.focus();
  };
  mount(downloadPage({
    book: info.book, coverImg,
    topRight: h('a', { href: '/login', 'data-nav': true }, 'Sign in'),
    onDownload: needAccess, onStart: needAccess,
  }));
}

// ===========================================================================
// Installation guide  (/install)
// ===========================================================================
function viewInstallGuide() {
  const sec = (title, steps) => h('div', {}, h('h2', { class: 'label', text: title }), h('ol', { class: 'steps' }, steps.map((s) => h('li', { text: s }))));
  mount(screen(
    h('h1', { text: 'Install the reader' }),
    h('p', { class: 'muted', text: 'Installing adds “My Books” to your home screen or desktop. It opens straight to your book. Your book is never downloaded as a file.' }),
    installPrompt ? h('button', { class: 'btn btn-primary btn-block', onclick: () => showInstallModal({}) }, 'Install Reader') : null,
    sec('iPhone and iPad (Safari)', ['Tap Share.', 'Tap “Add to Home Screen”.', 'Open “My Books” and sign in with your WhatsApp number.']),
    sec('Android (Chrome, Edge, Samsung Internet)', ['Tap the menu (⋮).', 'Tap “Install app” or “Add to Home screen”.']),
    sec('Windows, macOS, ChromeOS (Chrome or Edge)', ['Click the install icon in the address bar.', 'Click “Install”.']),
    sec('macOS (Safari 17+)', ['File → Add to Dock.']),
    h('a', { class: 'btn btn-block', href: '/app', 'data-nav': true }, 'Back to my book')));
}

// ===========================================================================
// Unauthorized access screen  (/denied and any unknown route)
// ===========================================================================
function viewDenied(reason) {
  const extra = {
    device: 'Access on this device was removed by the book owner, or moved to another device.',
    suspended: 'Access to this account is currently paused.',
  }[reason];
  mount(h('main', { class: 'screen denied' }, h('div', { class: 'panel' },
    h('div', { class: 'lock', 'aria-hidden': 'true', text: '🔒' }),
    h('h1', { text: 'Private book access' }),
    h('p', { text: 'This reading space is protected and available only to its authorized purchaser.' }),
    h('p', { text: 'This device does not have permission to access this book.' }),
    extra ? h('p', { class: 'muted', text: extra }) : null,
    h('p', { class: 'muted', text: 'If you purchased this book, use your original invitation or contact the book owner.' }),
    h('div', { class: 'stack' }, h('a', { class: 'btn btn-primary btn-block', href: '/login', 'data-nav': true }, 'I purchased this book — sign in')))));
}

// ===========================================================================
// Reader  (/read/:id)
// ===========================================================================
const prefs = {
  get(k, d) { try { return localStorage.getItem(`pref:${k}`) ?? d; } catch { return d; } },
  set(k, v) { try { localStorage.setItem(`pref:${k}`, v); } catch { /* ignore */ } },
};

async function viewReader(bookId) {
  let s; let manifest; let book; let progress;
  try {
    s = await loadSession();
    if (!s.authenticated) {
      if (['DEVICE_REVOKED', 'ACCOUNT_SUSPENDED'].includes(s.code)) return handleAuthError(new ApiError(403, { code: s.code }));
      if (s.code === 'SESSION_EXPIRED') return go('/login?reason=expired', true);
      return viewDenied('signin');
    }
    [book, manifest, progress] = await Promise.all([
      api('GET', `/api/reader/books/${bookId}`, undefined, { signed: true }),
      api('GET', `/api/reader/books/${bookId}/manifest`, undefined, { signed: true }),
      api('GET', `/api/reader/progress/${bookId}`, undefined, { signed: true }),
    ]);
  } catch (err) {
    if (err.code === 'NOT_READY') return mount(screen(h('h1', { text: 'Preparing your book' }), h('p', { class: 'muted', text: err.message }), h('button', { class: 'btn btn-primary btn-block', onclick: () => route() }, 'Check again')));
    if (await handleAuthError(err)) return; return viewOffline(err);
  }
  new Reader(bookId, book.book, manifest, progress.progress, s.books.length > 1).start();
}

class Reader {
  constructor(bookId, book, manifest, progress, hasLibrary) {
    Object.assign(this, { bookId, book, manifest, hasLibrary });
    this.isPdf = manifest.format === 'PDF';
    this.items = manifest.items;
    this.loc = { index: Math.min(progress?.location?.index ?? 0, this.items.length - 1), page: progress?.location?.page ?? 0 };
    this.pages = 1;
    this.html = new Map(); // chapter index -> sanitized HTML (memory only)
    this.assets = new Map(); // asset id -> blob URL (EPUB images)
    this.pages_ = new Map(); // PDF page id -> ImageBitmap
    this.busy = false;
    this.fs = Number(prefs.get('fs', 19));
    this.theme = prefs.get('theme', 'sepia');
  }

  async fetchItem(i) {
    const id = this.items[i].id;
    const url = `/api/reader/books/${this.bookId}/content/${id}`;
    if (this.isPdf) {
      // Pages are decoded straight into memory bitmaps and drawn on a canvas: no image URL or
      // file exists to save, and only a few neighbouring pages are kept.
      if (!this.pages_.has(id)) {
        const res = await api('GET', url, undefined, { signed: true, raw: true });
        this.pages_.set(id, await createImageBitmap(await res.blob()));
        for (const [k, bmp] of this.pages_) {
          if (this.pages_.size <= 6) break;
          if (k !== id) { bmp.close(); this.pages_.delete(k); }
        }
      }
      return this.pages_.get(id);
    }
    if (!this.html.has(i)) {
      const res = await api('GET', url, undefined, { signed: true, raw: true });
      this.html.set(i, await res.text());
      // Keep only nearby chapters in memory.
      for (const k of this.html.keys()) if (Math.abs(k - i) > 2) this.html.delete(k);
    }
    return this.html.get(i);
  }

  /** Load chapter images through signed requests. Returns how many were attached. */
  async hydrateImages(container) {
    let loaded = 0;
    for (const img of container.querySelectorAll('img[data-asset]')) {
      const id = img.getAttribute('data-asset');
      if (!this.assets.has(id)) {
        try {
          const res = await api('GET', `/api/reader/books/${this.bookId}/content/${id}`, undefined, { signed: true, raw: true });
          this.assets.set(id, URL.createObjectURL(await res.blob()));
        } catch { continue; }
      }
      img.src = this.assets.get(id);
      loaded += 1;
    }
    if (loaded) await Promise.all([...container.querySelectorAll('img')].map((i) => (i.complete ? null : new Promise((r) => { i.onload = r; i.onerror = r; }))));
    return loaded;
  }

  // --- Layout ---------------------------------------------------------------
  geometry() {
    const vp = this.top.querySelector('.viewport');
    const w = vp.clientWidth; const gap = 40;
    return { w, gap, step: w + gap };
  }

  /** Render chapter i into a layer and position it at page p. Returns page count. */
  async paint(layer, i, p) {
    const vp = layer.querySelector('.viewport');
    if (this.isPdf) {
      const bmp = await this.fetchItem(i);
      const c = h('canvas', { role: 'img', 'aria-label': `Page ${i + 1}` });
      c.width = bmp.width; c.height = bmp.height;
      c.getContext('2d').drawImage(bmp, 0, 0);
      vp.replaceChildren(h('div', { class: 'pdfpage' }, c));
      layer.dataset.idx = String(i);
      layer.querySelector('.pageno').textContent = `${i + 1} / ${this.items.length}`;
      return 1;
    }
    if (layer.dataset.idx !== String(i)) {
      const html = await this.fetchItem(i);
      const flow = h('div', { class: 'flow' });
      // Content was sanitized server-side; the CSP additionally blocks any script execution.
      flow.innerHTML = html;
      flow.querySelectorAll('a[href]').forEach((a) => { a.target = '_blank'; a.rel = 'noopener noreferrer'; });
      vp.replaceChildren(flow);
      layer.dataset.idx = String(i);
      // Images change the column layout, so re-measure once they are in (only if there were any).
      this.hydrateImages(flow).then((n) => { if (n && layer === this.top && flow.isConnected) this.remeasure(); });
    }
    const flow = vp.querySelector('.flow');
    const { w, gap, step } = this.geometry();
    flow.style.columnWidth = `${w}px`;
    flow.style.columnGap = `${gap}px`;
    flow.style.width = `${w}px`;
    const pages = Math.max(1, Math.round((flow.scrollWidth + gap) / step));
    const page = p === 'last' ? pages - 1 : Math.min(Math.max(0, p), pages - 1);
    flow.style.transform = `translateX(${-page * step}px)`;
    layer.dataset.page = String(page);
    layer.querySelector('.pageno').textContent = `${page + 1} / ${pages}`;
    return pages;
  }

  next(loc) {
    if (this.isPdf) return loc.index + 1 < this.items.length ? { index: loc.index + 1, page: 0 } : null;
    if (loc.page + 1 < this.pages) return { index: loc.index, page: loc.page + 1 };
    return loc.index + 1 < this.items.length ? { index: loc.index + 1, page: 0 } : null;
  }

  prev(loc) {
    if (this.isPdf) return loc.index > 0 ? { index: loc.index - 1, page: 0 } : null;
    if (loc.page > 0) return { index: loc.index, page: loc.page - 1 };
    return loc.index > 0 ? { index: loc.index - 1, page: 'last' } : null;
  }

  async show(loc) {
    this.pages = await this.paint(this.top, loc.index, loc.page);
    this.loc = { index: loc.index, page: Number(this.top.dataset.page || 0) };
    this.resetTop();
    this.updateChrome();
    this.saveProgress();
    // Prepare the page underneath (the next page) for forward flips.
    const n = this.next(this.loc);
    if (n) await this.paint(this.under, n.index, n.page); else this.under.querySelector('.viewport').replaceChildren();
  }

  resetTop() {
    this.top.classList.remove('anim');
    this.top.style.transform = 'rotateY(0deg)';
    this.top.querySelector('.shade').style.opacity = '0';
  }

  /** Recount pages of the current chapter without re-rendering it. */
  async remeasure() {
    const ratio = this.pages > 1 ? this.loc.page / (this.pages - 1) : 0;
    this.pages = await this.paint(this.top, this.loc.index, 0);
    await this.show({ index: this.loc.index, page: Math.round(ratio * (this.pages - 1)) });
  }

  async relayout(keep) {
    if (this.isPdf) return;
    const ratio = this.pages > 1 ? this.loc.page / (this.pages - 1) : 0;
    this.top.dataset.idx = ''; this.under.dataset.idx = '';
    this.pages = await this.paint(this.top, this.loc.index, 0);
    await this.show({ index: this.loc.index, page: keep ? Math.round(ratio * (this.pages - 1)) : this.loc.page });
  }

  // --- Page turning with the page-flip effect --------------------------------
  setAngle(layer, deg) {
    layer.style.transform = `rotateY(${deg}deg)`;
    layer.querySelector('.shade').style.opacity = String(Math.sin((Math.abs(deg) * Math.PI) / 180) * 0.9);
  }

  animateTo(layer, deg) {
    return new Promise((resolve) => {
      if (matchMedia('(prefers-reduced-motion: reduce)').matches) { this.setAngle(layer, deg); return resolve(); }
      layer.classList.add('anim');
      requestAnimationFrame(() => {
        this.setAngle(layer, deg);
        const done = () => { layer.classList.remove('anim'); resolve(); };
        layer.addEventListener('transitionend', done, { once: true });
        setTimeout(done, 600);
      });
    });
  }

  /** Begin a turn: returns a controller with update(progress 0..1), commit(), cancel(). */
  async beginTurn(dir) {
    const target = dir > 0 ? this.next(this.loc) : this.prev(this.loc);
    if (!target) return null;
    const top = this.top; const under = this.under;
    if (dir > 0) {
      // Top shows the current page and folds away to reveal the next page underneath.
      return {
        update: (t) => this.setAngle(top, -180 * t),
        commit: async () => { await this.animateTo(top, -180); await this.show(target); },
        cancel: async () => { await this.animateTo(top, 0); },
      };
    }
    // Backward: underneath shows the current page; the previous page folds back in on top.
    await this.paint(under, this.loc.index, this.loc.page);
    await this.paint(top, target.index, target.page);
    this.setAngle(top, -180);
    return {
      update: (t) => this.setAngle(top, -180 + 180 * t),
      commit: async () => { await this.animateTo(top, 0); await this.show({ index: target.index, page: Number(top.dataset.page) }); },
      cancel: async () => { await this.animateTo(top, -180); await this.show(this.loc); },
    };
  }

  async turn(dir) {
    if (this.busy) return;
    this.busy = true;
    try {
      const t = await this.beginTurn(dir);
      if (t) await t.commit();
    } catch (err) { if (!(await handleAuthError(err))) toast(err.message); } finally { this.busy = false; }
  }

  bindGestures(stage) {
    let start = null; let ctl = null; let dir = 0; let pending = null;
    stage.addEventListener('pointerdown', (e) => {
      if (this.busy || e.button > 0 || e.target.closest('a')) return;
      start = { x: e.clientX, y: e.clientY, t: Date.now() }; dir = 0; ctl = null;
    });
    stage.addEventListener('pointermove', async (e) => {
      if (!start) return;
      const dx = e.clientX - start.x;
      if (!dir) {
        if (Math.abs(dx) < 10 || Math.abs(dx) < Math.abs(e.clientY - start.y)) return;
        dir = dx < 0 ? 1 : -1;
        stage.setPointerCapture(e.pointerId);
        this.busy = true;
        pending = this.beginTurn(dir).then((c) => { ctl = c; if (!c) this.busy = false; return c; });
      }
      if (ctl) ctl.update(Math.min(1, Math.abs(dx) / (stage.clientWidth * 0.9)));
    });
    const end = async (e) => {
      if (!start) return;
      const dx = e.clientX - start.x; const quick = Date.now() - start.t < 250;
      const s = start; start = null;
      if (!dir) {
        // A tap: side zones turn pages, the middle toggles the reading chrome.
        const x = e.clientX - stage.getBoundingClientRect().left;
        if (Math.abs(dx) < 10 && Math.abs(e.clientY - s.y) < 10 && !e.target.closest('a')) {
          if (x < stage.clientWidth * 0.25) this.turn(-1);
          else if (x > stage.clientWidth * 0.75) this.turn(1);
          else this.el.classList.toggle('immersive');
        }
        return;
      }
      const c = await pending;
      try {
        if (c) {
          if (Math.abs(dx) > stage.clientWidth * 0.22 || (quick && Math.abs(dx) > 30)) await c.commit(); else await c.cancel();
        }
      } catch (err) { if (!(await handleAuthError(err))) toast(err.message); } finally { this.busy = false; dir = 0; }
    };
    stage.addEventListener('pointerup', end);
    stage.addEventListener('pointercancel', end);
  }

  // --- Chrome: progress, TOC, bookmarks, search, settings ---------------------
  percent() {
    const n = this.items.length;
    const within = this.isPdf ? 1 : (this.loc.page + 1) / this.pages;
    return Math.min(100, Math.round(((this.loc.index + within) / n) * 100));
  }

  updateChrome() {
    const item = this.items[this.loc.index];
    const toc = [...this.manifest.toc].reverse().find((t) => t.chapter <= this.loc.index);
    this.footLeft.textContent = this.isPdf ? `Page ${this.loc.index + 1} of ${this.items.length}` : (toc?.label || item.title || `Chapter ${this.loc.index + 1}`);
    this.footRight.textContent = `${this.percent()}%`;
    this.progressBar.style.width = `${this.percent()}%`;
    this.progressBar.parentElement.setAttribute('aria-valuenow', String(this.percent()));
  }

  saveProgress() {
    clearTimeout(this.saveTimer);
    this.saveTimer = setTimeout(() => {
      api('POST', '/api/reader/progress', { bookId: this.bookId, location: { index: this.loc.index, page: this.loc.page }, percent: this.percent() }, { signed: true })
        .catch((err) => handleAuthError(err));
    }, 1200);
  }

  drawer(title, body) {
    this.closeDrawer();
    const close = () => this.closeDrawer();
    const scrim = h('div', { class: 'drawer-scrim', onclick: close });
    const d = h('aside', { class: 'drawer', role: 'dialog', 'aria-label': title },
      h('header', {}, h('h2', { text: title }), h('button', { class: 'ibtn', 'aria-label': 'Close', onclick: close }, '✕')),
      h('div', { class: 'body' }, body));
    d.addEventListener('keydown', (e) => { if (e.key === 'Escape') close(); });
    document.body.append(scrim, d);
    this.openDrawer = [scrim, d];
    d.querySelector('button, input')?.focus();
    return d;
  }

  closeDrawer() { (this.openDrawer || []).forEach((n) => n.remove()); this.openDrawer = null; }

  async gotoChapter(index, anchor) {
    this.closeDrawer();
    this.top.dataset.idx = '';
    this.pages = await this.paint(this.top, index, 0);
    let page = 0;
    if (anchor && !this.isPdf) {
      const flow = this.top.querySelector('.flow');
      const target = flow.querySelector(`#${CSS.escape(anchor)}`);
      if (target) {
        flow.style.transform = 'none';
        page = Math.floor((target.getBoundingClientRect().left - flow.getBoundingClientRect().left) / this.geometry().step);
      }
    }
    await this.show({ index, page });
  }

  showToc() {
    const list = this.manifest.toc.length ? this.manifest.toc : this.items.map((it) => ({ label: it.title || `Section ${it.index + 1}`, chapter: it.index, level: 0 }));
    this.drawer('Contents', list.map((t) => {
      const b = h('button', { class: 'item', onclick: () => this.gotoChapter(t.chapter, t.anchor) }, t.label);
      b.style.paddingLeft = `${16 + (t.level || 0) * 16}px`;
      if (t.chapter === this.loc.index) b.setAttribute('aria-current', 'true');
      return b;
    }));
  }

  async showBookmarks() {
    const body = h('div', {}, h('div', { class: 'pad' }, h('button', { class: 'btn btn-primary btn-block', onclick: () => this.addBookmark() }, 'Bookmark this page')));
    const list = h('div');
    body.append(list);
    this.drawer('Bookmarks', body);
    try {
      const { bookmarks } = await api('GET', `/api/reader/bookmarks/${this.bookId}`, undefined, { signed: true });
      if (!bookmarks.length) list.append(h('p', { class: 'pad hint', text: 'No bookmarks yet.' }));
      for (const bm of bookmarks) {
        const row = h('div', { class: 'item' },
          h('button', { class: 'btn-link', onclick: () => { this.closeDrawer(); this.top.dataset.idx = ''; this.show({ index: bm.location.index, page: bm.location.page || 0 }); } }, bm.label || `Location ${bm.location.index + 1}`),
          h('small', { text: new Date(bm.created_at).toLocaleString() }),
          h('button', { class: 'btn btn-small btn-danger', onclick: async () => { await api('DELETE', `/api/reader/bookmarks/${bm.id}`, undefined, { signed: true }); row.remove(); } }, 'Remove'));
        list.append(row);
      }
    } catch (err) { if (!(await handleAuthError(err))) list.append(h('p', { class: 'pad error-text', text: err.message })); }
  }

  async addBookmark() {
    const label = `${this.footLeft.textContent} · ${this.isPdf ? '' : `page ${this.loc.page + 1}`}`.replace(/ · $/, '');
    try {
      await api('POST', '/api/reader/bookmarks', { bookId: this.bookId, location: { index: this.loc.index, page: this.loc.page }, label }, { signed: true });
      toast('Bookmarked');
      this.showBookmarks();
    } catch (err) { if (!(await handleAuthError(err))) toast(err.message); }
  }

  showSearch() {
    const input = h('input', { type: 'search', placeholder: 'Search this book', 'aria-label': 'Search this book' });
    const results = h('div');
    const form = h('form', { class: 'pad' }, input);
    form.addEventListener('submit', async (e) => {
      e.preventDefault();
      results.replaceChildren(h('p', { class: 'pad hint', text: 'Searching…' }));
      try {
        const r = await api('GET', `/api/reader/books/${this.bookId}/search?q=${encodeURIComponent(input.value)}`, undefined, { signed: true });
        if (r.supported === false) return results.replaceChildren(h('p', { class: 'pad hint', text: 'Search is not available for page-image books.' }));
        if (!r.results.length) return results.replaceChildren(h('p', { class: 'pad hint', text: 'No matches.' }));
        results.replaceChildren(...r.results.map((m) => h('button', { class: 'item', onclick: () => this.gotoSearchHit(m) },
          h('small', { text: m.chapter || `Section ${m.index + 1}` }), m.snippet)));
      } catch (err) { if (!(await handleAuthError(err))) results.replaceChildren(h('p', { class: 'pad error-text', text: err.message })); }
    });
    this.drawer('Search', h('div', {}, form, results));
  }

  async gotoSearchHit(m) {
    await this.gotoChapter(m.index);
    const flow = this.top.querySelector('.flow');
    const total = (flow?.textContent || '').length || 1;
    await this.show({ index: m.index, page: Math.floor((m.offset / total) * this.pages) });
  }

  showSettings() {
    const seg = (items, current, onPick) => {
      const wrap = h('div', { class: 'seg' });
      for (const [val, label] of items) {
        wrap.append(h('button', { class: 'btn btn-small', 'aria-pressed': String(val === current), onclick: (e) => {
          wrap.querySelectorAll('button').forEach((b) => b.setAttribute('aria-pressed', 'false'));
          e.currentTarget.setAttribute('aria-pressed', 'true'); onPick(val);
        } }, label));
      }
      return wrap;
    };
    this.drawer('Reading settings', h('div', { class: 'pad' },
      h('div', { class: 'label', text: 'Text size' }),
      h('div', { class: 'seg' },
        h('button', { class: 'btn btn-small', 'aria-label': 'Smaller text', onclick: () => this.setFont(this.fs - 1), disabled: this.isPdf }, 'A−'),
        h('button', { class: 'btn btn-small', 'aria-label': 'Larger text', onclick: () => this.setFont(this.fs + 1), disabled: this.isPdf }, 'A+')),
      h('div', { class: 'label', text: 'Theme' }),
      seg([['light', 'Light'], ['sepia', 'Sepia'], ['dark', 'Dark']], this.theme, (v) => this.setTheme(v)),
      h('p', { class: 'hint', text: 'Keyboard: ← → to turn pages, T contents, B bookmark, F search.' }),
      h('button', { class: 'btn btn-block', onclick: () => { this.closeDrawer(); this.leave(); go('/install'); } }, 'Install the reader'),
      h('button', { class: 'btn btn-block btn-danger', onclick: () => { this.leave(); logout(); } }, 'Sign out')));
  }

  setFont(px) {
    this.fs = Math.max(14, Math.min(30, px));
    prefs.set('fs', this.fs);
    this.el.style.setProperty('--fs', `${this.fs}px`);
    this.relayout(true);
  }

  setTheme(t) {
    this.theme = t; prefs.set('theme', t);
    this.el.classList.remove('theme-light', 'theme-dark');
    if (t !== 'sepia') this.el.classList.add(`theme-${t}`);
  }

  leave() {
    clearTimeout(this.saveTimer);
    this.closeDrawer();
    for (const u of this.assets.values()) URL.revokeObjectURL(u);
    for (const b of this.pages_.values()) b.close();
    this.assets.clear(); this.html.clear(); this.pages_.clear();
  }

  // --- Mount -------------------------------------------------------------------
  async start() {
    const layer = (cls) => h('div', { class: `layer ${cls}` }, h('div', { class: 'viewport' }), h('div', { class: 'pageno' }), h('div', { class: 'shade' }));
    this.top = layer('top'); this.under = layer('under');
    const wm = h('div', { class: 'watermark', 'aria-hidden': 'true' });
    // PDF pages already carry the buyer's watermark in their pixels; EPUB text gets an overlay.
    if (!this.isPdf) for (let i = 0; i < 24; i += 1) wm.append(h('span', { text: this.manifest.watermark }));
    const stage = h('div', { class: 'stage' }, h('div', { class: 'book' }, this.under, this.top), wm,
      h('button', { class: 'zone l', 'aria-label': 'Previous page', tabindex: '-1', onclick: (e) => e.preventDefault() }),
      h('button', { class: 'zone r', 'aria-label': 'Next page', tabindex: '-1', onclick: (e) => e.preventDefault() }));
    this.footLeft = h('span'); this.footRight = h('span');
    this.progressBar = h('i');
    const ib = (label, icon, fn) => h('button', { class: 'ibtn', 'aria-label': label, title: label, onclick: fn }, icon);
    this.el = h('div', { class: 'reader' },
      h('header', { class: 'rbar' },
        ib(this.hasLibrary ? 'My books' : 'Book details', '←', () => { this.leave(); go(this.hasLibrary ? '/library' : (isStandalone() ? '/app' : `/book/${this.bookId}`)); }),
        h('div', { class: 'ttl', text: this.book.title }),
        ib('Search', '⌕', () => this.showSearch()),
        ib('Contents', '☰', () => this.showToc()),
        ib('Bookmarks', '🔖', () => this.showBookmarks()),
        ib('Reading settings', 'Aa', () => this.showSettings())),
      stage,
      h('footer', { class: 'rfoot' },
        h('div', { class: 'bar', role: 'progressbar', 'aria-valuemin': '0', 'aria-valuemax': '100', 'aria-label': 'Reading progress' }, this.progressBar),
        h('div', { class: 'row' }, this.footLeft, this.footRight)));
    this.el.style.setProperty('--fs', `${this.fs}px`);
    this.setTheme(this.theme);
    // Deterrents only (not security): no context menu, drag or copy of reading content.
    this.el.addEventListener('contextmenu', (e) => e.preventDefault());
    this.el.addEventListener('dragstart', (e) => e.preventDefault());
    this.el.addEventListener('copy', (e) => e.preventDefault());
    stage.addEventListener('click', (e) => {
      const a = e.target.closest('a[data-chapter]');
      if (a) { e.preventDefault(); this.gotoChapter(Number(a.dataset.chapter), a.dataset.anchor); }
    });
    mount(this.el);
    onCleanup(() => this.leave());
    this.bindGestures(stage);

    const onKey = (e) => {
      if (e.target.closest('input, textarea') || this.openDrawer) return;
      if (e.key === 'ArrowRight' || e.key === 'PageDown' || e.key === ' ') { e.preventDefault(); this.turn(1); }
      else if (e.key === 'ArrowLeft' || e.key === 'PageUp') { e.preventDefault(); this.turn(-1); }
      else if (e.key.toLowerCase() === 't') this.showToc();
      else if (e.key.toLowerCase() === 'b') this.addBookmark();
      else if (e.key.toLowerCase() === 'f') { e.preventDefault(); this.showSearch(); }
    };
    addEventListener('keydown', onKey);
    // Privacy shield: blur the page whenever the reader is not the focused window (app switcher
    // thumbnails, desktop screen-capture tools that take focus) and block print/save shortcuts.
    // A deterrent only; see docs/SECURITY_LIMITATIONS.md.
    const shield = (on) => this.el.classList.toggle('shielded', on);
    const onBlur = () => shield(true);
    const onFocus = () => shield(false);
    const onVis = () => shield(document.visibilityState !== 'visible');
    const onGuardKey = (e) => {
      if (e.target.closest?.('input, textarea')) return;
      const k = e.key.toLowerCase();
      if ((e.ctrlKey || e.metaKey) && ['p', 's', 'c', 'a'].includes(k)) { e.preventDefault(); }
      if (k === 'printscreen') { shield(true); setTimeout(() => { if (document.hasFocus()) shield(false); }, 1500); }
    };
    addEventListener('blur', onBlur); addEventListener('focus', onFocus);
    document.addEventListener('visibilitychange', onVis);
    addEventListener('keyup', onGuardKey); addEventListener('keydown', onGuardKey);
    onCleanup(() => {
      removeEventListener('blur', onBlur); removeEventListener('focus', onFocus);
      document.removeEventListener('visibilitychange', onVis);
      removeEventListener('keyup', onGuardKey); removeEventListener('keydown', onGuardKey);
    });
    let rt;
    const onResize = () => { clearTimeout(rt); rt = setTimeout(() => this.relayout(true), 200); };
    addEventListener('resize', onResize);
    // Revalidate access whenever the app returns to the foreground.
    const onVisible = () => { if (document.visibilityState === 'visible') api('POST', '/api/access/validate-license', { bookId: this.bookId }).catch((err) => handleAuthError(err)); };
    document.addEventListener('visibilitychange', onVisible);
    onCleanup(() => { removeEventListener('keydown', onKey); removeEventListener('resize', onResize); document.removeEventListener('visibilitychange', onVisible); });

    try {
      this.pages = await this.paint(this.top, this.loc.index, 0);
      await this.show(this.loc);
    } catch (err) { if (!(await handleAuthError(err))) toast(err.message); }
  }
}

// ===========================================================================
// Boot
// ===========================================================================
if ('serviceWorker' in navigator) navigator.serviceWorker.register('/sw.js', { scope: '/' }).catch(() => {});
route();

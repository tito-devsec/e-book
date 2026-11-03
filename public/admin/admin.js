// Management dashboard (single-page app). All text is inserted via textContent.

// ===========================================================================
// Helpers
// ===========================================================================
function h(tag, attrs = {}, ...children) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === undefined || v === null || v === false) continue;
    if (k === 'class') el.className = v;
    else if (k.startsWith('on') && typeof v === 'function') el.addEventListener(k.slice(2), v);
    else if (k === 'text') el.textContent = v;
    else if (k === 'value') el.value = v;
    else el.setAttribute(k, v === true ? '' : v);
  }
  for (const c of children.flat(Infinity)) {
    if (c === null || c === undefined || c === false) continue;
    el.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return el;
}
const root = document.getElementById('root');
let me = null; let csrf = null;

class ApiError extends Error { constructor(status, data) { super(data?.message || `Request failed (${status})`); this.status = status; this.code = data?.code; } }

async function api(method, url, body) {
  const headers = {};
  let payload;
  if (body instanceof FormData) payload = body;
  else if (body !== undefined) { payload = JSON.stringify(body); headers['content-type'] = 'application/json'; }
  if (csrf && method !== 'GET') headers['x-csrf-token'] = csrf;
  const res = await fetch(url, { method, headers, body: payload, credentials: 'same-origin', cache: 'no-store' });
  const data = (res.headers.get('content-type') || '').includes('json') ? await res.json().catch(() => ({})) : {};
  if (res.status === 401 && !url.includes('/auth/')) { me = null; renderLogin(); throw new ApiError(401, data); }
  if (!res.ok) throw new ApiError(res.status, data);
  return data;
}

function toast(msg, err = false) {
  const t = h('div', { class: `toast${err ? ' err' : ''}`, role: err ? 'alert' : 'status', text: msg });
  document.body.append(t);
  setTimeout(() => t.remove(), err ? 6000 : 3000);
}

/** Run an action with error reporting; optionally reload the current view. */
async function act(fn, { ok, reload = true } = {}) {
  try {
    const r = await fn();
    if (ok) toast(ok);
    if (reload) route();
    return r;
  } catch (e) { if (e.status !== 401) toast(e.message, true); return undefined; }
}

const fmtDate = (d) => (d ? new Date(d).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' }) : '—');
// Tanzanian shillings are shown the local way ("TSh 15,000"), without decimals for whole amounts.
const fmtMoney = (a, c) => {
  const n = Number(a);
  try {
    return new Intl.NumberFormat(c === 'TZS' ? 'en-TZ' : undefined, { style: 'currency', currency: c, minimumFractionDigits: 0, maximumFractionDigits: n % 1 ? 2 : 0 }).format(n);
  } catch { return `${c} ${a}`; }
};
const STATUS_TONE = {
  ACTIVE: 'ok', PAID: 'ok', VERIFIED: 'ok', READY: 'ok', CONSUMED: 'ok', ACTIVATED: 'ok', ADMIN_APPROVED: 'ok', SELF_SERVICE: 'ok',
  PENDING: 'warn', PENDING_PAYMENT: 'warn', PENDING_ACTIVATION: 'warn', INVITED: 'info', PROCESSING: 'warn', PENDING_APPROVAL: 'warn', MEDIUM: 'warn',
  SUSPENDED: 'bad', REVOKED: 'bad', REJECTED: 'bad', FAILED: 'bad', HIGH: 'bad', ADMIN_REJECTED: 'bad', DISABLED: 'bad',
  EXPIRED: '', REPLACED: '', ARCHIVED: '', LOW: '',
};
const badge = (s) => h('span', { class: `badge ${STATUS_TONE[s] ?? ''}`, text: String(s || '—').replace(/_/g, ' ') });
const can = (p) => me?.permissions?.includes(p);

function table(columns, rows, empty = 'Nothing here yet.') {
  if (!rows.length) return h('div', { class: 'tbl-wrap' }, h('div', { class: 'empty', text: empty }));
  return h('div', { class: 'tbl-wrap' }, h('table', { class: 'tbl' },
    h('thead', {}, h('tr', {}, columns.map((c) => h('th', { scope: 'col', text: c.label })))),
    h('tbody', {}, rows.map((r) => h('tr', {}, columns.map((c) => h('td', {}, c.render ? c.render(r) : (r[c.key] ?? '—'))))))));
}

// Customers added by name only carry a placeholder number; show nothing for it.
const showPhone = (p) => (!p || String(p).startsWith('+000') ? '' : p);
const btn = (label, onclick, cls = 'btn btn-small') => h('button', { class: cls, type: 'button', onclick }, label);
const link = (href, text) => h('a', { href, 'data-nav': true, text });

/** Build a form from field definitions. Returns { form, values() }. */
function buildForm(fields, values = {}, { submit = 'Save', onSubmit, columns = true } = {}) {
  const inputs = {};
  const err = h('p', { class: 'error-text', role: 'alert' });
  const controls = fields.map((f) => {
    const id = `f-${f.name}-${Math.random().toString(36).slice(2, 7)}`;
    let input;
    const v = values[f.name] ?? f.default ?? '';
    if (f.type === 'select') {
      input = h('select', { id, name: f.name }, f.options.map(([val, label]) => h('option', { value: val, text: label })));
      input.value = v === null ? '' : String(v);
    } else if (f.type === 'textarea') {
      input = h('textarea', { id, name: f.name, rows: f.rows || 4, maxlength: f.max }); input.value = v ?? '';
    } else if (f.type === 'checkbox') {
      input = h('input', { id, name: f.name, type: 'checkbox' }); input.checked = Boolean(v);
    } else if (f.type === 'file') {
      input = h('input', { id, name: f.name, type: 'file', accept: f.accept });
    } else if (f.type === 'multiselect') {
      input = h('select', { id, name: f.name, multiple: true, size: Math.min(6, f.options.length) }, f.options.map(([val, label]) => h('option', { value: val, text: label })));
      for (const o of input.options) o.selected = (v || []).includes(o.value);
    } else {
      input = h('input', { id, name: f.name, type: f.type || 'text', placeholder: f.placeholder, maxlength: f.max, min: f.min, max: f.maxv, step: f.step, autocomplete: f.autocomplete || 'off' });
      input.value = v ?? '';
    }
    if (f.required) input.required = true;
    inputs[f.name] = { el: input, f };
    return h('div', { class: `field${f.full ? ' full' : ''}` },
      f.type === 'checkbox' ? h('label', { for: id }, input, ' ', f.label) : [h('label', { for: id, text: f.label + (f.required ? ' *' : '') }), input],
      f.hint ? h('span', { class: 'hint', text: f.hint }) : null);
  });
  const values_ = () => {
    const out = {};
    for (const [name, { el, f }] of Object.entries(inputs)) {
      if (f.type === 'checkbox') out[name] = el.checked;
      else if (f.type === 'file') out[name] = el.files[0] || null;
      else if (f.type === 'multiselect') out[name] = [...el.selectedOptions].map((o) => o.value);
      else if (f.type === 'number') out[name] = el.value === '' ? (f.nullable ? null : undefined) : Number(el.value);
      else out[name] = el.value === '' && f.nullable ? null : el.value;
    }
    return out;
  };
  const submitBtn = h('button', { class: 'btn btn-primary', type: 'submit' }, submit);
  const form = h('form', { novalidate: true }, h('div', { class: columns ? 'form-grid' : '' }, controls), err, onSubmit ? submitBtn : null);
  if (onSubmit) {
    form.addEventListener('submit', async (e) => {
      e.preventDefault(); err.textContent = '';
      for (const { el, f } of Object.values(inputs)) {
        if (f.required && f.type !== 'checkbox' && !(f.type === 'file' ? el.files.length : String(el.value).trim())) { err.textContent = `${f.label} is required`; el.focus(); return; }
      }
      submitBtn.disabled = true;
      try { await onSubmit(values_()); } catch (ex) { if (ex.status !== 401) err.textContent = ex.message; } finally { submitBtn.disabled = false; }
    });
  }
  return { form, values: values_, inputs };
}

function modal(title, body, { wide } = {}) {
  const close = () => m.remove();
  const m = h('div', { class: 'modal', role: 'dialog', 'aria-modal': 'true', 'aria-label': title },
    h('div', { class: 'card' }, h('div', { class: 'mhead' }, h('h2', { text: title }), btn('Close', close)), body));
  if (wide) m.querySelector('.card').style.maxWidth = '900px';
  m.addEventListener('keydown', (e) => { if (e.key === 'Escape') close(); });
  m.addEventListener('click', (e) => { if (e.target === m) close(); });
  document.body.append(m);
  m.querySelector('input, textarea, select, button')?.focus();
  return close;
}

/** Ask for confirmation with optional fields; resolves with values or null. */
function ask(title, message, fields = [], confirmLabel = 'Confirm', danger = false) {
  return new Promise((resolve) => {
    let done = false;
    const { form } = buildForm(fields, {}, {
      submit: confirmLabel, columns: false,
      onSubmit: async (v) => { done = true; close(); resolve(v); },
    });
    if (danger) form.querySelector('button[type=submit]').className = 'btn btn-danger';
    const close = modal(title, h('div', {}, h('p', { text: message }), form));
    const obs = new MutationObserver(() => { if (!document.body.contains(form)) { obs.disconnect(); if (!done) resolve(null); } });
    obs.observe(document.body, { childList: true });
  });
}

function pager(data, onPage) {
  const page = data.page || 1;
  const hasMore = data.total !== undefined ? page * data.limit < data.total : (data.rows ?? 0) >= data.limit;
  const prev = btn('Previous', () => onPage(page - 1)); prev.disabled = page <= 1;
  const next = btn('Next', () => onPage(page + 1)); next.disabled = !hasMore;
  return h('div', { class: 'pager' }, data.total !== undefined ? h('span', { text: `${data.total} total` }) : null, prev, h('span', { text: `Page ${page}` }), next);
}

// ===========================================================================
// Icons (inline SVG, stroke style)
// ===========================================================================
const SVGNS = 'http://www.w3.org/2000/svg';
// Icons: UIcons by Flaticon (https://www.flaticon.com/uicons), regular rounded set.
const UICONS = {
  home: 'rr-home', orders: 'rr-shopping-bag', payments: 'rr-credit-card', customers: 'rr-users', invitations: 'rr-envelope',
  devices: 'rr-mobile-notch', licenses: 'rr-key', books: 'rr-book-alt', editions: 'rr-layers', activity: 'rr-chart-histogram',
  security: 'rr-shield-check', audit: 'rr-list', website: 'rr-globe', whatsapp: 'brands-whatsapp', admins: 'rr-user-gear',
  settings: 'rr-settings', account: 'rr-user', search: 'rr-search', bell: 'rr-bell', check: 'rr-check', clock: 'rr-clock',
  x: 'rr-cross', plus: 'rr-plus', arrow: 'rr-arrow-right', book: 'rr-book-alt',
};
function icon(name, size = 18) {
  const el = h('i', { class: `fi fi-${UICONS[name] || 'rr-circle'}`, 'aria-hidden': 'true' });
  el.style.fontSize = `${size}px`;
  return el;
}
const initials = (name) => String(name || '?').trim().split(/\s+/).slice(0, 2).map((p) => p[0]?.toUpperCase() || '').join('');

// ===========================================================================
// Charts (hand-built SVG; colours validated for contrast and colour-blind separation)
// ===========================================================================
const SERIES = ['#e8592a', '#3f4fb5'];
/** Round-topped bar anchored to the baseline. */
let gradSeq = 0;
/** Card with a chart and a "view as table" toggle for accessibility. */
// ===========================================================================
// Shell, navigation, routing
// ===========================================================================
const NAV = [
  ['/admin/customers', 'Customers', 'customers.view', 'customers'],
  ['/admin/editions', 'Book Editions', 'books.manage', 'editions'],
  ['/admin/account', 'My Account', null, 'account'],
];

function go(path) { history.pushState({}, '', path); route(); }
addEventListener('popstate', () => route());
document.addEventListener('click', (e) => {
  const a = e.target.closest('a[data-nav]');
  if (a && !e.metaKey && !e.ctrlKey) { e.preventDefault(); document.querySelector('.side')?.classList.remove('open'); document.querySelector('.menu')?.remove(); go(a.getAttribute('href')); }
  if (!e.target.closest('.menu, .avatar')) document.querySelector('.menu')?.remove();
});

let mainEl = null; let contentEl = null; let titleEl = null;
function shell() {
  const side = h('aside', { class: 'side' },
    h('div', { class: 'brand' },
      h('a', { class: 'logo', href: '/admin', 'data-nav': true }, h('span', { class: 'mark' }, icon('book', 18)), 'BookVault'),
      btn('Menu', () => side.classList.toggle('open'), 'menu-btn')),
    h('nav', { 'aria-label': 'Dashboard' }, NAV.filter(([, , p]) => !p || can(p)).map(([href, label, , ic]) => h('a', { href, 'data-nav': true }, icon(ic), h('span', { text: label }))),
      ));
  titleEl = h('h1');
  const q = h('input', { type: 'search', placeholder: 'Search customers by name or phone', 'aria-label': 'Search customers' });
  const search = h('form', { class: 'search', role: 'search' }, icon('search', 18), q);
  search.addEventListener('submit', (e) => { e.preventDefault(); go(`/admin/customers?q=${encodeURIComponent(q.value.trim())}`); });
  const avatar = h('button', { class: 'avatar', type: 'button', 'aria-label': 'Account menu', 'aria-haspopup': 'menu', text: initials(me.name) });
  avatar.addEventListener('click', () => {
    const open = document.querySelector('.menu');
    if (open) return open.remove();
    mainEl.append(h('div', { class: 'menu', role: 'menu' },
      h('div', { class: 'who' }, h('strong', { text: me.name }), `${me.email} · ${me.role}`),
      h('a', { href: '/admin/account', 'data-nav': true, role: 'menuitem' }, 'My account'),
      h('button', { type: 'button', role: 'menuitem', onclick: logout }, 'Sign out')));
  });
  contentEl = h('div', { class: 'content', id: 'content' });
  const credit = h('p', { class: 'credit' }, 'Icons: ', h('a', { href: 'https://www.flaticon.com/uicons', target: '_blank', rel: 'noopener noreferrer' }, 'UIcons by Flaticon'));
  mainEl = h('main', { class: 'main', id: 'main' }, h('header', { class: 'topbar' }, titleEl, search, avatar), contentEl, credit);
  root.replaceChildren(h('div', { class: 'shell' }, side, mainEl));
}

function page(title, ...content) {
  document.title = `${title} · BookVault`;
  titleEl.textContent = title;
  for (const a of document.querySelectorAll('.side nav a')) {
    const href = a.getAttribute('href');
    const active = href === '/admin' ? location.pathname === '/admin' : location.pathname.startsWith(href);
    if (active) a.setAttribute('aria-current', 'page'); else a.removeAttribute('aria-current');
  }
  const nodes = [
    me.mfaRequiredButMissing ? h('div', { class: 'warnbar' }, 'Two-factor authentication is required. ', link('/admin/account', 'Set it up now.')) : null,
    ...content,
  ];
  contentEl.replaceChildren(...nodes.flat(Infinity).filter((c) => c !== null && c !== undefined && c !== false));
  window.scrollTo(0, 0);
}

async function route() {
  if (!me) return boot();
  if (!mainEl || !document.body.contains(mainEl)) shell();
  const p = location.pathname.replace(/\/$/, '') || '/admin';
  const q = new URLSearchParams(location.search);
  const m = (re) => p.match(re);
  let r;
  try {
    if (p === '/admin') return go('/admin/customers');
    if (p === '/admin/editions') return await viewEditions();
    if (p === '/admin/customers') return await viewCustomers(q);
    if ((r = m(/^\/admin\/customers\/([0-9a-f-]{36})$/))) return await viewCustomer(r[1]);
    if (p === '/admin/orders/new') return await viewNewOrder();
    if ((r = m(/^\/admin\/orders\/([0-9a-f-]{36})$/))) return await viewOrder(r[1]);
    if (p === '/admin/account') return viewAccount();
    page('Not found', h('p', { text: 'This page does not exist.' }));
  } catch (e) {
    if (e.status === 401) return undefined;
    page('Error', h('div', { class: 'card' }, h('p', { class: 'error-text', text: e.status === 403 ? 'You do not have permission to view this page.' : e.message })));
  }
  return undefined;
}

function setQuery(params) {
  const q = new URLSearchParams(location.search);
  for (const [k, v] of Object.entries(params)) { if (v === '' || v === null || v === undefined) q.delete(k); else q.set(k, v); }
  go(`${location.pathname}?${q}`);
}

// ===========================================================================
// Authentication
// ===========================================================================
async function boot() {
  try {
    const s = await api('GET', '/api/admin/auth/session');
    csrf = s.csrf;
    if (s.authenticated) { me = { ...s.admin, mfaRequiredButMissing: s.mfaRequiredButMissing }; shell(); return route(); }
    if (s.mfaRequired) return renderMfa();
  } catch { /* not signed in */ }
  return renderLogin();
}

function renderLogin() {
  const { form } = buildForm([
    { name: 'email', label: 'Email', type: 'email', required: true, autocomplete: 'username' },
    { name: 'password', label: 'Password', type: 'password', required: true, autocomplete: 'current-password' },
  ], {}, {
    submit: 'Sign in', columns: false,
    onSubmit: async (v) => {
      const r = await api('POST', '/api/admin/auth/login', v);
      csrf = r.csrf;
      if (r.mfaRequired) return renderMfa();
      return boot();
    },
  });
  root.replaceChildren(h('main', { class: 'login' }, h('div', { class: 'card' }, h('div', { class: 'brand' }, h('span', { class: 'logo' }, h('span', { class: 'mark' }, icon('book', 18)), 'BookVault')), h('h1', { text: 'Welcome back' }), h('p', { class: 'hint', text: 'Sign in to manage books, customers and access.' }), form)));
  root.querySelector('input').focus();
}

function renderMfa() {
  const { form } = buildForm([{ name: 'code', label: 'Authentication code', required: true, autocomplete: 'one-time-code', placeholder: '6 digits' }], {}, {
    submit: 'Verify', columns: false,
    onSubmit: async (v) => { const r = await api('POST', '/api/admin/auth/mfa', v); csrf = r.csrf; return boot(); },
  });
  root.replaceChildren(h('main', { class: 'login' }, h('div', { class: 'card' }, h('div', { class: 'brand' }, h('span', { class: 'logo' }, h('span', { class: 'mark' }, icon('book', 18)), 'BookVault')), h('h1', { text: 'Two-factor authentication' }), h('p', { class: 'hint', text: 'Enter the code from your authenticator app.' }), form)));
  root.querySelector('input').focus();
}

async function logout() {
  await api('POST', '/api/admin/auth/logout').catch(() => {});
  me = null; csrf = null; history.pushState({}, '', '/admin'); renderLogin();
}

// ===========================================================================
// Overview
// ===========================================================================
// ===========================================================================
// Books and editions
// ===========================================================================
function editionsTable(bookId, book, editions) {
  return table([
    { label: 'Version', render: (e) => h('div', {}, `v${e.version}`, h('div', { class: 'sub', text: e.label })) },
    { label: 'Format', key: 'format' },
    { label: 'Status', render: (e) => h('div', {}, badge(e.status), e.id === book.current_edition_id ? h('div', { class: 'sub', text: 'Current' }) : null, e.error ? h('div', { class: 'error-text', text: e.error }) : null) },
    { label: 'Pages/chapters', key: 'page_count' },
    { label: 'Size', render: (e) => `${(Number(e.original_size) / 1048576).toFixed(2)} MB` },
    { label: 'SHA-256', render: (e) => h('span', { class: 'mono', text: `${e.original_sha256.slice(0, 16)}…` }) },
    { label: 'Uploaded', render: (e) => h('div', {}, fmtDate(e.created_at), h('div', { class: 'sub', text: e.uploaded_by_name || '' })) },
    { label: '', render: (e) => h('div', { class: 'actions' },
      e.status === 'READY' && e.id !== book.current_edition_id ? btn('Make current', () => act(() => api('POST', `/api/admin/books/${bookId}/editions/${e.id}/activate`), { ok: 'Edition is now current' })) : null,
      e.id !== book.current_edition_id && e.status !== 'ARCHIVED' ? btn('Archive', () => act(() => api('POST', `/api/admin/books/${bookId}/editions/${e.id}/archive`), { ok: 'Archived' })) : null) },
  ], editions, 'No editions uploaded yet.');
}

async function viewEditions() {
  const { books } = await api('GET', '/api/admin/books');
  const sections = [];
  for (const b of books) {
    const id = b.id;
    const d = await api('GET', `/api/admin/books/${id}`);
    const cover = buildForm([{ name: 'file', label: 'Cover image (PNG, JPEG or WebP, max 5 MB)', type: 'file', accept: 'image/png,image/jpeg,image/webp', required: true }], {}, {
      submit: 'Upload cover', columns: false,
      onSubmit: async (v) => { const fd = new FormData(); fd.append('file', v.file); await act(() => api('POST', `/api/admin/books/${id}/cover`, fd), { ok: 'Cover uploaded. Upload the book file again so it becomes the front cover.' }); },
    });
    const upload = buildForm([
      { name: 'file', label: 'Book file (PDF or EPUB)', type: 'file', accept: '.epub,.pdf,application/epub+zip,application/pdf', required: true, full: true },
      { name: 'label', label: 'Edition label', placeholder: 'e.g. Second edition' },
      { name: 'makeCurrent', label: 'Make this the edition customers read', type: 'checkbox', default: true },
    ], {}, {
      submit: 'Upload and process',
      onSubmit: async (v) => {
        const fd = new FormData(); fd.append('file', v.file); fd.append('label', v.label || ''); fd.append('makeCurrent', String(v.makeCurrent));
        toast('Uploading and processing… this can take a minute for large files.');
        await act(() => api('POST', `/api/admin/books/${id}/upload`, fd), { ok: 'Edition processed and stored securely' });
      },
    });
    sections.push(h('section', { class: 'card' },
      h('h2', { text: d.book.title }),
      h('p', { class: 'hint', text: `${d.book.author} · ${fmtMoney(d.book.price_amount, d.book.currency)}${d.book.published ? '' : ' · not published'}` }),
      editionsTable(id, d.book, d.editions)),
    h('div', { class: 'grid2' },
      h('section', { class: 'card' }, h('h2', { text: 'Upload a new edition' }),
        h('p', { class: 'hint', text: 'The file is checked, encrypted and stored privately. The cover image becomes the full-page front cover. Customers always read the current edition and keep their access when you replace it.' }),
        upload.form),
      h('section', { class: 'card' }, h('h2', { text: 'Cover' }),
        d.book.has_cover && d.book.published ? h('img', { src: `/media/covers/${id}?v=${Date.now()}`, alt: 'Current cover', class: 'cover-preview' }) : h('p', { class: 'hint', text: d.book.has_cover ? 'Cover uploaded.' : 'No cover yet.' }),
        cover.form)));
  }
  page('Book Editions', sections.length ? sections : h('div', { class: 'card' }, h('p', { text: 'No book yet. Run “npm run seed:dev” to add the book.' })));
}

// ===========================================================================
// Customers
// ===========================================================================
const CUSTOMER_STATUSES = ['PENDING_PAYMENT', 'PAID', 'INVITED', 'ACTIVATED', 'ACTIVE', 'SUSPENDED', 'REVOKED', 'EXPIRED'];

function filterBar(q, defs) {
  const form = h('form', { class: 'filters' });
  const inputs = {};
  for (const d of defs) {
    let el;
    if (d.options) { el = h('select', { 'aria-label': d.label }, h('option', { value: '', text: d.label }), d.options.map(([v, l]) => h('option', { value: v, text: l }))); }
    else el = h('input', { type: 'search', placeholder: d.label, 'aria-label': d.label });
    el.value = q.get(d.name) || '';
    if (d.options) el.addEventListener('change', () => form.requestSubmit());
    inputs[d.name] = el;
    form.append(el);
  }
  form.append(h('button', { class: 'btn btn-small', type: 'submit' }, 'Apply'));
  form.addEventListener('submit', (e) => { e.preventDefault(); setQuery({ ...Object.fromEntries(Object.entries(inputs).map(([k, el]) => [k, el.value])), page: '' }); });
  return form;
}

async function viewCustomers(q) {
  const d = await api('GET', `/api/admin/customers?${q}`);
  page('Customers',
    can('customers.manage') && can('invitations.manage') ? quickLinkBox() : null,
    can('customers.manage') ? h('p', {}, link('/admin/orders/new', 'Full order form (amount, payment details)')) : null,
    filterBar(q, [
      { name: 'q', label: 'Search name, phone or email' },
      { name: 'status', label: 'All statuses', options: CUSTOMER_STATUSES.map((s) => [s, s.replace(/_/g, ' ')]) },
      { name: 'sort', label: 'Sort: newest', options: [['name', 'Sort: name'], ['status', 'Sort: status'], ['created', 'Sort: created']] },
      { name: 'dir', label: 'Direction', options: [['asc', 'Ascending'], ['desc', 'Descending']] },
    ]),
    customersTable(d.customers),
    pager(d, (p) => setQuery({ page: p })));
}

function customersTable(rows) {
  return table([
    { label: 'Customer', render: (c) => h('div', {}, link(`/admin/customers/${c.id}`, c.full_name), h('div', { class: 'sub', text: c.email || '' })) },
    { label: 'WhatsApp', render: (c) => showPhone(c.phone_e164) || '—' },
    { label: 'Status', render: (c) => badge(c.status) },
    { label: 'Orders', key: 'orders' },
    { label: 'Active licenses', key: 'active_licenses' },
    { label: 'Registered', render: (c) => fmtDate(c.created_at) },
  ], rows, 'No customers match.');
}

function invitationsTable(rows) {
  return table([
    { label: 'Customer', render: (i) => h('div', {}, link(`/admin/customers/${i.customer_id}`, i.full_name), h('div', { class: 'sub', text: showPhone(i.phone_e164) })) },
    { label: 'Book', key: 'book_title' },
    { label: 'Link', render: (i) => h('span', { class: 'mono', text: `…/access/${i.token_hint}…` }) },
    { label: 'Status', render: (i) => badge(i.status) },
    { label: 'Expires', render: (i) => fmtDate(i.expires_at) },
    { label: 'Opened / used', render: (i) => h('div', {}, h('div', { class: 'sub', text: `opened ${fmtDate(i.opened_at)}` }), h('div', { class: 'sub', text: `used ${fmtDate(i.consumed_at)}` })) },
    { label: '', render: (i) => (can('invitations.manage') ? h('div', { class: 'actions' },
      i.status === 'PENDING' ? btn('Revoke', () => act(() => api('POST', `/api/admin/invitations/${i.id}/revoke`), { ok: 'Invitation revoked' }), 'btn btn-small btn-danger') : null,
      btn(i.status === 'CONSUMED' ? 'New link' : 'Reissue', () => generateInvite(i.license_id, i.id))) : '') },
  ], rows, 'No invitations.');
}

function devicesTable(rows) {
  return table([
    { label: 'Customer', render: (d) => link(`/admin/customers/${d.customer_id}`, d.full_name) },
    { label: 'Book(s)', render: (d) => d.books || '—' },
    { label: 'Device', render: (d) => h('div', {}, `${d.browser} on ${d.os}`, h('div', { class: 'sub', text: d.device_category })) },
    { label: 'Status', render: (d) => h('div', {}, badge(d.status), d.revoked_reason ? h('div', { class: 'sub', text: d.revoked_reason }) : null, d.transition_until ? h('div', { class: 'sub', text: `works until ${fmtDate(d.transition_until)}` }) : null) },
    { label: 'Registered', render: (d) => fmtDate(d.registered_at) },
    { label: 'App installed', render: (d) => (d.installed_at ? fmtDate(d.installed_at) : h('span', { class: 'sub', text: 'Not yet' })) },
    { label: 'Last activity', render: (d) => fmtDate(d.last_seen_at) },
    { label: 'Sessions', render: (d) => String(d.active_sessions ?? 0) },
    { label: '', render: (d) => (can('access.manage') && ['ACTIVE', 'PENDING_APPROVAL'].includes(d.status)
      ? btn('Revoke device', async () => { const v = await ask('Revoke device', 'This browser stops working immediately. The customer can register another device by signing in.', [{ name: 'reason', label: 'Reason' }], 'Revoke device', true); if (v) act(() => api('POST', `/api/admin/devices/${d.id}/revoke`, v.reason ? v : {}), { ok: 'Device revoked' }); }, 'btn btn-small btn-danger') : '') },
  ], rows, 'No devices.');
}

function licensesTable(rows) {
  const mng = can('access.manage');
  return table([
    { label: 'Customer', render: (l) => (l.full_name ? link(`/admin/customers/${l.customer_id}`, l.full_name) : '—') },
    { label: 'Book', key: 'book_title' },
    { label: 'Order', render: (l) => (l.order_reference ? link(`/admin/orders/${l.order_id}`, l.order_reference) : link(`/admin/orders/${l.order_id}`, 'Open order')) },
    { label: 'Status', render: (l) => h('div', {}, badge(l.status), l.status_reason ? h('div', { class: 'sub', text: l.status_reason }) : null) },
    { label: 'Devices', render: (l) => `${l.active_devices ?? '—'} / ${l.max_devices}` },
    { label: 'Activated', render: (l) => fmtDate(l.activated_at) },
    { label: 'Expires', render: (l) => (l.expires_at ? fmtDate(l.expires_at) : 'Never') },
    { label: '', render: (l) => h('div', { class: 'actions' },
      ['PENDING_ACTIVATION', 'ACTIVE'].includes(l.status) && can('invitations.manage') ? btn(l.status === 'ACTIVE' ? 'New link' : 'Access link', () => generateInvite(l.id), 'btn btn-small btn-primary') : null,
      mng && l.status === 'ACTIVE' ? btn('Suspend', async () => { const v = await ask('Suspend license', 'Reading stops on the next request until reactivated.', [{ name: 'reason', label: 'Reason' }], 'Suspend', true); if (v) act(() => api('POST', `/api/admin/licenses/${l.id}/suspend`, v), { ok: 'Suspended' }); }) : null,
      mng && l.status === 'SUSPENDED' ? btn('Reactivate', () => act(() => api('POST', `/api/admin/licenses/${l.id}/reactivate`), { ok: 'Reactivated' })) : null,
      mng && ['ACTIVE', 'EXPIRED', 'SUSPENDED'].includes(l.status) && l.activated_at ? btn('Renew', async () => { const v = await ask('Renew license', 'Extend access from today (or from the current expiry if later).', [{ name: 'days', label: 'Days (empty = no expiry)', type: 'number', min: 1, nullable: true }], 'Renew'); if (v) act(() => api('POST', `/api/admin/licenses/${l.id}/renew`, v), { ok: 'Renewed' }); }) : null,
      mng && l.status !== 'REVOKED' ? btn('Devices allowed', async () => { const v = await ask('Devices allowed', 'How many browsers or devices may read this purchase at the same time.', [{ name: 'maxDevices', label: 'Devices', type: 'number', min: 1, maxv: 10, default: l.max_devices, required: true }], 'Save'); if (v) act(() => api('PATCH', `/api/admin/licenses/${l.id}`, v), { ok: 'Updated' }); }) : null,
      mng && l.status !== 'REVOKED' ? btn('Revoke', async () => { const v = await ask('Revoke license', 'Access to this book ends permanently for this purchase.', [{ name: 'reason', label: 'Reason', required: true }], 'Revoke', true); if (v) act(() => api('POST', `/api/admin/licenses/${l.id}/revoke`, v), { ok: 'License revoked' }); }, 'btn btn-small btn-danger') : null) },
  ], rows, 'No licenses.');
}

async function viewCustomer(id) {
  const d = await api('GET', `/api/admin/customers/${id}`);
  const c = d.customer;
  const mng = can('access.manage');
  const edit = can('customers.manage') ? buildForm([
    { name: 'fullName', label: 'Full name', required: true }, { name: 'phone', label: 'WhatsApp number', required: true, hint: 'Changing it cancels pending invitations' },
    { name: 'email', label: 'Email (optional)', type: 'email', nullable: true }, { name: 'notes', label: 'Internal notes', type: 'textarea', full: true },
  ], { fullName: c.full_name, phone: showPhone(c.phone_e164), email: c.email, notes: c.notes }, { submit: 'Save customer', onSubmit: (v) => act(() => api('PATCH', `/api/admin/customers/${id}`, v), { ok: 'Saved' }) }).form : null;

  page(c.full_name,
    h('p', {}, link('/admin/customers', '← All customers')),
    h('section', { class: 'card' },
      h('dl', { class: 'kv' }, h('dt', { text: 'Status' }), h('dd', {}, badge(c.status)), h('dt', { text: 'WhatsApp' }), h('dd', { text: showPhone(c.phone_e164) || '—' }),
        h('dt', { text: 'Email' }), h('dd', { text: c.email || '—' }), h('dt', { text: 'Registered' }), h('dd', { text: fmtDate(c.created_at) })),
      mng ? h('div', { class: 'row-actions' },
        c.status === 'SUSPENDED'
          ? btn('Reactivate', () => act(() => api('POST', `/api/admin/customers/${id}/reactivate`), { ok: 'Reactivated' }))
          : btn('Suspend access', async () => { const v = await ask('Suspend access', 'The customer is signed out everywhere and cannot read until reactivated.', [{ name: 'reason', label: 'Reason' }], 'Suspend', true); if (v) act(() => api('POST', `/api/admin/customers/${id}/suspend`, v), { ok: 'Suspended' }); }, 'btn btn-small btn-danger'),
        btn('Sign out all sessions', () => act(() => api('POST', `/api/admin/customers/${id}/revoke-sessions`), { ok: 'Sessions ended' })),
        c.status !== 'REVOKED' ? btn('Revoke all access', async () => { const v = await ask('Revoke all access', 'All licenses are revoked permanently. This cannot be undone; a new order would be needed.', [{ name: 'reason', label: 'Reason', required: true }], 'Revoke access', true); if (v) act(() => api('POST', `/api/admin/customers/${id}/revoke-access`, v), { ok: 'Access revoked' }); }, 'btn btn-small btn-danger') : null) : null),
    edit ? h('section', { class: 'card' }, h('h2', { text: 'Edit customer' }), edit) : null,
    h('section', { class: 'card' }, h('h2', { text: 'Licenses' }), licensesTable(d.licenses.map((l) => ({ ...l, full_name: c.full_name, customer_id: id })))),
    h('section', { class: 'card' }, h('h2', { text: 'Orders' }), table([
      { label: 'Order', render: (o) => link(`/admin/orders/${o.id}`, o.reference) },
      { label: 'Books', render: (o) => (o.books || []).map((b) => b.title).join(', ') },
      { label: 'Amount', render: (o) => fmtMoney(o.total_amount, o.currency) },
      { label: 'Status', render: (o) => badge(o.status) }, { label: 'Created', render: (o) => fmtDate(o.created_at) },
    ], d.orders, 'No orders.')),
    h('section', { class: 'card' }, h('h2', { text: 'Invitations' }), invitationsTable(d.invitations.map((i) => ({ ...i, full_name: c.full_name, customer_id: id })))),
    h('section', { class: 'card' }, h('h2', { text: 'Devices' }), devicesTable(d.devices.map((x) => ({ ...x, full_name: c.full_name, customer_id: id })))),
    h('div', { class: 'grid2' },
      h('section', { class: 'card' }, h('h2', { text: 'Access history' }), table([
        { label: 'Activity', render: (e) => e.event_type.replace(/_/g, ' ').toLowerCase() }, { label: 'Book', key: 'book' }, { label: 'When', render: (e) => fmtDate(e.created_at) }], d.activity, 'No activity yet.')),
      h('section', { class: 'card' }, h('h2', { text: 'Security events' }), table([
        { label: 'Event', render: (e) => e.event_type.replace(/_/g, ' ') }, { label: 'Severity', render: (e) => badge(e.severity) },
        { label: 'When', render: (e) => fmtDate(e.created_at) }, { label: 'Resolved', render: (e) => (e.resolved_at ? fmtDate(e.resolved_at) : badge('PENDING')) }], d.security, 'No security events.'))));
}

// ===========================================================================
// Orders and payments
// ===========================================================================
/** Name in, link out: the usual way to add a customer. */
function quickLinkBox() {
  const name = h('input', { type: 'text', name: 'fullName', placeholder: 'Customer name', required: true, maxlength: 200, autocomplete: 'off', 'aria-label': 'Customer name' });
  const phone = h('input', { type: 'tel', name: 'phone', placeholder: 'WhatsApp number (optional)', maxlength: 32, autocomplete: 'off', 'aria-label': 'WhatsApp number' });
  const submit = h('button', { class: 'btn btn-primary', type: 'submit' }, 'Generate link');
  const out = h('div', { class: 'quick-out' });
  const form = h('form', { class: 'quick' }, name, phone, submit);
  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    submit.disabled = true;
    try {
      const r = await api('POST', '/api/admin/quick-link', { fullName: name.value.trim(), phone: phone.value.trim() || undefined });
      const copy = async (text, label) => { try { await navigator.clipboard.writeText(text); toast(`${label} copied`); } catch { toast('Copy failed, select and copy manually', true); } };
      const linkEl = h('input', { type: 'text', readonly: true, value: r.link, 'aria-label': 'Private link' });
      out.replaceChildren(h('div', { class: 'card quick-result' },
        h('p', {}, h('strong', { text: name.value.trim() }), ' is added. Send this private link on WhatsApp:'),
        h('div', { class: 'row-actions' }, linkEl, btn('Copy link', () => copy(r.link, 'Link'), 'btn btn-primary btn-small'), btn('Copy message', () => copy(r.message, 'Message'), 'btn btn-small')),
        h('p', { class: 'hint', text: 'The link works once: it is used up when the book is added to their phone. ' + (r.invitation?.expires_at ? `Valid until ${fmtDate(r.invitation.expires_at)}.` : '') })));
      linkEl.select();
      name.value = ''; phone.value = '';
      // Show the new customer in the list below without losing the link box.
      const fresh = await api('GET', `/api/admin/customers${location.search || '?'}`);
      document.querySelector('.content table')?.replaceWith(customersTable(fresh.customers));
    } catch (err) { toast(err.message, true); } finally { submit.disabled = false; }
  });
  return h('section', { class: 'card' }, h('h2', { text: 'Add a customer and get their link' }), form, out);
}

async function viewNewOrder() {
  const { books } = await api('GET', '/api/admin/books-options');
  const fields = [
    { name: 'fullName', label: 'Customer full name', required: true, max: 200 },
    { name: 'phone', label: 'WhatsApp number', required: true, placeholder: '+255712345678', hint: 'International format. An existing customer with this number is reused.' },
    { name: 'email', label: 'Email (optional)', type: 'email' },
    { name: 'bookIds', label: 'Book(s)', type: 'multiselect', required: true, options: books.map((b) => [b.id, `${b.title} — ${fmtMoney(b.price_amount, b.currency)}`]), default: books.length === 1 ? [books[0].id] : [] },
    { name: 'reference', label: 'Order reference', placeholder: 'Leave empty to generate' },
    { name: 'amount', label: 'Payment amount', required: true, default: books[0]?.price_amount || '' },
    { name: 'currency', label: 'Currency', default: books[0]?.currency || 'TZS' },
    { name: 'paymentMethod', label: 'Payment method', required: true, placeholder: 'e.g. M-Pesa, Tigo Pesa, Airtel Money, bank' },
    { name: 'paymentReference', label: 'Payment reference', placeholder: 'e.g. M-PESA code' },
    can('payments.verify') ? { name: 'paymentStatus', label: 'Payment verification status', type: 'select', options: [['PENDING', 'Pending — verify later'], ['VERIFIED', 'Verified — I have confirmed this payment']] } : null,
    { name: 'notes', label: 'Internal notes', type: 'textarea', full: true },
  ].filter(Boolean);
  const { form } = buildForm(fields, {}, {
    submit: 'Register order',
    onSubmit: async (v) => {
      if (!v.bookIds.length) throw new Error('Select at least one book');
      if (v.paymentStatus === 'VERIFIED' && !v.paymentReference) throw new Error('Enter the payment reference you verified');
      const body = Object.fromEntries(Object.entries(v).filter(([, x]) => x !== '' && x !== undefined));
      const r = await api('POST', '/api/admin/orders', { ...body, currency: (v.currency || '').toUpperCase() || undefined });
      toast(r.licenses.length ? 'Order registered and payment verified' : 'Order registered — payment pending verification');
      go(`/admin/orders/${r.orderId}`);
    },
  });
  page('Register customer and order', h('p', {}, link('/admin/customers', '← Customers')), h('section', { class: 'card' }, form));
}

async function viewOrder(id) {
  const d = await api('GET', `/api/admin/orders/${id}`);
  const o = d.order;
  const pending = d.payments.find((p) => p.status === 'PENDING');
  let verifyBox = null;
  if (o.status === 'PENDING_PAYMENT' && can('payments.verify') && pending) {
    const vf = buildForm([{ name: 'reference', label: 'Payment reference (confirm or correct)', required: true }], { reference: pending.reference }, {
      submit: 'Mark payment as verified', columns: false,
      onSubmit: (v) => act(() => api('POST', `/api/admin/orders/${id}/verify-payment`, v), { ok: 'Payment verified. You can now generate the access link.' }),
    });
    verifyBox = h('section', { class: 'card' }, h('h2', { text: 'Verify payment' }),
      h('p', { class: 'hint', text: `Check that ${fmtMoney(pending.amount, pending.currency)} via ${pending.method} arrived before verifying. Only verified orders can receive reading access.` }),
      vf.form,
      h('div', { class: 'row-actions' }, btn('Reject payment', async () => {
        const v = await ask('Reject payment', 'The order is marked rejected and no access can be issued.', [{ name: 'reason', label: 'Reason', required: true }], 'Reject payment', true);
        if (v) act(() => api('POST', `/api/admin/orders/${id}/reject-payment`, v), { ok: 'Payment rejected' });
      }, 'btn btn-small btn-danger')));
  }
  page(`Order ${o.reference}`,
    h('p', {}, link('/admin/customers', '← Customers')),
    h('section', { class: 'card' }, h('dl', { class: 'kv' },
      h('dt', { text: 'Status' }), h('dd', {}, badge(o.status)),
      h('dt', { text: 'Customer' }), h('dd', {}, link(`/admin/customers/${o.customer_id}`, o.full_name), showPhone(o.phone_e164) ? ` · ${o.phone_e164}` : ''),
      h('dt', { text: 'Books' }), h('dd', { text: d.items.map((i) => i.title).join(', ') }),
      h('dt', { text: 'Total' }), h('dd', { text: fmtMoney(o.total_amount, o.currency) }),
      h('dt', { text: 'Notes' }), h('dd', { text: o.notes || '—' }))),
    verifyBox,
    h('section', { class: 'card' }, h('h2', { text: 'Payments' }), table([
      { label: 'Amount', render: (p) => fmtMoney(p.amount, p.currency) }, { label: 'Method', key: 'method' }, { label: 'Reference', key: 'reference' },
      { label: 'Status', render: (p) => h('div', {}, badge(p.status), p.rejection_reason ? h('div', { class: 'sub', text: p.rejection_reason }) : null) },
      { label: 'Decided by', render: (p) => (p.verified_at ? `${p.verified_by_name || ''} · ${fmtDate(p.verified_at)}` : '—') },
    ], d.payments)),
    h('section', { class: 'card' }, h('h2', { text: 'Reading access' }),
      o.status !== 'PAID' ? h('p', { class: 'hint', text: 'Access links can be generated after the payment is verified.' }) : null,
      table([
        { label: 'Book', key: 'title' }, { label: 'License', render: (l) => badge(l.status) },
        { label: 'Latest invitation', render: (l) => (l.latest_invitation ? h('div', {}, badge(l.latest_invitation.status), h('div', { class: 'sub', text: `expires ${fmtDate(l.latest_invitation.expires_at)}` })) : '—') },
        { label: '', render: (l) => (['PENDING_ACTIVATION', 'ACTIVE'].includes(l.status) && can('invitations.manage')
          ? btn(l.status === 'ACTIVE' ? 'New link (new phone)' : l.latest_invitation?.status === 'PENDING' ? 'Generate new access link' : 'Generate Access Link', () => generateInvite(l.id), 'btn btn-small btn-primary') : '') },
      ], d.licenses, 'No licenses yet.')),
    h('section', { class: 'card' }, h('h2', { text: 'Verification audit trail' }), table([
      { label: 'Action', key: 'action' }, { label: 'By', key: 'admin' }, { label: 'When', render: (a) => fmtDate(a.created_at) },
      { label: 'Details', render: (a) => h('pre', { class: 'details', text: JSON.stringify(a.details, null, 1) }) }], d.auditTrail)));
}

async function generateInvite(licenseId, invitationId) {
  const v = await ask(invitationId ? 'New access link' : 'Generate access link',
    'A new private link is created. It opens only once, on the device the customer reads on. Any earlier unused link stops working. If the book is already on another device, opening this link moves it to the new device.',
    [{ name: 'expiryHours', label: 'Link valid for (hours)', type: 'number', min: 1, maxv: 720, default: 24 }], 'Generate link');
  if (!v) return;
  const r = await act(() => (invitationId
    ? api('POST', `/api/admin/invitations/${invitationId}/resend`, { expiryHours: v.expiryHours })
    : api('POST', '/api/admin/invitations', { licenseId, expiryHours: v.expiryHours })), { reload: false });
  if (!r) return;
  const copy = async (text, label) => { try { await navigator.clipboard.writeText(text); toast(`${label} copied`); } catch { toast('Copy failed — select and copy manually', true); } };
  modal('Private access link', h('div', {},
    h('p', { class: 'hint', text: 'This link is shown only once. Send it to the customer now. It opens only once: the customer should open it on the phone or computer they will read on.' }),
    h('div', { class: 'label', text: 'Link' }), h('div', { class: 'copybox mono', text: r.link }),
    h('div', { class: 'label', text: 'WhatsApp message' }), h('div', { class: 'copybox', text: r.message }),
    h('div', { class: 'row-actions' },
      btn('Copy link', () => copy(r.link, 'Link')),
      btn('Copy message', () => copy(r.message, 'Message')),
      h('a', { class: 'btn btn-small btn-primary', href: r.whatsappUrl, target: '_blank', rel: 'noopener noreferrer' }, 'Send via WhatsApp'))));
  route();
}

// ===========================================================================
// Invitations, devices, licenses
// ===========================================================================
// ===========================================================================
// Monitoring
// ===========================================================================
const EVENT_TYPES = ['INVITATION_OPENED', 'OTP_REQUESTED', 'OTP_VERIFIED', 'DEVICE_REGISTERED', 'LICENSE_ACTIVATED', 'READER_OPENED', 'CHAPTER_ACCESSED', 'READING_SESSION_ENDED', 'ACCESS_DENIED', 'SESSION_EXPIRED', 'DEVICE_REPLACED', 'ACCOUNT_SUSPENDED', 'LICENSE_REVOKED'];

// ===========================================================================
// Website content and WhatsApp
// ===========================================================================
// ===========================================================================
// Administrators, settings, account
// ===========================================================================
const SETTING_LABELS = {
  invitation_expiry_hours: ['Default link validity (hours)', 'How long a new private link can be used before the book is added. Can be changed per link'],
  session_ttl_hours: ['Reading session length (hours)', 'Customers confirm their number again after this'],
  session_idle_minutes: ['Sign out after inactivity (minutes)'],
  default_max_devices: ['Default devices per purchase'],
  default_license_duration_days: ['Default license duration (days)', 'Empty = no expiry'],
  content_requests_per_minute: ['Reader requests allowed per minute', 'Above this, requests are blocked and flagged'],
  require_app_install: ['Reading only in the installed app', 'Customers must add the reader to their device before reading; the download page expires once installed'],
};

function viewAccount() {
  const mfaBox = h('div');
  if (me.mfaEnabled) mfaBox.append(h('p', {}, badge('ACTIVE'), ' Two-factor authentication is on.'));
  else {
    mfaBox.append(h('p', { class: 'hint', text: 'Protect your account with an authenticator app (Google Authenticator, Microsoft Authenticator, 1Password…).' }),
      btn('Set up two-factor authentication', async () => {
        const r = await act(() => api('POST', '/api/admin/auth/mfa/setup'), { reload: false });
        if (!r) return;
        const f = buildForm([{ name: 'code', label: 'Code from the app', required: true, autocomplete: 'one-time-code' }], {}, {
          submit: 'Turn on', columns: false,
          onSubmit: async (v) => { await api('POST', '/api/admin/auth/mfa/enable', v); toast('Two-factor authentication is on'); me.mfaEnabled = true; me.mfaRequiredButMissing = false; route(); },
        });
        mfaBox.replaceChildren(
          h('p', { text: 'Add this key in your authenticator app (choose “enter a setup key”, time-based):' }),
          h('div', { class: 'copybox mono', text: r.secret.replace(/(.{4})/g, '$1 ').trim() }),
          h('p', { class: 'hint', text: 'Or paste this setup URI into an app that accepts it:' }), h('div', { class: 'copybox mono', text: r.uri }), f.form);
      }, 'btn btn-primary'));
  }
  const pw = buildForm([
    { name: 'current', label: 'Current password', type: 'password', required: true, autocomplete: 'current-password' },
    { name: 'next', label: 'New password (12+ characters)', type: 'password', required: true, autocomplete: 'new-password' },
  ], {}, { submit: 'Change password', onSubmit: (v) => act(() => api('POST', '/api/admin/auth/password', v), { ok: 'Password changed. Other sessions were signed out.' }) });
  page('My Account',
    h('section', { class: 'card' }, h('dl', { class: 'kv' }, h('dt', { text: 'Name' }), h('dd', { text: me.name }), h('dt', { text: 'Email' }), h('dd', { text: me.email }), h('dt', { text: 'Role' }), h('dd', { text: me.role }))),
    h('section', { class: 'card' }, h('h2', { text: 'Two-factor authentication' }), mfaBox),
    h('section', { class: 'card' }, h('h2', { text: 'Password' }), pw.form));
}

boot();

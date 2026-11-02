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
const fmtMoney = (a, c) => { try { return new Intl.NumberFormat(undefined, { style: 'currency', currency: c }).format(Number(a)); } catch { return `${c} ${a}`; } };
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
    h('div', { class: 'card' }, h('div', { class: 'topbar' }, h('h2', { text: title }), btn('Close', close)), body));
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
// Shell, navigation, routing
// ===========================================================================
const NAV = [
  ['Sales', [['/admin', 'Overview', 'dashboard.view'], ['/admin/orders', 'Orders', 'customers.view'], ['/admin/payments', 'Payment Verification', 'payments.verify'], ['/admin/customers', 'Customers', 'customers.view']]],
  ['Access', [['/admin/invitations', 'Access Invitations', 'customers.view'], ['/admin/devices', 'Registered Devices', 'customers.view'], ['/admin/licenses', 'Reading Licenses', 'customers.view']]],
  ['Books', [['/admin/books', 'Books', 'books.manage'], ['/admin/editions', 'Book Editions', 'books.manage']]],
  ['Monitoring', [['/admin/activity', 'Reading Activity', 'security.view'], ['/admin/security', 'Security Events', 'security.view'], ['/admin/audit', 'Audit Logs', 'audit.view']]],
  ['Website', [['/admin/website', 'Marketing Website Content', 'content.manage'], ['/admin/whatsapp', 'WhatsApp Settings', 'content.manage']]],
  ['System', [['/admin/admins', 'Administrators', 'admins.manage'], ['/admin/settings', 'System Settings', 'settings.manage'], ['/admin/account', 'My Account', null]]],
];

function go(path) { history.pushState({}, '', path); route(); }
addEventListener('popstate', () => route());
document.addEventListener('click', (e) => {
  const a = e.target.closest('a[data-nav]');
  if (a && !e.metaKey && !e.ctrlKey) { e.preventDefault(); document.querySelector('.side')?.classList.remove('open'); go(a.getAttribute('href')); }
});

let mainEl = null;
function shell() {
  const side = h('aside', { class: 'side' },
    h('div', { class: 'brand' }, 'Book Management', btn('Menu', () => side.classList.toggle('open'), 'menu-btn')),
    h('nav', { 'aria-label': 'Dashboard' }, NAV.map(([grp, items]) => {
      const visible = items.filter(([, , p]) => !p || can(p));
      return visible.length ? [h('div', { class: 'grp', text: grp }), visible.map(([href, label]) => h('a', { href, 'data-nav': true, text: label }))] : [];
    })));
  mainEl = h('main', { class: 'main', id: 'main' });
  root.replaceChildren(h('div', { class: 'shell' }, side, mainEl));
}

function page(title, ...content) {
  document.title = `${title} · Book Management`;
  for (const a of document.querySelectorAll('.side nav a')) {
    const href = a.getAttribute('href');
    const active = href === '/admin' ? location.pathname === '/admin' : location.pathname.startsWith(href);
    if (active) a.setAttribute('aria-current', 'page'); else a.removeAttribute('aria-current');
  }
  mainEl.replaceChildren(
    h('div', { class: 'topbar' }, h('h1', { text: title }),
      h('div', { class: 'who' }, h('span', { text: `${me.name} · ${me.role}` }), btn('Sign out', logout))),
    me.mfaRequiredButMissing ? h('div', { class: 'warnbar' }, 'Two-factor authentication is required. ', link('/admin/account', 'Set it up now.')) : null,
    ...content.flat(Infinity).filter((c) => c !== null && c !== undefined && c !== false));
}

async function route() {
  if (!me) return boot();
  if (!mainEl || !document.body.contains(mainEl)) shell();
  const p = location.pathname.replace(/\/$/, '') || '/admin';
  const q = new URLSearchParams(location.search);
  const m = (re) => p.match(re);
  let r;
  try {
    if (p === '/admin') return await viewOverview();
    if (p === '/admin/books') return await viewBooks();
    if ((r = m(/^\/admin\/books\/([0-9a-f-]{36})$/))) return await viewBook(r[1]);
    if (p === '/admin/editions') return await viewEditions();
    if (p === '/admin/customers') return await viewCustomers(q);
    if ((r = m(/^\/admin\/customers\/([0-9a-f-]{36})$/))) return await viewCustomer(r[1]);
    if (p === '/admin/orders') return await viewOrders(q);
    if (p === '/admin/orders/new') return await viewNewOrder();
    if ((r = m(/^\/admin\/orders\/([0-9a-f-]{36})$/))) return await viewOrder(r[1]);
    if (p === '/admin/payments') return await viewOrders(new URLSearchParams({ status: 'PENDING_PAYMENT', ...Object.fromEntries(q) }), 'Payment Verification');
    if (p === '/admin/invitations') return await viewInvitations(q);
    if (p === '/admin/devices') return await viewDevices(q);
    if (p === '/admin/licenses') return await viewLicenses(q);
    if (p === '/admin/activity') return await viewActivity(q);
    if (p === '/admin/security') return await viewSecurity(q);
    if (p === '/admin/audit') return await viewAudit(q);
    if (p === '/admin/website') return await viewWebsite();
    if (p === '/admin/whatsapp') return await viewWhatsapp();
    if (p === '/admin/admins') return await viewAdmins();
    if (p === '/admin/settings') return await viewSettings();
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
  root.replaceChildren(h('main', { class: 'login' }, h('div', { class: 'card' }, h('h1', { text: 'Book Management' }), h('p', { class: 'hint', text: 'Sign in to manage books, customers and access.' }), form)));
  root.querySelector('input').focus();
}

function renderMfa() {
  const { form } = buildForm([{ name: 'code', label: 'Authentication code', required: true, autocomplete: 'one-time-code', placeholder: '6 digits' }], {}, {
    submit: 'Verify', columns: false,
    onSubmit: async (v) => { const r = await api('POST', '/api/admin/auth/mfa', v); csrf = r.csrf; return boot(); },
  });
  root.replaceChildren(h('main', { class: 'login' }, h('div', { class: 'card' }, h('h1', { text: 'Two-factor authentication' }), h('p', { class: 'hint', text: 'Enter the code from your authenticator app.' }), form)));
  root.querySelector('input').focus();
}

async function logout() {
  await api('POST', '/api/admin/auth/logout').catch(() => {});
  me = null; csrf = null; history.pushState({}, '', '/admin'); renderLogin();
}

// ===========================================================================
// Overview
// ===========================================================================
async function viewOverview() {
  const d = await api('GET', '/api/admin/overview');
  const m = d.metrics;
  const tiles = [
    ['Total books', m.total_books], ['Total orders', m.total_orders], ['Verified payments', m.verified_payments], ['Pending payments', m.pending_payments, '/admin/payments'],
    ['Registered customers', m.registered_customers], ['Active invitations', m.active_invitations], ['Activated customers', m.activated_customers],
    ['Active reading licenses', m.active_licenses], ['Suspended accounts', m.suspended_accounts], ['Revoked access', m.revoked_access], ['Open security events', m.open_security_events, '/admin/security?open=true'],
  ];
  page('Overview',
    h('div', { class: 'metrics' }, tiles.map(([k, v, href]) => h('div', { class: 'metric' }, h('div', { class: 'v', text: String(v) }), href ? link(href, k) : h('div', { class: 'k', text: k })))),
    h('div', { class: 'grid2' },
      h('section', { class: 'card' }, h('h2', { text: 'Recent security events' }),
        table([{ label: 'Event', render: (r) => r.event_type.replace(/_/g, ' ') }, { label: 'Severity', render: (r) => badge(r.severity) }, { label: 'Customer', key: 'customer' }, { label: 'When', render: (r) => fmtDate(r.created_at) }], d.recentSecurity, 'No security events.'),
        h('p', {}, link('/admin/security', 'All security events'))),
      h('section', { class: 'card' }, h('h2', { text: 'Recent customer activity' }),
        table([{ label: 'Activity', render: (r) => r.event_type.replace(/_/g, ' ').toLowerCase() }, { label: 'Customer', key: 'customer' }, { label: 'Book', key: 'book' }, { label: 'When', render: (r) => fmtDate(r.created_at) }], d.recentActivity, 'No activity yet.'),
        h('p', {}, link('/admin/activity', 'All reading activity')))),
    can('customers.manage') ? h('p', {}, link('/admin/orders/new', '+ Register a customer and order')) : null);
}

// ===========================================================================
// Books and editions
// ===========================================================================
const bookFields = (currency = 'KES') => [
  { name: 'title', label: 'Title', required: true, max: 300 },
  { name: 'subtitle', label: 'Subtitle', max: 300 },
  { name: 'author', label: 'Author', required: true, max: 200 },
  { name: 'priceAmount', label: 'Price', required: true, placeholder: '1500', hint: 'Numbers only, e.g. 1500 or 1500.00' },
  { name: 'currency', label: 'Currency', required: true, default: currency, max: 3, hint: 'ISO code, e.g. KES, USD' },
  { name: 'availability', label: 'Availability', type: 'select', options: [['AVAILABLE', 'Available'], ['COMING_SOON', 'Coming soon'], ['UNAVAILABLE', 'Unavailable']] },
  { name: 'preferredFormat', label: 'Preferred reading format', type: 'select', options: [['EPUB', 'EPUB (reflowable text)'], ['PDF', 'PDF (page images)']] },
  { name: 'maxDevices', label: 'Devices per purchase', type: 'number', min: 1, maxv: 10, default: 1, hint: 'Applies to new licenses' },
  { name: 'licenseDurationDays', label: 'License duration (days)', type: 'number', min: 1, nullable: true, hint: 'Leave empty for no expiry' },
  { name: 'description', label: 'Description', type: 'textarea', full: true, rows: 6, max: 10000 },
];

async function viewBooks() {
  const { books } = await api('GET', '/api/admin/books');
  page('Books',
    h('section', { class: 'card' }, h('h2', { text: 'Create a book' }), buildForm(bookFields(), {}, {
      submit: 'Create book',
      onSubmit: async (v) => { const r = await api('POST', '/api/admin/books', { ...v, currency: v.currency.toUpperCase() }); toast('Book created'); go(`/admin/books/${r.book.id}`); },
    }).form),
    table([
      { label: 'Book', render: (b) => h('div', {}, link(`/admin/books/${b.id}`, b.title), h('div', { class: 'sub', text: b.author })) },
      { label: 'Price', render: (b) => fmtMoney(b.price_amount, b.currency) },
      { label: 'Published', render: (b) => badge(b.published ? 'ACTIVE' : 'PENDING') },
      { label: 'Current edition', render: (b) => (b.current_version ? h('span', {}, `v${b.current_version} ${b.current_format} `, badge(b.current_status)) : badge('PENDING')) },
      { label: 'Active readers', key: 'active_licenses' },
    ], books, 'No books yet. Create one above.'));
}

async function viewBook(id) {
  const { book, editions } = await api('GET', `/api/admin/books/${id}`);
  const edit = buildForm(bookFields(book.currency), {
    title: book.title, subtitle: book.subtitle, author: book.author, priceAmount: book.price_amount, currency: book.currency, availability: book.availability,
    preferredFormat: book.preferred_format, maxDevices: book.max_devices, licenseDurationDays: book.license_duration_days, description: book.description,
  }, { submit: 'Save changes', onSubmit: (v) => act(() => api('PATCH', `/api/admin/books/${id}`, { ...v, currency: v.currency.toUpperCase() }), { ok: 'Saved' }) });

  const cover = buildForm([{ name: 'file', label: 'Cover image (PNG, JPEG or WebP, max 5 MB)', type: 'file', accept: 'image/png,image/jpeg,image/webp', required: true }], {}, {
    submit: 'Upload cover', columns: false,
    onSubmit: async (v) => { const fd = new FormData(); fd.append('file', v.file); await act(() => api('POST', `/api/admin/books/${id}/cover`, fd), { ok: 'Cover uploaded' }); },
  });
  const upload = buildForm([
    { name: 'file', label: 'Book file (EPUB or PDF)', type: 'file', accept: '.epub,.pdf,application/epub+zip,application/pdf', required: true, full: true },
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

  page(book.title,
    h('p', {}, link('/admin/books', '← All books'), '  ', book.published ? link('/', 'View on website') : null),
    h('div', { class: 'row-actions' },
      book.published
        ? btn('Unpublish', () => act(() => api('POST', `/api/admin/books/${id}/unpublish`), { ok: 'Unpublished' }), 'btn btn-small btn-danger')
        : btn('Publish', () => act(() => api('POST', `/api/admin/books/${id}/publish`), { ok: 'Published' }), 'btn btn-small btn-primary'),
      badge(book.published ? 'ACTIVE' : 'PENDING')),
    h('div', { class: 'grid2' },
      h('section', { class: 'card' }, h('h2', { text: 'Details' }), edit.form),
      h('div', {},
        h('section', { class: 'card' }, h('h2', { text: 'Cover' }),
          book.has_cover && book.published ? h('img', { src: `/media/covers/${id}?v=${Date.now()}`, alt: 'Current cover' }) : h('p', { class: 'hint', text: book.has_cover ? 'Cover uploaded (visible publicly once published).' : 'No cover yet.' }),
          cover.form),
        h('section', { class: 'card' }, h('h2', { text: 'Upload a new edition' }),
          h('p', { class: 'hint', text: 'Files are checked by content type, scanned for malware when a scanner is configured, encrypted, and stored privately. Existing customers keep their access when you replace an edition.' }),
          upload.form))),
    h('section', { class: 'card', id: 'editions' }, h('h2', { text: 'Editions' }), editionsTable(id, book, editions)));
}

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
    const d = await api('GET', `/api/admin/books/${b.id}`);
    sections.push(h('section', { class: 'card' }, h('h2', {}, link(`/admin/books/${b.id}`, b.title)), editionsTable(b.id, d.book, d.editions)));
  }
  page('Book Editions', h('p', { class: 'hint', text: 'Upload new editions from each book page. Customers always read the current edition; their access is tied to the book, not to an edition.' }),
    sections.length ? sections : h('p', { text: 'No books yet.' }));
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
    can('customers.manage') ? h('p', {}, link('/admin/orders/new', '+ Register a customer and order')) : null,
    filterBar(q, [
      { name: 'q', label: 'Search name, phone or email' },
      { name: 'status', label: 'All statuses', options: CUSTOMER_STATUSES.map((s) => [s, s.replace(/_/g, ' ')]) },
      { name: 'sort', label: 'Sort: newest', options: [['name', 'Sort: name'], ['status', 'Sort: status'], ['created', 'Sort: created']] },
      { name: 'dir', label: 'Direction', options: [['asc', 'Ascending'], ['desc', 'Descending']] },
    ]),
    table([
      { label: 'Customer', render: (c) => h('div', {}, link(`/admin/customers/${c.id}`, c.full_name), h('div', { class: 'sub', text: c.email || '' })) },
      { label: 'WhatsApp', key: 'phone_e164' },
      { label: 'Status', render: (c) => badge(c.status) },
      { label: 'Orders', key: 'orders' },
      { label: 'Active licenses', key: 'active_licenses' },
      { label: 'Registered', render: (c) => fmtDate(c.created_at) },
    ], d.customers, 'No customers match.'),
    pager(d, (p) => setQuery({ page: p })));
}

async function viewCustomer(id) {
  const d = await api('GET', `/api/admin/customers/${id}`);
  const c = d.customer;
  const mng = can('access.manage');
  const edit = can('customers.manage') ? buildForm([
    { name: 'fullName', label: 'Full name', required: true }, { name: 'phone', label: 'WhatsApp number', required: true, hint: 'Changing it cancels pending invitations' },
    { name: 'email', label: 'Email (optional)', type: 'email', nullable: true }, { name: 'notes', label: 'Internal notes', type: 'textarea', full: true },
  ], { fullName: c.full_name, phone: c.phone_e164, email: c.email, notes: c.notes }, { submit: 'Save customer', onSubmit: (v) => act(() => api('PATCH', `/api/admin/customers/${id}`, v), { ok: 'Saved' }) }).form : null;

  page(c.full_name,
    h('p', {}, link('/admin/customers', '← All customers')),
    h('section', { class: 'card' },
      h('dl', { class: 'kv' }, h('dt', { text: 'Status' }), h('dd', {}, badge(c.status)), h('dt', { text: 'WhatsApp' }), h('dd', { text: c.phone_e164 }),
        h('dt', { text: 'Email' }), h('dd', { text: c.email || '—' }), h('dt', { text: 'Registered' }), h('dd', { text: fmtDate(c.created_at) })),
      mng ? h('div', { class: 'row-actions' },
        c.status === 'SUSPENDED'
          ? btn('Reactivate', () => act(() => api('POST', `/api/admin/customers/${id}/reactivate`), { ok: 'Reactivated' }))
          : btn('Suspend access', async () => { const v = await ask('Suspend access', 'The customer is signed out everywhere and cannot read until reactivated.', [{ name: 'reason', label: 'Reason' }], 'Suspend', true); if (v) act(() => api('POST', `/api/admin/customers/${id}/suspend`, v), { ok: 'Suspended' }); }, 'btn btn-small btn-danger'),
        btn('Sign out all sessions', () => act(() => api('POST', `/api/admin/customers/${id}/revoke-sessions`), { ok: 'Sessions ended' })),
        c.status !== 'REVOKED' ? btn('Revoke all access', async () => { const v = await ask('Revoke all access', 'All licenses are revoked permanently. This cannot be undone; a new order would be needed.', [{ name: 'reason', label: 'Reason', required: true }], 'Revoke access', true); if (v) act(() => api('POST', `/api/admin/customers/${id}/revoke-access`, v), { ok: 'Access revoked' }); }, 'btn btn-small btn-danger') : null) : null),
    edit ? h('section', { class: 'card' }, h('h2', { text: 'Edit customer' }), edit) : null,
    h('section', { class: 'card' }, h('h2', { text: 'Licenses' }), licensesTable(d.licenses)),
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
async function viewOrders(q, title = 'Orders') {
  const d = await api('GET', `/api/admin/orders?${q}`);
  page(title,
    can('customers.manage') ? h('p', {}, link('/admin/orders/new', '+ Register a customer and order')) : null,
    title === 'Payment Verification' ? h('p', { class: 'hint', text: 'Orders waiting for you to confirm the payment. Open an order to check the reference and verify or reject it.' }) : null,
    filterBar(q, [{ name: 'q', label: 'Search reference, name or phone' }, { name: 'status', label: 'All statuses', options: [['PENDING_PAYMENT', 'Pending payment'], ['PAID', 'Paid'], ['REJECTED', 'Rejected'], ['CANCELLED', 'Cancelled']] }]),
    table([
      { label: 'Order', render: (o) => h('div', {}, link(`/admin/orders/${o.id}`, o.reference), h('div', { class: 'sub', text: fmtDate(o.created_at) })) },
      { label: 'Customer', render: (o) => h('div', {}, link(`/admin/customers/${o.customer_id}`, o.full_name), h('div', { class: 'sub', text: o.phone_e164 })) },
      { label: 'Books', key: 'books' }, { label: 'Amount', render: (o) => fmtMoney(o.total_amount, o.currency) },
      { label: 'Payment', key: 'payment' }, { label: 'Status', render: (o) => badge(o.status) },
      { label: '', render: (o) => (o.status === 'PENDING_PAYMENT' && can('payments.verify') ? link(`/admin/orders/${o.id}`, 'Verify →') : '') },
    ], d.orders, 'No orders.'),
    pager(d, (p) => setQuery({ page: p })));
}

async function viewNewOrder() {
  const { books } = await api('GET', '/api/admin/books-options');
  const fields = [
    { name: 'fullName', label: 'Customer full name', required: true, max: 200 },
    { name: 'phone', label: 'WhatsApp number', required: true, placeholder: '+254712345678', hint: 'International format. An existing customer with this number is reused.' },
    { name: 'email', label: 'Email (optional)', type: 'email' },
    { name: 'bookIds', label: 'Book(s)', type: 'multiselect', required: true, options: books.map((b) => [b.id, `${b.title} — ${fmtMoney(b.price_amount, b.currency)}`]), default: books.length === 1 ? [books[0].id] : [] },
    { name: 'reference', label: 'Order reference', placeholder: 'Leave empty to generate' },
    { name: 'amount', label: 'Payment amount', required: true, default: books[0]?.price_amount || '' },
    { name: 'currency', label: 'Currency', default: books[0]?.currency || 'KES' },
    { name: 'paymentMethod', label: 'Payment method', required: true, placeholder: 'e.g. M-PESA, bank transfer' },
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
  page('Register customer and order', h('p', {}, link('/admin/orders', '← Orders')), h('section', { class: 'card' }, form));
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
    h('p', {}, link('/admin/orders', '← Orders')),
    h('section', { class: 'card' }, h('dl', { class: 'kv' },
      h('dt', { text: 'Status' }), h('dd', {}, badge(o.status)),
      h('dt', { text: 'Customer' }), h('dd', {}, link(`/admin/customers/${o.customer_id}`, o.full_name), ` · ${o.phone_e164}`),
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
        { label: '', render: (l) => (l.status === 'PENDING_ACTIVATION' && can('invitations.manage') ? btn(l.latest_invitation?.status === 'PENDING' ? 'Generate new access link' : 'Generate Access Link', () => generateInvite(l.id), 'btn btn-small btn-primary') : '') },
      ], d.licenses, 'No licenses yet.')),
    h('section', { class: 'card' }, h('h2', { text: 'Verification audit trail' }), table([
      { label: 'Action', key: 'action' }, { label: 'By', key: 'admin' }, { label: 'When', render: (a) => fmtDate(a.created_at) },
      { label: 'Details', render: (a) => h('pre', { class: 'details', text: JSON.stringify(a.details, null, 1) }) }], d.auditTrail)));
}

async function generateInvite(licenseId, invitationId) {
  const v = await ask(invitationId ? 'Reissue access link' : 'Generate access link',
    'A new private link is created. Any earlier unused link for this purchase stops working.',
    [{ name: 'expiryHours', label: 'Link valid for (hours)', type: 'number', min: 1, maxv: 720, default: 24 }], 'Generate link');
  if (!v) return;
  const r = await act(() => (invitationId
    ? api('POST', `/api/admin/invitations/${invitationId}/resend`, { expiryHours: v.expiryHours })
    : api('POST', '/api/admin/invitations', { licenseId, expiryHours: v.expiryHours })), { reload: false });
  if (!r) return;
  const copy = async (text, label) => { try { await navigator.clipboard.writeText(text); toast(`${label} copied`); } catch { toast('Copy failed — select and copy manually', true); } };
  modal('Private access link', h('div', {},
    h('p', { class: 'hint', text: 'This link is shown only once. Send it to the customer now. It works only with their registered WhatsApp number.' }),
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
function invitationsTable(rows) {
  return table([
    { label: 'Customer', render: (i) => h('div', {}, link(`/admin/customers/${i.customer_id}`, i.full_name), h('div', { class: 'sub', text: i.phone_e164 || '' })) },
    { label: 'Book', key: 'book_title' },
    { label: 'Link', render: (i) => h('span', { class: 'mono', text: `…/access/${i.token_hint}…` }) },
    { label: 'Status', render: (i) => badge(i.status) },
    { label: 'Expires', render: (i) => fmtDate(i.expires_at) },
    { label: 'Opened / used', render: (i) => h('div', {}, h('div', { class: 'sub', text: `opened ${fmtDate(i.opened_at)}` }), h('div', { class: 'sub', text: `used ${fmtDate(i.consumed_at)}` })) },
    { label: '', render: (i) => (can('invitations.manage') ? h('div', { class: 'actions' },
      i.status === 'PENDING' ? btn('Revoke', () => act(() => api('POST', `/api/admin/invitations/${i.id}/revoke`), { ok: 'Invitation revoked' }), 'btn btn-small btn-danger') : null,
      ['PENDING', 'EXPIRED', 'REVOKED'].includes(i.status) ? btn('Reissue', () => generateInvite(i.license_id, i.id)) : null) : '') },
  ], rows, 'No invitations.');
}

async function viewInvitations(q) {
  const d = await api('GET', `/api/admin/invitations?${q}`);
  page('Access Invitations',
    h('p', { class: 'hint', text: 'Generate links from a verified order. Only a hint of each link is stored; the full link is shown once when generated.' }),
    filterBar(q, [{ name: 'status', label: 'All statuses', options: ['PENDING', 'CONSUMED', 'EXPIRED', 'REVOKED', 'REPLACED'].map((s) => [s, s]) }]),
    invitationsTable(d.invitations), pager({ ...d, rows: d.invitations.length }, (p) => setQuery({ page: p })));
}

function devicesTable(rows) {
  return table([
    { label: 'Customer', render: (d) => link(`/admin/customers/${d.customer_id}`, d.full_name) },
    { label: 'Book(s)', render: (d) => d.books || '—' },
    { label: 'Device', render: (d) => h('div', {}, `${d.browser} on ${d.os}`, h('div', { class: 'sub', text: d.device_category })) },
    { label: 'Status', render: (d) => h('div', {}, badge(d.status), d.revoked_reason ? h('div', { class: 'sub', text: d.revoked_reason }) : null, d.transition_until ? h('div', { class: 'sub', text: `works until ${fmtDate(d.transition_until)}` }) : null) },
    { label: 'Registered', render: (d) => fmtDate(d.registered_at) },
    { label: 'Last activity', render: (d) => fmtDate(d.last_seen_at) },
    { label: 'Sessions', render: (d) => String(d.active_sessions ?? 0) },
    { label: '', render: (d) => (can('access.manage') && ['ACTIVE', 'PENDING_APPROVAL'].includes(d.status)
      ? btn('Revoke device', async () => { const v = await ask('Revoke device', 'This browser stops working immediately. The customer can register another device by signing in.', [{ name: 'reason', label: 'Reason' }], 'Revoke device', true); if (v) act(() => api('POST', `/api/admin/devices/${d.id}/revoke`, v.reason ? v : {}), { ok: 'Device revoked' }); }, 'btn btn-small btn-danger') : '') },
  ], rows, 'No devices.');
}

async function viewDevices(q) {
  const [d, reps] = await Promise.all([api('GET', `/api/admin/devices?${q}`), api('GET', '/api/admin/device-replacements')]);
  const pending = reps.replacements.filter((r) => r.mode === 'PENDING');
  page('Registered Devices',
    h('p', { class: 'hint', text: 'A device is a browser holding a registered cryptographic key. It is a useful signal, not proof of a specific physical phone.' }),
    pending.length ? h('section', { class: 'card' }, h('h2', { text: 'Replacement requests waiting for approval' }), table([
      { label: 'Customer', render: (r) => link(`/admin/customers/${r.customer_id}`, r.full_name) },
      { label: 'New device', render: (r) => `${r.new_browser} on ${r.new_os}` }, { label: 'Requested', render: (r) => fmtDate(r.created_at) },
      { label: '', render: (r) => (can('access.manage') ? h('div', { class: 'actions' },
        btn('Approve', async () => { const v = await ask('Approve replacement', 'The new device gets access. The old device stops working now, or after a transition period you choose.', [{ name: 'transitionHours', label: 'Keep old device working for (hours, 0 = stop now)', type: 'number', min: 0, maxv: 168, default: 0 }], 'Approve'); if (v) act(() => api('POST', `/api/admin/device-replacements/${r.id}/approve`, v), { ok: 'Replacement approved' }); }, 'btn btn-small btn-primary'),
        btn('Reject', () => act(() => api('POST', `/api/admin/device-replacements/${r.id}/reject`), { ok: 'Rejected' }), 'btn btn-small btn-danger')) : '') },
    ], pending)) : null,
    filterBar(q, [{ name: 'status', label: 'All statuses', options: ['ACTIVE', 'PENDING_APPROVAL', 'REVOKED', 'REPLACED', 'REJECTED'].map((s) => [s, s.replace('_', ' ')]) }]),
    devicesTable(d.devices), pager({ ...d, rows: d.devices.length }, (p) => setQuery({ page: p })),
    h('section', { class: 'card' }, h('h2', { text: 'Device replacement history' }), table([
      { label: 'Customer', key: 'full_name' }, { label: 'From', render: (r) => (r.old_browser ? `${r.old_browser} on ${r.old_os}` : '—') },
      { label: 'To', render: (r) => `${r.new_browser} on ${r.new_os}` }, { label: 'Decision', render: (r) => badge(r.mode) },
      { label: 'By', render: (r) => r.decided_by_name || (r.mode === 'SELF_SERVICE' ? 'Customer (OTP verified)' : '—') }, { label: 'When', render: (r) => fmtDate(r.decided_at || r.created_at) },
    ], reps.replacements, 'No replacements yet.')));
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
      l.status === 'PENDING_ACTIVATION' && can('invitations.manage') ? btn('Access link', () => generateInvite(l.id), 'btn btn-small btn-primary') : null,
      mng && l.status === 'ACTIVE' ? btn('Suspend', async () => { const v = await ask('Suspend license', 'Reading stops on the next request until reactivated.', [{ name: 'reason', label: 'Reason' }], 'Suspend', true); if (v) act(() => api('POST', `/api/admin/licenses/${l.id}/suspend`, v), { ok: 'Suspended' }); }) : null,
      mng && l.status === 'SUSPENDED' ? btn('Reactivate', () => act(() => api('POST', `/api/admin/licenses/${l.id}/reactivate`), { ok: 'Reactivated' })) : null,
      mng && ['ACTIVE', 'EXPIRED', 'SUSPENDED'].includes(l.status) && l.activated_at ? btn('Renew', async () => { const v = await ask('Renew license', 'Extend access from today (or from the current expiry if later).', [{ name: 'days', label: 'Days (empty = no expiry)', type: 'number', min: 1, nullable: true }], 'Renew'); if (v) act(() => api('POST', `/api/admin/licenses/${l.id}/renew`, v), { ok: 'Renewed' }); }) : null,
      mng && l.status !== 'REVOKED' ? btn('Devices allowed', async () => { const v = await ask('Devices allowed', 'How many browsers or devices may read this purchase at the same time.', [{ name: 'maxDevices', label: 'Devices', type: 'number', min: 1, maxv: 10, default: l.max_devices, required: true }], 'Save'); if (v) act(() => api('PATCH', `/api/admin/licenses/${l.id}`, v), { ok: 'Updated' }); }) : null,
      mng && l.status !== 'REVOKED' ? btn('Revoke', async () => { const v = await ask('Revoke license', 'Access to this book ends permanently for this purchase.', [{ name: 'reason', label: 'Reason', required: true }], 'Revoke', true); if (v) act(() => api('POST', `/api/admin/licenses/${l.id}/revoke`, v), { ok: 'License revoked' }); }, 'btn btn-small btn-danger') : null) },
  ], rows, 'No licenses.');
}

async function viewLicenses(q) {
  const d = await api('GET', `/api/admin/licenses?${q}`);
  page('Reading Licenses',
    filterBar(q, [{ name: 'status', label: 'All statuses', options: ['PENDING_ACTIVATION', 'ACTIVE', 'SUSPENDED', 'REVOKED', 'EXPIRED'].map((s) => [s, s.replace('_', ' ')]) }]),
    licensesTable(d.licenses), pager({ ...d, rows: d.licenses.length }, (p) => setQuery({ page: p })));
}

// ===========================================================================
// Monitoring
// ===========================================================================
const EVENT_TYPES = ['INVITATION_OPENED', 'OTP_REQUESTED', 'OTP_VERIFIED', 'DEVICE_REGISTERED', 'LICENSE_ACTIVATED', 'READER_OPENED', 'CHAPTER_ACCESSED', 'READING_SESSION_ENDED', 'ACCESS_DENIED', 'SESSION_EXPIRED', 'DEVICE_REPLACED', 'ACCOUNT_SUSPENDED', 'LICENSE_REVOKED'];

async function viewActivity(q) {
  const d = await api('GET', `/api/admin/reading-events?${q}`);
  page('Reading Activity',
    h('p', { class: 'hint', text: 'Access events, not proof of reading. A chapter being opened does not mean it was read.' }),
    filterBar(q, [{ name: 'type', label: 'All activity', options: EVENT_TYPES.map((t) => [t, t.replace(/_/g, ' ').toLowerCase()]) }]),
    table([
      { label: 'Activity', render: (e) => e.event_type.replace(/_/g, ' ').toLowerCase() },
      { label: 'Customer', render: (e) => (e.customer_id ? link(`/admin/customers/${e.customer_id}`, e.full_name) : '—') },
      { label: 'Book', key: 'book' },
      { label: 'Details', render: (e) => (Object.keys(e.details || {}).length ? h('pre', { class: 'details', text: JSON.stringify(e.details) }) : '') },
      { label: 'When', render: (e) => fmtDate(e.created_at) },
    ], d.events, 'No activity.'), pager({ ...d, rows: d.events.length }, (p) => setQuery({ page: p })));
}

async function viewSecurity(q) {
  const d = await api('GET', `/api/admin/security-events?${q}`);
  page('Security Events',
    filterBar(q, [{ name: 'open', label: 'All events', options: [['true', 'Open only']] }, { name: 'severity', label: 'Any severity', options: [['HIGH', 'High'], ['MEDIUM', 'Medium'], ['LOW', 'Low']] }]),
    table([
      { label: 'Event', render: (e) => h('div', {}, e.event_type.replace(/_/g, ' '), Object.keys(e.details || {}).length ? h('pre', { class: 'details', text: JSON.stringify(e.details) }) : null) },
      { label: 'Severity', render: (e) => badge(e.severity) },
      { label: 'Customer', render: (e) => (e.customer_id ? link(`/admin/customers/${e.customer_id}`, e.full_name || 'Customer') : '—') },
      { label: 'When', render: (e) => fmtDate(e.created_at) },
      { label: 'Resolution', render: (e) => (e.resolved_at ? h('div', {}, e.resolution, h('div', { class: 'sub', text: `${e.resolved_by_name || ''} · ${fmtDate(e.resolved_at)}` }))
        : (can('security.manage') ? btn('Resolve', async () => { const v = await ask('Resolve event', 'Record what you found or did.', [{ name: 'resolution', label: 'Resolution note', required: true }], 'Resolve'); if (v) act(() => api('POST', `/api/admin/security-events/${e.id}/resolve`, v), { ok: 'Resolved' }); }) : badge('PENDING'))) },
    ], d.events, 'No security events.'), pager({ ...d, rows: d.events.length }, (p) => setQuery({ page: p })));
}

async function viewAudit(q) {
  const d = await api('GET', `/api/admin/audit-logs?${q}`);
  page('Audit Logs',
    filterBar(q, [{ name: 'action', label: 'Action contains' }, { name: 'entityType', label: 'Any entity', options: ['book', 'book_edition', 'customer', 'order', 'invitation', 'license', 'device', 'administrator', 'website_settings', 'testimonial', 'system_settings', 'security_event'].map((x) => [x, x]) }]),
    table([
      { label: 'When', render: (l) => fmtDate(l.created_at) }, { label: 'Administrator', render: (l) => l.admin_name || 'System' },
      { label: 'Action', key: 'action' }, { label: 'Entity', render: (l) => h('div', {}, l.entity_type, h('div', { class: 'sub mono', text: l.entity_id || '' })) },
      { label: 'Details', render: (l) => h('pre', { class: 'details', text: JSON.stringify(l.details) }) },
    ], d.logs, 'No entries.'), pager({ ...d, rows: d.logs.length }, (p) => setQuery({ page: p })));
}

// ===========================================================================
// Website content and WhatsApp
// ===========================================================================
function listEditor(items, keys) {
  const wrap = h('div', { class: 'list-editor' });
  const rows = [];
  const addRow = (val = {}) => {
    const inputs = {};
    const row = h('div', { class: 'item' }, keys.map(([k, label, long]) => {
      const el = long ? h('textarea', { rows: 3 }) : h('input', { type: 'text' });
      el.value = val[k] || ''; inputs[k] = el;
      return h('div', { class: 'field' }, h('label', { text: label }), el);
    }), btn('Remove', () => { row.remove(); rows.splice(rows.indexOf(entry), 1); }, 'btn btn-small btn-danger'));
    const entry = { inputs };
    rows.push(entry);
    list.append(row);
  };
  const list = h('div');
  wrap.append(list, btn('+ Add item', () => addRow()));
  (items || []).forEach(addRow);
  return { el: wrap, value: () => rows.map((r) => Object.fromEntries(Object.entries(r.inputs).map(([k, el]) => [k, el.value]))) };
}

async function viewWebsite() {
  const [{ content, testimonials }, { books }] = await Promise.all([api('GET', '/api/admin/website'), api('GET', '/api/admin/books')]);
  const save = (key, value) => act(() => api('PUT', `/api/admin/website/${key}`, value), { ok: 'Saved', reload: false });
  const simple = (key, title, fields) => {
    const f = buildForm(fields, content[key] || {}, { submit: 'Save', onSubmit: (v) => save(key, v) });
    return h('section', { class: 'card' }, h('h2', { text: title }), f.form);
  };
  const listSection = (key, title, keys) => {
    const heading = h('input', { type: 'text' }); heading.value = content[key]?.heading || '';
    const ed = listEditor(content[key]?.items, keys);
    return h('section', { class: 'card' }, h('h2', { text: title }), h('div', { class: 'field' }, h('label', { text: 'Section heading' }), heading), ed.el,
      h('div', { class: 'row-actions' }, btn('Save', () => save(key, { heading: heading.value, items: ed.value() }), 'btn btn-primary')));
  };
  const tForm = buildForm([
    { name: 'authorName', label: 'Name', required: true }, { name: 'authorTitle', label: 'Title or role' },
    { name: 'rating', label: 'Rating (1-5)', type: 'number', min: 1, maxv: 5, nullable: true }, { name: 'sortOrder', label: 'Order', type: 'number', min: 0, default: 0 },
    { name: 'quote', label: 'Quote', type: 'textarea', required: true, full: true }, { name: 'published', label: 'Show on website', type: 'checkbox', default: true },
  ], {}, { submit: 'Add testimonial', onSubmit: (v) => act(() => api('POST', '/api/admin/testimonials', v), { ok: 'Testimonial added' }) });

  page('Marketing Website Content',
    h('p', {}, h('a', { href: '/', target: '_blank', rel: 'noopener' }, 'Open the website ↗'), h('span', { class: 'hint', text: '  Book title, price and cover come from the featured book.' })),
    simple('site', 'Site and search engines', [
      { name: 'siteName', label: 'Site name', max: 120 },
      { name: 'featuredBookId', label: 'Featured book', type: 'select', options: [['', 'First published book'], ...books.map((b) => [b.id, b.title])], nullable: true },
      { name: 'seoDescription', label: 'Search description', type: 'textarea', full: true, max: 300 }]),
    simple('hero', 'Hero', [{ name: 'headline', label: 'Headline (defaults to book title)', full: true }, { name: 'subheadline', label: 'Short description', type: 'textarea', full: true }]),
    simple('about', 'About the book', [{ name: 'heading', label: 'Heading' }, { name: 'body', label: 'Text (defaults to the book description)', type: 'textarea', full: true, rows: 8 }]),
    listSection('learn', 'What readers will learn', [['title', 'Point'], ['text', 'Explanation', true]]),
    simple('author', 'Author introduction', [{ name: 'heading', label: 'Heading' }, { name: 'name', label: 'Author name' }, { name: 'bio', label: 'Biography', type: 'textarea', full: true, rows: 8 }]),
    listSection('benefits', 'Book benefits', [['title', 'Benefit'], ['text', 'Explanation', true]]),
    listSection('faq', 'Frequently asked questions', [['question', 'Question'], ['answer', 'Answer', true]]),
    simple('cta', 'Final call to action', [{ name: 'heading', label: 'Heading' }, { name: 'body', label: 'Text', type: 'textarea', full: true }]),
    simple('footer', 'Footer', [{ name: 'copyright', label: 'Copyright line', full: true }]),
    h('section', { class: 'card' }, h('h2', { text: 'Testimonials' }),
      table([
        { label: 'Name', render: (t) => h('div', {}, t.author_name, h('div', { class: 'sub', text: t.author_title })) },
        { label: 'Quote', key: 'quote' }, { label: 'Rating', render: (t) => (t.rating ? '★'.repeat(t.rating) : '—') },
        { label: 'Shown', render: (t) => badge(t.published ? 'ACTIVE' : 'DISABLED') },
        { label: '', render: (t) => h('div', { class: 'actions' },
          btn(t.published ? 'Hide' : 'Show', () => act(() => api('PUT', `/api/admin/testimonials/${t.id}`, { authorName: t.author_name, authorTitle: t.author_title, quote: t.quote, rating: t.rating, published: !t.published, sortOrder: t.sort_order, bookId: t.book_id }), { ok: 'Updated' })),
          btn('Delete', async () => { if (await ask('Delete testimonial', `Delete the testimonial from ${t.author_name}?`, [], 'Delete', true)) act(() => api('DELETE', `/api/admin/testimonials/${t.id}`), { ok: 'Deleted' }); }, 'btn btn-small btn-danger')) },
      ], testimonials, 'No testimonials yet.'),
      h('h2', { text: 'Add a testimonial' }), tForm.form));
}

async function viewWhatsapp() {
  const { content } = await api('GET', '/api/admin/website');
  const f = buildForm([
    { name: 'number', label: 'Business WhatsApp number', placeholder: '+254712345678', hint: 'Used for the Order on WhatsApp buttons on the website' },
    { name: 'orderMessage', label: 'Prefilled order message', type: 'textarea', full: true, hint: 'Placeholders: {book_title}' },
    { name: 'invitationTemplate', label: 'Invitation message sent to customers', type: 'textarea', full: true, rows: 10, required: true,
      hint: 'Placeholders: {customer_name}, {book_title}, {invitation_link} (required), {expiry_hours}' },
  ], content.whatsapp || {}, { submit: 'Save WhatsApp settings', onSubmit: (v) => act(() => api('PUT', '/api/admin/website/whatsapp', v), { ok: 'Saved', reload: false }) });
  page('WhatsApp Settings',
    h('section', { class: 'card' }, f.form),
    h('section', { class: 'card' }, h('h2', { text: 'Verification codes (OTP)' }),
      h('p', { class: 'hint', text: 'Customer verification codes are sent through the WhatsApp Business Cloud API configured on the server (WHATSAPP_* environment variables). Invitations are sent by you with the “Send via WhatsApp” button after generating a link.' })));
}

// ===========================================================================
// Administrators, settings, account
// ===========================================================================
async function viewAdmins() {
  const d = await api('GET', '/api/admin/administrators');
  const roleOpts = d.roles.map((r) => [r.name, `${r.name} — ${r.description}`]);
  const f = buildForm([
    { name: 'fullName', label: 'Full name', required: true }, { name: 'email', label: 'Email', type: 'email', required: true },
    { name: 'role', label: 'Role', type: 'select', options: roleOpts, default: 'MANAGER' },
    { name: 'password', label: 'Temporary password', type: 'password', required: true, hint: 'At least 12 characters. Ask them to change it after signing in.', autocomplete: 'new-password' },
  ], {}, { submit: 'Add administrator', onSubmit: (v) => act(() => api('POST', '/api/admin/administrators', v), { ok: 'Administrator added' }) });
  page('Administrators',
    table([
      { label: 'Name', render: (a) => h('div', {}, a.full_name, h('div', { class: 'sub', text: a.email })) },
      { label: 'Role', render: (a) => badge(a.role) }, { label: 'Status', render: (a) => badge(a.status) },
      { label: '2FA', render: (a) => (a.mfa_enabled ? badge('ACTIVE') : badge('PENDING')) },
      { label: 'Last sign-in', render: (a) => fmtDate(a.last_login_at) },
      { label: '', render: (a) => (a.id === me.id ? h('span', { class: 'hint', text: 'You' }) : h('div', { class: 'actions' },
        btn('Change role', async () => { const v = await ask('Change role', `Choose a role for ${a.full_name}.`, [{ name: 'role', label: 'Role', type: 'select', options: roleOpts, default: a.role }], 'Save'); if (v) act(() => api('PATCH', `/api/admin/administrators/${a.id}`, v), { ok: 'Role updated' }); }),
        a.status === 'ACTIVE'
          ? btn('Disable', () => act(() => api('PATCH', `/api/admin/administrators/${a.id}`, { status: 'DISABLED' }), { ok: 'Disabled' }), 'btn btn-small btn-danger')
          : btn('Enable', () => act(() => api('PATCH', `/api/admin/administrators/${a.id}`, { status: 'ACTIVE' }), { ok: 'Enabled' })))) },
    ], d.administrators),
    h('section', { class: 'card' }, h('h2', { text: 'Add an administrator' }), f.form));
}

const SETTING_LABELS = {
  invitation_expiry_hours: ['Default invitation validity (hours)', 'Can be changed per link'],
  otp_ttl_minutes: ['Verification code validity (minutes)'],
  otp_max_attempts: ['Wrong code attempts allowed'],
  otp_max_requests_per_hour: ['Codes a customer may request per hour'],
  otp_resend_cooldown_seconds: ['Seconds between code requests'],
  session_ttl_hours: ['Reading session length (hours)', 'Customers confirm their number again after this'],
  session_idle_minutes: ['Sign out after inactivity (minutes)'],
  default_max_devices: ['Default devices per purchase'],
  device_replacement_mode: ['Moving access to a new device'],
  max_self_replacements_per_30d: ['Self-service device moves allowed per 30 days', 'After this, requests need your approval'],
  default_license_duration_days: ['Default license duration (days)', 'Empty = no expiry'],
  content_requests_per_minute: ['Reader requests allowed per minute', 'Above this, requests are blocked and flagged'],
};

async function viewSettings() {
  const { settings, schema } = await api('GET', '/api/admin/settings');
  const fields = Object.entries(schema).map(([k, s]) => (s.enum
    ? { name: k, label: SETTING_LABELS[k]?.[0] || k, type: 'select', options: s.enum.map((v) => [v, v === 'SELF_SERVICE' ? 'Customer can move it after verifying their number' : 'Requires my approval']), hint: SETTING_LABELS[k]?.[1] }
    : { name: k, label: SETTING_LABELS[k]?.[0] || k, type: 'number', min: s.min, maxv: s.max, nullable: s.nullable, hint: SETTING_LABELS[k]?.[1] }));
  const f = buildForm(fields, settings, { submit: 'Save settings', onSubmit: (v) => act(() => api('PUT', '/api/admin/settings', v), { ok: 'Settings saved' }) });
  page('System Settings', h('p', { class: 'hint', text: 'Access policy for invitations, verification codes, sessions and devices. Changes apply to new requests immediately.' }), h('section', { class: 'card' }, f.form));
}

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

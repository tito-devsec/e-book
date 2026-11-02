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
function svgEl(tag, attrs = {}, ...children) {
  const el = document.createElementNS(SVGNS, tag);
  for (const [k, v] of Object.entries(attrs)) if (v !== undefined && v !== null) el.setAttribute(k, String(v));
  for (const c of children.flat(Infinity)) if (c) el.append(c);
  return el;
}
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
function niceMax(v) {
  if (v <= 4) return 4;
  const p = 10 ** Math.floor(Math.log10(v));
  for (const m of [1, 2, 2.5, 5, 10]) if (m * p >= v) return m * p;
  return 10 * p;
}
function tooltipLayer(container) {
  const tip = h('div', { class: 'tip', role: 'tooltip' }); tip.hidden = true;
  container.append(tip);
  return {
    show(x, y, rows, title) {
      tip.replaceChildren(h('div', {}, h('b', { text: title })), ...rows.map(([color, label, value]) => h('div', {},
        color ? Object.assign(h('span', { class: 'sw' }), { style: '' }) : null, `${label}: `, h('b', { text: value }))));
      tip.querySelectorAll('.sw').forEach((s, i) => { s.style.background = rows[i][0]; });
      tip.style.left = `${x}px`; tip.style.top = `${y}px`; tip.hidden = false;
    },
    hide() { tip.hidden = true; },
  };
}
/** Round-topped bar anchored to the baseline. */
function barPath(x, y, w, hgt, r = 4) {
  if (hgt <= 0) return '';
  const rr = Math.min(r, w / 2, hgt);
  return `M${x},${y + hgt}V${y + rr}Q${x},${y} ${x + rr},${y}H${x + w - rr}Q${x + w},${y} ${x + w},${y + rr}V${y + hgt}Z`;
}
function groupedBarChart({ labels, fullLabels, series, height = 230 }) {
  const W = 640; const H = height; const L = 34; const B = 26; const T = 10; const R = 6;
  const max = niceMax(Math.max(1, ...series.flatMap((s) => s.values)));
  const pw = W - L - R; const ph = H - T - B;
  const gw = pw / labels.length; const bw = Math.min(16, gw * 0.24); const gap = 4;
  const svg = svgEl('svg', { viewBox: `0 0 ${W} ${H}`, role: 'img', 'aria-label': `${series.map((s) => s.name).join(' and ')} per day` });
  for (let i = 0; i <= 4; i += 1) {
    const y = T + ph - (ph * i) / 4;
    svg.append(svgEl('line', { class: 'gridline', x1: L, x2: W - R, y1: y, y2: y }));
    svg.append(svgEl('text', { class: 'axis-label', x: L - 8, y: y + 4, 'text-anchor': 'end' }, document.createTextNode(String((max * i) / 4))));
  }
  const wrap = h('div', { class: 'chart' }, svg);
  const tip = tooltipLayer(wrap);
  labels.forEach((lab, i) => {
    const cx = L + gw * i + gw / 2;
    const total = series.length * bw + (series.length - 1) * gap;
    svg.append(svgEl('text', { class: 'axis-label', x: cx, y: H - 6, 'text-anchor': 'middle' }, document.createTextNode(lab)));
    series.forEach((s, k) => {
      const v = s.values[i]; const bh = (v / max) * ph;
      const x = cx - total / 2 + k * (bw + gap);
      const show = () => {
        const r = wrap.getBoundingClientRect(); const sr = svg.getBoundingClientRect();
        tip.show(((cx) / W) * sr.width + (sr.left - r.left), ((T + ph - bh) / H) * sr.height + (sr.top - r.top),
          series.map((ss) => [ss.color, ss.name, String(ss.values[i])]), fullLabels?.[i] || lab);
      };
      // Hit target covers the whole column height so small bars are easy to hover.
      const hit = svgEl('rect', { x: x - 2, y: T, width: bw + 4, height: ph, fill: 'transparent', tabindex: 0, 'aria-label': `${fullLabels?.[i] || lab}: ${s.name} ${v}` });
      hit.addEventListener('pointerenter', show); hit.addEventListener('focus', show);
      hit.addEventListener('pointerleave', () => tip.hide()); hit.addEventListener('blur', () => tip.hide());
      if (bh > 0) svg.append(svgEl('path', { class: 'bar', d: barPath(x, T + ph - bh, bw, bh), fill: s.color }));
      svg.append(hit);
    });
  });
  return wrap;
}
function smoothPath(pts) {
  if (pts.length < 2) return '';
  let d = `M${pts[0][0]},${pts[0][1]}`;
  for (let i = 1; i < pts.length; i += 1) {
    const [x0, y0] = pts[i - 1]; const [x1, y1] = pts[i]; const mx = (x0 + x1) / 2;
    d += ` C${mx},${y0} ${mx},${y1} ${x1},${y1}`;
  }
  return d;
}
let gradSeq = 0;
function areaChart({ labels, fullLabels, values, color, format, height = 230 }) {
  const W = 640; const H = height; const L = 54; const B = 26; const T = 12; const R = 10;
  const max = niceMax(Math.max(1, ...values));
  const pw = W - L - R; const ph = H - T - B;
  const xs = (i) => L + (labels.length === 1 ? pw / 2 : (pw * i) / (labels.length - 1));
  const ys = (v) => T + ph - (v / max) * ph;
  const pts = values.map((v, i) => [xs(i), ys(v)]);
  const id = `grad${gradSeq += 1}`;
  const svg = svgEl('svg', { viewBox: `0 0 ${W} ${H}`, role: 'img', 'aria-label': 'Verified revenue per month' },
    svgEl('defs', {}, svgEl('linearGradient', { id, x1: 0, y1: 0, x2: 0, y2: 1 },
      svgEl('stop', { offset: '0%', 'stop-color': color, 'stop-opacity': 0.28 }), svgEl('stop', { offset: '100%', 'stop-color': color, 'stop-opacity': 0.02 }))));
  for (let i = 0; i <= 4; i += 1) {
    const y = T + ph - (ph * i) / 4;
    svg.append(svgEl('line', { class: 'gridline', x1: L, x2: W - R, y1: y, y2: y }));
    svg.append(svgEl('text', { class: 'axis-label', x: L - 8, y: y + 4, 'text-anchor': 'end' }, document.createTextNode(format((max * i) / 4, true))));
  }
  labels.forEach((lab, i) => svg.append(svgEl('text', { class: 'axis-label', x: xs(i), y: H - 6, 'text-anchor': 'middle' }, document.createTextNode(lab))));
  const line = smoothPath(pts);
  svg.append(svgEl('path', { d: `${line} L${xs(labels.length - 1)},${T + ph} L${xs(0)},${T + ph} Z`, fill: `url(#${id})` }));
  svg.append(svgEl('path', { d: line, fill: 'none', stroke: color, 'stroke-width': 2.5, 'stroke-linecap': 'round' }));
  const hair = svgEl('line', { x1: 0, x2: 0, y1: T, y2: T + ph, stroke: '#c5cbd6', 'stroke-width': 1, 'stroke-dasharray': '3 3', visibility: 'hidden' });
  const dot = svgEl('circle', { r: 5, fill: color, stroke: '#fff', 'stroke-width': 2, visibility: 'hidden' });
  svg.append(hair, dot);
  const wrap = h('div', { class: 'chart' }, svg);
  const tip = tooltipLayer(wrap);
  const overlay = svgEl('rect', { x: L, y: T, width: pw, height: ph, fill: 'transparent', tabindex: 0, 'aria-label': 'Revenue by month; use arrow keys' });
  let cur = labels.length - 1;
  const showAt = (i) => {
    cur = Math.max(0, Math.min(labels.length - 1, i));
    const [x, y] = pts[cur];
    for (const el of [hair]) { el.setAttribute('x1', x); el.setAttribute('x2', x); el.setAttribute('visibility', 'visible'); }
    dot.setAttribute('cx', x); dot.setAttribute('cy', y); dot.setAttribute('visibility', 'visible');
    const r = wrap.getBoundingClientRect(); const sr = svg.getBoundingClientRect();
    tip.show((x / W) * sr.width + (sr.left - r.left), (y / H) * sr.height + (sr.top - r.top), [[color, 'Revenue', format(values[cur])]], fullLabels?.[cur] || labels[cur]);
  };
  const hide = () => { hair.setAttribute('visibility', 'hidden'); dot.setAttribute('visibility', 'hidden'); tip.hide(); };
  overlay.addEventListener('pointermove', (e) => {
    const sr = svg.getBoundingClientRect(); const x = ((e.clientX - sr.left) / sr.width) * W;
    let best = 0; pts.forEach(([px], i) => { if (Math.abs(px - x) < Math.abs(pts[best][0] - x)) best = i; });
    showAt(best);
  });
  overlay.addEventListener('pointerleave', hide); overlay.addEventListener('blur', hide);
  overlay.addEventListener('focus', () => showAt(cur));
  overlay.addEventListener('keydown', (e) => { if (e.key === 'ArrowLeft') showAt(cur - 1); if (e.key === 'ArrowRight') showAt(cur + 1); });
  svg.append(overlay);
  return wrap;
}
/** Card with a chart and a "view as table" toggle for accessibility. */
function chartCard({ title, cls = '', legend, chart, tableCols, tableRows, extraHead }) {
  const tbl = table(tableCols, tableRows); tbl.hidden = true;
  const toggle = h('button', { class: 'btn-link', type: 'button' }, 'View as table');
  toggle.addEventListener('click', () => { const showTable = tbl.hidden; tbl.hidden = !showTable; chart.hidden = showTable; toggle.textContent = showTable ? 'View as chart' : 'View as table'; });
  return h('section', { class: `card ${cls}` },
    h('div', { class: 'sec-head' }, h('h2', { text: title }), extraHead || null, legend || null),
    chart, tbl, h('div', { class: 'chart-tools' }, toggle));
}

// ===========================================================================
// Shell, navigation, routing
// ===========================================================================
const NAV = [
  ['Sales', [['/admin', 'Overview', 'dashboard.view', 'home'], ['/admin/orders', 'Orders', 'customers.view', 'orders'], ['/admin/payments', 'Payment Verification', 'payments.verify', 'payments'], ['/admin/customers', 'Customers', 'customers.view', 'customers']]],
  ['Access', [['/admin/invitations', 'Access Invitations', 'customers.view', 'invitations'], ['/admin/devices', 'Registered Devices', 'customers.view', 'devices'], ['/admin/licenses', 'Reading Licenses', 'customers.view', 'licenses']]],
  ['Books', [['/admin/books', 'Books', 'books.manage', 'books'], ['/admin/editions', 'Book Editions', 'books.manage', 'editions']]],
  ['Monitoring', [['/admin/activity', 'Reading Activity', 'security.view', 'activity'], ['/admin/security', 'Security Events', 'security.view', 'security'], ['/admin/audit', 'Audit Logs', 'audit.view', 'audit']]],
  ['Store', [['/admin/whatsapp', 'Download Page & WhatsApp', 'content.manage', 'whatsapp']]],
  ['System', [['/admin/admins', 'Administrators', 'admins.manage', 'admins'], ['/admin/settings', 'System Settings', 'settings.manage', 'settings'], ['/admin/account', 'My Account', null, 'account']]],
];

function go(path) { history.pushState({}, '', path); route(); }
addEventListener('popstate', () => route());
document.addEventListener('click', (e) => {
  const a = e.target.closest('a[data-nav]');
  if (a && !e.metaKey && !e.ctrlKey) { e.preventDefault(); document.querySelector('.side')?.classList.remove('open'); document.querySelector('.menu')?.remove(); go(a.getAttribute('href')); }
  if (!e.target.closest('.menu, .avatar')) document.querySelector('.menu')?.remove();
});

let mainEl = null; let contentEl = null; let titleEl = null; let bellDot = null;
function setAlerts(n) {
  if (!bellDot) return;
  bellDot.hidden = !n; bellDot.textContent = n > 99 ? '99+' : String(n);
}
function shell() {
  const side = h('aside', { class: 'side' },
    h('div', { class: 'brand' },
      h('a', { class: 'logo', href: '/admin', 'data-nav': true }, h('span', { class: 'mark' }, icon('book', 18)), 'BookVault'),
      btn('Menu', () => side.classList.toggle('open'), 'menu-btn')),
    h('nav', { 'aria-label': 'Dashboard' }, NAV.map(([grp, items]) => {
      const visible = items.filter(([, , p]) => !p || can(p));
      return visible.length ? [h('div', { class: 'grp', text: grp }), visible.map(([href, label, , ic]) => h('a', { href, 'data-nav': true }, icon(ic), h('span', { text: label })))] : [];
    }), h('p', { class: 'credit' }, 'Icons: ', h('a', { href: 'https://www.flaticon.com/uicons', target: '_blank', rel: 'noopener noreferrer' }, 'UIcons by Flaticon'))));
  titleEl = h('h1');
  const q = h('input', { type: 'search', placeholder: 'Search customers by name or phone', 'aria-label': 'Search customers' });
  const search = h('form', { class: 'search', role: 'search' }, icon('search', 18), q);
  search.addEventListener('submit', (e) => { e.preventDefault(); go(`/admin/customers?q=${encodeURIComponent(q.value.trim())}`); });
  bellDot = h('span', { class: 'dot' }); bellDot.hidden = true;
  const bell = can('security.view') ? h('a', { class: 'icon-btn', href: '/admin/security?open=true', 'data-nav': true, 'aria-label': 'Open security events', title: 'Security alerts' }, icon('bell'), bellDot) : null;
  const settingsBtn = can('settings.manage') ? h('a', { class: 'icon-btn', href: '/admin/settings', 'data-nav': true, 'aria-label': 'System settings', title: 'System settings' }, icon('settings')) : null;
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
  mainEl = h('main', { class: 'main', id: 'main' }, h('header', { class: 'topbar' }, titleEl, search, settingsBtn, bell, avatar), contentEl);
  root.replaceChildren(h('div', { class: 'shell' }, side, mainEl));
  if (can('security.view')) api('GET', '/api/admin/security-events?open=true&limit=100').then((r) => setAlerts(r.events.length)).catch(() => {});
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
    if (p === '/admin/website') return go('/admin/whatsapp');
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
async function viewOverview() {
  const d = await api('GET', '/api/admin/overview');
  const m = d.metrics;
  setAlerts(m.open_security_events);
  const cur = d.currency;
  const rev = d.revenue.find((r) => r.currency === cur) || { verified: '0', pending: '0', pending_count: 0 };
  const money = (v) => fmtMoney(v || 0, cur);
  const compact = (v) => { try { return new Intl.NumberFormat(undefined, { notation: 'compact', maximumFractionDigits: 1 }).format(v); } catch { return String(v); } };

  // --- Revenue cards -------------------------------------------------------
  const cards = h('section', { class: 'span2' },
    h('div', { class: 'sec-head' }, h('h2', { text: 'Sales' }), link('/admin/orders', 'See all')),
    h('div', { class: 'paycards' },
      h('a', { class: 'paycard hot', href: '/admin/orders?status=PAID', 'data-nav': true },
        h('div', {}, h('div', { class: 'k', text: 'Verified revenue' }), h('div', { class: 'v', text: money(rev.verified) })),
        h('div', { class: 'row' }, h('div', {}, 'Paid orders', h('strong', { text: String(m.verified_payments) })), h('div', {}, 'Active readers', h('strong', { text: String(m.active_licenses) }))),
        h('div', { class: 'foot' }, h('span', { text: `${m.total_books} book${m.total_books === 1 ? '' : 's'} on sale` }), icon('arrow'))),
      h('a', { class: 'paycard', href: '/admin/payments', 'data-nav': true },
        h('div', {}, h('div', { class: 'k', text: 'Awaiting verification' }), h('div', { class: 'v', text: money(rev.pending) })),
        h('div', { class: 'row' }, h('div', {}, 'Pending payments', h('strong', { text: String(m.pending_payments) })), h('div', {}, 'Open invitations', h('strong', { text: String(m.active_invitations) }))),
        h('div', { class: 'foot' }, h('span', { text: m.pending_payments ? 'Verify payments' : 'All caught up' }), icon('arrow')))));

  // --- Recent transactions -------------------------------------------------
  const txIcon = (s) => (s === 'VERIFIED' ? h('span', { class: 'ico ok' }, icon('check')) : s === 'REJECTED' ? h('span', { class: 'ico bad' }, icon('x')) : h('span', { class: 'ico' }, icon('clock')));
  const recent = h('section', { class: 'card' },
    h('div', { class: 'sec-head' }, h('h2', { text: 'Recent Transactions' }), link('/admin/orders', 'See all')),
    d.recentPayments.length ? h('ul', { class: 'tx' }, d.recentPayments.map((p) => h('li', {},
      txIcon(p.status),
      h('div', { class: 't' }, h('strong', {}, link(`/admin/orders/${p.order_id}`, p.full_name)), h('span', { text: `${p.method} · ${new Date(p.at).toLocaleDateString(undefined, { day: 'numeric', month: 'short', year: 'numeric' })}` })),
      h('div', { class: `amt${p.status === 'VERIFIED' ? ' plus' : ''}`, text: `${p.status === 'VERIFIED' ? '+' : ''}${fmtMoney(p.amount, p.currency)}` }))))
      : h('p', { class: 'chart-empty', text: 'No payments yet.' }));

  // --- Weekly activity (grouped bars) --------------------------------------
  const days = d.weekly.map((w) => new Date(`${w.day}T00:00:00`));
  const series = [
    { name: 'New orders', color: SERIES[0], values: d.weekly.map((w) => w.orders) },
    { name: 'Payments verified', color: SERIES[1], values: d.weekly.map((w) => w.verified) },
  ];
  const legend = h('div', { class: 'legend' }, series.map((s) => { const i = h('i'); i.style.background = s.color; return h('span', {}, i, s.name); }));
  const weekly = chartCard({
    title: 'Weekly Activity', cls: 'span2', legend,
    chart: groupedBarChart({ labels: days.map((x) => x.toLocaleDateString(undefined, { weekday: 'short' })), fullLabels: days.map((x) => x.toLocaleDateString(undefined, { weekday: 'long', day: 'numeric', month: 'short' })), series }),
    tableCols: [{ label: 'Day', render: (r) => r.label }, { label: 'New orders', key: 'orders' }, { label: 'Payments verified', key: 'verified' }, { label: 'Activations', key: 'activations' }],
    tableRows: d.weekly.map((w, i) => ({ ...w, label: days[i].toLocaleDateString() })),
  });

  // --- Licences by status (segmented bar, status colours + glyph + label) ----
  const ST = {
    ACTIVE: ['Active', 'var(--st-good)', 'check'], PENDING_ACTIVATION: ['Not yet activated', 'var(--st-warning)', 'clock'],
    SUSPENDED: ['Suspended', 'var(--st-serious)', 'exclamation'], REVOKED: ['Revoked', 'var(--st-critical)', 'cross'], EXPIRED: ['Expired', 'var(--st-neutral)', 'minus'],
  };
  const counts = Object.keys(ST).map((k) => [k, d.licenseStatus.find((x) => x.status === k)?.n || 0]);
  const totalLic = counts.reduce((a, [, n]) => a + n, 0);
  const seg = h('div', { class: 'segbar', role: 'img', 'aria-label': counts.map(([k, n]) => `${ST[k][0]} ${n}`).join(', ') });
  for (const [k, n] of counts) {
    if (!n) continue;
    const part = h('div', { title: `${ST[k][0]}: ${n}` });
    part.style.flex = String(n); part.style.background = ST[k][1];
    seg.append(part);
  }
  const licences = h('section', { class: 'card' },
    h('div', { class: 'sec-head' }, h('h2', { text: 'Reading Licences' }), link('/admin/licenses', 'Manage')),
    totalLic ? [seg, h('ul', { class: 'status-list' }, counts.map(([k, n]) => {
      const g = h('span', { class: 'glyph', 'aria-hidden': 'true' }, h('i', { class: `fi fi-rr-${ST[k][2]}` })); g.style.background = ST[k][1];
      return h('li', {}, g, h('span', { text: ST[k][0] }), h('b', { text: `${n} · ${Math.round((n / totalLic) * 100)}%` }));
    }))] : h('p', { class: 'chart-empty', text: 'No licences yet. They appear when a payment is verified.' }));

  // --- Quick actions (recent customers) ------------------------------------
  const quick = h('section', { class: 'card' },
    h('div', { class: 'sec-head' }, h('h2', { text: 'Quick Access' }), link('/admin/customers', 'All customers')),
    d.recentCustomers.length ? h('div', { class: 'people' }, d.recentCustomers.map((c) => h('a', { class: 'person', href: `/admin/customers/${c.id}`, 'data-nav': true },
      h('span', { class: 'avatar lg', 'aria-hidden': 'true', text: initials(c.full_name) }), h('span', { class: 'n', text: c.full_name }), h('span', { class: 'r', text: c.status.replace(/_/g, ' ').toLowerCase() }))))
      : h('p', { class: 'hint', text: 'Customers you register appear here.' }),
    can('customers.manage') ? h('div', { class: 'quick-row' }, h('span', { class: 'pill', text: 'New sale on WhatsApp?' }),
      h('a', { class: 'btn btn-primary', href: '/admin/orders/new', 'data-nav': true }, icon('plus', 18), 'Register order')) : null);

  // --- Revenue history (area, single series) --------------------------------
  const months = d.monthly.map((x) => new Date(`${x.month}-01T00:00:00`));
  const revenueVals = d.monthly.map((x) => Number(x.amount));
  const history = chartCard({
    title: 'Revenue History', cls: 'span2',
    extraHead: h('span', { class: 'hint', text: `Verified payments, ${cur}` }),
    chart: areaChart({
      labels: months.map((x) => x.toLocaleDateString(undefined, { month: 'short' })),
      fullLabels: months.map((x) => x.toLocaleDateString(undefined, { month: 'long', year: 'numeric' })),
      values: revenueVals, color: SERIES[0], format: (v, axis) => (axis ? compact(v) : money(v)),
    }),
    tableCols: [{ label: 'Month', key: 'label' }, { label: `Revenue (${cur})`, key: 'amount' }],
    tableRows: d.monthly.map((x, i) => ({ label: months[i].toLocaleDateString(undefined, { month: 'long', year: 'numeric' }), amount: money(x.amount) })),
  });

  // --- Totals and recent activity --------------------------------------------
  const tiles = [
    ['Registered customers', m.registered_customers, '/admin/customers'], ['Activated customers', m.activated_customers, '/admin/customers?status=ACTIVE'],
    ['Total orders', m.total_orders, '/admin/orders'], ['Active invitations', m.active_invitations, '/admin/invitations?status=PENDING'],
    ['Suspended accounts', m.suspended_accounts, '/admin/customers?status=SUSPENDED'], ['Revoked access', m.revoked_access, '/admin/licenses?status=REVOKED'],
    ['Open security events', m.open_security_events, '/admin/security?open=true'],
  ];
  const totals = h('section', { class: 'span3' }, h('div', { class: 'metrics' },
    tiles.map(([k, v, href]) => h('a', { class: 'metric', href, 'data-nav': true }, h('div', { class: 'v', text: String(v) }), h('div', { class: 'k', text: k })))));

  const lists = h('div', { class: 'grid2 span3' },
    h('section', { class: 'card' }, h('div', { class: 'sec-head' }, h('h2', { text: 'Security Alerts' }), link('/admin/security', 'See all')),
      table([{ label: 'Event', render: (r) => r.event_type.replace(/_/g, ' ').toLowerCase() }, { label: 'Severity', render: (r) => badge(r.severity) }, { label: 'Customer', key: 'customer' }, { label: 'When', render: (r) => fmtDate(r.created_at) }], d.recentSecurity, 'No security events.')),
    h('section', { class: 'card' }, h('div', { class: 'sec-head' }, h('h2', { text: 'Customer Activity' }), link('/admin/activity', 'See all')),
      table([{ label: 'Activity', render: (r) => r.event_type.replace(/_/g, ' ').toLowerCase() }, { label: 'Customer', key: 'customer' }, { label: 'Book', key: 'book' }, { label: 'When', render: (r) => fmtDate(r.created_at) }], d.recentActivity, 'No activity yet.')));

  page('Overview', h('div', { class: 'dash' }, cards, recent, weekly, licences, quick, history, totals, lists));
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
    h('p', {}, link('/admin/books', '← All books')),
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
      btn(i.status === 'CONSUMED' ? 'New link' : 'Reissue', () => generateInvite(i.license_id, i.id))) : '') },
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
    { label: 'App installed', render: (d) => (d.installed_at ? fmtDate(d.installed_at) : h('span', { class: 'sub', text: 'Not yet' })) },
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
      { label: 'By', render: (r) => r.decided_by_name || (r.mode === 'SELF_SERVICE' ? 'Customer (OTP verified)' : r.mode === 'APP_INSTALL' ? 'Customer installed the app (not counted)' : '—') }, { label: 'When', render: (r) => fmtDate(r.decided_at || r.created_at) },
    ], reps.replacements, 'No replacements yet.')));
}

function licensesTable(rows) {
  const mng = can('access.manage');
  return table([
    { label: 'Customer', render: (l) => (l.full_name ? link(`/admin/customers/${l.customer_id}`, l.full_name) : '—') },
    { label: 'Book', key: 'book_title' },
    { label: 'Watermark ref', render: (l) => h('span', { class: 'mono', text: l.trace_code || '—', title: 'Printed on every page this buyer views' }) },
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

async function viewLicenses(q) {
  const d = await api('GET', `/api/admin/licenses?${q}`);
  page('Reading Licenses',
    h('p', { class: 'hint', text: 'Every PDF page a buyer views carries their name, masked number and watermark ref. To trace a leaked page, enter the ref printed on it.' }),
    filterBar(q, [{ name: 'ref', label: 'Watermark ref, e.g. 3FA9C21B' }, { name: 'status', label: 'All statuses', options: ['PENDING_ACTIVATION', 'ACTIVE', 'SUSPENDED', 'REVOKED', 'EXPIRED'].map((s) => [s, s.replace('_', ' ')]) }]),
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
    filterBar(q, [{ name: 'action', label: 'Action contains' }, { name: 'entityType', label: 'Any entity', options: ['book', 'book_edition', 'customer', 'order', 'invitation', 'license', 'device', 'administrator', 'website_settings', 'system_settings', 'security_event'].map((x) => [x, x]) }]),
    table([
      { label: 'When', render: (l) => fmtDate(l.created_at) }, { label: 'Administrator', render: (l) => l.admin_name || 'System' },
      { label: 'Action', key: 'action' }, { label: 'Entity', render: (l) => h('div', {}, l.entity_type, h('div', { class: 'sub mono', text: l.entity_id || '' })) },
      { label: 'Details', render: (l) => h('pre', { class: 'details', text: JSON.stringify(l.details) }) },
    ], d.logs, 'No entries.'), pager({ ...d, rows: d.logs.length }, (p) => setQuery({ page: p })));
}

// ===========================================================================
// Website content and WhatsApp
// ===========================================================================
async function viewWhatsapp() {
  const [{ content }, { books }] = await Promise.all([api('GET', '/api/admin/website'), api('GET', '/api/admin/books')]);
  const published = books.filter((b) => b.published);
  const featured = buildForm([
    { name: 'featuredBookId', label: 'Book named in the WhatsApp order message', type: 'select', nullable: true,
      options: [['', 'First published book'], ...published.map((b) => [b.id, b.title])],
      hint: 'Used for {book_title} in the order message. The download page itself is only ever shown through a private link.' },
  ], content.site || {}, { submit: 'Save', columns: false, onSubmit: (v) => act(() => api('PUT', '/api/admin/website/site', v), { ok: 'Saved', reload: false }) });
  const f = buildForm([
    { name: 'contactName', label: 'Contact name shown to visitors', placeholder: 'e.g. Kenedy Njume', hint: 'Visitors without a private link see: “To get a book, contact [name] on WhatsApp”' },
    { name: 'number', label: 'Business WhatsApp number', placeholder: '+254712345678', hint: 'The “Chat on WhatsApp” button opens a chat with this number' },
    { name: 'orderMessage', label: 'Prefilled order message', type: 'textarea', full: true, hint: 'Placeholders: {book_title}' },
    { name: 'invitationTemplate', label: 'Invitation message sent to customers', type: 'textarea', full: true, rows: 10, required: true,
      hint: 'Placeholders: {customer_name}, {book_title}, {invitation_link} (required), {expiry_hours}' },
  ], content.whatsapp || {}, { submit: 'Save WhatsApp settings', onSubmit: (v) => act(() => api('PUT', '/api/admin/website/whatsapp', v), { ok: 'Saved', reload: false }) });
  page('Download Page & WhatsApp',
    h('section', { class: 'card' }, h('h2', { text: 'Download page' }), featured.form),
    h('section', { class: 'card' }, h('h2', { text: 'WhatsApp' }), f.form),
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
  require_app_install: ['Reading only in the installed app', 'Customers must add the reader to their device before reading; the download page expires once installed'],
  require_whatsapp_code: ['Ask for a WhatsApp code when opening a link', 'Off: the link opens once with no code. On: the customer confirms their number with a code, and can sign in again with a code'],
};

async function viewSettings() {
  const { settings, schema } = await api('GET', '/api/admin/settings');
  const fields = Object.entries(schema).map(([k, s]) => (s.type === 'bool'
    ? { name: k, label: SETTING_LABELS[k]?.[0] || k, type: 'select', options: [['true', 'Yes'], ['false', 'No']], hint: SETTING_LABELS[k]?.[1] }
    : s.enum
    ? { name: k, label: SETTING_LABELS[k]?.[0] || k, type: 'select', options: s.enum.map((v) => [v, v === 'SELF_SERVICE' ? 'Customer can move it after verifying their number' : 'Requires my approval']), hint: SETTING_LABELS[k]?.[1] }
    : { name: k, label: SETTING_LABELS[k]?.[0] || k, type: 'number', min: s.min, maxv: s.max, nullable: s.nullable, hint: SETTING_LABELS[k]?.[1] }));
  const values = Object.fromEntries(Object.entries(settings).map(([k, v]) => [k, typeof v === 'boolean' ? String(v) : v]));
  const f = buildForm(fields, values, { submit: 'Save settings', onSubmit: (v) => act(() => api('PUT', '/api/admin/settings', v), { ok: 'Settings saved' }) });
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

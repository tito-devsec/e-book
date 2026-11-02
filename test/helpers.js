// Test harness: real PostgreSQL database, real HTTP server, real WebCrypto device keys.
import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import JSZip from 'jszip';

const { subtle } = crypto.webcrypto;

export async function setupEnv() {
  const storageDir = await fs.mkdtemp(path.join(os.tmpdir(), 'book-test-'));
  Object.assign(process.env, {
    NODE_ENV: 'test',
    DATABASE_URL: process.env.TEST_DATABASE_URL || 'postgres://bookapp:bookapp@localhost:5432/bookapp_test',
    HASH_PEPPER: 'test-pepper-0123456789abcdef0123456789abcdef',
    LOCAL_MASTER_KEY: crypto.randomBytes(32).toString('hex'),
    KMS_PROVIDER: 'local',
    STORAGE_DRIVER: 'local',
    STORAGE_LOCAL_DIR: storageDir,
    OTP_PROVIDER: 'memory',
    LOG_LEVEL: 'error',
    COOKIE_SECURE: 'false',
    TRUST_PROXY: 'false',
    READER_BASE_URL: 'http://127.0.0.1',
    DEFAULT_COUNTRY_CODE: '254',
  });
  return { storageDir };
}

export async function startServer() {
  const { storageDir } = await setupEnv();
  const { loadConfig } = await import('../src/config.js');
  const { createContext, createApp } = await import('../src/app.js');
  const { runMigrations } = await import('../src/migrate.js');
  const cfg = loadConfig();
  const ctx = createContext(cfg, { logger: { debug() {}, info() {}, warn() {}, error(m, f) { if (process.env.TEST_LOG) console.error(m, f); } } });
  await ctx.pool.query('DROP SCHEMA public CASCADE; CREATE SCHEMA public;');
  await runMigrations(ctx.pool, { info() {} });
  const app = createApp(ctx);
  const server = await new Promise((resolve) => { const s = app.listen(0, '127.0.0.1', () => resolve(s)); });
  const base = `http://127.0.0.1:${server.address().port}`;
  cfg.readerBaseUrl = base;
  return {
    ctx, base, cfg,
    async close() {
      await new Promise((r) => server.close(r));
      await ctx.pool.end();
      await fs.rm(storageDir, { recursive: true, force: true });
    },
  };
}

/** HTTP client with a cookie jar, CSRF token and optional device key (a "browser"). */
export class Browser {
  constructor(base, ua = 'Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 Chrome/126.0 Mobile Safari/537.36') {
    this.base = base; this.cookies = {}; this.csrf = null; this.ua = ua; this.keys = null;
  }

  async newDeviceKey() {
    this.keys = await subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign', 'verify']);
    const jwk = await subtle.exportKey('jwk', this.keys.publicKey);
    this.jwk = { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y };
    return this.jwk;
  }

  cookieHeader() { return Object.entries(this.cookies).map(([k, v]) => `${k}=${v}`).join('; '); }

  async request(method, url, body, { sign = false, headers = {}, signOverride } = {}) {
    const h = { 'user-agent': this.ua, ...headers };
    if (this.cookieHeader()) h.cookie = this.cookieHeader();
    if (this.csrf && !['GET', 'HEAD'].includes(method)) h['x-csrf-token'] = this.csrf;
    let payload;
    if (body instanceof FormData) payload = body;
    else if (body !== undefined) { payload = JSON.stringify(body); h['content-type'] = 'application/json'; }
    if (sign) {
      const ts = Date.now();
      const nonce = crypto.randomBytes(16).toString('base64url');
      const bodyHash = crypto.createHash('sha256').update(typeof payload === 'string' ? payload : '').digest('hex');
      const msg = `${method}\n${url}\n${ts}\n${nonce}\n${bodyHash}`;
      const sig = Buffer.from(await subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, this.keys.privateKey, Buffer.from(msg))).toString('base64url');
      Object.assign(h, { 'x-sig-ts': String(ts), 'x-sig-nonce': nonce, 'x-sig': sig }, signOverride || {});
    }
    const res = await fetch(this.base + url, { method, headers: h, body: payload, redirect: 'manual' });
    for (const c of res.headers.getSetCookie()) {
      const [pair, ...attrs] = c.split(';');
      const [k, v] = pair.split('=');
      if (attrs.some((a) => /max-age=0|expires=thu, 01 jan 1970/i.test(a.trim())) || v === '') delete this.cookies[k.trim()];
      else this.cookies[k.trim()] = v;
    }
    const ct = res.headers.get('content-type') || '';
    const data = ct.includes('json') ? await res.json() : Buffer.from(await res.arrayBuffer());
    return { status: res.status, data, headers: res.headers };
  }

  get(url, opts) { return this.request('GET', url, undefined, opts); }
  post(url, body, opts) { return this.request('POST', url, body ?? {}, opts); }
}

export async function loginAdmin(env, { email = 'owner@example.com', password = 'correct horse battery 1', role = 'OWNER' } = {}) {
  const { hashPassword } = await import('../src/lib/crypto.js');
  await env.ctx.pool.query(
    `INSERT INTO administrators (email, full_name, password_hash, role_id) VALUES ($1,$2,$3,(SELECT id FROM roles WHERE name=$4))
     ON CONFLICT DO NOTHING`, [email, `${role} user`, await hashPassword(password), role]);
  const b = new Browser(env.base, 'admin-test');
  const r = await b.post('/api/admin/auth/login', { email, password });
  if (r.status !== 200) throw new Error(`admin login failed ${r.status} ${JSON.stringify(r.data)}`);
  b.csrf = r.data.csrf;
  return b;
}

export async function makeEpub({ chapters = 3 } = {}) {
  const zip = new JSZip();
  zip.file('mimetype', 'application/epub+zip', { compression: 'STORE' });
  zip.file('META-INF/container.xml', `<?xml version="1.0"?><container version="1.0" xmlns="urn:oasis:names:tc:opendocument:xmlns:container">
    <rootfiles><rootfile full-path="OEBPS/content.opf" media-type="application/oebps-package+xml"/></rootfiles></container>`);
  const items = []; const spine = []; const navLis = [];
  for (let i = 1; i <= chapters; i += 1) {
    items.push(`<item id="c${i}" href="text/ch${i}.xhtml" media-type="application/xhtml+xml"/>`);
    spine.push(`<itemref idref="c${i}"/>`);
    navLis.push(`<li><a href="text/ch${i}.xhtml">Chapter ${i}</a></li>`);
    zip.file(`OEBPS/text/ch${i}.xhtml`, `<?xml version="1.0" encoding="utf-8"?><html xmlns="http://www.w3.org/1999/xhtml"><head><title>c${i}</title>
      <script>alert('x')</script></head><body><h1>Chapter ${i}</h1><p onclick="steal()">Secret text of chapter ${i}.</p>
      ${i === 1 ? '<img src="../images/fig.png" alt="figure"/><a href="ch2.xhtml#start">next</a><a href="javascript:alert(1)">bad</a><iframe src="https://evil.example"></iframe>' : ''}
      </body></html>`);
  }
  items.push('<item id="nav" href="nav.xhtml" media-type="application/xhtml+xml" properties="nav"/>');
  items.push('<item id="fig" href="images/fig.png" media-type="image/png"/>');
  zip.file('OEBPS/nav.xhtml', `<html xmlns="http://www.w3.org/1999/xhtml" xmlns:epub="http://www.idpf.org/2007/ops"><body>
    <nav epub:type="toc"><ol>${navLis.join('')}</ol></nav></body></html>`);
  zip.file('OEBPS/images/fig.png', Buffer.from('89504e470d0a1a0a0000000d49484452000000010000000108060000001f15c4890000000d49444154789c6360000002000154a24f5d0000000049454e44ae426082', 'hex'));
  zip.file('OEBPS/content.opf', `<?xml version="1.0"?><package xmlns="http://www.idpf.org/2007/opf" version="3.0">
    <metadata xmlns:dc="http://purl.org/dc/elements/1.1/"><dc:title>Test Book</dc:title><dc:creator>Author</dc:creator></metadata>
    <manifest>${items.join('')}</manifest><spine>${spine.join('')}</spine></package>`);
  return zip.generateAsync({ type: 'nodebuffer' });
}

export function makePdf(pages = 2) {
  const objs = [];
  const kids = [];
  objs.push('<< /Type /Catalog /Pages 2 0 R >>');
  objs.push(null); // pages placeholder
  for (let i = 0; i < pages; i += 1) {
    const pageNum = objs.length + 1;
    const contentNum = pageNum + 1;
    kids.push(`${pageNum} 0 R`);
    const stream = `BT /F1 24 Tf 40 300 Td (Page ${i + 1}) Tj ET`;
    objs.push(`<< /Type /Page /Parent 2 0 R /MediaBox [0 0 300 400] /Contents ${contentNum} 0 R /Resources << /Font << /F1 << /Type /Font /Subtype /Type1 /BaseFont /Helvetica >> >> >> >>`);
    objs.push(`<< /Length ${stream.length} >>\nstream\n${stream}\nendstream`);
  }
  objs[1] = `<< /Type /Pages /Kids [${kids.join(' ')}] /Count ${pages} >>`;
  let out = '%PDF-1.4\n';
  const offsets = [];
  objs.forEach((o, i) => { offsets.push(out.length); out += `${i + 1} 0 obj\n${o}\nendobj\n`; });
  const xref = out.length;
  out += `xref\n0 ${objs.length + 1}\n0000000000 65535 f \n${offsets.map((o) => `${String(o).padStart(10, '0')} 00000 n \n`).join('')}`;
  out += `trailer\n<< /Size ${objs.length + 1} /Root 1 0 R >>\nstartxref\n${xref}\n%%EOF\n`;
  return Buffer.from(out, 'latin1');
}

export const PNG_1PX = Buffer.from('89504e470d0a1a0a0000000d49484452000000010000000108060000001f15c4890000000d49444154789c6360000002000154a24f5d0000000049454e44ae426082', 'hex');

/** Create a published book with a ready EPUB edition. */
export async function createBook(admin, { title = 'Test Book', epub, maxDevices } = {}) {
  const r = await admin.post('/api/admin/books', { title, author: 'Kenedy Njume', priceAmount: '1500', currency: 'KES', description: 'A book.', ...(maxDevices ? { maxDevices } : {}) });
  if (r.status !== 201) throw new Error(JSON.stringify(r.data));
  const id = r.data.book.id;
  const fd = new FormData();
  fd.append('file', new Blob([epub || await makeEpub()]), 'book.epub');
  const up = await admin.post(`/api/admin/books/${id}/upload`, fd);
  if (up.status !== 201) throw new Error(JSON.stringify(up.data));
  const cover = new FormData();
  cover.append('file', new Blob([PNG_1PX]), 'cover.png');
  await admin.post(`/api/admin/books/${id}/cover`, cover);
  await admin.post(`/api/admin/books/${id}/publish`);
  return id;
}

let phoneSeq = 100000;
/** Register a customer + order; optionally verify payment. Returns ids. */
export async function createOrder(admin, bookId, { verify = true, phone } = {}) {
  phoneSeq += 1;
  const p = phone || `+2547${String(phoneSeq).padStart(8, '0')}`;
  const r = await admin.post('/api/admin/orders', {
    fullName: 'Jane Reader', phone: p, bookIds: [bookId], amount: '1500', currency: 'KES',
    paymentMethod: 'M-PESA', paymentReference: `REF${phoneSeq}`,
  });
  if (r.status !== 201) throw new Error(JSON.stringify(r.data));
  if (verify) {
    const v = await admin.post(`/api/admin/orders/${r.data.orderId}/verify-payment`, {});
    if (v.status !== 200) throw new Error(JSON.stringify(v.data));
    return { ...r.data, phone: p, licenseId: v.data.licenses[0] };
  }
  return { ...r.data, phone: p };
}

export async function invite(admin, licenseId, expiryHours) {
  const r = await admin.post('/api/admin/invitations', { licenseId, ...(expiryHours ? { expiryHours } : {}) });
  if (r.status !== 201) throw new Error(JSON.stringify(r.data));
  return { ...r.data, token: r.data.link.split('/access/')[1] };
}

export function lastOtp(env, phone) {
  const out = env.ctx.otpDelivery.outbox.filter((m) => m.phone === phone);
  return out[out.length - 1]?.code;
}

/** Full activation through the public API as a customer browser. */
export async function activate(env, browser, token, phone, { install = true } = {}) {
  await browser.newDeviceKey();
  const v = await browser.post('/api/access/validate-invitation', { token });
  if (v.data.state !== 'VALID') throw new Error(`invitation ${v.data.state}`);
  const otp = await browser.post('/api/access/request-otp', { token, phone });
  if (otp.status !== 200) throw new Error(`otp ${otp.status} ${JSON.stringify(otp.data)}`);
  const r = await browser.post('/api/access/activate', { token, challengeId: otp.data.challengeId, code: lastOtp(env, phone), deviceKey: browser.jwk });
  if (r.status !== 200) throw new Error(`activate ${r.status} ${JSON.stringify(r.data)}`);
  browser.csrf = r.data.csrf;
  if (install) await installApp(browser);
  return r.data;
}

/** What the installed app does on its first launch: mark this device as having the app. */
export async function installApp(browser) {
  const r = await browser.post('/api/reader/app-installed', {}, { sign: true });
  if (r.status !== 200) throw new Error(`app-installed ${r.status} ${JSON.stringify(r.data)}`);
}

/** Clear OTP cooldown so tests can request codes back to back. */
export async function clearOtpCooldown(env) {
  await env.ctx.pool.query(`UPDATE otp_challenges SET created_at = created_at - interval '2 minutes'`);
}

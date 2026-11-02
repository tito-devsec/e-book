// Administrative acceptance tests, plus reader content, progress and bookmarks.
import { test, before, after, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import {
  startServer, loginAdmin, createBook, createOrder, invite, Browser, activate, makePdf, makeEpub, PNG_1PX,
} from './helpers.js';

let env; let owner; let bookId;
before(async () => {
  env = await startServer();
  owner = await loginAdmin(env);
  bookId = await createBook(owner);
});
after(async () => { await env.close(); });
beforeEach(() => env.ctx.rateLimiter.reset());

test('unauthenticated users cannot reach management functions', async () => {
  const anon = new Browser(env.base);
  for (const url of ['/api/admin/overview', '/api/admin/customers', '/api/admin/books', '/api/admin/audit-logs']) {
    assert.equal((await anon.get(url)).status, 401, url);
  }
  assert.equal((await anon.post('/api/admin/books', { title: 'x' })).status, 401);
});

test('customer reading session cannot use admin routes', async () => {
  const o = await createOrder(owner, bookId);
  const inv = await invite(owner, o.licenseId);
  const reader = new Browser(env.base);
  await activate(env, reader, inv.token, o.phone);
  assert.equal((await reader.get('/api/admin/customers')).status, 401);
});

test('RBAC: support role is read-only', async () => {
  const support = await loginAdmin(env, { email: 'support@example.com', role: 'SUPPORT' });
  assert.equal((await support.get('/api/admin/customers')).status, 200);
  const r = await support.post('/api/admin/books', { title: 'Nope', author: 'x', priceAmount: '1', currency: 'TZS' });
  assert.equal(r.status, 403);
  assert.equal(r.data.code, 'PERMISSION_DENIED');
  assert.equal((await support.get('/api/admin/audit-logs')).status, 403);
});

test('CSRF token is required for admin state changes', async () => {
  const csrf = owner.csrf;
  owner.csrf = null;
  const r = await owner.post('/api/admin/books', { title: 'x', author: 'y', priceAmount: '1', currency: 'TZS' });
  owner.csrf = csrf;
  assert.equal(r.status, 403);
  assert.equal(r.data.code, 'CSRF');
});

test('cross-origin and form posts are rejected', async () => {
  const r = await owner.post('/api/admin/books', { title: 'x' }, { headers: { origin: 'https://evil.example' } });
  assert.equal(r.status, 403);
  const form = await fetch(`${env.base}/api/auth/request-otp`, { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: 'phone=%2B255700000000' });
  assert.equal(form.status, 415);
});

test('admin login: wrong password is generic and locks after repeated failures', async () => {
  await loginAdmin(env, { email: 'lock@example.com', role: 'MANAGER' });
  const b = new Browser(env.base);
  for (let i = 0; i < 5; i += 1) {
    const r = await b.post('/api/admin/auth/login', { email: 'lock@example.com', password: 'wrong password 123' });
    assert.equal(r.status, 401);
  }
  const locked = await b.post('/api/admin/auth/login', { email: 'lock@example.com', password: 'correct horse battery 1' });
  assert.equal(locked.status, 403);
  assert.equal(locked.data.code, 'ACCOUNT_LOCKED');
  const unknown = await b.post('/api/admin/auth/login', { email: 'nobody@example.com', password: 'whatever 12345' });
  assert.equal(unknown.data.code, 'INVALID_CREDENTIALS');
});

test('admin MFA (TOTP) enrolment and login', async () => {
  const { totpAt } = await import('../src/lib/crypto.js');
  const a = await loginAdmin(env, { email: 'mfa@example.com', role: 'MANAGER' });
  const setup = await a.post('/api/admin/auth/mfa/setup');
  assert.match(setup.data.uri, /^otpauth:\/\/totp\//);
  const step = Math.floor(Date.now() / 30000);
  assert.equal((await a.post('/api/admin/auth/mfa/enable', { code: totpAt(setup.data.secret, step) })).status, 200);
  const b = new Browser(env.base);
  const login = await b.post('/api/admin/auth/login', { email: 'mfa@example.com', password: 'correct horse battery 1' });
  assert.equal(login.data.mfaRequired, true);
  b.csrf = login.data.csrf;
  assert.equal((await b.get('/api/admin/overview')).status, 401, 'no access before second factor');
  assert.equal((await b.post('/api/admin/auth/mfa', { code: totpAt(setup.data.secret, step) })).status, 401, 'same code cannot be replayed');
  const ok = await b.post('/api/admin/auth/mfa', { code: totpAt(setup.data.secret, step + 1) });
  assert.equal(ok.status, 200);
  b.csrf = ok.data.csrf;
  assert.equal((await b.get('/api/admin/overview')).status, 200);
});

test('admin can create and edit books, upload covers, and replace editions without changing permissions', async () => {
  const created = await owner.post('/api/admin/books', { title: 'Edition Book', author: 'A', priceAmount: '999.50', currency: 'USD' });
  assert.equal(created.status, 201);
  const id = created.data.book.id;
  const patched = await owner.request('PATCH', `/api/admin/books/${id}`, { title: 'Edition Book 2', priceAmount: '1200' });
  assert.equal(patched.data.book.title, 'Edition Book 2');
  assert.equal(patched.data.book.price_amount, '1200.00');

  const bad = new FormData(); bad.append('file', new Blob([Buffer.from('not a book at all')]), 'x.epub');
  const badUp = await owner.post(`/api/admin/books/${id}/upload`, bad);
  assert.equal(badUp.status, 400);
  assert.equal(badUp.data.code, 'UNSUPPORTED_FILE');
  const badCover = new FormData(); badCover.append('file', new Blob([Buffer.from('<svg onload=alert(1)>')]), 'x.png');
  assert.equal((await owner.post(`/api/admin/books/${id}/cover`, badCover)).status, 400);
  assert.equal((await owner.post(`/api/admin/books/${id}/publish`)).status, 400, 'cannot publish without cover');

  const fd = new FormData(); fd.append('file', new Blob([await makeEpub({ chapters: 2 })]), 'v1.epub');
  const v1 = await owner.post(`/api/admin/books/${id}/upload`, fd);
  assert.equal(v1.status, 201);
  const o = await createOrder(owner, id);
  const inv = await invite(owner, o.licenseId);
  const reader = new Browser(env.base);
  await activate(env, reader, inv.token, o.phone);
  const m1 = await reader.get(`/api/reader/books/${id}/manifest`, { sign: true });
  assert.equal(m1.data.items.length, 2);

  const fd2 = new FormData(); fd2.append('file', new Blob([await makeEpub({ chapters: 4 })]), 'v2.epub'); fd2.append('label', 'Second edition');
  const v2 = await owner.post(`/api/admin/books/${id}/upload`, fd2);
  assert.equal(v2.data.edition.version, 2);
  const m2 = await reader.get(`/api/reader/books/${id}/manifest`, { sign: true });
  assert.equal(m2.status, 200, 'existing customer keeps access after edition replacement');
  assert.equal(m2.data.items.length, 4);
  // Roll back to v1
  assert.equal((await owner.post(`/api/admin/books/${id}/editions/${v1.data.edition.id}/activate`)).status, 200);
  assert.equal((await reader.get(`/api/reader/books/${id}/manifest`, { sign: true })).data.items.length, 2);
  const detail = await owner.get(`/api/admin/books/${id}`);
  assert.equal(detail.data.editions.length, 2);
});

test('original source file is encrypted at rest and never reachable by URL', async () => {
  const { rows: [e] } = await env.ctx.pool.query(`SELECT * FROM book_editions WHERE book_id=$1`, [bookId]);
  const raw = await fs.readFile(path.join(process.env.STORAGE_LOCAL_DIR, e.original_storage_key));
  assert.ok(!raw.includes(Buffer.from('Secret text')), 'ciphertext does not contain plaintext');
  assert.ok(!raw.subarray(0, 4).equals(Buffer.from([0x50, 0x4b, 0x03, 0x04])), 'not a readable zip');
  const anon = new Browser(env.base);
  for (const url of [`/${e.original_storage_key}`, `/storage/${e.original_storage_key}`, `/var/storage/${e.original_storage_key}`, '/static/../var/storage']) {
    const r = await anon.get(url);
    assert.notEqual(r.status, 200, url);
  }
  // Even an authorized reader gets sanitized chapters, never the original.
  const o = await createOrder(owner, bookId);
  const inv = await invite(owner, o.licenseId);
  const reader = new Browser(env.base);
  await activate(env, reader, inv.token, o.phone);
  const m = await reader.get(`/api/reader/books/${bookId}/manifest`, { sign: true });
  assert.ok(!JSON.stringify(m.data).includes('original'));
  const ch = await reader.get(`/api/reader/books/${bookId}/content/${m.data.items[0].id}`, { sign: true });
  const html = ch.data.toString();
  assert.match(html, /Secret text of chapter 1/);
  assert.doesNotMatch(html, /<script|onclick|javascript:|<iframe/i);
  assert.equal(ch.headers.get('cache-control'), 'no-store, private');
  assert.match(ch.headers.get('content-security-policy'), /sandbox/);
  // Image referenced by the chapter is served through the same authorized route.
  const imgId = html.match(/data-asset="([0-9a-f-]+)"/)[1];
  const img = await reader.get(`/api/reader/books/${bookId}/content/${imgId}`, { sign: true });
  assert.equal(img.status, 200);
  assert.ok(img.data.equals(PNG_1PX));
});

test('PDF editions: rendered server-side, never sent as PDF, watermarked per buyer, searchable', async () => {
  const created = await owner.post('/api/admin/books', { title: 'PDF Book', author: 'A', priceAmount: '10', currency: 'TZS', preferredFormat: 'PDF' });
  const id = created.data.book.id;
  const fd = new FormData(); fd.append('file', new Blob([makePdf(3)]), 'b.pdf');
  const up = await owner.post(`/api/admin/books/${id}/upload`, fd);
  assert.equal(up.status, 201, JSON.stringify(up.data));
  assert.equal(up.data.edition.format, 'PDF');
  assert.equal(up.data.edition.pageCount, 3);
  // Stored original is ciphertext.
  const { rows: [e] } = await env.ctx.pool.query('SELECT * FROM book_editions WHERE id=$1', [up.data.edition.id]);
  const stored = await fs.readFile(path.join(process.env.STORAGE_LOCAL_DIR, e.original_storage_key));
  assert.ok(!stored.includes(Buffer.from('%PDF')), 'original PDF is encrypted at rest');

  const readers = [];
  for (const name of ['Alice Reader', 'Bob Reader']) {
    const o = await createOrder(owner, id);
    await env.ctx.pool.query('UPDATE customers SET full_name=$2 WHERE id=$1', [o.customerId, name]);
    const inv = await invite(owner, o.licenseId);
    const b = new Browser(env.base);
    await activate(env, b, inv.token, o.phone);
    readers.push(b);
  }
  const m = await readers[0].get(`/api/reader/books/${id}/manifest`, { sign: true });
  assert.equal(m.data.format, 'PDF');
  assert.equal(m.data.items.length, 3);
  const pageA = await readers[0].get(`/api/reader/books/${id}/content/${m.data.items[1].id}`, { sign: true });
  const pageB = await readers[1].get(`/api/reader/books/${id}/content/${m.data.items[1].id}`, { sign: true });
  assert.equal(pageA.headers.get('content-type'), 'image/webp');
  assert.equal(pageA.data.subarray(8, 12).toString(), 'WEBP');
  assert.ok(!pageA.data.includes(Buffer.from('%PDF')));
  assert.ok(!pageA.data.equals(pageB.data), 'each buyer gets a differently watermarked page');
  const { rows: [clean] } = await env.ctx.pool.query(`SELECT * FROM book_assets WHERE id=$1`, [m.data.items[1].id]);
  assert.ok(!pageA.data.equals(await env.ctx.ingest.readAsset(e, clean)), 'delivered page is not the stored clean page');
  // Page text is used only for search and is never served whole.
  const { rows: [txt] } = await env.ctx.pool.query(`SELECT id FROM book_assets WHERE edition_id=$1 AND kind='PAGE_TEXT' LIMIT 1`, [e.id]);
  assert.equal((await readers[0].get(`/api/reader/books/${id}/content/${txt.id}`, { sign: true })).status, 404);
  const search = await readers[0].get(`/api/reader/books/${id}/search?q=Page%202`, { sign: true });
  assert.equal(search.data.supported, true);
  assert.equal(search.data.results[0].index, 1);
  // The admin can trace a page back to its buyer by the watermark reference.
  const { traceCode } = await import('../src/services/watermark.js');
  const lic = (await env.ctx.pool.query(`SELECT l.id FROM reading_licenses l JOIN customers c ON c.id=l.customer_id WHERE c.full_name='Alice Reader'`)).rows[0];
  const traced = await owner.get(`/api/admin/licenses?ref=${traceCode(process.env.HASH_PEPPER, lic.id)}`);
  assert.equal(traced.data.licenses.length, 1);
  assert.equal(traced.data.licenses[0].full_name, 'Alice Reader');
});

test('password-protected or broken PDFs are rejected', async () => {
  const created = await owner.post('/api/admin/books', { title: 'Broken', author: 'A', priceAmount: '10', currency: 'TZS' });
  const fd = new FormData(); fd.append('file', new Blob([Buffer.from('%PDF-1.4\nnot really a pdf')]), 'x.pdf');
  const up = await owner.post(`/api/admin/books/${created.data.book.id}/upload`, fd);
  assert.equal(up.status, 400);
  assert.equal(up.data.code, 'INVALID_PDF');
});

test('reader: chapter navigation, progress and bookmarks', async () => {
  const o = await createOrder(owner, bookId);
  const inv = await invite(owner, o.licenseId);
  const reader = new Browser(env.base);
  await activate(env, reader, inv.token, o.phone);
  const m = await reader.get(`/api/reader/books/${bookId}/manifest`, { sign: true });
  assert.equal(m.data.toc.length, 3);
  for (const item of m.data.items) {
    const c = await reader.get(`/api/reader/books/${bookId}/content/${item.id}`, { sign: true });
    assert.match(c.data.toString(), new RegExp(`Chapter ${item.index + 1}`));
  }
  const p = await reader.post('/api/reader/progress', { bookId, location: { index: 2, page: 1 }, percent: 80 }, { sign: true });
  assert.equal(p.status, 200);
  const g = await reader.get(`/api/reader/progress/${bookId}`, { sign: true });
  assert.deepEqual(g.data.progress.location, { index: 2, page: 1 });
  assert.equal(g.data.progress.percent, 80);
  const bm = await reader.post('/api/reader/bookmarks', { bookId, location: { index: 1, page: 0 }, label: 'Good part' }, { sign: true });
  assert.equal(bm.status, 201);
  const list = await reader.get(`/api/reader/bookmarks/${bookId}`, { sign: true });
  assert.equal(list.data.bookmarks.length, 1);
  const del = await reader.request('DELETE', `/api/reader/bookmarks/${bm.data.bookmark.id}`, undefined, { sign: true });
  assert.equal(del.status, 200);
  // Signature binds the body: tampering is rejected.
  const tampered = await reader.post('/api/reader/progress', { bookId, location: { index: 0 }, percent: 1 }, { sign: true, signOverride: { 'x-sig-ts': String(Date.now() - 1) } });
  assert.equal(tampered.status, 401);
  const { rows } = await env.ctx.pool.query(`SELECT event_type FROM reading_events WHERE customer_id=$1`, [o.customerId]);
  const types = new Set(rows.map((r) => r.event_type));
  for (const t of ['INVITATION_OPENED', 'DEVICE_REGISTERED', 'LICENSE_ACTIVATED', 'APP_INSTALLED', 'READER_OPENED', 'CHAPTER_ACCESSED']) {
    assert.ok(types.has(t), `event ${t}`);
  }
});

test('payment verification: reject, duplicate reference, audit trail', async () => {
  const o = await createOrder(owner, bookId, { verify: false });
  const rej = await owner.post(`/api/admin/orders/${o.orderId}/reject-payment`, { reason: 'Reference not found in statement' });
  assert.equal(rej.status, 200);
  assert.equal((await owner.post(`/api/admin/orders/${o.orderId}/verify-payment`, {})).status, 400, 'rejected order cannot be verified');

  const a = await createOrder(owner, bookId, { verify: false });
  const b = await createOrder(owner, bookId, { verify: false });
  assert.equal((await owner.post(`/api/admin/orders/${a.orderId}/verify-payment`, { reference: 'DUPREF1' })).status, 200);
  const dup = await owner.post(`/api/admin/orders/${b.orderId}/verify-payment`, { reference: 'DUPREF1' });
  assert.equal(dup.status, 409, 'same payment reference cannot verify two orders');
  const detail = await owner.get(`/api/admin/orders/${a.orderId}`);
  assert.deepEqual(detail.data.auditTrail.map((x) => x.action), ['order.create', 'payment.verify']);
  assert.equal(detail.data.licenses.length, 1);
  assert.equal(detail.data.payments[0].status, 'VERIFIED');
});

test('register customer with verified payment in one step; search and filter customers', async () => {
  const r = await owner.post('/api/admin/orders', {
    fullName: 'Searchable Person', phone: '0711222333', email: 'p@example.com', bookIds: [bookId], amount: '1500',
    paymentMethod: 'Bank', paymentReference: 'BANK-777', paymentStatus: 'VERIFIED', notes: 'VIP',
  });
  assert.equal(r.status, 201, JSON.stringify(r.data));
  assert.equal(r.data.licenses.length, 1);
  const s = await owner.get('/api/admin/customers?q=Searchable');
  assert.equal(s.data.customers.length, 1);
  assert.equal(s.data.customers[0].phone_e164, '+255711222333');
  assert.equal(s.data.customers[0].status, 'PAID');
  const f = await owner.get('/api/admin/customers?status=PAID&sort=name&dir=asc&limit=2&page=1');
  assert.ok(f.data.customers.length <= 2);
  const d = await owner.get(`/api/admin/customers/${r.data.customerId}`);
  assert.equal(d.data.orders.length, 1);
});

test('admin can review security events, resolve them, and every action is audited', async () => {
  const ev = await owner.get('/api/admin/security-events?open=true');
  assert.equal(ev.status, 200);
  assert.ok(ev.data.events.length > 0);
  const id = ev.data.events[0].id;
  assert.equal((await owner.post(`/api/admin/security-events/${id}/resolve`, { resolution: 'Investigated' })).status, 200);
  const logs = await owner.get('/api/admin/audit-logs?limit=200');
  const actions = new Set(logs.data.logs.map((l) => l.action));
  for (const a of ['book.create', 'book.edition_upload', 'book.publish', 'order.create', 'payment.verify', 'invitation.create', 'security_event.resolve']) {
    assert.ok(actions.has(a), a);
  }
  await assert.rejects(env.ctx.pool.query('DELETE FROM audit_logs'), /append-only/);
});

test('overview metrics come from the database', async () => {
  const r = await owner.get('/api/admin/overview');
  const { rows: [{ n }] } = await env.ctx.pool.query('SELECT count(*)::int AS n FROM orders');
  assert.equal(r.data.metrics.total_orders, n);
  assert.ok(Array.isArray(r.data.recentActivity));
});

test('visitors without a link see only a contact message; no book, no marketing website', async () => {
  assert.equal((await owner.request('PUT', '/api/admin/website/whatsapp', {
    number: '+255700111222', orderMessage: 'Hi, I want {book_title}', invitationTemplate: 'Hi {customer_name} {invitation_link}',
  })).status, 200);
  assert.equal((await owner.request('PUT', '/api/admin/website/site', { featuredBookId: bookId })).status, 200);
  const bad = await owner.request('PUT', '/api/admin/website/whatsapp', { number: '+255700111222', invitationTemplate: 'no link' });
  assert.equal(bad.status, 400);
  assert.equal((await owner.request('PUT', '/api/admin/website/hero', { headline: 'x' })).status, 404, 'website sections are gone');
  assert.equal((await owner.post('/api/admin/testimonials', { authorName: 'A', quote: 'q' })).status, 404, 'testimonials are gone');
  assert.equal((await owner.request('PUT', '/api/admin/website/whatsapp', {
    contactName: 'Kenedy Njume', number: '+255700111222', orderMessage: 'Hi, I want {book_title}', invitationTemplate: 'Hi {customer_name} {invitation_link}',
  })).status, 200);
  const anon = new Browser(env.base);
  const info = await anon.get('/api/public/contact');
  assert.equal(info.data.contactName, 'Kenedy Njume');
  assert.match(info.data.orderUrl, /^https:\/\/wa\.me\/255700111222\?text=Hi%2C%20I%20want%20Test%20Book$/);
  assert.equal(info.data.book, undefined, 'no book is exposed to visitors without a link');
  assert.ok(!JSON.stringify(info.data).match(/storage_key|edition|phone_e164|cover/));
  assert.equal((await anon.get('/api/public/book')).status, 404);
  const home = await anon.get('/');
  assert.equal(home.status, 200);
  assert.match(home.data.toString(), /static\/reader\/app\.js/, 'home is the customer app');
  assert.doesNotMatch(home.data.toString(), /Order on WhatsApp|static\/site|DOWNLOAD BOOK/);
  assert.equal((await anon.get(`/media/covers/${bookId}`)).status, 200);
});

test('license suspend, reactivate and renew', async () => {
  const o = await createOrder(owner, bookId);
  const inv = await invite(owner, o.licenseId);
  const reader = new Browser(env.base);
  await activate(env, reader, inv.token, o.phone);
  assert.equal((await owner.post(`/api/admin/licenses/${o.licenseId}/suspend`, { reason: 'check' })).status, 200);
  assert.equal((await reader.get(`/api/reader/books/${bookId}/manifest`, { sign: true })).status, 404);
  assert.equal((await owner.post(`/api/admin/licenses/${o.licenseId}/reactivate`)).status, 200);
  assert.equal((await reader.get(`/api/reader/books/${bookId}/manifest`, { sign: true })).status, 200);
  assert.equal((await owner.post(`/api/admin/licenses/${o.licenseId}/renew`, { days: 30 })).status, 200);
  const { rows: [l] } = await env.ctx.pool.query('SELECT expires_at FROM reading_licenses WHERE id=$1', [o.licenseId]);
  assert.ok(new Date(l.expires_at) > new Date(Date.now() + 29 * 86400000));
});

test('service worker never caches API or book content', async () => {
  const sw = await fs.readFile(new URL('../public/reader/sw.js', import.meta.url), 'utf8');
  assert.match(sw, /\/api\//);
  assert.doesNotMatch(sw, /cache\.put\([^)]*api/i);
  const res = await new Browser(env.base).get('/sw.js');
  assert.equal(res.status, 200);
  const manifest = (await new Browser(env.base).get('/manifest.webmanifest')).data;
  assert.equal(manifest.display, 'standalone');
  assert.equal(manifest.start_url, '/app');
  assert.doesNotMatch(JSON.stringify(manifest), /access/);
});

test('the book kept in content/ is loaded once as the current edition and never replaces later uploads', async () => {
  const { loadBundledBook } = await import('../src/services/bundledBook.js');
  const fs = await import('node:fs/promises'); const os = await import('node:os'); const path = await import('node:path');
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'bundled-'));
  const file = path.join(dir, 'book.pdf');
  const { rows: [b] } = await env.ctx.pool.query(`SELECT id, slug, current_edition_id FROM books LIMIT 1`);
  await fs.writeFile(file, makePdf(3));
  const first = await loadBundledBook(env.ctx, { slug: b.slug, file });
  assert.ok(first && first.status === 'READY');
  const { rows: [after] } = await env.ctx.pool.query('SELECT current_edition_id FROM books WHERE id=$1', [b.id]);
  assert.equal(after.current_edition_id, first.id);
  assert.equal(await loadBundledBook(env.ctx, { slug: b.slug, file }), null, 'the same file is not loaded twice');
  assert.equal(await loadBundledBook(env.ctx, { slug: 'no-such-book', file }), null);
  // An earlier attempt that failed must not stop the file from being loaded again.
  await env.ctx.pool.query(`UPDATE book_editions SET status='FAILED' WHERE id=$1`, [first.id]);
  const retry = await loadBundledBook(env.ctx, { slug: b.slug, file });
  assert.ok(retry && retry.status === 'READY' && retry.id !== first.id, 'loaded again after a failed attempt');
  await fs.rm(dir, { recursive: true, force: true });
});

test('PDF font folders end with a forward slash on every operating system (Windows paths)', async () => {
  const { factoryUrl } = await import('../src/services/ingest.js');
  assert.equal(factoryUrl('C:\\Users\\BAB AL SAFA\\e-book\\node_modules\\pdfjs-dist\\standard_fonts'), 'C:/Users/BAB AL SAFA/e-book/node_modules/pdfjs-dist/standard_fonts/');
  assert.equal(factoryUrl('C:\\x\\cmaps\\'), 'C:/x/cmaps/');
  assert.equal(factoryUrl('/opt/app/cmaps/'), '/opt/app/cmaps/');
});

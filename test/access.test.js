// Payment, private link and shared-link acceptance tests (spec sections 5 and 12).
// A private link is the proof of purchase: no WhatsApp code. It stays valid until the book is
// added to a device and the app opens; then it is used up.
import { test, before, after, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import {
  startServer, loginAdmin, createBook, createOrder, invite, Browser, activate, installApp,
} from './helpers.js';

let env; let admin; let bookId;
before(async () => {
  env = await startServer();
  admin = await loginAdmin(env);
  bookId = await createBook(admin);
});
after(async () => { await env.close(); });
// Every test runs from 127.0.0.1; reset the per-IP limiter so tests are independent.
beforeEach(() => env.ctx.rateLimiter.reset());

const openLink = async (b, token) => {
  const v = await b.post('/api/access/validate-invitation', { token });
  const p = await b.post('/api/access/prepare-app', { token });
  return { v, p };
};

// ---------------------------------------------------------------------------
// Payment and private links
// ---------------------------------------------------------------------------
test('unverified payment cannot receive a link', async () => {
  const o = await createOrder(admin, bookId, { verify: false });
  const { rows } = await env.ctx.pool.query('SELECT id FROM reading_licenses WHERE order_id=$1', [o.orderId]);
  assert.equal(rows.length, 0, 'no license exists before verification');
  const r = await admin.post('/api/admin/invitations', { licenseId: '00000000-0000-4000-8000-000000000000' });
  assert.equal(r.status, 404);
});

test('verified payment gets a link with a 256-bit token, stored only as a hash', async () => {
  const o = await createOrder(admin, bookId);
  const inv = await invite(admin, o.licenseId);
  assert.match(inv.link, /\/access\/[A-Za-z0-9_-]{43}$/);
  assert.equal(Buffer.from(inv.token, 'base64url').length, 32);
  const { rows: [row] } = await env.ctx.pool.query('SELECT * FROM invitations WHERE id=$1', [inv.invitation.id]);
  assert.equal(row.status, 'PENDING');
  assert.ok(!JSON.stringify(row).includes(inv.token), 'raw token is not stored');
  assert.ok(inv.message.includes(inv.link) && inv.message.includes('Jane Reader'));
  assert.ok(inv.whatsappUrl.startsWith('https://wa.me/'));
  const { rows: logs } = await env.ctx.pool.query(`SELECT details::text AS d FROM audit_logs WHERE entity_id=$1`, [inv.invitation.id]);
  assert.ok(logs.length > 0 && logs.every((l) => !l.d.includes(inv.token)), 'raw token is never logged');
});

test('link tokens are unique', async () => {
  const tokens = new Set();
  for (let i = 0; i < 5; i += 1) {
    const o = await createOrder(admin, bookId);
    tokens.add((await invite(admin, o.licenseId)).token);
  }
  assert.equal(tokens.size, 5);
});

test('link expires correctly', async () => {
  const o = await createOrder(admin, bookId);
  const inv = await invite(admin, o.licenseId);
  await env.ctx.pool.query(`UPDATE invitations SET expires_at = now() - interval '1 minute' WHERE id=$1`, [inv.invitation.id]);
  const { v, p } = await openLink(new Browser(env.base), inv.token);
  assert.equal(v.data.state, 'EXPIRED');
  assert.equal(p.status, 400);
});

test('opening the link does not use it up; adding the book and opening the app does', async () => {
  const o = await createOrder(admin, bookId);
  const inv = await invite(admin, o.licenseId);
  const b = new Browser(env.base);
  await b.newDeviceKey();
  // Open and refresh the page several times: still valid.
  for (let i = 0; i < 3; i += 1) {
    const { v, p } = await openLink(b, inv.token);
    assert.equal(v.data.state, 'VALID');
    assert.equal(v.data.book.title, 'Test Book');
    assert.ok(!JSON.stringify(v.data).includes(o.phone), 'customer phone is not revealed');
    assert.match(p.data.claim, /^[A-Za-z0-9_-]{43}$/);
  }
  const { rows: [still] } = await env.ctx.pool.query('SELECT status FROM invitations WHERE id=$1', [inv.invitation.id]);
  assert.equal(still.status, 'PENDING');
  // The app's first open claims the link.
  const { p } = await openLink(b, inv.token);
  const c = await b.post('/api/access/claim', { claim: p.data.claim, deviceKey: b.jwk });
  assert.equal(c.status, 200);
  assert.equal(c.data.bookId, bookId);
  const { rows: [done] } = await env.ctx.pool.query('SELECT status FROM invitations WHERE id=$1', [inv.invitation.id]);
  assert.equal(done.status, 'CONSUMED');
  // The link is used up: another device cannot use any code from it...
  const other = new Browser(env.base);
  await other.newDeviceKey();
  assert.equal((await other.post('/api/access/claim', { claim: p.data.claim, deviceKey: other.jwk })).data.code, 'CLAIM_INVALID');
  // ...but the app on this device can always sign itself in again with the code it was added with.
  b.cookies = {};
  const again = await b.post('/api/access/claim', { claim: p.data.claim, deviceKey: b.jwk });
  assert.equal(again.status, 200);
  assert.equal(again.data.bookId, bookId);
  const { rows: [{ n }] } = await env.ctx.pool.query('SELECT count(*)::int AS n FROM registered_devices WHERE customer_id=$1', [o.customerId]);
  assert.equal(n, 1, 'still one device');
  c.data.csrf = again.data.csrf;
  b.csrf = c.data.csrf;
  assert.equal((await b.get(`/api/reader/books/${bookId}/manifest`, { sign: true })).status, 200, 'app is ready to read');
});

test('reloading the page after adding the book does not break the app that was added', async () => {
  const o = await createOrder(admin, bookId);
  const inv = await invite(admin, o.licenseId);
  const b = new Browser(env.base);
  await b.newDeviceKey();
  const added = (await openLink(b, inv.token)).p.data.claim; // the app is added with this code
  await openLink(b, inv.token); // the page reloads afterwards
  assert.equal((await b.post('/api/access/claim', { claim: added, deviceKey: b.jwk })).status, 200);
  // Once used, the newer code does not work on another phone.
  const later = (await b.post('/api/access/validate-invitation', { token: inv.token })).data.state;
  assert.equal(later, 'CONSUMED');
});

test('a code from a used link does not work on another phone', async () => {
  const o = await createOrder(admin, bookId);
  const inv = await invite(admin, o.licenseId);
  const b = new Browser(env.base);
  await b.newDeviceKey();
  const first = (await openLink(b, inv.token)).p.data.claim;
  const second = (await openLink(b, inv.token)).p.data.claim;
  assert.equal((await b.post('/api/access/claim', { claim: second, deviceKey: b.jwk })).status, 200);
  const thief = new Browser(env.base);
  await thief.newDeviceKey();
  assert.equal((await thief.post('/api/access/claim', { claim: first, deviceKey: thief.jwk })).data.code, 'CLAIM_INVALID');
  assert.equal((await thief.post('/api/access/claim', { claim: second, deviceKey: thief.jwk })).data.code, 'CLAIM_INVALID');
});

test('visiting the link page alone does not activate anything', async () => {
  const o = await createOrder(admin, bookId);
  const inv = await invite(admin, o.licenseId);
  const b = new Browser(env.base);
  const page = await b.get(`/access/${inv.token}`);
  assert.equal(page.status, 200);
  assert.equal(page.headers.get('referrer-policy'), 'no-referrer');
  await openLink(b, inv.token);
  const { rows: [l] } = await env.ctx.pool.query('SELECT status FROM reading_licenses WHERE id=$1', [o.licenseId]);
  assert.equal(l.status, 'PENDING_ACTIVATION');
});

test('a used link cannot be used by anyone else (Scenario B)', async () => {
  const o = await createOrder(admin, bookId);
  const inv = await invite(admin, o.licenseId);
  await activate(env, new Browser(env.base), inv.token);
  const other = new Browser(env.base);
  const { v, p } = await openLink(other, inv.token);
  assert.equal(v.data.state, 'CONSUMED');
  assert.ok(!JSON.stringify(v.data).includes('Jane'), 'no customer information revealed');
  assert.equal(p.status, 400);
  const { rows } = await env.ctx.pool.query(`SELECT 1 FROM security_events WHERE invitation_id=$1 AND event_type='REUSED_INVITATION'`, [inv.invitation.id]);
  assert.ok(rows.length >= 1);
});

test('a revoked link cannot be used, even with a claim token prepared earlier', async () => {
  const o = await createOrder(admin, bookId);
  const inv = await invite(admin, o.licenseId);
  const b = new Browser(env.base);
  await b.newDeviceKey();
  const { p } = await openLink(b, inv.token);
  assert.equal((await admin.post(`/api/admin/invitations/${inv.invitation.id}/revoke`)).status, 200);
  const c = await b.post('/api/access/claim', { claim: p.data.claim, deviceKey: b.jwk });
  assert.equal(c.status, 400);
  assert.equal(c.data.code, 'CLAIM_INVALID');
});

test('a new link replaces the old one: the old link stops working', async () => {
  const o = await createOrder(admin, bookId);
  const first = await invite(admin, o.licenseId);
  const r = await admin.post(`/api/admin/invitations/${first.invitation.id}/resend`, {});
  assert.equal(r.status, 201);
  const second = r.data.link.split('/access/')[1];
  assert.notEqual(second, first.token);
  const b = new Browser(env.base);
  assert.equal((await b.post('/api/access/validate-invitation', { token: first.token })).data.state, 'REVOKED');
  assert.equal((await b.post('/api/access/validate-invitation', { token: second })).data.state, 'VALID');
});

test('the WhatsApp code endpoints are gone', async () => {
  const b = new Browser(env.base);
  for (const url of ['/api/access/request-otp', '/api/auth/request-otp', '/api/auth/verify-otp', '/api/access/replace-device', '/api/access/activate']) {
    assert.equal((await b.post(url, { phone: '+255700000000' })).status, 404, url);
  }
});

// ---------------------------------------------------------------------------
// Shared reader URL and sessions
// ---------------------------------------------------------------------------
test('reader URL shared with an unauthorized browser gets no content (Scenario C)', async () => {
  const o = await createOrder(admin, bookId);
  const inv = await invite(admin, o.licenseId);
  const owner = new Browser(env.base);
  await activate(env, owner, inv.token);
  const man = await owner.get(`/api/reader/books/${bookId}/manifest`, { sign: true });
  const chapterId = man.data.items[0].id;
  const stranger = new Browser(env.base);
  const page = await stranger.get(`/read/${bookId}`);
  assert.equal(page.status, 200, 'shell loads');
  assert.ok(!page.data.toString().includes('Secret text'), 'shell contains no book content');
  assert.equal((await stranger.get('/api/auth/session')).status, 401);
  for (const url of [`/api/reader/books/${bookId}/manifest`, `/api/reader/books/${bookId}/content/${chapterId}`, '/api/reader/library']) {
    const r = await stranger.get(url);
    assert.equal(r.status, 401, url);
    assert.ok(!JSON.stringify(r.data).includes('Secret'));
  }
});

test('another customer cannot read a book they did not buy (404, not 403)', async () => {
  const otherBook = await createBook(admin, { title: 'Other Book' });
  const o = await createOrder(admin, bookId);
  const inv = await invite(admin, o.licenseId);
  const b = new Browser(env.base);
  await activate(env, b, inv.token);
  assert.equal((await b.get(`/api/reader/books/${otherBook}/manifest`, { sign: true })).status, 404);
  const { rows } = await env.ctx.pool.query(`SELECT 1 FROM security_events WHERE customer_id=$1 AND event_type='UNAUTHORIZED_CONTENT_REQUEST'`, [o.customerId]);
  assert.ok(rows.length >= 1);
});

test('stolen session cookie without the device key is rejected', async () => {
  const o = await createOrder(admin, bookId);
  const inv = await invite(admin, o.licenseId);
  const owner = new Browser(env.base);
  await activate(env, owner, inv.token);
  const thief = new Browser(env.base);
  thief.cookies = { ...owner.cookies };
  thief.csrf = owner.csrf;
  assert.equal((await thief.get('/api/reader/library')).status, 401, 'unsigned');
  await thief.newDeviceKey();
  const r = await thief.get('/api/reader/library', { sign: true });
  assert.equal(r.status, 401);
  assert.equal(r.data.code, 'SIGNATURE_INVALID');
});

test('replayed signed request is rejected', async () => {
  const o = await createOrder(admin, bookId);
  const inv = await invite(admin, o.licenseId);
  const b = new Browser(env.base);
  await activate(env, b, inv.token);
  const ts = Date.now(); const nonce = crypto.randomBytes(16).toString('base64url');
  const bodyHash = crypto.createHash('sha256').update('').digest('hex');
  const msg = `GET\n/api/reader/library\n${ts}\n${nonce}\n${bodyHash}`;
  const sig = Buffer.from(await crypto.webcrypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, b.keys.privateKey, Buffer.from(msg))).toString('base64url');
  const h = { 'x-sig-ts': String(ts), 'x-sig-nonce': nonce, 'x-sig': sig };
  assert.equal((await b.get('/api/reader/library', { headers: h })).status, 200);
  assert.equal((await b.get('/api/reader/library', { headers: h })).status, 401);
});

test('expired session: the customer gets back in with a new link from the owner (Scenario D)', async () => {
  const o = await createOrder(admin, bookId);
  const b = new Browser(env.base);
  await activate(env, b, (await invite(admin, o.licenseId)).token);
  await env.ctx.pool.query(`UPDATE reading_sessions SET expires_at = now() - interval '1 second' WHERE customer_id=$1`, [o.customerId]);
  const r = await b.get('/api/reader/library', { sign: true });
  assert.equal(r.status, 401);
  assert.equal(r.data.code, 'SESSION_EXPIRED');
  // No new purchase: the owner sends a new link for the same license.
  const again = await admin.post('/api/admin/invitations', { licenseId: o.licenseId });
  assert.equal(again.status, 201);
  await activate(env, b, again.data.link.split('/access/')[1]);
  assert.equal((await b.get(`/api/reader/books/${bookId}/manifest`, { sign: true })).status, 200);
});

test('logout ends the session and asks the browser to clear stored data', async () => {
  const o = await createOrder(admin, bookId);
  const b = new Browser(env.base);
  await activate(env, b, (await invite(admin, o.licenseId)).token);
  const cookies = { ...b.cookies };
  const out = await b.post('/api/auth/logout');
  assert.equal(out.status, 200);
  assert.match(out.headers.get('clear-site-data'), /storage/);
  b.cookies = cookies;
  assert.equal((await b.get('/api/reader/library', { sign: true })).status, 401);
});

// ---------------------------------------------------------------------------
// Devices, licenses, suspension
// ---------------------------------------------------------------------------
test('previously authorized device after admin revocation is denied (Scenario 10)', async () => {
  const o = await createOrder(admin, bookId);
  const b = new Browser(env.base);
  await activate(env, b, (await invite(admin, o.licenseId)).token);
  const { rows: [d] } = await env.ctx.pool.query(`SELECT id FROM registered_devices WHERE customer_id=$1`, [o.customerId]);
  assert.equal((await admin.post(`/api/admin/devices/${d.id}/revoke`, {})).status, 200);
  const r = await b.get(`/api/reader/books/${bookId}/manifest`, { sign: true });
  assert.equal(r.status, 403);
  assert.equal(r.data.code, 'DEVICE_REVOKED');
});

test('revoked license blocks content on the next request (Scenario 8)', async () => {
  const o = await createOrder(admin, bookId);
  const b = new Browser(env.base);
  await activate(env, b, (await invite(admin, o.licenseId)).token);
  assert.equal((await b.get(`/api/reader/books/${bookId}/manifest`, { sign: true })).status, 200);
  assert.equal((await admin.post(`/api/admin/licenses/${o.licenseId}/revoke`, { reason: 'refund' })).status, 200);
  assert.equal((await b.get(`/api/reader/books/${bookId}/manifest`, { sign: true })).status, 404);
  assert.equal((await b.get('/api/reader/library', { sign: true })).data.books.length, 0);
});

test('suspended customer is locked out and their unused links stop working', async () => {
  const o = await createOrder(admin, bookId);
  const b = new Browser(env.base);
  await activate(env, b, (await invite(admin, o.licenseId)).token);
  const pending = await admin.post('/api/admin/invitations', { licenseId: o.licenseId });
  assert.equal((await admin.post(`/api/admin/customers/${o.customerId}/suspend`, { reason: 'sharing' })).status, 200);
  const r = await b.get('/api/reader/library', { sign: true });
  assert.equal(r.status, 403);
  assert.equal(r.data.code, 'ACCOUNT_SUSPENDED');
  const v = await new Browser(env.base).post('/api/access/validate-invitation', { token: pending.data.link.split('/access/')[1] });
  assert.equal(v.data.state, 'REVOKED');
});

test('expired license denies access', async () => {
  const o = await createOrder(admin, bookId);
  const b = new Browser(env.base);
  await activate(env, b, (await invite(admin, o.licenseId)).token);
  await env.ctx.pool.query(`UPDATE reading_licenses SET expires_at = now() - interval '1 minute' WHERE id=$1`, [o.licenseId]);
  assert.equal((await b.get(`/api/reader/books/${bookId}/manifest`, { sign: true })).status, 404);
  const { rows: [l] } = await env.ctx.pool.query('SELECT status FROM reading_licenses WHERE id=$1', [o.licenseId]);
  assert.equal(l.status, 'EXPIRED');
});

test('per-IP limiter blocks guessing of link tokens', async () => {
  const b = new Browser(env.base);
  let last;
  for (let i = 0; i < 31; i += 1) last = await b.post('/api/access/validate-invitation', { token: crypto.randomBytes(32).toString('base64url') });
  assert.equal(last.status, 429);
  assert.ok(last.headers.get('retry-after'));
});

// ---------------------------------------------------------------------------
// Reading only in the added app
// ---------------------------------------------------------------------------
test('the claim marks the app as added; content is refused on a device without the app', async () => {
  const o = await createOrder(admin, bookId);
  const b = new Browser(env.base);
  await activate(env, b, (await invite(admin, o.licenseId)).token);
  assert.equal((await b.get('/api/auth/session')).data.device.installed, true);
  assert.equal((await b.get(`/api/reader/books/${bookId}`, { sign: true })).data.installedOnThisDevice, true);
  await env.ctx.pool.query(`UPDATE registered_devices SET installed_at=NULL WHERE customer_id=$1`, [o.customerId]);
  const blocked = await b.get(`/api/reader/books/${bookId}/manifest`, { sign: true });
  assert.equal(blocked.status, 403);
  assert.equal(blocked.data.code, 'APP_INSTALL_REQUIRED');
  await installApp(b);
  assert.equal((await b.get(`/api/reader/books/${bookId}/manifest`, { sign: true })).status, 200);
});

test('owner can allow reading in the browser by turning the app requirement off', async () => {
  const o = await createOrder(admin, bookId);
  const b = new Browser(env.base);
  await activate(env, b, (await invite(admin, o.licenseId)).token);
  await env.ctx.pool.query(`UPDATE registered_devices SET installed_at=NULL WHERE customer_id=$1`, [o.customerId]);
  await admin.request('PUT', '/api/admin/settings', { require_app_install: false });
  try {
    assert.equal((await b.get(`/api/reader/books/${bookId}/manifest`, { sign: true })).status, 200);
    assert.equal((await b.get('/api/auth/session')).data.requireApp, false);
  } finally {
    await admin.request('PUT', '/api/admin/settings', { require_app_install: true });
  }
});

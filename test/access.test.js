// Payment, invitation, identity and shared-link acceptance tests (spec sections 5 and 12).
import { test, before, after, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import {
  startServer, loginAdmin, createBook, createOrder, invite, Browser, activate, lastOtp, clearOtpCooldown,
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

// ---------------------------------------------------------------------------
// Payment and invitation
// ---------------------------------------------------------------------------
test('unverified payment cannot receive an invitation', async () => {
  const o = await createOrder(admin, bookId, { verify: false });
  const { rows } = await env.ctx.pool.query('SELECT id FROM reading_licenses WHERE order_id=$1', [o.orderId]);
  assert.equal(rows.length, 0, 'no license exists before verification');
  // Even a forged license id for this order cannot be invited.
  const r = await admin.post('/api/admin/invitations', { licenseId: '00000000-0000-4000-8000-000000000000' });
  assert.equal(r.status, 404);
});

test('verified payment can receive an invitation with a 256-bit token, stored only as a hash', async () => {
  const o = await createOrder(admin, bookId);
  const inv = await invite(admin, o.licenseId);
  assert.match(inv.link, /\/access\/[A-Za-z0-9_-]{43}$/);
  assert.equal(Buffer.from(inv.token, 'base64url').length, 32);
  const { rows: [row] } = await env.ctx.pool.query('SELECT * FROM invitations WHERE id=$1', [inv.invitation.id]);
  assert.equal(row.status, 'PENDING');
  assert.notEqual(row.token_hash, inv.token);
  assert.ok(!JSON.stringify(row).includes(inv.token), 'raw token is not stored');
  assert.ok(inv.message.includes(inv.link) && inv.message.includes('Jane Reader'));
  assert.ok(inv.whatsappUrl.startsWith('https://wa.me/'));
  const { rows: logs } = await env.ctx.pool.query(`SELECT details::text AS d FROM audit_logs WHERE entity_id=$1`, [inv.invitation.id]);
  assert.ok(logs.length > 0 && logs.every((l) => !l.d.includes(inv.token)), 'raw token is never logged');
});

test('invitation tokens are unique', async () => {
  const tokens = new Set();
  for (let i = 0; i < 5; i += 1) {
    const o = await createOrder(admin, bookId);
    tokens.add((await invite(admin, o.licenseId)).token);
  }
  assert.equal(tokens.size, 5);
});

test('invitation expires correctly', async () => {
  const o = await createOrder(admin, bookId);
  const inv = await invite(admin, o.licenseId);
  await env.ctx.pool.query(`UPDATE invitations SET expires_at = now() - interval '1 minute' WHERE id=$1`, [inv.invitation.id]);
  const b = new Browser(env.base);
  const v = await b.post('/api/access/validate-invitation', { token: inv.token });
  assert.equal(v.data.state, 'EXPIRED');
  const otp = await b.post('/api/access/request-otp', { token: inv.token, phone: o.phone });
  assert.equal(otp.status, 400);
  assert.equal(otp.data.code, 'INVITATION_EXPIRED');
});

test('invitation is consumed only after successful activation; failed OTP does not consume it', async () => {
  const o = await createOrder(admin, bookId);
  const inv = await invite(admin, o.licenseId);
  const b = new Browser(env.base);
  await b.newDeviceKey();
  const v = await b.post('/api/access/validate-invitation', { token: inv.token });
  assert.equal(v.data.state, 'VALID');
  assert.equal(v.data.book.title, 'Test Book');
  assert.ok(!JSON.stringify(v.data).includes(o.phone), 'full phone number is not revealed');
  const otp = await b.post('/api/access/request-otp', { token: inv.token, phone: o.phone });
  const wrong = lastOtp(env, o.phone) === '000000' ? '111111' : '000000';
  const bad = await b.post('/api/access/activate', { token: inv.token, challengeId: otp.data.challengeId, code: wrong, deviceKey: b.jwk });
  assert.equal(bad.status, 400);
  assert.equal(bad.data.code, 'OTP_WRONG');
  const { rows: [still] } = await env.ctx.pool.query('SELECT status FROM invitations WHERE id=$1', [inv.invitation.id]);
  assert.equal(still.status, 'PENDING');
  const good = await b.post('/api/access/activate', { token: inv.token, challengeId: otp.data.challengeId, code: lastOtp(env, o.phone), deviceKey: b.jwk });
  assert.equal(good.status, 200);
  const { rows: [done] } = await env.ctx.pool.query('SELECT status FROM invitations WHERE id=$1', [inv.invitation.id]);
  assert.equal(done.status, 'CONSUMED');
});

test('visiting the invitation URL alone does not activate anything', async () => {
  const o = await createOrder(admin, bookId);
  const inv = await invite(admin, o.licenseId);
  const b = new Browser(env.base);
  const page = await b.get(`/access/${inv.token}`);
  assert.equal(page.status, 200);
  await b.post('/api/access/validate-invitation', { token: inv.token });
  const { rows: [l] } = await env.ctx.pool.query('SELECT status FROM reading_licenses WHERE id=$1', [o.licenseId]);
  assert.equal(l.status, 'PENDING_ACTIVATION');
  assert.equal(page.headers.get('referrer-policy'), 'no-referrer');
});

test('reused invitation cannot activate a second customer (Scenario B)', async () => {
  const o = await createOrder(admin, bookId);
  const inv = await invite(admin, o.licenseId);
  await activate(env, new Browser(env.base), inv.token, o.phone);
  const other = new Browser(env.base);
  const v = await other.post('/api/access/validate-invitation', { token: inv.token });
  assert.equal(v.data.state, 'CONSUMED');
  assert.ok(!JSON.stringify(v.data).includes('Jane'), 'no customer information revealed');
  const otp = await other.post('/api/access/request-otp', { token: inv.token, phone: o.phone });
  assert.equal(otp.data.code, 'INVITATION_CONSUMED');
  const { rows } = await env.ctx.pool.query(`SELECT 1 FROM security_events WHERE invitation_id=$1 AND event_type='REUSED_INVITATION'`, [inv.invitation.id]);
  assert.ok(rows.length >= 1);
});

test('revoked invitation cannot activate', async () => {
  const o = await createOrder(admin, bookId);
  const inv = await invite(admin, o.licenseId);
  const b = new Browser(env.base);
  await b.newDeviceKey();
  const otp = await b.post('/api/access/request-otp', { token: inv.token, phone: o.phone });
  assert.equal(otp.status, 200);
  const rv = await admin.post(`/api/admin/invitations/${inv.invitation.id}/revoke`);
  assert.equal(rv.status, 200);
  const r = await b.post('/api/access/activate', { token: inv.token, challengeId: otp.data.challengeId, code: lastOtp(env, o.phone), deviceKey: b.jwk });
  assert.equal(r.status, 400);
  assert.equal(r.data.code, 'INVITATION_REVOKED');
});

test('resending reissues a new token and the old link stops working', async () => {
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

// ---------------------------------------------------------------------------
// Identity (OTP)
// ---------------------------------------------------------------------------
test('OTP is delivered only to the registered phone; wrong phone cannot claim (Scenario A)', async () => {
  const o = await createOrder(admin, bookId);
  const inv = await invite(admin, o.licenseId);
  const attacker = new Browser(env.base);
  const before = env.ctx.otpDelivery.outbox.length;
  const r = await attacker.post('/api/access/request-otp', { token: inv.token, phone: '+254799999999' });
  assert.equal(r.status, 400);
  assert.equal(r.data.code, 'PHONE_MISMATCH');
  assert.equal(env.ctx.otpDelivery.outbox.length, before, 'no code sent to a substituted number');
  // Local format of the right number works and the code goes to the stored E.164 number.
  const local = `0${o.phone.slice(4)}`;
  const ok = await attacker.post('/api/access/request-otp', { token: inv.token, phone: local });
  assert.equal(ok.status, 200);
  const sent = env.ctx.otpDelivery.outbox.at(-1);
  assert.equal(sent.phone, o.phone);
  // The attacker does not have the code: guessing fails and the invitation stays valid.
  await attacker.newDeviceKey();
  const guess = await attacker.post('/api/access/activate', { token: inv.token, challengeId: ok.data.challengeId, code: sent.code === '123456' ? '654321' : '123456', deviceKey: attacker.jwk });
  assert.equal(guess.status, 400);
  assert.equal((await attacker.post('/api/access/validate-invitation', { token: inv.token })).data.state, 'VALID');
});

test('OTP expires', async () => {
  const o = await createOrder(admin, bookId);
  const inv = await invite(admin, o.licenseId);
  const b = new Browser(env.base);
  await b.newDeviceKey();
  const otp = await b.post('/api/access/request-otp', { token: inv.token, phone: o.phone });
  await env.ctx.pool.query(`UPDATE otp_challenges SET expires_at = now() - interval '1 second' WHERE id=$1`, [otp.data.challengeId]);
  const r = await b.post('/api/access/activate', { token: inv.token, challengeId: otp.data.challengeId, code: lastOtp(env, o.phone), deviceKey: b.jwk });
  assert.equal(r.data.code, 'OTP_EXPIRED');
});

test('OTP attempts are limited and requests are rate limited', async () => {
  const o = await createOrder(admin, bookId);
  const inv = await invite(admin, o.licenseId);
  const b = new Browser(env.base);
  await b.newDeviceKey();
  const otp = await b.post('/api/access/request-otp', { token: inv.token, phone: o.phone });
  const real = lastOtp(env, o.phone);
  const wrong = real === '000001' ? '000002' : '000001';
  let last;
  for (let i = 0; i < 5; i += 1) last = await b.post('/api/access/activate', { token: inv.token, challengeId: otp.data.challengeId, code: wrong, deviceKey: b.jwk });
  assert.equal(last.data.code, 'OTP_LOCKED');
  const after = await b.post('/api/access/activate', { token: inv.token, challengeId: otp.data.challengeId, code: real, deviceKey: b.jwk });
  assert.equal(after.data.code, 'OTP_LOCKED', 'correct code no longer accepted after lockout');
  const { rows } = await env.ctx.pool.query(`SELECT 1 FROM security_events WHERE customer_id=$1 AND event_type='OTP_FAILURES'`, [o.customerId]);
  assert.equal(rows.length, 1);
  // Cooldown between requests
  const again = await b.post('/api/access/request-otp', { token: inv.token, phone: o.phone });
  assert.equal(again.data.code, 'OTP_COOLDOWN');
  // Hourly cap
  for (let i = 0; i < 4; i += 1) { await clearOtpCooldown(env); await b.post('/api/access/request-otp', { token: inv.token, phone: o.phone }); }
  await clearOtpCooldown(env);
  const capped = await b.post('/api/access/request-otp', { token: inv.token, phone: o.phone });
  assert.equal(capped.status, 429);
  assert.equal(capped.data.code, 'OTP_RATE_LIMITED');
});

// ---------------------------------------------------------------------------
// Shared reader URL and sessions
// ---------------------------------------------------------------------------
test('reader URL shared with an unauthorized browser gets no content (Scenario C)', async () => {
  const o = await createOrder(admin, bookId);
  const inv = await invite(admin, o.licenseId);
  const owner = new Browser(env.base);
  await activate(env, owner, inv.token, o.phone);
  const man = await owner.get(`/api/reader/books/${bookId}/manifest`, { sign: true });
  const chapterId = man.data.items[0].id;

  const stranger = new Browser(env.base);
  const page = await stranger.get(`/read/${bookId}`);
  assert.equal(page.status, 200, 'shell loads');
  assert.ok(!page.data.toString().includes('Secret text'), 'shell contains no book content');
  const session = await stranger.get('/api/auth/session');
  assert.equal(session.status, 401);
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
  await activate(env, b, inv.token, o.phone);
  const r = await b.get(`/api/reader/books/${otherBook}/manifest`, { sign: true });
  assert.equal(r.status, 404);
  const { rows } = await env.ctx.pool.query(`SELECT 1 FROM security_events WHERE customer_id=$1 AND event_type='UNAUTHORIZED_CONTENT_REQUEST'`, [o.customerId]);
  assert.ok(rows.length >= 1);
});

test('stolen session cookie without the device key is rejected', async () => {
  const o = await createOrder(admin, bookId);
  const inv = await invite(admin, o.licenseId);
  const owner = new Browser(env.base);
  await activate(env, owner, inv.token, o.phone);
  const thief = new Browser(env.base);
  thief.cookies = { ...owner.cookies };
  thief.csrf = owner.csrf;
  assert.equal((await thief.get('/api/reader/library')).status, 401, 'unsigned');
  await thief.newDeviceKey(); // a different key
  const r = await thief.get('/api/reader/library', { sign: true });
  assert.equal(r.status, 401);
  assert.equal(r.data.code, 'SIGNATURE_INVALID');
});

test('replayed signed request is rejected', async () => {
  const o = await createOrder(admin, bookId);
  const inv = await invite(admin, o.licenseId);
  const b = new Browser(env.base);
  await activate(env, b, inv.token, o.phone);
  const first = await b.get('/api/reader/library', { sign: true, signOverride: { 'x-sig-nonce': 'fixed-nonce-value-123456' } });
  assert.equal(first.status, 401, 'override invalidates the signature itself');
  // Capture real headers and replay them.
  const crypto = await import('node:crypto');
  const ts = Date.now(); const nonce = crypto.randomBytes(16).toString('base64url');
  const bodyHash = crypto.createHash('sha256').update('').digest('hex');
  const msg = `GET\n/api/reader/library\n${ts}\n${nonce}\n${bodyHash}`;
  const sig = Buffer.from(await crypto.webcrypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, b.keys.privateKey, Buffer.from(msg))).toString('base64url');
  const h = { 'x-sig-ts': String(ts), 'x-sig-nonce': nonce, 'x-sig': sig };
  assert.equal((await b.get('/api/reader/library', { headers: h })).status, 200);
  const replay = await b.get('/api/reader/library', { headers: h });
  assert.equal(replay.status, 401);
});

test('expired session requires re-authentication; existing license still works without a new invitation (Scenario D)', async () => {
  const o = await createOrder(admin, bookId);
  const inv = await invite(admin, o.licenseId);
  const b = new Browser(env.base);
  await activate(env, b, inv.token, o.phone);
  await env.ctx.pool.query(`UPDATE reading_sessions SET expires_at = now() - interval '1 second' WHERE customer_id=$1`, [o.customerId]);
  const r = await b.get('/api/reader/library', { sign: true });
  assert.equal(r.status, 401);
  assert.equal(r.data.code, 'SESSION_EXPIRED');
  // Re-authenticate on the same browser (same device key) with phone + OTP.
  await clearOtpCooldown(env);
  const req = await b.post('/api/auth/request-otp', { phone: o.phone });
  const v = await b.post('/api/auth/verify-otp', { challengeId: req.data.challengeId, code: lastOtp(env, o.phone), deviceKey: b.jwk });
  assert.equal(v.status, 200);
  b.csrf = v.data.csrf;
  assert.equal((await b.get('/api/reader/library', { sign: true })).status, 200);
});

test('logout ends the session and asks the browser to clear stored data', async () => {
  const o = await createOrder(admin, bookId);
  const inv = await invite(admin, o.licenseId);
  const b = new Browser(env.base);
  await activate(env, b, inv.token, o.phone);
  const cookies = { ...b.cookies };
  const out = await b.post('/api/auth/logout');
  assert.equal(out.status, 200);
  assert.match(out.headers.get('clear-site-data'), /storage/);
  b.cookies = cookies; // even if the old cookie is kept, it no longer works
  assert.equal((await b.get('/api/reader/library', { sign: true })).status, 401);
});

test('login OTP request does not reveal whether a number is a customer', async () => {
  const b = new Browser(env.base);
  const unknown = await b.post('/api/auth/request-otp', { phone: '+254700000001' });
  assert.equal(unknown.status, 200);
  assert.ok(unknown.data.challengeId);
  const v = await b.post('/api/auth/verify-otp', { challengeId: unknown.data.challengeId, code: '123456', deviceKey: (await b.newDeviceKey()) });
  assert.equal(v.status, 400);
});

// ---------------------------------------------------------------------------
// Devices
// ---------------------------------------------------------------------------
test('new device: self-service replacement revokes the previous device (Scenarios E, 9)', async () => {
  const o = await createOrder(admin, bookId);
  const inv = await invite(admin, o.licenseId);
  const phoneA = new Browser(env.base);
  await activate(env, phoneA, inv.token, o.phone);
  const laptop = new Browser(env.base, 'Mozilla/5.0 (Windows NT 10.0) Chrome/126.0');
  await laptop.newDeviceKey();
  await clearOtpCooldown(env);
  const req = await laptop.post('/api/auth/request-otp', { phone: o.phone });
  const v = await laptop.post('/api/auth/verify-otp', { challengeId: req.data.challengeId, code: lastOtp(env, o.phone), deviceKey: laptop.jwk });
  assert.equal(v.status, 409, 'device limit reached');
  assert.equal(v.data.code, 'DEVICE_LIMIT');
  assert.equal((await laptop.get('/api/reader/library', { sign: true })).status, 401, 'no access before replacement');
  const rep = await laptop.post('/api/access/replace-device', { grantToken: v.data.grantToken });
  assert.equal(rep.status, 200);
  laptop.csrf = rep.data.csrf;
  assert.equal((await laptop.get(`/api/reader/books/${bookId}/manifest`, { sign: true })).status, 200);
  const old = await phoneA.get('/api/reader/library', { sign: true });
  assert.equal(old.status, 403);
  assert.equal(old.data.code, 'DEVICE_REVOKED');
  const { rows } = await env.ctx.pool.query(`SELECT mode FROM device_replacements WHERE customer_id=$1`, [o.customerId]);
  assert.deepEqual(rows.map((r) => r.mode), ['SELF_SERVICE']);
});

test('admin-approval replacement mode holds the new device until approved', async () => {
  await admin.request('PUT', '/api/admin/settings', { device_replacement_mode: 'ADMIN_APPROVAL' });
  try {
    const o = await createOrder(admin, bookId);
    const inv = await invite(admin, o.licenseId);
    const first = new Browser(env.base);
    await activate(env, first, inv.token, o.phone);
    const second = new Browser(env.base);
    await second.newDeviceKey();
    await clearOtpCooldown(env);
    const req = await second.post('/api/auth/request-otp', { phone: o.phone });
    const v = await second.post('/api/auth/verify-otp', { challengeId: req.data.challengeId, code: lastOtp(env, o.phone), deviceKey: second.jwk });
    const rep = await second.post('/api/access/replace-device', { grantToken: v.data.grantToken });
    assert.equal(rep.status, 202);
    assert.equal((await first.get('/api/reader/library', { sign: true })).status, 200, 'old device still works while pending');
    const list = await admin.get('/api/admin/device-replacements');
    const pending = list.data.replacements.find((x) => x.customer_id === o.customerId && x.mode === 'PENDING');
    assert.ok(pending);
    assert.equal((await admin.post(`/api/admin/device-replacements/${pending.id}/approve`, {})).status, 200);
    // Customer signs in again on the approved browser.
    await clearOtpCooldown(env);
    const req2 = await second.post('/api/auth/request-otp', { phone: o.phone });
    const v2 = await second.post('/api/auth/verify-otp', { challengeId: req2.data.challengeId, code: lastOtp(env, o.phone), deviceKey: second.jwk });
    assert.equal(v2.status, 200);
    second.csrf = v2.data.csrf;
    assert.equal((await second.get(`/api/reader/books/${bookId}/manifest`, { sign: true })).status, 200);
    assert.equal((await first.get('/api/reader/library', { sign: true })).status, 403, 'old device revoked');
  } finally {
    await admin.request('PUT', '/api/admin/settings', { device_replacement_mode: 'SELF_SERVICE' });
  }
});

test('previously authorized device after admin revocation is denied (Scenario 10)', async () => {
  const o = await createOrder(admin, bookId);
  const inv = await invite(admin, o.licenseId);
  const b = new Browser(env.base);
  await activate(env, b, inv.token, o.phone);
  const { rows: [d] } = await env.ctx.pool.query(`SELECT id FROM registered_devices WHERE customer_id=$1`, [o.customerId]);
  assert.equal((await admin.post(`/api/admin/devices/${d.id}/revoke`, {})).status, 200);
  const r = await b.get(`/api/reader/books/${bookId}/manifest`, { sign: true });
  assert.equal(r.status, 403);
  assert.equal(r.data.code, 'DEVICE_REVOKED');
});

test('revoked license blocks content on the next request (Scenario 8)', async () => {
  const o = await createOrder(admin, bookId);
  const inv = await invite(admin, o.licenseId);
  const b = new Browser(env.base);
  await activate(env, b, inv.token, o.phone);
  assert.equal((await b.get(`/api/reader/books/${bookId}/manifest`, { sign: true })).status, 200);
  assert.equal((await admin.post(`/api/admin/licenses/${o.licenseId}/revoke`, { reason: 'refund' })).status, 200);
  assert.equal((await b.get(`/api/reader/books/${bookId}/manifest`, { sign: true })).status, 404);
  const lib = await b.get('/api/reader/library', { sign: true });
  assert.equal(lib.data.books.length, 0);
});

test('suspended customer is locked out and cannot sign in again', async () => {
  const o = await createOrder(admin, bookId);
  const inv = await invite(admin, o.licenseId);
  const b = new Browser(env.base);
  await activate(env, b, inv.token, o.phone);
  assert.equal((await admin.post(`/api/admin/customers/${o.customerId}/suspend`, { reason: 'sharing' })).status, 200);
  const r = await b.get('/api/reader/library', { sign: true });
  assert.equal(r.status, 403);
  assert.equal(r.data.code, 'ACCOUNT_SUSPENDED');
  await clearOtpCooldown(env);
  const before = env.ctx.otpDelivery.outbox.length;
  await b.post('/api/auth/request-otp', { phone: o.phone });
  assert.equal(env.ctx.otpDelivery.outbox.length, before, 'no OTP sent to suspended account');
});

test('expired license denies access', async () => {
  const o = await createOrder(admin, bookId);
  const inv = await invite(admin, o.licenseId);
  const b = new Browser(env.base);
  await activate(env, b, inv.token, o.phone);
  await env.ctx.pool.query(`UPDATE reading_licenses SET expires_at = now() - interval '1 minute' WHERE id=$1`, [o.licenseId]);
  assert.equal((await b.get(`/api/reader/books/${bookId}/manifest`, { sign: true })).status, 404);
  const { rows: [l] } = await env.ctx.pool.query('SELECT status FROM reading_licenses WHERE id=$1', [o.licenseId]);
  assert.equal(l.status, 'EXPIRED');
});

test('per-IP limiter blocks OTP request floods across numbers', async () => {
  const b = new Browser(env.base);
  let last;
  for (let i = 0; i < 11; i += 1) last = await b.post('/api/auth/request-otp', { phone: `+2547000000${String(i).padStart(2, '0')}` });
  assert.equal(last.status, 429);
  assert.ok(last.headers.get('retry-after'));
});

// Default mode: one-time private links without a WhatsApp code, download page shown once,
// daily reading in the installed app, new link from the owner for a new phone.
import { test, before, after, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { startServer, loginAdmin, createBook, createOrder, invite, Browser, installApp } from './helpers.js';

let env; let admin; let bookId;
before(async () => {
  env = await startServer();
  admin = await loginAdmin(env);
  bookId = await createBook(admin);
});
after(async () => { await env.close(); });
beforeEach(() => env.ctx.rateLimiter.reset());

async function open(link, browser = new Browser(env.base)) {
  const token = link.split('/access/')[1];
  await browser.newDeviceKey();
  const v = await browser.post('/api/access/validate-invitation', { token });
  const r = await browser.post('/api/access/activate', { token, deviceKey: browser.jwk });
  if (r.status === 200) browser.csrf = r.data.csrf;
  return { browser, v, r, token };
}

test('opening the link activates the book at once, with no code; the link opens only once', async () => {
  const o = await createOrder(admin, bookId);
  const before = env.ctx.otpDelivery.outbox.length;
  const inv = await invite(admin, o.licenseId);
  const first = await open(inv.link);
  assert.equal(first.v.data.codeRequired, false);
  assert.equal(first.r.status, 200);
  assert.equal(first.r.data.book.title, 'Test Book', 'download page data comes with the activation');
  assert.equal(env.ctx.otpDelivery.outbox.length, before, 'no WhatsApp code was sent');
  // Same link again, from anywhere (including the same person): refused.
  const again = await open(inv.link);
  assert.equal(again.v.data.state, 'CONSUMED');
  assert.equal(again.r.status, 400);
  // The person who opened it reads in the app every day.
  await installApp(first.browser);
  assert.equal((await first.browser.get(`/api/reader/books/${bookId}/manifest`, { sign: true })).status, 200);
  // The download page is not offered again: the book endpoint reports the device has the app.
  assert.equal((await first.browser.get(`/api/reader/books/${bookId}`, { sign: true })).data.installedOnThisDevice, true);
});

test('sign-in with a WhatsApp code is off: a lost app needs a new link', async () => {
  const b = new Browser(env.base);
  const r = await b.post('/api/auth/request-otp', { phone: '+254700000001' });
  assert.equal(r.status, 403);
  assert.equal(r.data.code, 'SIGN_IN_WITH_LINK');
  assert.equal((await b.get('/api/public/contact')).data.signInWithCode, false);
});

test('owner issues a new link for a new phone: it moves the book and the old phone loses access', async () => {
  const o = await createOrder(admin, bookId);
  const oldPhone = (await open((await invite(admin, o.licenseId)).link)).browser;
  await installApp(oldPhone);
  const newLink = await admin.post('/api/admin/invitations', { licenseId: o.licenseId });
  assert.equal(newLink.status, 201, 'a new link can be issued for an active purchase');
  const { browser: newPhone, r } = await open(newLink.data.link);
  assert.equal(r.status, 200);
  await installApp(newPhone);
  assert.equal((await newPhone.get(`/api/reader/books/${bookId}/manifest`, { sign: true })).status, 200);
  const old = await oldPhone.get('/api/reader/library', { sign: true });
  assert.equal(old.status, 403);
  assert.equal(old.data.code, 'DEVICE_REVOKED');
  const { rows } = await env.ctx.pool.query(`SELECT mode FROM device_replacements WHERE customer_id=$1`, [o.customerId]);
  assert.deepEqual(rows.map((x) => x.mode), ['OWNER_LINK']);
});

test('iPhone: the home-screen app takes over the access once with the pairing token', async () => {
  const o = await createOrder(admin, bookId);
  const { browser: safari } = await open((await invite(admin, o.licenseId)).link);
  const pairing = await safari.post('/api/reader/pairing', {}, { sign: true });
  assert.match(pairing.data.token, /^[A-Za-z0-9_-]{43}$/);
  const manifest = await safari.get(`/manifest.webmanifest?pair=${pairing.data.token}`);
  assert.equal(manifest.data.start_url, `/app?pair=${pairing.data.token}`);
  assert.equal(manifest.data.id, '/app', 'the app identity stays the same');
  // The home-screen app has no cookies or keys from Safari.
  const app = new Browser(env.base);
  await app.newDeviceKey();
  const p = await app.post('/api/access/pair', { token: pairing.data.token, deviceKey: app.jwk });
  assert.equal(p.status, 200);
  app.csrf = p.data.csrf;
  assert.equal((await app.get(`/api/reader/books/${bookId}/manifest`, { sign: true })).status, 200, 'the app is marked installed');
  assert.equal((await safari.get('/api/reader/library', { sign: true })).data.code, 'DEVICE_REVOKED', 'Safari handed over its access');
  // The pairing token works once.
  const other = new Browser(env.base);
  await other.newDeviceKey();
  assert.equal((await other.post('/api/access/pair', { token: pairing.data.token, deviceKey: other.jwk })).data.code, 'PAIRING_INVALID');
  // Plain manifest has the normal start URL.
  assert.equal((await other.get('/manifest.webmanifest')).data.start_url, '/app');
});

test('sessions renew themselves with use so the app keeps working daily', async () => {
  const o = await createOrder(admin, bookId);
  const { browser } = await open((await invite(admin, o.licenseId)).link);
  await installApp(browser);
  await env.ctx.pool.query(`UPDATE reading_sessions SET expires_at = now() + interval '2 hours' WHERE customer_id=$1`, [o.customerId]);
  assert.equal((await browser.get('/api/reader/library', { sign: true })).status, 200);
  const { rows: [s] } = await env.ctx.pool.query(`SELECT expires_at FROM reading_sessions WHERE customer_id=$1 AND ended_at IS NULL`, [o.customerId]);
  assert.ok(new Date(s.expires_at) > new Date(Date.now() + 20 * 86400000), 'renewed to the full session length');
});

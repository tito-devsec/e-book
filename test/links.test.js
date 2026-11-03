// Default customer journey: the private link stays valid until the book is added to the device;
// the added app's first open uses it up. New phone = new link from the owner.
import { test, before, after, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { startServer, loginAdmin, createBook, createOrder, invite, Browser, activate } from './helpers.js';

let env; let admin; let bookId;
before(async () => {
  env = await startServer();
  admin = await loginAdmin(env);
  bookId = await createBook(admin);
});
after(async () => { await env.close(); });
beforeEach(() => env.ctx.rateLimiter.reset());

test('iPhone: the home-screen app starts with the claim token and uses up the link on first open', async () => {
  const o = await createOrder(admin, bookId);
  const inv = await invite(admin, o.licenseId);
  const safari = new Browser(env.base, 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) Safari/604.1');
  const p = await safari.post('/api/access/prepare-app', { token: inv.token });
  const manifest = await safari.get(`/manifest.webmanifest?claim=${p.data.claim}`);
  assert.equal(manifest.data.start_url, `/app?claim=${p.data.claim}`);
  assert.equal(manifest.data.id, '/app', 'the app identity stays the same');
  assert.doesNotMatch(JSON.stringify(manifest.data), new RegExp(inv.token), 'the link token itself is not in the app');
  // The home-screen app has its own storage: no cookies or keys from Safari.
  const app = new Browser(env.base, 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) Mobile/15E148');
  await app.newDeviceKey();
  const c = await app.post('/api/access/claim', { claim: p.data.claim, deviceKey: app.jwk });
  assert.equal(c.status, 200);
  app.csrf = c.data.csrf;
  assert.equal((await app.get(`/api/reader/books/${bookId}/manifest`, { sign: true })).status, 200);
  assert.equal((await safari.post('/api/access/validate-invitation', { token: inv.token })).data.state, 'CONSUMED');
  assert.equal((await safari.get('/api/auth/session')).status, 401, 'Safari never had access');
});

test('owner issues a new link for a new phone: it moves the book and the old phone loses access', async () => {
  const o = await createOrder(admin, bookId);
  const oldPhone = new Browser(env.base);
  await activate(env, oldPhone, (await invite(admin, o.licenseId)).token);
  const newLink = await admin.post('/api/admin/invitations', { licenseId: o.licenseId });
  assert.equal(newLink.status, 201, 'a new link can be issued for an active purchase');
  const newPhone = new Browser(env.base);
  await activate(env, newPhone, newLink.data.link.split('/access/')[1]);
  assert.equal((await newPhone.get(`/api/reader/books/${bookId}/manifest`, { sign: true })).status, 200);
  const old = await oldPhone.get('/api/reader/library', { sign: true });
  assert.equal(old.status, 403);
  assert.equal(old.data.code, 'DEVICE_REVOKED');
  const { rows } = await env.ctx.pool.query(`SELECT mode FROM device_replacements WHERE customer_id=$1`, [o.customerId]);
  assert.deepEqual(rows.map((x) => x.mode), ['OWNER_LINK']);
});

test('sessions renew themselves with use so the app keeps working daily', async () => {
  const o = await createOrder(admin, bookId);
  const b = new Browser(env.base);
  await activate(env, b, (await invite(admin, o.licenseId)).token);
  await env.ctx.pool.query(`UPDATE reading_sessions SET expires_at = now() + interval '2 hours' WHERE customer_id=$1`, [o.customerId]);
  assert.equal((await b.get('/api/reader/library', { sign: true })).status, 200);
  const { rows: [s] } = await env.ctx.pool.query(`SELECT expires_at FROM reading_sessions WHERE customer_id=$1 AND ended_at IS NULL`, [o.customerId]);
  assert.ok(new Date(s.expires_at) > new Date(Date.now() + 20 * 86400000), 'renewed to the full session length');
});

test('default link validity is three days', async () => {
  const o = await createOrder(admin, bookId);
  const inv = await invite(admin, o.licenseId);
  const hours = (new Date(inv.invitation.expires_at) - Date.now()) / 3600000;
  assert.ok(hours > 71 && hours <= 72, `got ${hours}`);
});

test('iPhone: the link page itself carries the app start address, so the added icon opens the book', async () => {
  const o = await createOrder(admin, bookId);
  const inv = await invite(admin, o.licenseId);
  const token = inv.link.split('/access/')[1];
  const safari = new Browser(env.base, 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) Safari/604.1');
  const page = await fetch(`${env.base}/access/${token}`, { headers: { 'user-agent': safari.ua } }).then((r) => r.text());
  const claim = page.match(/<link rel="manifest" href="\/manifest\.webmanifest\?claim=([A-Za-z0-9_-]{43})">/)?.[1];
  assert.ok(claim, 'manifest link with the code is in the first HTML, before any script runs');
  assert.equal(page.match(/name="app-claim" content="([^"]+)"/)?.[1], claim);
  const manifest = await safari.get(`/manifest.webmanifest?claim=${claim}`);
  assert.equal(manifest.data.start_url, `/app?claim=${claim}`);
  const app = new Browser(env.base, 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) Mobile/15E148');
  await app.newDeviceKey();
  const c = await app.post('/api/access/claim', { claim, deviceKey: app.jwk });
  assert.equal(c.status, 200);
  assert.doesNotMatch(page, new RegExp(token), 'the link token is not written into the page');
  // A wrong or used link gets the plain page, no code.
  const bad = await fetch(`${env.base}/access/${'A'.repeat(43)}`).then((r) => r.text());
  assert.doesNotMatch(bad, /app-claim/);
  assert.match(bad, /<link rel="manifest" href="\/manifest\.webmanifest">/);
});

test('a browser tab at the app start address: the link is unused until the added app opens', async () => {
  const o = await createOrder(admin, bookId);
  const inv = await invite(admin, o.licenseId);
  const b = new Browser(env.base);
  await b.newDeviceKey();
  const { claim } = (await b.post('/api/access/prepare-app', { token: inv.token })).data;
  // Reload / shared preview of /app?claim=...: the page can still show the download page.
  let st = await b.post('/api/access/claim-status', { claim });
  assert.equal(st.data.state, 'VALID');
  assert.equal(st.data.book.title, 'Test Book');
  assert.ok(!JSON.stringify(st.data).includes(inv.token));
  // After the added app opened, the same address no longer offers the download page.
  assert.equal((await b.post('/api/access/claim', { claim, deviceKey: b.jwk })).status, 200);
  st = await b.post('/api/access/claim-status', { claim });
  assert.equal(st.data.state, 'CONSUMED');
  assert.equal((await b.post('/api/access/claim-status', { claim: 'x'.repeat(43) })).data.state, 'INVALID');
});

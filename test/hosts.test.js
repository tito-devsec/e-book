// Separate-domain deployment: each application is served only on its own host.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { setupEnv } from './helpers.js';

let server; let port; let ctx;
const get = (host, path) => new Promise((resolve, reject) => {
  http.get({ host: '127.0.0.1', port, path, headers: { host, accept: 'text/html' } }, (res) => {
    let body = ''; res.on('data', (d) => { body += d; }); res.on('end', () => resolve({ status: res.statusCode, body, headers: res.headers }));
  }).on('error', reject);
});

before(async () => {
  await setupEnv();
  Object.assign(process.env, { ADMIN_BASE_URL: 'https://admin.example.test', READER_BASE_URL: 'https://reader.example.test' });
  const { loadConfig } = await import('../src/config.js');
  const { createContext, createApp } = await import('../src/app.js');
  const { runMigrations } = await import('../src/migrate.js');
  ctx = createContext(loadConfig(), { logger: { debug() {}, info() {}, warn() {}, error() {} } });
  await ctx.pool.query('DROP SCHEMA public CASCADE; CREATE SCHEMA public;');
  await runMigrations(ctx.pool, { info() {} });
  server = createApp(ctx).listen(0, '127.0.0.1');
  await new Promise((r) => server.once('listening', r));
  port = server.address().port;
});
after(async () => { server.close(); await ctx.pool.end(); });

test('admin is only on the admin host', async () => {
  assert.equal((await get('admin.example.test', '/admin')).status, 200);
  assert.equal((await get('reader.example.test', '/admin')).status, 404);
  assert.equal((await get('reader.example.test', '/api/admin/overview')).status, 404);
  assert.equal((await get('admin.example.test', '/')).status, 302);
});

test('customer site is only on the reader host; its home is the download page', async () => {
  assert.equal((await get('reader.example.test', '/read/00000000-0000-4000-8000-000000000000')).status, 200);
  assert.equal((await get('admin.example.test', '/access/abc')).status, 404);
  assert.equal((await get('admin.example.test', '/manifest.webmanifest')).status, 404);
  assert.equal((await get('admin.example.test', '/api/public/contact')).status, 404);
  const root = await get('reader.example.test', '/');
  assert.equal(root.status, 200);
  assert.match(root.body, /static\/reader\/app\.js/);
  assert.equal((await get('reader.example.test', '/robots.txt')).status, 200);
});

test('localhost: the customer site and dashboard are selected by port', async () => {
  const { createApp } = await import('../src/app.js');
  const servers = await Promise.all([0, 1].map(() => new Promise((r) => { const sv = http.createServer(); sv.listen(0, '127.0.0.1', () => r(sv)); })));
  const [rp, ap] = servers.map((sv) => sv.address().port);
  const cfg = { ...ctx.cfg, readerBaseUrl: `http://localhost:${rp}`, adminBaseUrl: `http://localhost:${ap}` };
  const app = createApp({ ...ctx, cfg });
  servers.forEach((sv) => sv.on('request', app));
  const at = (p, path, host = '192.168.1.20') => new Promise((resolve, reject) => {
    http.get({ host: '127.0.0.1', port: p, path, headers: { host: `${host}:${p}`, accept: 'text/html' } }, (res) => { res.resume(); res.on('end', () => resolve(res.statusCode)); }).on('error', reject);
  });
  try {
    // Host header is a LAN address (phone on Wi-Fi): the port still decides.
    assert.equal(await at(rp, '/'), 200);
    assert.equal(await at(rp, '/admin'), 404);
    assert.equal(await at(rp, '/api/admin/overview'), 404);
    assert.equal(await at(ap, '/admin'), 200);
    assert.equal(await at(ap, '/access/abc'), 404);
    assert.equal(await at(ap, '/api/public/contact'), 404);
  } finally {
    servers.forEach((sv) => sv.close());
  }
});

test('tunnels: with separate local ports, the port decides whatever public host arrives', async () => {
  const { createApp } = await import('../src/app.js');
  const servers = await Promise.all([0, 1].map(() => new Promise((r) => { const sv = http.createServer(); sv.listen(0, '127.0.0.1', () => r(sv)); })));
  const [rp, ap] = servers.map((sv) => sv.address().port);
  const cfg = {
    ...ctx.cfg, readerPort: rp, adminPort: ap,
    readerBaseUrl: 'https://quiet-river.trycloudflare.com', adminBaseUrl: 'https://bold-lake.trycloudflare.com',
  };
  const app = createApp({ ...ctx, cfg });
  servers.forEach((sv) => sv.on('request', app));
  const at = (p, path, host) => new Promise((resolve, reject) => {
    http.get({ host: '127.0.0.1', port: p, path, headers: { host, accept: 'text/html' } }, (res) => { res.resume(); res.on('end', () => resolve(res.statusCode)); }).on('error', reject);
  });
  try {
    for (const host of ['bold-lake.trycloudflare.com', `localhost:${ap}`]) {
      assert.equal(await at(ap, '/admin', host), 200, host);
      assert.equal(await at(ap, '/access/abc', host), 404, host);
    }
    for (const host of ['quiet-river.trycloudflare.com', `localhost:${rp}`]) {
      assert.equal(await at(rp, '/', host), 200, host);
      assert.equal(await at(rp, '/admin', host), 404, host);
      assert.equal(await at(rp, '/api/admin/overview', host), 404, host);
    }
  } finally {
    servers.forEach((sv) => sv.close());
  }
});

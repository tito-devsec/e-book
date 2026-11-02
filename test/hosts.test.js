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
  Object.assign(process.env, { PUBLIC_BASE_URL: 'https://example.test', ADMIN_BASE_URL: 'https://admin.example.test', READER_BASE_URL: 'https://reader.example.test' });
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
  assert.equal((await get('example.test', '/admin')).status, 404);
  assert.equal((await get('reader.example.test', '/admin')).status, 404);
  assert.equal((await get('example.test', '/api/admin/overview')).status, 404);
});

test('reader is only on the reader host and its root opens the app', async () => {
  assert.equal((await get('reader.example.test', '/read/00000000-0000-4000-8000-000000000000')).status, 200);
  assert.equal((await get('example.test', '/access/abc')).status, 404);
  assert.equal((await get('example.test', '/manifest.webmanifest')).status, 404);
  const root = await get('reader.example.test', '/');
  assert.equal(root.status, 302);
  assert.equal(root.headers.location, '/app');
});

test('marketing site is only on the public host', async () => {
  assert.equal((await get('example.test', '/')).status, 200);
  assert.equal((await get('admin.example.test', '/')).status, 302);
  assert.equal((await get('reader.example.test', '/robots.txt')).status, 404);
});

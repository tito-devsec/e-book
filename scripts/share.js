// Share this computer's copy with someone remote, for testing.
// Opens two temporary public HTTPS addresses with Cloudflare quick tunnels (no account needed):
//   one for the customer site (download page + reader app) and one for the dashboard.
// Then starts the server with those addresses, so the links made in the dashboard work anywhere.
// Usage: npm run share        (needs cloudflared: winget install --id Cloudflare.cloudflared)
// The addresses change every time this is started.
import { spawn } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const readerPort = Number(process.env.READER_PORT || process.env.PORT || 3000);
const adminPort = Number(process.env.ADMIN_PORT || 3002);
const children = [];

function stopAll(code = 0) {
  for (const c of children) if (c.exitCode === null) c.kill();
  process.exit(code);
}
process.on('SIGINT', () => stopAll(0));
process.on('SIGTERM', () => stopAll(0));

function openTunnel(port) {
  return new Promise((resolve, reject) => {
    const child = spawn('cloudflared', ['tunnel', '--no-autoupdate', '--url', `http://localhost:${port}`], { stdio: ['ignore', 'pipe', 'pipe'] });
    children.push(child);
    let log = '';
    const timer = setTimeout(() => reject(new Error(`No address from cloudflared after 60 seconds.\n${log.slice(-1500)}`)), 60000);
    const onData = (d) => {
      log += d;
      const m = log.match(/https:\/\/[a-z0-9-]+\.trycloudflare\.com/);
      if (m) { clearTimeout(timer); resolve(m[0]); }
    };
    child.stdout.on('data', onData);
    child.stderr.on('data', onData);
    child.on('error', (err) => {
      clearTimeout(timer);
      reject(err.code === 'ENOENT'
        ? new Error('cloudflared is not installed. Install it, then close and reopen the terminal:\n  winget install --id Cloudflare.cloudflared')
        : err);
    });
    child.on('exit', (code) => { clearTimeout(timer); reject(new Error(`cloudflared stopped (code ${code}).\n${log.slice(-1500)}`)); });
  });
}

try {
  console.log('Opening public addresses (takes a few seconds)...');
  const [readerUrl, adminUrl] = await Promise.all([openTunnel(readerPort), openTunnel(adminPort)]);
  const server = spawn(process.execPath, ['--env-file-if-exists=.env', 'src/server.js'], {
    cwd: root,
    stdio: 'inherit',
    // Values set here win over the ones in .env.
    env: {
      ...process.env,
      PORT: String(readerPort),
      READER_PORT: String(readerPort),
      ADMIN_PORT: String(adminPort),
      READER_BASE_URL: readerUrl,
      ADMIN_BASE_URL: adminUrl,
      TRUST_PROXY: 'loopback',
    },
  });
  children.push(server);
  server.on('exit', (code) => stopAll(code ?? 0));
  setTimeout(() => {
    console.log(`
==================================================================
 Shared. Send these to your tester:

   Dashboard:      ${adminUrl}/admin
   Customer site:  ${readerUrl}

 Links created in the dashboard now start with the customer site
 address, so they open on any phone.
 On this computer you can still use http://localhost:${adminPort}/admin

 Keep this window open and the computer awake. Ctrl+C stops sharing.
 If a page does not open yet, wait 30 seconds and refresh.
==================================================================
`);
  }, 1500);
} catch (err) {
  console.error(`\n${err.message}\n`);
  stopAll(1);
}

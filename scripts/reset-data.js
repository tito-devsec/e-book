// DEVELOPMENT ONLY. Deletes every book, edition, customer, order, payment, link, device, session,
// reading record and log, and the stored book files, so you can start afresh. Administrator
// accounts, roles and system settings are kept. Refuses to run in production.
// Usage: npm run reset:data -- --yes        then:  npm run seed:dev
import fs from 'node:fs/promises';
import path from 'node:path';
import { loadConfig } from '../src/config.js';
import { createPool } from '../src/db.js';

const cfg = loadConfig();
if (cfg.isProd) { console.error('reset:data refuses to run with NODE_ENV=production'); process.exit(1); }
const DATA_TABLES = ['reading_events', 'security_events', 'audit_logs', 'bookmarks', 'reading_progress', 'request_nonces', 'reading_sessions',
  'device_replacements', 'device_authorizations', 'registered_devices', 'invitation_claims', 'invitations', 'reading_licenses', 'payments',
  'order_items', 'orders', 'customers', 'book_assets', 'book_editions', 'books', 'admin_sessions'];

const pool = createPool(cfg);
try {
  const { rows } = await pool.query(`SELECT table_name FROM information_schema.tables WHERE table_schema='public' AND table_name = ANY($1)`, [DATA_TABLES]);
  const tables = DATA_TABLES.filter((t) => rows.some((r) => r.table_name === t));
  const counts = [];
  for (const t of ['books', 'customers', 'orders', 'reading_licenses', 'registered_devices']) {
    if (tables.includes(t)) counts.push(`${(await pool.query(`SELECT count(*)::int AS n FROM ${t}`)).rows[0].n} ${t.replace('_', ' ')}`);
  }
  console.log(`This will delete everything in: ${counts.join(', ')} (and all related records and stored book files).`);
  console.log('Administrator accounts and system settings are kept.');
  if (!process.argv.includes('--yes')) {
    console.log('Nothing was deleted. Run again with --yes to go ahead:  npm run reset:data -- --yes');
    process.exit(0);
  }
  await pool.query(`TRUNCATE ${tables.join(', ')} RESTART IDENTITY CASCADE`);
  await pool.query(`UPDATE website_settings SET value='{"featuredBookId": null}'::jsonb WHERE key='site'`);
  if (cfg.storageDriver === 'local') {
    const dir = path.resolve(cfg.storageLocalDir);
    await fs.rm(dir, { recursive: true, force: true });
    await fs.mkdir(dir, { recursive: true });
    console.log(`Stored book files in ${dir} deleted.`);
  } else {
    console.log('Files in your S3 bucket were not touched; remove them there if needed.');
  }
  console.log('Done. Now load the book:  npm run seed:dev');
} finally {
  await pool.end();
}

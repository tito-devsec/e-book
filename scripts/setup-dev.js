// DEVELOPMENT ONLY. Creates a .env with random local secrets and creates the database.
// Usage: npm run setup -- [--db-user postgres] [--db-password secret] [--db-host localhost] [--db-port 5432] [--db-name bookapp] [--port 3000]
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import pg from 'pg';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const envPath = path.join(root, '.env');

const args = {};
const argv = process.argv.slice(2);
for (let i = 0; i < argv.length; i += 1) {
  if (argv[i].startsWith('--')) { args[argv[i].slice(2)] = argv[i + 1] ?? ''; i += 1; }
}
const db = {
  user: args['db-user'] || 'postgres',
  password: args['db-password'] ?? 'postgres',
  host: args['db-host'] || 'localhost',
  port: args['db-port'] || '5432',
  name: args['db-name'] || 'bookapp',
};
const enc = encodeURIComponent;
const databaseUrl = `postgres://${enc(db.user)}:${enc(db.password)}@${db.host}:${db.port}/${db.name}`;

if (fs.existsSync(envPath) && !('force' in args)) {
  console.log('.env already exists; keeping it. (Add --force to replace it.)');
} else {
  const env = [
    '# Development settings created by `npm run setup`. Do not use in production.',
    'NODE_ENV=development',
    `PORT=${args.port || 3000}`,
    `DATABASE_URL=${databaseUrl}`,
    `HASH_PEPPER=${crypto.randomBytes(36).toString('base64url')}`,
    'KMS_PROVIDER=local',
    `LOCAL_MASTER_KEY=${crypto.randomBytes(32).toString('hex')}`,
    'STORAGE_DRIVER=local',
    'STORAGE_LOCAL_DIR=./var/storage',
    '# Verification codes are printed in the terminal instead of being sent on WhatsApp.',
    'OTP_PROVIDER=console',
    'COOKIE_SECURE=false',
    'DEFAULT_COUNTRY_CODE=254',
    'LOG_LEVEL=warn',
    '',
  ].join('\n');
  fs.writeFileSync(envPath, env, { mode: 0o600 });
  console.log('Created .env');
}

// Create the database if it does not exist yet.
const url = (fs.readFileSync(envPath, 'utf8').match(/^DATABASE_URL=(.+)$/m) || [])[1]?.trim() || databaseUrl;
const target = new URL(url);
const dbName = decodeURIComponent(target.pathname.slice(1));
const admin = new URL(url); admin.pathname = '/postgres';
const client = new pg.Client({ connectionString: admin.toString() });
try {
  await client.connect();
  const { rowCount } = await client.query('SELECT 1 FROM pg_database WHERE datname=$1', [dbName]);
  if (rowCount) console.log(`Database "${dbName}" already exists.`);
  else { await client.query(`CREATE DATABASE "${dbName.replace(/"/g, '""')}"`); console.log(`Created database "${dbName}".`); }
  console.log('\nNext:  npm run migrate  then  npm run seed:dev  then  npm run dev');
} catch (err) {
  console.error(`\nCould not connect to PostgreSQL at ${target.host} as "${decodeURIComponent(target.username)}": ${err.message}`);
  if (err.code === 'ECONNREFUSED') console.error('Is PostgreSQL installed and running? (Windows: Services → postgresql-x64-NN → Start)');
  if (err.code === '28P01') console.error('Wrong password. Run again with:  npm run setup -- --force --db-password YOUR_POSTGRES_PASSWORD');
  process.exitCode = 1;
} finally {
  await client.end().catch(() => {});
}

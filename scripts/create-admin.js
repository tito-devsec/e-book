// Create an administrator account.
// Usage: npm run admin:create -- --email owner@example.com --name "Owner Name" [--role OWNER]
// The password is read from the ADMIN_PASSWORD environment variable or prompted for.
import readline from 'node:readline/promises';
import { loadConfig } from '../src/config.js';
import { createPool } from '../src/db.js';
import { hashPassword } from '../src/lib/crypto.js';
import { validatePasswordStrength } from '../src/routes/adminAuth.js';

const args = Object.fromEntries(process.argv.slice(2).join(' ').split('--').filter(Boolean)
  .map((s) => { const [k, ...v] = s.trim().split(' '); return [k, v.join(' ').replace(/^"|"$/g, '')]; }));
if (!args.email || !args.name) {
  console.error('Usage: npm run admin:create -- --email you@example.com --name "Your Name" [--role OWNER|MANAGER|SUPPORT]');
  process.exit(1);
}
let password = process.env.ADMIN_PASSWORD;
if (!password) {
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  password = await rl.question('Password (min 12 characters): ');
  rl.close();
}
validatePasswordStrength(password);
const pool = createPool(loadConfig());
try {
  const { rows: [a] } = await pool.query(
    `INSERT INTO administrators (email, full_name, password_hash, role_id)
     VALUES ($1,$2,$3,(SELECT id FROM roles WHERE name=$4)) RETURNING id`,
    [args.email, args.name, await hashPassword(password), (args.role || 'OWNER').toUpperCase()]);
  await pool.query(`INSERT INTO audit_logs (action, entity_type, entity_id, details) VALUES ('admin.create_cli','administrator',$1,$2)`,
    [a.id, { email: args.email, role: (args.role || 'OWNER').toUpperCase() }]);
  console.log(`Administrator created: ${args.email}`);
} finally {
  await pool.end();
}

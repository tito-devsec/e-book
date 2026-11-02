import { loadConfig } from '../src/config.js';
import { createPool } from '../src/db.js';
import { runMigrations } from '../src/migrate.js';

const pool = createPool(loadConfig());
try {
  await pool.query('SELECT 1').catch((err) => {
    console.error(`Cannot reach the database: ${err.message}`);
    console.error('Check DATABASE_URL in .env and that PostgreSQL is running. For local development run: npm run setup');
    process.exit(1);
  });
  await runMigrations(pool, { info: (m, f) => console.log(m, f?.name ?? '') });
  console.log('Migrations complete');
} finally {
  await pool.end();
}

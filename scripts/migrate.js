import { loadConfig } from '../src/config.js';
import { createPool } from '../src/db.js';
import { runMigrations } from '../src/migrate.js';

const pool = createPool(loadConfig());
try {
  await runMigrations(pool, { info: (m, f) => console.log(m, f?.name ?? '') });
  console.log('Migrations complete');
} finally {
  await pool.end();
}

import pg from 'pg';

// numeric -> string by default; keep it that way to avoid float rounding on money.
// bigint (int8) counts are small enough to parse as numbers.
pg.types.setTypeParser(20, (v) => Number.parseInt(v, 10));

export function createPool(cfg) {
  return new pg.Pool({
    connectionString: cfg.databaseUrl,
    ssl: cfg.databaseSsl ? { rejectUnauthorized: true } : undefined,
    max: 10,
  });
}

/** Run fn inside a transaction. fn receives a client with .query(). */
export async function tx(pool, fn) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const result = await fn(client);
    await client.query('COMMIT');
    return result;
  } catch (err) {
    try { await client.query('ROLLBACK'); } catch { /* connection may be broken */ }
    throw err;
  } finally {
    client.release();
  }
}

import { loadConfig } from './config.js';
import { createContext, createApp } from './app.js';
import { runMigrations } from './migrate.js';

const cfg = loadConfig();
const ctx = createContext(cfg);

if (process.env.MIGRATE_ON_START === 'true') await runMigrations(ctx.pool, ctx.logger);

const app = createApp(ctx);
const server = app.listen(cfg.port, () => ctx.logger.info('server listening', { port: cfg.port, env: cfg.nodeEnv }));
server.requestTimeout = 15 * 60 * 1000; // large uploads are processed inline

// Housekeeping: expire stale replay nonces, device grants and invitations.
const sweep = setInterval(async () => {
  try {
    await ctx.pool.query('DELETE FROM request_nonces WHERE expires_at < now()');
    await ctx.pool.query(`DELETE FROM pending_device_grants WHERE expires_at < now() - interval '1 day'`);
    await ctx.pool.query(`UPDATE invitations SET status='EXPIRED' WHERE status='PENDING' AND expires_at <= now()`);
    await ctx.pool.query(`UPDATE reading_licenses SET status='EXPIRED', updated_at=now() WHERE status='ACTIVE' AND expires_at IS NOT NULL AND expires_at <= now()`);
    await ctx.pool.query(`UPDATE registered_devices SET transition_until=NULL WHERE transition_until IS NOT NULL AND transition_until <= now()`);
  } catch (err) {
    ctx.logger.error('sweep failed', { err });
  }
}, 60000);

const shutdown = (sig) => {
  ctx.logger.info('shutting down', { sig });
  clearInterval(sweep);
  server.close(() => ctx.pool.end().then(() => process.exit(0)));
  setTimeout(() => process.exit(1), 10000).unref();
};
process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);

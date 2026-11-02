import express from 'express';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import multer from 'multer';
import { HttpError } from './lib/http.js';
import { createLogger } from './lib/logger.js';
import { createRateLimiter } from './lib/rateLimit.js';
import { createPool } from './db.js';
import { createKms } from './services/kms.js';
import { createStorage } from './services/storage.js';
import { createOtpDelivery } from './services/otpDelivery.js';
import { createScanner } from './services/malwareScan.js';
import { createSettings } from './services/settings.js';
import { createEvents } from './services/events.js';
import { createAccess } from './services/access.js';
import { createIngest } from './services/ingest.js';
import {
  securityHeaders, originCheck, requestLogger, createAdminAuth, createReaderAuth,
} from './middleware.js';
import { customerRoutes } from './routes/customer.js';
import { readerRoutes } from './routes/reader.js';
import { adminAuthRoutes } from './routes/adminAuth.js';
import { adminRoutes } from './routes/admin.js';
import { siteRoutes, coverRoutes } from './routes/site.js';

const here = path.dirname(fileURLToPath(import.meta.url));
export const PUBLIC_DIR = path.resolve(here, '..', 'public');

export function createContext(cfg, overrides = {}) {
  const logger = overrides.logger || createLogger(cfg.logLevel);
  const pool = overrides.pool || createPool(cfg);
  const kms = createKms(cfg);
  const storage = overrides.storage || createStorage(cfg);
  const otpDelivery = overrides.otpDelivery || createOtpDelivery(cfg, logger);
  const scanner = createScanner(cfg, logger);
  const settings = createSettings(pool);
  const events = createEvents({ pool, cfg, logger });
  const rateLimiter = createRateLimiter();
  const access = createAccess({ pool, cfg, settings, events, otpDelivery, logger });
  const ingest = createIngest({ pool, cfg, kms, storage, scanner, logger });
  const adminAuth = createAdminAuth({ pool, cfg });
  const readerAuth = createReaderAuth({ pool, access, events, rateLimiter, settings });
  return { cfg, logger, pool, kms, storage, otpDelivery, scanner, settings, events, rateLimiter, access, ingest, adminAuth, readerAuth };
}

export function createApp(ctx) {
  const { cfg, logger, pool } = ctx;
  const app = express();
  app.disable('x-powered-by');
  app.set('trust proxy', cfg.trustProxy === 'false' ? false : (/^\d+$/.test(cfg.trustProxy) ? Number(cfg.trustProxy) : cfg.trustProxy));

  // Which application answers a request. In production each app has its own domain and the
  // Host header decides. For local hosts (localhost / 127.0.0.1) the listening port decides, so
  // the reader also works when opened from a phone on the LAN via the computer's IP address.
  const parse = (u) => (u ? new URL(u) : null);
  const urls = { public: parse(cfg.publicBaseUrl), admin: parse(cfg.adminBaseUrl), reader: parse(cfg.readerBaseUrl) };
  const sameApp = (a, b) => Boolean(a && b && a.host === b.host);
  const separate = { admin: Boolean(urls.admin && !sameApp(urls.admin, urls.public)), reader: Boolean(urls.reader && !sameApp(urls.reader, urls.public)) };
  const isLocal = (u) => ['localhost', '127.0.0.1', '[::1]'].includes(u.hostname);
  const onApp = (u, req) => (isLocal(u)
    ? req.socket.localPort === Number(u.port || (u.protocol === 'https:' ? 443 : 80))
    : req.get('host') === u.host);
  // When an app has its own host/port, it is served only there and other apps are not served on it.
  const gate = (kind) => (req, res, next) => {
    if (kind !== 'public') return separate[kind] && !onApp(urls[kind], req) ? next('router') : next();
    if ((separate.admin && onApp(urls.admin, req)) || (separate.reader && onApp(urls.reader, req))) return next('router');
    return next();
  };
  const gated = (kind, router) => { const r = express.Router(); r.use(gate(kind), router); return r; };

  app.use(securityHeaders(cfg));
  app.use(requestLogger(logger));

  app.get('/healthz', (req, res) => res.json({ status: 'ok' }));
  app.get('/readyz', async (req, res) => {
    try { await pool.query('SELECT 1'); res.json({ status: 'ready' }); } catch { res.status(503).json({ status: 'unavailable' }); }
  });

  app.use('/api', express.json({ limit: '100kb', verify: (req, res, buf) => { req.rawBody = buf; } }));
  app.use('/api', originCheck(cfg));

  // ---- APIs -------------------------------------------------------------------
  app.use('/api/admin/auth', gated('admin', adminAuthRoutes(ctx)));
  app.use('/api/admin', gated('admin', adminRoutes(ctx)));
  app.use('/api/reader', gated('reader', readerRoutes(ctx)));
  app.use('/api', gated('reader', customerRoutes(ctx)));
  app.use('/api', (req, res) => res.status(404).json({ code: 'NOT_FOUND', message: 'Not found' }));

  // ---- Static assets (shell only; no book content is ever static) -------------
  const staticOpts = { index: false, fallthrough: true, maxAge: cfg.isProd ? '1h' : 0 };
  app.use('/assets', express.static(path.join(PUBLIC_DIR, 'assets'), staticOpts));
  app.use('/static/shared', express.static(path.join(PUBLIC_DIR, 'shared'), staticOpts));
  app.use('/static/site', gated('public', express.static(path.join(PUBLIC_DIR, 'site'), staticOpts)));
  app.use('/static/admin', gated('admin', express.static(path.join(PUBLIC_DIR, 'admin'), staticOpts)));
  app.use('/static/reader', gated('reader', express.static(path.join(PUBLIC_DIR, 'reader'), staticOpts)));

  app.use(coverRoutes(ctx));

  // ---- Admin SPA ----------------------------------------------------------------
  const adminShell = (req, res) => { res.set('Cache-Control', 'no-store'); res.sendFile(path.join(PUBLIC_DIR, 'admin', 'index.html')); };
  const adminPages = express.Router();
  adminPages.get(['/admin', '/admin/*splat'], adminShell);
  if (separate.admin) adminPages.get('/', (req, res) => res.redirect('/admin'));
  app.use(gated('admin', adminPages));

  // ---- Reader PWA -----------------------------------------------------------------
  const readerShell = (req, res) => {
    res.set('Cache-Control', 'no-store');
    res.sendFile(path.join(PUBLIC_DIR, 'reader', 'index.html'));
  };
  const readerPages = express.Router();
  readerPages.get(['/access/:token', '/login', '/app', '/library', '/book/:id', '/read/:id', '/denied', '/install'], readerShell);
  readerPages.get('/manifest.webmanifest', (req, res) => {
    res.set('Cache-Control', 'no-cache');
    res.type('application/manifest+json').sendFile(path.join(PUBLIC_DIR, 'reader', 'manifest.webmanifest'));
  });
  readerPages.get('/sw.js', (req, res) => {
    res.set('Cache-Control', 'no-cache');
    res.set('Service-Worker-Allowed', '/');
    res.type('application/javascript').sendFile(path.join(PUBLIC_DIR, 'reader', 'sw.js'));
  });
  // On its own host/port, the reader's home page is the book download page.
  if (separate.reader) readerPages.get('/', readerShell);
  app.use(gated('reader', readerPages));

  // ---- Public marketing site --------------------------------------------------------
  app.use(gated('public', siteRoutes({ ...ctx, publicDir: PUBLIC_DIR })));

  // ---- Errors ---------------------------------------------------------------------
  app.use((req, res) => {
    if (req.accepts('html')) return res.status(404).type('html').send('<!doctype html><meta charset="utf-8"><title>Not found</title><p>Page not found.</p>');
    res.status(404).json({ code: 'NOT_FOUND', message: 'Not found' });
  });

  // eslint-disable-next-line no-unused-vars
  app.use((err, req, res, next) => {
    if (err instanceof multer.MulterError) {
      const status = err.code === 'LIMIT_FILE_SIZE' ? 413 : 400;
      return res.status(status).json({ code: err.code, message: status === 413 ? 'The file is too large' : 'Invalid upload' });
    }
    if (err?.type === 'entity.too.large') return res.status(413).json({ code: 'TOO_LARGE', message: 'Request is too large' });
    if (err?.type === 'entity.parse.failed') return res.status(400).json({ code: 'BAD_JSON', message: 'Invalid JSON' });
    if (err instanceof HttpError) {
      if (err.status >= 500) logger.error('request failed', { code: err.code, err });
      return res.status(err.status).json({ code: err.code, message: err.message, ...(err.extra || {}) });
    }
    logger.error('unhandled error', { err, path: req.path });
    res.status(500).json({ code: 'INTERNAL', message: 'Something went wrong. Please try again.' });
  });

  return app;
}

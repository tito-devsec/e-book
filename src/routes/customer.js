// Customer-facing API: private link pages, claiming a link from the added app, sessions.
import express from 'express';
import { validate, notFound } from '../lib/http.js';
import { cookieOptions, parseCookies } from '../middleware.js';

export function customerRoutes({ access, cfg, rateLimiter, readerAuth, pool, settings }) {
  const r = express.Router();
  const limitAccess = rateLimiter.middleware('access', 30, 10 * 60000);
  const limitVerify = rateLimiter.middleware('verify', 20, 10 * 60000);

  const setSession = (res, session) => {
    res.cookie(access.SESSION_COOKIE, session.token, cookieOptions(cfg, new Date(session.expiresAt).getTime() - Date.now()));
  };
  const noStore = (req, res, next) => { res.set('Cache-Control', 'no-store'); next(); };
  r.use(noStore);

  // ---- Public contact information for visitors without a link ---------------
  // No book is shown publicly: only who to contact and the WhatsApp link.
  r.get('/public/contact', async (req, res) => {
    const c = await settings.website();
    const wa = c.whatsapp || {};
    const id = c.site?.featuredBookId;
    const { rows: [b] } = id
      ? await pool.query('SELECT title, author FROM books WHERE id=$1 AND published', [id])
      : await pool.query('SELECT title, author FROM books WHERE published ORDER BY created_at LIMIT 1');
    const msg = (wa.orderMessage || '').replaceAll('{book_title}', b?.title || 'your book');
    res.json({
      contactName: wa.contactName || b?.author || '',
      orderUrl: wa.number ? `https://wa.me/${wa.number.replace(/^\+/, '')}?text=${encodeURIComponent(msg)}` : null,
    });
  });

  // ---- Invitations ---------------------------------------------------------
  r.post('/access/validate-invitation', limitAccess, async (req, res) => {
    const { token } = validate(req.body, { token: { type: 'string', required: true, max: 100 } });
    const result = await access.validateInvitation(token, req.ip);
    res.json(result);
  });

  // The page behind the private link asks for a one-time claim token for the app's start address.
  r.post('/access/prepare-app', limitAccess, async (req, res) => {
    const { token } = validate(req.body, { token: { type: 'string', required: true, max: 100 } });
    res.json({ claim: await access.prepareApp(token, req.ip) });
  });

  // First open of the added app: uses up the link, registers this device and signs it in.
  r.post('/access/claim', limitVerify, async (req, res) => {
    const b = validate(req.body, { claim: { type: 'string', required: true, max: 100 }, deviceKey: { type: 'object', required: true } });
    const result = await access.claimLink({ ...b, userAgent: req.get('user-agent'), ip: req.ip });
    setSession(res, result.session);
    res.json({ ok: true, bookId: result.bookId, csrf: result.session.csrf });
  });

  r.get('/auth/session', async (req, res) => {
    const token = parseCookies(req.headers.cookie)[access.SESSION_COOKIE];
    const s = await access.resolveSession(token);
    if (s.error) {
      return res.status(s.error === 'NO_SESSION' ? 401 : (['ACCOUNT_SUSPENDED', 'DEVICE_REVOKED'].includes(s.error) ? 403 : 401))
        .json({ authenticated: false, code: s.error });
    }
    const books = await access.libraryFor(s.session);
    const policy = await settings.policy();
    res.json({
      authenticated: true,
      csrf: s.session.csrf_token,
      device: { installed: Boolean(s.session.device_installed_at) },
      requireApp: policy.require_app_install !== false,
      customer: { name: s.session.full_name },
      books: books.map((b) => ({ id: b.id, title: b.title, author: b.author })),
    });
  });

  r.post('/auth/logout', async (req, res) => {
    const token = parseCookies(req.headers.cookie)[access.SESSION_COOKIE];
    await access.logout(token);
    res.clearCookie(access.SESSION_COOKIE, { path: '/' });
    res.set('Clear-Site-Data', '"cache", "storage"');
    res.json({ ok: true });
  });

  // License validation for an already authenticated session (used by the installed PWA on launch).
  r.post('/access/validate-license', readerAuth.sessionOnly(), async (req, res) => {
    const b = validate(req.body, { bookId: { type: 'uuid', required: true } });
    const lic = await access.requireBookAccess(req.reader, b.bookId, req.ip);
    res.json({ valid: true, expiresAt: lic.expires_at });
  });

  r.all('/access/*splat', () => { throw notFound(); });
  return r;
}

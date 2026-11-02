// Customer-facing API: invitation validation and activation, OTP sign-in, device replacement.
import express from 'express';
import { validate, badRequest } from '../lib/http.js';
import { cookieOptions, parseCookies } from '../middleware.js';

export function customerRoutes({ access, cfg, rateLimiter, readerAuth }) {
  const r = express.Router();
  const limitAccess = rateLimiter.middleware('access', 30, 10 * 60000);
  const limitOtp = rateLimiter.middleware('otp', 10, 10 * 60000);
  const limitVerify = rateLimiter.middleware('verify', 20, 10 * 60000);

  const setSession = (res, session) => {
    res.cookie(access.SESSION_COOKIE, session.token, cookieOptions(cfg, new Date(session.expiresAt).getTime() - Date.now()));
  };
  const noStore = (req, res, next) => { res.set('Cache-Control', 'no-store'); next(); };
  r.use(noStore);

  // ---- Invitations ---------------------------------------------------------
  r.post('/access/validate-invitation', limitAccess, async (req, res) => {
    const { token } = validate(req.body, { token: { type: 'string', required: true, max: 100 } });
    const result = await access.validateInvitation(token, req.ip);
    res.json(result);
  });

  r.post('/access/request-otp', limitOtp, async (req, res) => {
    const b = validate(req.body, { token: { type: 'string', required: true, max: 100 }, phone: { type: 'string', required: true, max: 32 } });
    res.json(await access.requestActivationOtp({ token: b.token, phone: b.phone, ip: req.ip }));
  });

  r.post('/access/activate', limitVerify, async (req, res) => {
    const b = validate(req.body, {
      token: { type: 'string', required: true, max: 100 },
      challengeId: { type: 'string', required: true, max: 64 },
      code: { type: 'string', required: true, max: 12 },
      deviceKey: { type: 'object', required: true },
    });
    const result = await access.activate({ ...b, userAgent: req.get('user-agent'), ip: req.ip });
    setSession(res, result.session);
    res.json({ ok: true, bookId: result.bookId, csrf: result.session.csrf });
  });

  // ---- Returning customers (re-authentication) -----------------------------
  r.post('/auth/request-otp', limitOtp, async (req, res) => {
    const b = validate(req.body, { phone: { type: 'string', required: true, max: 32 } });
    res.json(await access.requestLoginOtp({ phone: b.phone, ip: req.ip }));
  });

  r.post('/auth/verify-otp', limitVerify, async (req, res) => {
    const b = validate(req.body, {
      challengeId: { type: 'string', required: true, max: 64 },
      code: { type: 'string', required: true, max: 12 },
      deviceKey: { type: 'object', required: true },
    });
    const result = await access.verifyLogin({ ...b, userAgent: req.get('user-agent'), ip: req.ip });
    if (result.replacement) return res.status(409).json({ code: 'DEVICE_LIMIT', ...result.replacement });
    setSession(res, result.session);
    res.json({ ok: true, csrf: result.session.csrf });
  });

  r.post('/access/replace-device', limitVerify, async (req, res) => {
    const b = validate(req.body, { grantToken: { type: 'string', required: true, max: 100 } });
    const result = await access.replaceDevice({ grantToken: b.grantToken, ip: req.ip });
    if (result.status === 'PENDING_APPROVAL') return res.status(202).json({ status: 'PENDING_APPROVAL' });
    setSession(res, result.session);
    res.json({ status: 'REPLACED', csrf: result.session.csrf });
  });

  r.get('/auth/session', async (req, res) => {
    const token = parseCookies(req.headers.cookie)[access.SESSION_COOKIE];
    const s = await access.resolveSession(token);
    if (s.error) {
      return res.status(s.error === 'NO_SESSION' ? 401 : (['ACCOUNT_SUSPENDED', 'DEVICE_REVOKED'].includes(s.error) ? 403 : 401))
        .json({ authenticated: false, code: s.error });
    }
    const books = await access.libraryFor(s.session);
    res.json({
      authenticated: true,
      csrf: s.session.csrf_token,
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

  r.all('/access/*splat', () => { throw badRequest('Unknown endpoint', 'NOT_FOUND'); });
  return r;
}

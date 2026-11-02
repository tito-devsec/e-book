// Administrator authentication: password (scrypt), optional TOTP MFA, session rotation, lockout.
import express from 'express';
import { validate, unauthorized, badRequest, forbidden } from '../lib/http.js';
import {
  randomToken, hashPassword, verifyPassword, DUMMY_PASSWORD_HASH, base32Encode, verifyTotp,
} from '../lib/crypto.js';
import crypto from 'node:crypto';
import { ADMIN_COOKIE, cookieOptions, parseCookies } from '../middleware.js';

export function validatePasswordStrength(pw) {
  if (typeof pw !== 'string' || pw.length < 12) throw badRequest('Password must be at least 12 characters', 'WEAK_PASSWORD');
  if (pw.length > 200) throw badRequest('Password is too long', 'WEAK_PASSWORD');
  if (!/[a-zA-Z]/.test(pw) || !/[0-9\W]/.test(pw)) throw badRequest('Use letters and at least one number or symbol', 'WEAK_PASSWORD');
}

export function adminAuthRoutes({ pool, cfg, adminAuth, events, kms, rateLimiter }) {
  const r = express.Router();
  r.use((req, res, next) => { res.set('Cache-Control', 'no-store'); next(); });
  const limitLogin = rateLimiter.middleware('admin-login', 10, 15 * 60000);

  async function startSession(res, adminId, mfaPending) {
    const token = randomToken(32);
    const csrf = randomToken(24);
    const minutes = mfaPending ? 15 : cfg.adminSessionHours * 60;
    await pool.query(
      `INSERT INTO admin_sessions (admin_id, token_hash, csrf_token, mfa_pending, expires_at)
       VALUES ($1,$2,$3,$4, now() + make_interval(mins => $5))`,
      [adminId, adminAuth.hash(token), csrf, mfaPending, minutes]);
    res.cookie(ADMIN_COOKIE, token, cookieOptions(cfg, minutes * 60000));
    return csrf;
  }

  r.post('/login', limitLogin, async (req, res) => {
    const b = validate(req.body, { email: { type: 'string', required: true, max: 200 }, password: { type: 'string', required: true, max: 200, trim: false } });
    const { rows: [a] } = await pool.query('SELECT * FROM administrators WHERE lower(email)=lower($1)', [b.email]);
    const ok = await verifyPassword(b.password, a ? a.password_hash : DUMMY_PASSWORD_HASH);
    const generic = unauthorized('INVALID_CREDENTIALS', 'Email or password is incorrect');
    if (!a) throw generic;
    if (a.locked_until && new Date(a.locked_until) > new Date()) {
      throw forbidden('ACCOUNT_LOCKED', 'Too many failed attempts. Try again later.');
    }
    if (!ok || a.status !== 'ACTIVE') {
      const { rows: [u] } = await pool.query(
        `UPDATE administrators SET failed_logins=failed_logins+1,
           locked_until = CASE WHEN failed_logins+1 >= 5 THEN now() + interval '15 minutes' ELSE locked_until END
         WHERE id=$1 RETURNING failed_logins`, [a.id]);
      if (u.failed_logins >= 5) await events.security(null, { type: 'ADMIN_LOGIN_LOCKOUT', severity: 'HIGH', ip: req.ip, details: { adminId: a.id } });
      throw generic;
    }
    await pool.query('UPDATE administrators SET failed_logins=0, locked_until=NULL WHERE id=$1', [a.id]);
    // Rotate: any previous session cookie on this browser is replaced.
    const old = parseCookies(req.headers.cookie)[ADMIN_COOKIE];
    if (old) await pool.query('UPDATE admin_sessions SET revoked_at=now() WHERE token_hash=$1', [adminAuth.hash(old)]);
    const csrf = await startSession(res, a.id, a.mfa_enabled);
    if (!a.mfa_enabled) {
      await pool.query('UPDATE administrators SET last_login_at=now() WHERE id=$1', [a.id]);
      await events.audit(null, { adminId: a.id, action: 'admin.login', entityType: 'administrator', entityId: a.id, ip: req.ip });
    }
    res.json({ mfaRequired: a.mfa_enabled, csrf });
  });

  r.post('/mfa', limitLogin, async (req, res) => {
    const b = validate(req.body, { code: { type: 'string', required: true, max: 10 } });
    const s = await adminAuth.load(req);
    if (!s || !s.mfa_pending) throw unauthorized();
    const { rows: [a] } = await pool.query('SELECT * FROM administrators WHERE id=$1', [s.admin_id]);
    const secret = await kms.openSecret(a.mfa_secret_enc, `mfa:${a.id}`);
    const step = verifyTotp(secret, b.code);
    if (step === null || (a.mfa_last_step && step <= Number(a.mfa_last_step))) {
      await pool.query(`UPDATE administrators SET failed_logins=failed_logins+1,
          locked_until = CASE WHEN failed_logins+1 >= 5 THEN now() + interval '15 minutes' ELSE locked_until END WHERE id=$1`, [a.id]);
      throw unauthorized('INVALID_MFA', 'Authentication code is incorrect');
    }
    await pool.query('UPDATE administrators SET mfa_last_step=$2, failed_logins=0, last_login_at=now() WHERE id=$1', [a.id, step]);
    await pool.query('UPDATE admin_sessions SET revoked_at=now() WHERE id=$1', [s.id]);
    const csrf = await startSession(res, a.id, false);
    await events.audit(null, { adminId: a.id, action: 'admin.login', entityType: 'administrator', entityId: a.id, details: { mfa: true }, ip: req.ip });
    res.json({ ok: true, csrf });
  });

  r.get('/session', async (req, res) => {
    const s = await adminAuth.load(req);
    if (!s) return res.status(401).json({ authenticated: false });
    if (s.mfa_pending) return res.json({ authenticated: false, mfaRequired: true, csrf: s.csrf_token });
    res.json({
      authenticated: true, csrf: s.csrf_token,
      admin: { id: s.admin_id, email: s.email, name: s.full_name, role: s.role, permissions: s.permissions, mfaEnabled: s.mfa_enabled },
      mfaRequiredButMissing: cfg.requireAdminMfa && !s.mfa_enabled,
    });
  });

  r.post('/logout', async (req, res) => {
    const s = await adminAuth.load(req);
    if (s) {
      await pool.query('UPDATE admin_sessions SET revoked_at=now() WHERE id=$1', [s.id]);
      await events.audit(null, { adminId: s.admin_id, action: 'admin.logout', entityType: 'administrator', entityId: s.admin_id, ip: req.ip });
    }
    res.clearCookie(ADMIN_COOKIE, { path: '/' });
    res.json({ ok: true });
  });

  r.post('/mfa/setup', adminAuth.require(), async (req, res) => {
    const secret = base32Encode(crypto.randomBytes(20));
    const sealed = await kms.sealSecret(secret, `mfa:${req.admin.id}`);
    await pool.query('UPDATE administrators SET mfa_secret_enc=$2 WHERE id=$1 AND mfa_enabled=false', [req.admin.id, sealed]);
    const issuer = encodeURIComponent('Book Admin');
    const uri = `otpauth://totp/${issuer}:${encodeURIComponent(req.admin.email)}?secret=${secret}&issuer=${issuer}&algorithm=SHA1&digits=6&period=30`;
    res.json({ secret, uri });
  });

  r.post('/mfa/enable', adminAuth.require(), async (req, res) => {
    const b = validate(req.body, { code: { type: 'string', required: true, max: 10 } });
    const { rows: [a] } = await pool.query('SELECT * FROM administrators WHERE id=$1', [req.admin.id]);
    if (!a.mfa_secret_enc || a.mfa_enabled) throw badRequest('Start MFA setup first', 'MFA_NOT_PENDING');
    const step = verifyTotp(await kms.openSecret(a.mfa_secret_enc, `mfa:${a.id}`), b.code);
    if (step === null) throw badRequest('Code is incorrect', 'INVALID_MFA');
    await pool.query('UPDATE administrators SET mfa_enabled=true, mfa_last_step=$2 WHERE id=$1', [a.id, step]);
    await events.audit(null, { adminId: a.id, action: 'admin.mfa_enabled', entityType: 'administrator', entityId: a.id, ip: req.ip });
    res.json({ ok: true });
  });

  r.post('/password', adminAuth.require(), async (req, res) => {
    const b = validate(req.body, { current: { type: 'string', required: true, trim: false }, next: { type: 'string', required: true, trim: false } });
    const { rows: [a] } = await pool.query('SELECT * FROM administrators WHERE id=$1', [req.admin.id]);
    if (!(await verifyPassword(b.current, a.password_hash))) throw badRequest('Current password is incorrect', 'INVALID_CREDENTIALS');
    validatePasswordStrength(b.next);
    await pool.query('UPDATE administrators SET password_hash=$2, updated_at=now() WHERE id=$1', [a.id, await hashPassword(b.next)]);
    await pool.query('UPDATE admin_sessions SET revoked_at=now() WHERE admin_id=$1 AND id<>$2 AND revoked_at IS NULL', [a.id, req.admin.sessionId]);
    await events.audit(null, { adminId: a.id, action: 'admin.password_changed', entityType: 'administrator', entityId: a.id, ip: req.ip });
    res.json({ ok: true });
  });

  return r;
}

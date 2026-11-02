import crypto from 'node:crypto';
import { keyedHash, importDevicePublicKey, verifyDeviceSignature, timingSafeEqualHex } from './lib/crypto.js';
import { HttpError, unauthorized, forbidden, tooMany } from './lib/http.js';
import { redactPath } from './lib/logger.js';

export const ADMIN_COOKIE = 'as';

export function cookieOptions(cfg, maxAgeMs) {
  return { httpOnly: true, secure: cfg.cookieSecure, sameSite: 'strict', path: '/', maxAge: maxAgeMs };
}

export function parseCookies(header = '') {
  const out = {};
  for (const part of header.split(';')) {
    const i = part.indexOf('=');
    if (i > 0) out[part.slice(0, i).trim()] = decodeURIComponent(part.slice(i + 1).trim());
  }
  return out;
}

export function securityHeaders(cfg) {
  const csp = [
    "default-src 'self'",
    "script-src 'self'",
    "style-src 'self'",
    "img-src 'self' blob: data:",
    "font-src 'self'",
    "connect-src 'self'",
    "worker-src 'self'",
    "manifest-src 'self'",
    "object-src 'none'",
    "base-uri 'none'",
    "form-action 'self'",
    "frame-ancestors 'none'",
  ].join('; ');
  return (req, res, next) => {
    res.set({
      'Content-Security-Policy': csp,
      'Referrer-Policy': 'no-referrer',
      'X-Content-Type-Options': 'nosniff',
      'X-Frame-Options': 'DENY',
      'Cross-Origin-Opener-Policy': 'same-origin',
      'Cross-Origin-Resource-Policy': 'same-origin',
      'Permissions-Policy': 'camera=(), microphone=(), geolocation=(), payment=(), usb=()',
    });
    if (cfg.cookieSecure) res.set('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
    next();
  };
}

/** Reject cross-site state-changing requests and form posts. */
export function originCheck(cfg) {
  const allowed = new Set([cfg.publicBaseUrl, cfg.adminBaseUrl, cfg.readerBaseUrl].filter(Boolean).map((u) => new URL(u).origin));
  return (req, res, next) => {
    if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) return next();
    const origin = req.get('origin');
    if (origin) {
      const self = `${req.protocol}://${req.get('host')}`;
      if (origin !== self && !allowed.has(origin)) return next(forbidden('BAD_ORIGIN', 'Cross-origin request blocked'));
    }
    const ct = req.get('content-type') || '';
    const hasBody = Number(req.headers['content-length'] || 0) > 0 || Boolean(req.headers['transfer-encoding']);
    // HTML forms cannot send these content types cross-site without a CORS preflight.
    if (hasBody && !/^(application\/json|multipart\/form-data)/i.test(ct)) {
      return next(new HttpError(415, 'UNSUPPORTED_MEDIA_TYPE', 'Send JSON'));
    }
    next();
  };
}

export function requestLogger(logger) {
  return (req, res, next) => {
    const start = process.hrtime.bigint();
    res.on('finish', () => {
      const ms = Number(process.hrtime.bigint() - start) / 1e6;
      logger.info('http', { method: req.method, path: redactPath(req.originalUrl.split('?')[0]), status: res.statusCode, ms: Math.round(ms) });
    });
    next();
  };
}

// ---------------------------------------------------------------------------
// Administrator authentication + RBAC
// ---------------------------------------------------------------------------
export function createAdminAuth({ pool, cfg }) {
  const hash = (t) => keyedHash(cfg.hashPepper, t, 'admin-session');

  async function load(req) {
    const token = parseCookies(req.headers.cookie)[ADMIN_COOKIE];
    if (!token) return null;
    const { rows: [s] } = await pool.query(
      `SELECT s.*, a.email, a.full_name, a.status AS admin_status, a.mfa_enabled, r.name AS role,
              ARRAY(SELECT p.code FROM role_permissions rp JOIN permissions p ON p.id=rp.permission_id WHERE rp.role_id=a.role_id) AS permissions
         FROM admin_sessions s JOIN administrators a ON a.id=s.admin_id JOIN roles r ON r.id=a.role_id
        WHERE s.token_hash=$1`, [hash(token)]);
    if (!s || s.revoked_at || new Date(s.expires_at) <= new Date() || s.admin_status !== 'ACTIVE') return null;
    if (Date.now() - new Date(s.last_seen_at).getTime() > cfg.adminIdleMinutes * 60000) {
      await pool.query('UPDATE admin_sessions SET revoked_at=now() WHERE id=$1', [s.id]);
      return null;
    }
    if (Date.now() - new Date(s.last_seen_at).getTime() > 30000) {
      await pool.query('UPDATE admin_sessions SET last_seen_at=now() WHERE id=$1', [s.id]);
    }
    return s;
  }

  /** Require a fully authenticated admin (MFA done) with every listed permission. */
  function require(...perms) {
    return async (req, res, next) => {
      try {
        const s = await load(req);
        if (!s || s.mfa_pending) throw unauthorized();
        if (!['GET', 'HEAD'].includes(req.method)) {
          const sent = req.get('x-csrf-token') || '';
          if (sent.length !== s.csrf_token.length || !crypto.timingSafeEqual(Buffer.from(sent), Buffer.from(s.csrf_token))) {
            throw forbidden('CSRF', 'Security token missing or invalid. Reload the page.');
          }
        }
        // When MFA is mandatory, an admin without MFA may only use permission-free routes (MFA setup).
        if (cfg.requireAdminMfa && !s.mfa_enabled && perms.length > 0) {
          throw forbidden('MFA_SETUP_REQUIRED', 'Set up two-factor authentication to continue');
        }
        for (const p of perms) if (!s.permissions.includes(p)) throw forbidden('PERMISSION_DENIED', 'You do not have permission for this action');
        req.admin = { id: s.admin_id, email: s.email, name: s.full_name, role: s.role, permissions: s.permissions, sessionId: s.id };
        next();
      } catch (e) { next(e); }
    };
  }
  return { load, require, hash };
}

// ---------------------------------------------------------------------------
// Reader authentication: session cookie + device signature + replay protection.
// ---------------------------------------------------------------------------
export function createReaderAuth({ pool, access, events, rateLimiter, settings }) {
  const SIG_WINDOW_MS = 120000;

  function sessionOnly({ csrf = true } = {}) {
    return async (req, res, next) => {
      try {
        const token = parseCookies(req.headers.cookie)[access.SESSION_COOKIE];
        const r = await access.resolveSession(token);
        if (r.error) {
          const status = r.error === 'ACCOUNT_SUSPENDED' || r.error === 'DEVICE_REVOKED' ? 403 : 401;
          throw new HttpError(status, r.error, 'Your reading session is not active');
        }
        if (csrf && !['GET', 'HEAD'].includes(req.method)) {
          const sent = req.get('x-csrf-token') || '';
          if (sent.length !== r.session.csrf_token.length || !crypto.timingSafeEqual(Buffer.from(sent), Buffer.from(r.session.csrf_token))) {
            throw forbidden('CSRF', 'Security token missing or invalid');
          }
        }
        req.reader = r.session;
        next();
      } catch (e) { next(e); }
    };
  }

  /** Verify the request is signed by the device key registered to this session. */
  function signed() {
    return async (req, res, next) => {
      try {
        const s = req.reader;
        const ts = Number(req.get('x-sig-ts'));
        const nonce = req.get('x-sig-nonce') || '';
        const sig = req.get('x-sig') || '';
        if (!Number.isFinite(ts) || Math.abs(Date.now() - ts) > SIG_WINDOW_MS || !/^[A-Za-z0-9_-]{16,64}$/.test(nonce)) {
          throw new HttpError(401, 'SIGNATURE_INVALID', 'Request could not be verified');
        }
        const bodyHash = crypto.createHash('sha256').update(req.rawBody || '').digest('hex');
        const message = `${req.method}\n${req.originalUrl}\n${ts}\n${nonce}\n${bodyHash}`;
        const key = importDevicePublicKey(s.public_key_jwk);
        if (!verifyDeviceSignature(key, message, sig)) {
          await events.security(null, { type: 'INVALID_DEVICE_SIGNATURE', severity: 'HIGH', customerId: s.customer_id, deviceId: s.device_id, ip: req.ip });
          throw new HttpError(401, 'SIGNATURE_INVALID', 'Request could not be verified');
        }
        const ins = await pool.query(
          `INSERT INTO request_nonces (device_id, nonce, expires_at) VALUES ($1,$2, now() + interval '5 minutes')
           ON CONFLICT DO NOTHING`, [s.device_id, nonce]);
        if (ins.rowCount !== 1) {
          await events.security(null, { type: 'REPLAYED_REQUEST', severity: 'HIGH', customerId: s.customer_id, deviceId: s.device_id, ip: req.ip });
          throw new HttpError(401, 'SIGNATURE_INVALID', 'Request could not be verified');
        }
        const policy = await settings.policy();
        const rl = rateLimiter.hit(`content:${s.id}`, policy.content_requests_per_minute, 60000);
        if (!rl.allowed) {
          if (rl.count === policy.content_requests_per_minute + 1) {
            await events.security(null, { type: 'ABNORMAL_REQUEST_VOLUME', severity: 'HIGH', customerId: s.customer_id, deviceId: s.device_id, ip: req.ip, details: { perMinute: rl.count } });
          }
          throw tooMany();
        }
        next();
      } catch (e) { next(e); }
    };
  }

  return { sessionOnly, signed };
}

export { timingSafeEqualHex };

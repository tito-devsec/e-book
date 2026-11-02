// Customer access lifecycle: invitations, OTP, activation, device registration and
// replacement, reading sessions, and license checks.
import crypto from 'node:crypto';
import { tx } from '../db.js';
import {
  randomToken, keyedHash, randomOtp, timingSafeEqualHex, importDevicePublicKey, jwkThumbprint,
} from '../lib/crypto.js';
import { HttpError, badRequest, unauthorized, forbidden, notFound, tooMany, maskPhone, normalizePhone } from '../lib/http.js';
import { describeUserAgent } from '../lib/userAgent.js';

const SESSION_COOKIE = 'rs';

/**
 * Compare a customer-typed number with the stored E.164 number. Accepts the full international
 * form or a local form (e.g. 0712 345 678) whose significant digits end the stored number.
 */
export function phoneMatches(input, e164) {
  if (typeof input !== 'string') return false;
  const stored = e164.replace(/\D/g, '');
  let typed = input.replace(/[\s().-]/g, '');
  if (typed.startsWith('+')) return typed.slice(1) === stored;
  if (typed.startsWith('00')) return typed.slice(2) === stored;
  typed = typed.replace(/\D/g, '').replace(/^0+/, '');
  return typed.length >= 7 && stored.endsWith(typed) && stored.length - typed.length <= 3;
}
export { SESSION_COOKIE };

export function createAccess({ pool, cfg, settings, events, otpDelivery, logger }) {
  const tokenHash = (t, purpose) => keyedHash(cfg.hashPepper, t, purpose);
  const readerBase = () => (cfg.readerBaseUrl || cfg.publicBaseUrl).replace(/\/$/, '');

  function parseDeviceKey(jwk) {
    try {
      importDevicePublicKey(jwk);
    } catch {
      throw badRequest('This browser could not be registered. Please use an up-to-date browser.', 'INVALID_DEVICE_KEY');
    }
    const clean = { kty: 'EC', crv: 'P-256', x: jwk.x, y: jwk.y };
    return { jwk: clean, thumbprint: jwkThumbprint(clean) };
  }

  // -------------------------------------------------------------------------
  // Invitations
  // -------------------------------------------------------------------------
  async function createInvitation({ licenseId, adminId, expiryHours, ip }) {
    const policy = await settings.policy();
    const hours = expiryHours || policy.invitation_expiry_hours || 24;
    return tx(pool, async (db) => {
      const { rows: [lic] } = await db.query(
        `SELECT l.*, o.status AS order_status, c.full_name, c.phone_e164, c.status AS customer_status,
                b.title AS book_title
           FROM reading_licenses l
           JOIN orders o ON o.id = l.order_id
           JOIN customers c ON c.id = l.customer_id
           JOIN books b ON b.id = l.book_id
          WHERE l.id = $1 FOR UPDATE OF l`, [licenseId]);
      if (!lic) throw notFound('License not found');
      if (lic.order_status !== 'PAID') throw badRequest('Payment must be verified before an invitation can be issued', 'PAYMENT_NOT_VERIFIED');
      if (lic.status !== 'PENDING_ACTIVATION') {
        throw badRequest('This license is already activated or not available. The customer signs in with their phone number instead.', 'LICENSE_NOT_PENDING');
      }
      if (['SUSPENDED', 'REVOKED'].includes(lic.customer_status)) throw badRequest('Customer access is suspended or revoked', 'CUSTOMER_BLOCKED');

      const { rows: prev } = await db.query(
        `UPDATE invitations SET status='REPLACED' WHERE license_id=$1 AND status='PENDING' RETURNING id`, [licenseId]);
      const token = randomToken(32); // 256 bits
      const { rows: [inv] } = await db.query(
        `INSERT INTO invitations (license_id, customer_id, book_id, order_id, phone_e164, token_hash, token_hint, expires_at, created_by)
         VALUES ($1,$2,$3,$4,$5,$6,$7, now() + make_interval(hours => $8), $9) RETURNING *`,
        [licenseId, lic.customer_id, lic.book_id, lic.order_id, lic.phone_e164, tokenHash(token, 'invite'), token.slice(0, 6), hours, adminId]);
      if (prev.length) await db.query('UPDATE invitations SET replaced_by=$1 WHERE id = ANY($2::uuid[])', [inv.id, prev.map((p) => p.id)]);
      await db.query(`UPDATE customers SET status='INVITED', updated_at=now() WHERE id=$1 AND status IN ('PAID','INVITED')`, [lic.customer_id]);
      await events.audit(db, {
        adminId, action: prev.length ? 'invitation.reissue' : 'invitation.create', entityType: 'invitation', entityId: inv.id,
        details: { licenseId, customerId: lic.customer_id, bookId: lic.book_id, expiresAt: inv.expires_at, tokenHint: inv.token_hint, replaced: prev.map((p) => p.id) }, ip,
      });
      const link = `${readerBase()}/access/${token}`;
      const website = await settings.website();
      const template = website.whatsapp?.invitationTemplate || '{invitation_link}';
      const message = template
        .replaceAll('{customer_name}', lic.full_name)
        .replaceAll('{book_title}', lic.book_title)
        .replaceAll('{invitation_link}', link)
        .replaceAll('{expiry_hours}', String(hours));
      const waLink = `https://wa.me/${lic.phone_e164.replace(/^\+/, '')}?text=${encodeURIComponent(message)}`;
      return { invitation: publicInvitation(inv), link, message, whatsappUrl: waLink };
    });
  }

  function publicInvitation(inv) {
    const { token_hash: _h, ...rest } = inv;
    return rest;
  }

  /** Look up an invitation by raw token. Returns { state, inv }. */
  async function findInvitation(db, token, lock = false) {
    if (typeof token !== 'string' || !/^[A-Za-z0-9_-]{40,64}$/.test(token)) return { state: 'INVALID' };
    const { rows: [inv] } = await db.query(
      `SELECT i.*, c.status AS customer_status, l.status AS license_status
         FROM invitations i JOIN customers c ON c.id=i.customer_id JOIN reading_licenses l ON l.id=i.license_id
        WHERE i.token_hash=$1 ${lock ? 'FOR UPDATE OF i' : ''}`, [tokenHash(token, 'invite')]);
    if (!inv) return { state: 'INVALID' };
    if (inv.status === 'CONSUMED') return { state: 'CONSUMED', inv };
    if (inv.status === 'REVOKED' || inv.status === 'REPLACED') return { state: 'REVOKED', inv };
    if (inv.status === 'EXPIRED' || new Date(inv.expires_at) <= new Date()) {
      if (inv.status === 'PENDING') await db.query(`UPDATE invitations SET status='EXPIRED' WHERE id=$1 AND status='PENDING'`, [inv.id]);
      return { state: 'EXPIRED', inv };
    }
    if (['SUSPENDED', 'REVOKED'].includes(inv.customer_status) || inv.license_status !== 'PENDING_ACTIVATION') return { state: 'REVOKED', inv };
    return { state: 'VALID', inv };
  }

  async function invitationAttemptEvent(state, inv, ip) {
    const map = { CONSUMED: ['REUSED_INVITATION', 'MEDIUM'], EXPIRED: ['EXPIRED_INVITATION', 'LOW'], REVOKED: ['REVOKED_INVITATION', 'MEDIUM'], INVALID: ['INVALID_INVITATION', 'LOW'] };
    const [type, severity] = map[state];
    await events.security(null, { type, severity, customerId: inv?.customer_id, invitationId: inv?.id, ip });
  }

  async function validateInvitation(token, ip) {
    const { state, inv } = await findInvitation(pool, token);
    if (state !== 'VALID') {
      await invitationAttemptEvent(state, inv, ip);
      return { state };
    }
    if (!inv.opened_at) await pool.query('UPDATE invitations SET opened_at=now() WHERE id=$1', [inv.id]);
    await events.reading(null, { type: 'INVITATION_OPENED', customerId: inv.customer_id, bookId: inv.book_id });
    const { rows: [book] } = await pool.query('SELECT id, title, author, subtitle, cover_storage_key, published FROM books WHERE id=$1', [inv.book_id]);
    return {
      state,
      book: { id: book.id, title: book.title, author: book.author, subtitle: book.subtitle, hasCover: Boolean(book.cover_storage_key && book.published) },
      phoneHint: maskPhone(inv.phone_e164),
      expiresAt: inv.expires_at,
    };
  }

  // -------------------------------------------------------------------------
  // OTP
  // -------------------------------------------------------------------------
  async function issueOtp(db, { customerId, phone, purpose, invitationId }) {
    const policy = await settings.policy();
    const { rows: [stats] } = await db.query(
      `SELECT count(*)::int AS n, max(created_at) AS last FROM otp_challenges
        WHERE customer_id=$1 AND created_at > now() - interval '1 hour'`, [customerId]);
    if (stats.n >= policy.otp_max_requests_per_hour) {
      await events.security(db, { type: 'OTP_REQUEST_LIMIT', severity: 'MEDIUM', customerId, invitationId });
      throw tooMany('Too many codes requested. Please wait before trying again.', 'OTP_RATE_LIMITED');
    }
    if (stats.last && Date.now() - new Date(stats.last).getTime() < policy.otp_resend_cooldown_seconds * 1000) {
      throw tooMany(`Please wait ${policy.otp_resend_cooldown_seconds} seconds before requesting another code.`, 'OTP_COOLDOWN');
    }
    const code = randomOtp(6);
    const id = crypto.randomUUID();
    await db.query(
      `INSERT INTO otp_challenges (id, customer_id, invitation_id, purpose, code_hash, max_attempts, expires_at)
       VALUES ($1,$2,$3,$4,$5,$6, now() + make_interval(mins => $7))`,
      [id, customerId, invitationId || null, purpose, tokenHash(`${id}:${code}`, 'otp'), policy.otp_max_attempts, policy.otp_ttl_minutes]);
    let status = 'SENT';
    try {
      status = await otpDelivery.send(phone, code);
    } catch (err) {
      logger.error('otp send failed', { customerId, err });
      throw new HttpError(502, 'OTP_DELIVERY_FAILED', 'We could not send your code right now. Please try again shortly.');
    }
    await db.query('UPDATE otp_challenges SET delivery_status=$2 WHERE id=$1', [id, status]);
    await events.reading(db, { type: 'OTP_REQUESTED', customerId, details: { purpose } });
    return { challengeId: id, expiresInSeconds: policy.otp_ttl_minutes * 60 };
  }

  /**
   * Check an OTP inside a transaction. On a wrong code, the attempt counter is committed by the
   * caller returning normally; never throw after incrementing.
   */
  async function checkOtp(db, { challengeId, code, purpose, invitationId }) {
    const { rows: [ch] } = await db.query('SELECT * FROM otp_challenges WHERE id=$1 FOR UPDATE', [challengeId]);
    if (!ch || ch.purpose !== purpose || (invitationId && ch.invitation_id !== invitationId)) return { ok: false, reason: 'INVALID' };
    if (ch.consumed_at) return { ok: false, reason: 'USED', ch };
    if (new Date(ch.expires_at) <= new Date()) return { ok: false, reason: 'EXPIRED', ch };
    if (ch.attempts >= ch.max_attempts) return { ok: false, reason: 'LOCKED', ch };
    const good = typeof code === 'string' && /^\d{6}$/.test(code)
      && timingSafeEqualHex(tokenHash(`${ch.id}:${code}`, 'otp'), ch.code_hash);
    if (!good) {
      const { rows: [u] } = await db.query('UPDATE otp_challenges SET attempts=attempts+1 WHERE id=$1 RETURNING attempts, max_attempts', [ch.id]);
      if (u.attempts >= u.max_attempts) {
        await events.security(db, { type: 'OTP_FAILURES', severity: 'HIGH', customerId: ch.customer_id, invitationId: ch.invitation_id, details: { attempts: u.attempts } });
      }
      return { ok: false, reason: u.attempts >= u.max_attempts ? 'LOCKED' : 'WRONG', remaining: u.max_attempts - u.attempts, ch };
    }
    await db.query('UPDATE otp_challenges SET consumed_at=now() WHERE id=$1', [ch.id]);
    await events.reading(db, { type: 'OTP_VERIFIED', customerId: ch.customer_id, details: { purpose } });
    return { ok: true, ch };
  }

  function otpError(r) {
    const messages = {
      WRONG: `That code is not correct.${r.remaining !== undefined ? ` ${r.remaining} attempt(s) left.` : ''}`,
      LOCKED: 'Too many incorrect attempts. Request a new code.',
      EXPIRED: 'This code has expired. Request a new code.',
      USED: 'This code was already used. Request a new code.',
      INVALID: 'This code is not valid. Request a new code.',
    };
    return badRequest(messages[r.reason] || messages.INVALID, `OTP_${r.reason}`);
  }

  async function requestActivationOtp({ token, phone, ip }) {
    const { state, inv } = await findInvitation(pool, token);
    if (state !== 'VALID') {
      await invitationAttemptEvent(state, inv, ip);
      throw badRequest('This invitation is no longer valid.', `INVITATION_${state}`);
    }
    if (!phoneMatches(phone, inv.phone_e164)) {
      await events.security(null, { type: 'WRONG_PHONE_FOR_INVITATION', severity: 'MEDIUM', customerId: inv.customer_id, invitationId: inv.id, ip });
      throw badRequest('This number is not registered for this invitation. Enter the WhatsApp number you used to order.', 'PHONE_MISMATCH');
    }
    // The code always goes to the number stored with the invitation, never a client-supplied one.
    return issueOtp(pool, { customerId: inv.customer_id, phone: inv.phone_e164, purpose: 'ACTIVATION', invitationId: inv.id });
  }

  // -------------------------------------------------------------------------
  // Devices and sessions
  // -------------------------------------------------------------------------
  async function createSession(db, { customerId, deviceId }) {
    const policy = await settings.policy();
    const token = randomToken(32);
    const csrf = randomToken(24);
    // One session per device: end older sessions on this device.
    await db.query(`UPDATE reading_sessions SET ended_at=now(), end_reason='ROTATED' WHERE device_id=$1 AND ended_at IS NULL`, [deviceId]);
    const { rows: [s] } = await db.query(
      `INSERT INTO reading_sessions (customer_id, device_id, token_hash, csrf_token, expires_at)
       VALUES ($1,$2,$3,$4, now() + make_interval(hours => $5)) RETURNING id, expires_at`,
      [customerId, deviceId, tokenHash(token, 'session'), csrf, policy.session_ttl_hours]);
    const { rows: [other] } = await db.query(
      `SELECT count(DISTINCT device_id)::int AS n FROM reading_sessions
        WHERE customer_id=$1 AND ended_at IS NULL AND expires_at > now() AND device_id <> $2`, [customerId, deviceId]);
    if (other.n > 0) {
      await events.security(db, { type: 'MULTIPLE_SESSIONS', severity: 'LOW', customerId, deviceId, details: { otherDevices: other.n } });
    }
    return { token, csrf, sessionId: s.id, expiresAt: s.expires_at };
  }

  async function activeAuthorizationCount(db, licenseId) {
    const { rows: [r] } = await db.query(
      `SELECT count(*)::int AS n FROM device_authorizations da JOIN registered_devices d ON d.id=da.device_id
        WHERE da.license_id=$1 AND da.status='ACTIVE' AND d.status='ACTIVE'`, [licenseId]);
    return r.n;
  }

  async function findActiveDevice(db, customerId, thumbprint) {
    const { rows: [d] } = await db.query(
      `SELECT * FROM registered_devices WHERE customer_id=$1 AND key_thumbprint=$2 AND status IN ('ACTIVE','PENDING_APPROVAL')`,
      [customerId, thumbprint]);
    return d;
  }

  async function insertDevice(db, { customerId, key, userAgent, status = 'ACTIVE', replaces = null }) {
    const ua = describeUserAgent(userAgent);
    const { rows: [d] } = await db.query(
      `INSERT INTO registered_devices (customer_id, public_key_jwk, key_thumbprint, browser, os, device_category, status, replaces_device_id)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING *`,
      [customerId, key.jwk, key.thumbprint, ua.browser, ua.os, ua.category, status, replaces]);
    await events.reading(db, { type: status === 'ACTIVE' ? 'DEVICE_REGISTERED' : 'DEVICE_PENDING_APPROVAL', customerId, deviceId: d.id, details: ua });
    return d;
  }

  async function authorize(db, deviceId, licenseId) {
    await db.query(
      `INSERT INTO device_authorizations (device_id, license_id) VALUES ($1,$2)
       ON CONFLICT (device_id, license_id) DO UPDATE SET status='ACTIVE', revoked_at=NULL`, [deviceId, licenseId]);
  }

  async function endDeviceSessions(db, deviceId, reason) {
    await db.query(`UPDATE reading_sessions SET ended_at=now(), end_reason=$2 WHERE device_id=$1 AND ended_at IS NULL`, [deviceId, reason]);
  }

  // -------------------------------------------------------------------------
  // Activation (invitation + OTP + device + session), exactly once.
  // -------------------------------------------------------------------------
  async function activate({ token, challengeId, code, deviceKey, userAgent, ip }) {
    const key = parseDeviceKey(deviceKey);
    const result = await tx(pool, async (db) => {
      const { state, inv } = await findInvitation(db, token, true);
      if (state !== 'VALID') return { error: badRequest('This invitation is no longer valid.', `INVITATION_${state}`), state, inv };
      const otp = await checkOtp(db, { challengeId, code, purpose: 'ACTIVATION', invitationId: inv.id });
      if (!otp.ok) return { error: otpError(otp) };

      const consumed = await db.query(
        `UPDATE invitations SET status='CONSUMED', consumed_at=now() WHERE id=$1 AND status='PENDING' RETURNING id`, [inv.id]);
      if (consumed.rowCount !== 1) throw badRequest('This invitation is no longer valid.', 'INVITATION_CONSUMED');

      const { rows: [lic] } = await db.query(
        `UPDATE reading_licenses SET status='ACTIVE', activated_at=now(), updated_at=now(),
           expires_at = CASE WHEN duration_days IS NULL THEN NULL ELSE now() + make_interval(days => duration_days) END
         WHERE id=$1 AND status='PENDING_ACTIVATION' RETURNING *`, [inv.license_id]);
      if (!lic) throw badRequest('This invitation is no longer valid.', 'INVITATION_REVOKED');

      let device = await findActiveDevice(db, inv.customer_id, key.thumbprint);
      if (device && device.status !== 'ACTIVE') throw forbidden('DEVICE_PENDING', 'This browser is waiting for approval by the book owner.');
      if (!device) device = await insertDevice(db, { customerId: inv.customer_id, key, userAgent });
      await authorize(db, device.id, lic.id);

      await db.query(`UPDATE customers SET status='ACTIVATED', updated_at=now() WHERE id=$1 AND status IN ('PAID','INVITED','EXPIRED')`, [inv.customer_id]);
      await events.reading(db, { type: 'LICENSE_ACTIVATED', customerId: inv.customer_id, bookId: inv.book_id, deviceId: device.id });
      const session = await createSession(db, { customerId: inv.customer_id, deviceId: device.id });
      return { session, bookId: inv.book_id, customerId: inv.customer_id };
    });
    if (result.error) {
      if (result.state) await invitationAttemptEvent(result.state, result.inv, ip);
      throw result.error;
    }
    return result;
  }

  // -------------------------------------------------------------------------
  // Returning customers: OTP login, device check, replacement.
  // -------------------------------------------------------------------------
  async function requestLoginOtp({ phone, ip }) {
    const e164 = normalizePhone(phone, process.env.DEFAULT_COUNTRY_CODE || '');
    if (!e164) throw badRequest('Enter your WhatsApp number in international format, for example +254712345678.', 'INVALID_PHONE');
    const { rows: [c] } = await pool.query(
      `SELECT c.id, c.status, c.phone_e164,
              EXISTS (SELECT 1 FROM reading_licenses l WHERE l.customer_id=c.id AND l.status='ACTIVE'
                        AND (l.expires_at IS NULL OR l.expires_at > now())) AS has_license
         FROM customers c WHERE c.phone_e164=$1`, [e164]);
    const eligible = c && c.has_license && !['SUSPENDED', 'REVOKED'].includes(c.status);
    if (!eligible) {
      if (c && ['SUSPENDED', 'REVOKED'].includes(c.status)) {
        await events.security(null, { type: 'SUSPENDED_ACCESS_ATTEMPT', severity: 'MEDIUM', customerId: c.id, ip });
      }
      // Identical response shape so the endpoint does not reveal who is a customer.
      const policy = await settings.policy();
      return { challengeId: crypto.randomUUID(), expiresInSeconds: policy.otp_ttl_minutes * 60 };
    }
    return issueOtp(pool, { customerId: c.id, phone: c.phone_e164, purpose: 'LOGIN' });
  }

  async function loginLicensesAndBlocks(db, customerId, deviceId) {
    const { rows: licenses } = await db.query(
      `SELECT l.* FROM reading_licenses l JOIN orders o ON o.id=l.order_id AND o.status='PAID'
        WHERE l.customer_id=$1 AND l.status='ACTIVE' AND (l.expires_at IS NULL OR l.expires_at > now())
        FOR UPDATE OF l`, [customerId]);
    const blocked = [];
    const free = [];
    for (const l of licenses) {
      if (deviceId) {
        const { rowCount } = await db.query(
          `SELECT 1 FROM device_authorizations WHERE device_id=$1 AND license_id=$2 AND status='ACTIVE'`, [deviceId, l.id]);
        if (rowCount) continue;
      }
      if ((await activeAuthorizationCount(db, l.id)) < l.max_devices) free.push(l); else blocked.push(l);
    }
    return { licenses, blocked, free };
  }

  async function verifyLogin({ challengeId, code, deviceKey, userAgent, ip }) {
    const key = parseDeviceKey(deviceKey);
    const result = await tx(pool, async (db) => {
      if (typeof challengeId !== 'string' || !/^[0-9a-f-]{36}$/i.test(challengeId)) return { error: otpError({ reason: 'INVALID' }) };
      const otp = await checkOtp(db, { challengeId, code, purpose: 'LOGIN' });
      if (!otp.ok) return { error: otpError(otp) };
      const customerId = otp.ch.customer_id;
      const { rows: [cust] } = await db.query('SELECT * FROM customers WHERE id=$1 FOR UPDATE', [customerId]);
      if (['SUSPENDED', 'REVOKED'].includes(cust.status)) {
        await events.security(db, { type: 'SUSPENDED_ACCESS_ATTEMPT', severity: 'MEDIUM', customerId, ip });
        return { error: forbidden('ACCOUNT_SUSPENDED', 'Access to this account is paused. Please contact the book owner.') };
      }
      let device = await findActiveDevice(db, customerId, key.thumbprint);
      if (device?.status === 'PENDING_APPROVAL') return { error: forbidden('DEVICE_PENDING', 'This browser is waiting for approval by the book owner.') };
      const { licenses, blocked, free } = await loginLicensesAndBlocks(db, customerId, device?.id);
      if (licenses.length === 0) return { error: forbidden('NO_ACTIVE_LICENSE', 'There is no active book access on this account.') };

      const authorizedHere = licenses.length - blocked.length - free.length;
      if (authorizedHere === 0 && free.length === 0) {
        // Every purchased book is already registered to another browser: replacement needed.
        const grant = randomToken(32);
        await db.query(
          `INSERT INTO pending_device_grants (customer_id, token_hash, public_key_jwk, key_thumbprint, user_agent, expires_at)
           VALUES ($1,$2,$3,$4,$5, now() + interval '15 minutes')`,
          [customerId, tokenHash(grant, 'grant'), key.jwk, key.thumbprint, String(userAgent || '').slice(0, 400)]);
        await events.security(db, { type: 'NEW_DEVICE_ATTEMPT', severity: 'LOW', customerId, ip });
        const policy = await settings.policy();
        return { replacement: { grantToken: grant, mode: policy.device_replacement_mode } };
      }
      if (!device) device = await insertDevice(db, { customerId, key, userAgent });
      for (const l of free) await authorize(db, device.id, l.id);
      await db.query('UPDATE registered_devices SET last_seen_at=now() WHERE id=$1', [device.id]);
      const session = await createSession(db, { customerId, deviceId: device.id });
      return { session, customerId };
    });
    if (result.error) throw result.error;
    return result;
  }

  async function replaceDevice({ grantToken, ip }) {
    const policy = await settings.policy();
    return tx(pool, async (db) => {
      const { rows: [g] } = await db.query(
        `SELECT * FROM pending_device_grants WHERE token_hash=$1 AND used_at IS NULL AND expires_at > now() FOR UPDATE`,
        [tokenHash(String(grantToken || ''), 'grant')]);
      if (!g) throw badRequest('This request has expired. Please sign in again.', 'GRANT_INVALID');
      await db.query('UPDATE pending_device_grants SET used_at=now() WHERE id=$1', [g.id]);
      const { rows: [cust] } = await db.query('SELECT * FROM customers WHERE id=$1 FOR UPDATE', [g.customer_id]);
      if (['SUSPENDED', 'REVOKED'].includes(cust.status)) throw forbidden('ACCOUNT_SUSPENDED', 'Access to this account is paused. Please contact the book owner.');

      const { rows: [{ n: recent }] } = await db.query(
        `SELECT count(*)::int AS n FROM device_replacements WHERE customer_id=$1 AND mode='SELF_SERVICE' AND created_at > now() - interval '30 days'`,
        [g.customer_id]);
      const selfService = policy.device_replacement_mode === 'SELF_SERVICE' && recent < policy.max_self_replacements_per_30d;
      const key = { jwk: g.public_key_jwk, thumbprint: g.key_thumbprint };

      if (!selfService) {
        const existing = await findActiveDevice(db, g.customer_id, key.thumbprint);
        const device = existing || await insertDevice(db, { customerId: g.customer_id, key, userAgent: g.user_agent, status: 'PENDING_APPROVAL' });
        await db.query(
          `INSERT INTO device_replacements (customer_id, new_device_id, mode) VALUES ($1,$2,'PENDING')`, [g.customer_id, device.id]);
        await events.security(db, { type: 'DEVICE_REPLACEMENT_REQUESTED', severity: 'LOW', customerId: g.customer_id, deviceId: device.id, ip });
        return { status: 'PENDING_APPROVAL' };
      }

      const known = await findActiveDevice(db, g.customer_id, key.thumbprint);
      if (known && known.status !== 'ACTIVE') throw forbidden('DEVICE_PENDING', 'This browser is waiting for approval by the book owner.');
      const { blocked, free } = await loginLicensesAndBlocks(db, g.customer_id, known?.id);
      const device = known || await insertDevice(db, { customerId: g.customer_id, key, userAgent: g.user_agent });
      const oldDevices = new Set();
      for (const l of blocked) {
        // Revoke the least recently used authorization on this license to free a slot.
        const { rows: [old] } = await db.query(
          `SELECT da.device_id FROM device_authorizations da JOIN registered_devices d ON d.id=da.device_id
            WHERE da.license_id=$1 AND da.status='ACTIVE' AND d.status='ACTIVE'
            ORDER BY d.last_seen_at NULLS FIRST, d.registered_at LIMIT 1`, [l.id]);
        if (old) {
          await db.query(`UPDATE device_authorizations SET status='REVOKED', revoked_at=now() WHERE device_id=$1 AND license_id=$2`, [old.device_id, l.id]);
          oldDevices.add(old.device_id);
        }
        await authorize(db, device.id, l.id);
      }
      for (const l of free) await authorize(db, device.id, l.id);
      for (const oldId of oldDevices) {
        const { rows: [{ n }] } = await db.query(
          `SELECT count(*)::int AS n FROM device_authorizations WHERE device_id=$1 AND status='ACTIVE'`, [oldId]);
        if (n === 0) {
          await db.query(`UPDATE registered_devices SET status='REPLACED', revoked_at=now(), revoked_reason='Replaced by customer' WHERE id=$1`, [oldId]);
        }
        await endDeviceSessions(db, oldId, 'DEVICE_REPLACED');
        await db.query(
          `INSERT INTO device_replacements (customer_id, old_device_id, new_device_id, mode, decided_at) VALUES ($1,$2,$3,'SELF_SERVICE', now())`,
          [g.customer_id, oldId, device.id]);
      }
      await events.reading(db, { type: 'DEVICE_REPLACED', customerId: g.customer_id, deviceId: device.id, details: { previous: [...oldDevices] } });
      const session = await createSession(db, { customerId: g.customer_id, deviceId: device.id });
      return { status: 'REPLACED', session };
    });
  }

  // -------------------------------------------------------------------------
  // Session resolution (used by middleware)
  // -------------------------------------------------------------------------
  async function resolveSession(rawToken) {
    if (!rawToken || typeof rawToken !== 'string') return { error: 'NO_SESSION' };
    const { rows: [s] } = await pool.query(
      `SELECT s.*, d.status AS device_status, d.public_key_jwk, d.transition_until, c.status AS customer_status,
              c.full_name, c.phone_e164
         FROM reading_sessions s JOIN registered_devices d ON d.id=s.device_id JOIN customers c ON c.id=s.customer_id
        WHERE s.token_hash=$1`, [tokenHash(rawToken, 'session')]);
    if (!s) return { error: 'NO_SESSION' };
    if (s.ended_at) {
      const map = { DEVICE_REVOKED: 'DEVICE_REVOKED', DEVICE_REPLACED: 'DEVICE_REVOKED', ACCOUNT_SUSPENDED: 'ACCOUNT_SUSPENDED', ACCESS_REVOKED: 'ACCOUNT_SUSPENDED' };
      return { error: map[s.end_reason] || 'SESSION_ENDED', session: s };
    }
    const policy = await settings.policy();
    const idleMs = policy.session_idle_minutes * 60000;
    if (new Date(s.expires_at) <= new Date() || Date.now() - new Date(s.last_seen_at).getTime() > idleMs) {
      await pool.query(`UPDATE reading_sessions SET ended_at=now(), end_reason='EXPIRED' WHERE id=$1 AND ended_at IS NULL`, [s.id]);
      await events.reading(null, { type: 'SESSION_EXPIRED', customerId: s.customer_id, deviceId: s.device_id });
      return { error: 'SESSION_EXPIRED', session: s };
    }
    const deviceOk = s.device_status === 'ACTIVE' || (s.transition_until && new Date(s.transition_until) > new Date());
    if (!deviceOk) return { error: 'DEVICE_REVOKED', session: s };
    if (['SUSPENDED', 'REVOKED'].includes(s.customer_status)) {
      await events.security(null, { type: 'SUSPENDED_ACCESS_ATTEMPT', severity: 'MEDIUM', customerId: s.customer_id, deviceId: s.device_id });
      return { error: 'ACCOUNT_SUSPENDED', session: s };
    }
    if (Date.now() - new Date(s.last_seen_at).getTime() > 60000) {
      await pool.query('UPDATE reading_sessions SET last_seen_at=now() WHERE id=$1', [s.id]);
      await pool.query('UPDATE registered_devices SET last_seen_at=now() WHERE id=$1', [s.device_id]);
    }
    return { session: s };
  }

  async function logout(rawToken) {
    const r = await resolveSession(rawToken);
    if (r.session) {
      await pool.query(`UPDATE reading_sessions SET ended_at=now(), end_reason='LOGOUT' WHERE id=$1 AND ended_at IS NULL`, [r.session.id]);
      await events.reading(null, { type: 'READING_SESSION_ENDED', customerId: r.session.customer_id, deviceId: r.session.device_id });
    }
  }

  /** All books this session's device may read right now. */
  async function libraryFor(session) {
    const { rows } = await pool.query(
      `SELECT b.id, b.title, b.subtitle, b.author, b.description, (b.cover_storage_key IS NOT NULL) AS has_cover,
              l.id AS license_id, l.expires_at, l.activated_at,
              e.status AS edition_status, e.format,
              p.percent, p.updated_at AS progress_at
         FROM reading_licenses l
         JOIN orders o ON o.id=l.order_id AND o.status='PAID'
         JOIN device_authorizations da ON da.license_id=l.id AND da.device_id=$2 AND da.status='ACTIVE'
         JOIN books b ON b.id=l.book_id
         LEFT JOIN book_editions e ON e.id=b.current_edition_id
         LEFT JOIN reading_progress p ON p.customer_id=l.customer_id AND p.book_id=b.id
        WHERE l.customer_id=$1 AND l.status='ACTIVE' AND (l.expires_at IS NULL OR l.expires_at > now())
        ORDER BY l.activated_at`, [session.customer_id, session.device_id]);
    return rows;
  }

  /** Throws 404 unless this session's device holds an active license for the book. */
  async function requireBookAccess(session, bookId, ip) {
    await pool.query(
      `UPDATE reading_licenses SET status='EXPIRED', updated_at=now()
        WHERE customer_id=$1 AND book_id=$2 AND status='ACTIVE' AND expires_at IS NOT NULL AND expires_at <= now()`,
      [session.customer_id, bookId]);
    const { rows: [lic] } = await pool.query(
      `SELECT l.*, b.current_edition_id FROM reading_licenses l
         JOIN orders o ON o.id=l.order_id AND o.status='PAID'
         JOIN device_authorizations da ON da.license_id=l.id AND da.device_id=$3 AND da.status='ACTIVE'
         JOIN books b ON b.id=l.book_id
        WHERE l.customer_id=$1 AND l.book_id=$2 AND l.status='ACTIVE' LIMIT 1`,
      [session.customer_id, bookId, session.device_id]);
    if (!lic) {
      await events.security(null, { type: 'UNAUTHORIZED_CONTENT_REQUEST', severity: 'MEDIUM', customerId: session.customer_id, deviceId: session.device_id, ip, details: { bookId } });
      await events.reading(null, { type: 'ACCESS_DENIED', customerId: session.customer_id, deviceId: session.device_id, details: { bookId } });
      throw notFound();
    }
    return lic;
  }

  return {
    createInvitation, validateInvitation, requestActivationOtp, activate,
    requestLoginOtp, verifyLogin, replaceDevice,
    resolveSession, logout, libraryFor, requireBookAccess, endDeviceSessions, authorize,
    tokenHash, SESSION_COOKIE,
  };
}

export { unauthorized };

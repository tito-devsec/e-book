// Customer access lifecycle: private links, claiming a link from the added app, device
// registration, reading sessions, and license checks.
const CLAIM_RE = /^[A-Za-z0-9_-]{43}$/;
import { tx } from '../db.js';
import { randomToken, keyedHash, importDevicePublicKey, jwkThumbprint } from '../lib/crypto.js';
import { badRequest, notFound } from '../lib/http.js';
import { describeUserAgent } from '../lib/userAgent.js';

const SESSION_COOKIE = 'rs';
export { SESSION_COOKIE };

export function createAccess({ pool, cfg, settings, events }) {
  const tokenHash = (t, purpose) => keyedHash(cfg.hashPepper, t, purpose);
  const readerBase = () => cfg.readerBaseUrl.replace(/\/$/, '');

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
      // A first link activates the purchase; a later link (new phone, lost app) moves it.
      const expired = lic.expires_at && new Date(lic.expires_at) <= new Date();
      if (!['PENDING_ACTIVATION', 'ACTIVE'].includes(lic.status) || expired) {
        throw badRequest('This license is suspended, revoked or expired. Reactivate or renew it first.', 'LICENSE_NOT_AVAILABLE');
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
    if (['SUSPENDED', 'REVOKED'].includes(inv.customer_status) || !['PENDING_ACTIVATION', 'ACTIVE'].includes(inv.license_status)) return { state: 'REVOKED', inv };
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
    const { rows: [book] } = await pool.query('SELECT id, title, author, subtitle, description, cover_storage_key, published FROM books WHERE id=$1', [inv.book_id]);
    return {
      state,
      book: { id: book.id, title: book.title, author: book.author, subtitle: book.subtitle, description: book.description, hasCover: Boolean(book.cover_storage_key && book.published) },
      expiresAt: inv.expires_at,
    };
  }

  // -------------------------------------------------------------------------
  // Devices and sessions
  // -------------------------------------------------------------------------
  async function createSession(db, { customerId, deviceId }) {
    const policy = await settings.policy();
    const token = randomToken(32);
    const csrf = randomToken(24);
    await db.query('UPDATE registered_devices SET last_seen_at=now() WHERE id=$1', [deviceId]);
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
  // Private link -> app. Opening the link never uses it up: the page can be opened and
  // refreshed until the book is added to the device. The page prepares a one-time claim token
  // that becomes part of the app's start address; the first time the added app opens, it
  // claims the link: the link is used up, this device is registered and signed in.
  // -------------------------------------------------------------------------
  async function prepareApp(token, ip) {
    const { state, inv } = await findInvitation(pool, token);
    if (state !== 'VALID') {
      await invitationAttemptEvent(state, inv, ip);
      throw badRequest('This link has already been used or is no longer valid.', `INVITATION_${state}`);
    }
    // Earlier codes from this link stay valid too: the page may be reloaded after the book was
    // added, and the app on the home screen keeps the code it was added with. Once one code is
    // used, the link is used up and the others only work again on that same device.
    const claim = randomToken(32);
    await pool.query(`INSERT INTO invitation_claims (invitation_id, token_hash, expires_at) VALUES ($1,$2,$3)`,
      [inv.id, tokenHash(claim, 'claim'), inv.expires_at]);
    return claim;
  }

  async function reopenOnSameDevice(db, inv, key) {
    if (['SUSPENDED', 'REVOKED'].includes(inv.customer_status) || inv.license_status !== 'ACTIVE') return null;
    const { rows: [d] } = await db.query(
      `SELECT d.id FROM registered_devices d
         JOIN device_authorizations da ON da.device_id=d.id AND da.license_id=$3 AND da.status='ACTIVE'
        WHERE d.customer_id=$1 AND d.key_thumbprint=$2 AND d.status='ACTIVE'`,
      [inv.customer_id, key.thumbprint, inv.license_id]);
    if (!d) return null;
    const session = await createSession(db, { customerId: inv.customer_id, deviceId: d.id });
    return { session, bookId: inv.book_id };
  }

  /** Is the link behind this app code still unused (so the download page should show)? */
  async function claimStatus(claim) {
    if (!CLAIM_RE.test(String(claim || ''))) return { state: 'INVALID' };
    const { rows: [c] } = await pool.query(
      `SELECT c.used_at, c.expires_at, i.status, i.expires_at AS inv_expires, i.book_id FROM invitation_claims c JOIN invitations i ON i.id=c.invitation_id WHERE c.token_hash=$1`,
      [tokenHash(claim, 'claim')]);
    if (!c) return { state: 'INVALID' };
    if (c.status === 'CONSUMED' || c.used_at) return { state: 'CONSUMED' };
    if (c.status !== 'PENDING' || new Date(c.inv_expires) <= new Date()) return { state: 'EXPIRED' };
    const { rows: [book] } = await pool.query('SELECT id, title, author, subtitle, description, cover_storage_key, published FROM books WHERE id=$1', [c.book_id]);
    return { state: 'VALID', book: { id: book.id, title: book.title, author: book.author, subtitle: book.subtitle, description: book.description, hasCover: Boolean(book.cover_storage_key && book.published) } };
  }

  async function claimLink({ claim, deviceKey, userAgent, ip }) {
    const key = parseDeviceKey(deviceKey);
    const result = await tx(pool, async (db) => {
      const { rows: [c] } = await db.query(`SELECT * FROM invitation_claims WHERE token_hash=$1 FOR UPDATE`, [tokenHash(String(claim || ''), 'claim')]);
      if (!c) return { error: badRequest('This link has already been used or is no longer valid.', 'CLAIM_INVALID') };
      const { rows: [inv] } = await db.query(
        `SELECT i.*, c.status AS customer_status, l.status AS license_status
           FROM invitations i JOIN customers c ON c.id=i.customer_id JOIN reading_licenses l ON l.id=i.license_id
          WHERE i.id=$1 FOR UPDATE OF i`, [c.invitation_id]);
      // The book is already on this device (the app was opened with this link before and its
      // sign-in was lost): sign the same device in again. Any other device is refused.
      if (inv && (c.used_at || inv.status === 'CONSUMED')) {
        const again = await reopenOnSameDevice(db, inv, key);
        if (again) return again;
        return { error: badRequest('This link has already been used or is no longer valid.', 'CLAIM_INVALID'), inv, state: 'CONSUMED' };
      }
      if (new Date(c.expires_at) <= new Date()) {
        return { error: badRequest('This link has already been used or is no longer valid.', 'CLAIM_INVALID') };
      }
      if (!inv || inv.status !== 'PENDING' || new Date(inv.expires_at) <= new Date()
        || ['SUSPENDED', 'REVOKED'].includes(inv.customer_status) || !['PENDING_ACTIVATION', 'ACTIVE'].includes(inv.license_status)) {
        return { error: badRequest('This link has already been used or is no longer valid.', 'CLAIM_INVALID'), inv, state: 'CONSUMED' };
      }
      // The link is used up now, once the book is on the device.
      await db.query(`UPDATE invitations SET status='CONSUMED', consumed_at=now() WHERE id=$1`, [inv.id]);
      await db.query(`UPDATE invitation_claims SET used_at=now() WHERE id=$1`, [c.id]);

      const { rows: [lic] } = await db.query(
        `UPDATE reading_licenses SET status='ACTIVE', updated_at=now(),
           activated_at = COALESCE(activated_at, now()),
           expires_at = CASE WHEN activated_at IS NOT NULL THEN expires_at
                             WHEN duration_days IS NULL THEN NULL ELSE now() + make_interval(days => duration_days) END
         WHERE id=$1 RETURNING *`, [inv.license_id]);

      let device = await findActiveDevice(db, inv.customer_id, key.thumbprint);
      if (!device) device = await insertDevice(db, { customerId: inv.customer_id, key, userAgent });
      await db.query(`UPDATE registered_devices SET status='ACTIVE', installed_at=COALESCE(installed_at, now()) WHERE id=$1`, [device.id]);

      // A link from the owner is their approval to put the book on this device: if all device
      // slots are taken, the least recently used other device loses access.
      const { rows: others } = await db.query(
        `SELECT da.device_id FROM device_authorizations da JOIN registered_devices d ON d.id=da.device_id
          WHERE da.license_id=$1 AND da.status='ACTIVE' AND d.status='ACTIVE' AND d.id<>$2
          ORDER BY d.last_seen_at NULLS FIRST, d.registered_at`, [lic.id, device.id]);
      const surplus = others.length + 1 - lic.max_devices;
      for (const o of others.slice(0, Math.max(0, surplus))) {
        await db.query(`UPDATE device_authorizations SET status='REVOKED', revoked_at=now() WHERE device_id=$1 AND license_id=$2`, [o.device_id, lic.id]);
        const { rows: [{ n }] } = await db.query(`SELECT count(*)::int AS n FROM device_authorizations WHERE device_id=$1 AND status='ACTIVE'`, [o.device_id]);
        if (n === 0) await db.query(`UPDATE registered_devices SET status='REPLACED', revoked_at=now(), revoked_reason='Replaced by a new link from the owner' WHERE id=$1`, [o.device_id]);
        await endDeviceSessions(db, o.device_id, 'DEVICE_REPLACED');
        await db.query(`INSERT INTO device_replacements (customer_id, old_device_id, new_device_id, mode, decided_at) VALUES ($1,$2,$3,'OWNER_LINK', now())`,
          [inv.customer_id, o.device_id, device.id]);
      }
      await authorize(db, device.id, lic.id);
      await db.query(`UPDATE customers SET status='ACTIVATED', updated_at=now() WHERE id=$1 AND status IN ('PAID','INVITED','EXPIRED')`, [inv.customer_id]);
      await events.reading(db, { type: 'LICENSE_ACTIVATED', customerId: inv.customer_id, bookId: inv.book_id, deviceId: device.id });
      await events.reading(db, { type: 'APP_INSTALLED', customerId: inv.customer_id, deviceId: device.id });
      const session = await createSession(db, { customerId: inv.customer_id, deviceId: device.id });
      return { session, bookId: inv.book_id };
    });
    if (result.error) {
      if (result.inv) await invitationAttemptEvent('CONSUMED', result.inv, ip);
      throw result.error;
    }
    return result;
  }

  // -------------------------------------------------------------------------
  // Session resolution (used by middleware)
  // -------------------------------------------------------------------------
  async function resolveSession(rawToken) {
    if (!rawToken || typeof rawToken !== 'string') return { error: 'NO_SESSION' };
    const { rows: [s] } = await pool.query(
      `SELECT s.*, d.status AS device_status, d.public_key_jwk, d.transition_until, d.installed_at AS device_installed_at, c.status AS customer_status,
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
    // Sessions renew themselves while in use, so the app keeps working every day.
    if (new Date(s.expires_at).getTime() - Date.now() < (policy.session_ttl_hours * 3600000) / 2) {
      await pool.query(`UPDATE reading_sessions SET expires_at = now() + make_interval(hours => $2) WHERE id=$1`, [s.id, policy.session_ttl_hours]);
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
    createInvitation, validateInvitation, prepareApp, claimStatus, claimLink,
    resolveSession, logout, libraryFor, requireBookAccess, endDeviceSessions, authorize,
    tokenHash, SESSION_COOKIE,
  };
}


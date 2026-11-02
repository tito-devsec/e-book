// Audit, security and reading event recording.
import { keyedHash } from '../lib/crypto.js';

export function createEvents({ pool, cfg, logger }) {
  const ipHash = (ip) => (ip ? keyedHash(cfg.hashPepper, ip, 'ip').slice(0, 32) : null);
  return {
    ipHash,
    async audit(db, { adminId, action, entityType, entityId, details = {}, ip }) {
      await (db || pool).query(
        `INSERT INTO audit_logs (admin_id, action, entity_type, entity_id, details, ip_hash)
         VALUES ($1,$2,$3,$4,$5,$6)`,
        [adminId || null, action, entityType, entityId ? String(entityId) : null, details, ipHash(ip)],
      );
    },
    async security(db, { type, severity = 'MEDIUM', customerId, invitationId, deviceId, ip, details = {} }) {
      logger.warn('security event', { type, severity, customerId, deviceId });
      await (db || pool).query(
        `INSERT INTO security_events (event_type, severity, customer_id, invitation_id, device_id, ip_hash, details)
         VALUES ($1,$2,$3,$4,$5,$6,$7)`,
        [type, severity, customerId || null, invitationId || null, deviceId || null, ipHash(ip), details],
      );
    },
    async reading(db, { type, customerId, bookId, deviceId, details = {} }) {
      await (db || pool).query(
        `INSERT INTO reading_events (event_type, customer_id, book_id, device_id, details) VALUES ($1,$2,$3,$4,$5)`,
        [type, customerId || null, bookId || null, deviceId || null, details],
      );
    },
  };
}

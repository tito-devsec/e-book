// Policy settings (system_settings) and website content (website_settings).

export const POLICY_SCHEMA = {
  invitation_expiry_hours: { type: 'int', min: 1, max: 24 * 30 },
  otp_ttl_minutes: { type: 'int', min: 2, max: 30 },
  otp_max_attempts: { type: 'int', min: 3, max: 10 },
  otp_max_requests_per_hour: { type: 'int', min: 1, max: 20 },
  otp_resend_cooldown_seconds: { type: 'int', min: 15, max: 600 },
  session_ttl_hours: { type: 'int', min: 1, max: 24 * 90 },
  session_idle_minutes: { type: 'int', min: 5, max: 60 * 24 * 30 },
  default_max_devices: { type: 'int', min: 1, max: 10 },
  device_replacement_mode: { type: 'string', enum: ['SELF_SERVICE', 'ADMIN_APPROVAL'] },
  max_self_replacements_per_30d: { type: 'int', min: 0, max: 20 },
  default_license_duration_days: { type: 'int', min: 1, max: 36500, nullable: true },
  content_requests_per_minute: { type: 'int', min: 20, max: 2000 },
  require_app_install: { type: 'bool' },
  require_whatsapp_code: { type: 'bool' },
};

export const WEBSITE_KEYS = ['site', 'whatsapp'];

export function createSettings(pool) {
  let cache = null; let cacheAt = 0;
  return {
    async policy() {
      if (cache && Date.now() - cacheAt < 5000) return cache;
      const { rows } = await pool.query('SELECT key, value FROM system_settings');
      cache = Object.fromEntries(rows.map((r) => [r.key, r.value]));
      cacheAt = Date.now();
      return cache;
    },
    invalidate() { cache = null; },
    async website() {
      const { rows } = await pool.query('SELECT key, value FROM website_settings');
      return Object.fromEntries(rows.map((r) => [r.key, r.value]));
    },
  };
}

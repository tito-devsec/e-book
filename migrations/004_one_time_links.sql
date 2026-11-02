-- One-time links without a WhatsApp code; daily reading in the installed app.

-- The owner can issue a new link for a customer who already activated (new phone, lost app).
-- Each link still opens only once; at most one unused link per license.
DROP INDEX IF EXISTS invitations_one_consumed_uq;

-- WhatsApp verification codes become optional (off by default).
INSERT INTO system_settings (key, value) VALUES ('require_whatsapp_code', 'false') ON CONFLICT (key) DO NOTHING;

-- Without codes, a session is the only way back into the app, so app sessions are long-lived and
-- renew themselves with use. Only the untouched original defaults are changed.
UPDATE system_settings SET value = '720' WHERE key = 'session_ttl_hours' AND value = '168';
UPDATE system_settings SET value = '43200' WHERE key = 'session_idle_minutes' AND value = '4320';

-- A new link replacing an older device is recorded as such.
ALTER TABLE device_replacements DROP CONSTRAINT IF EXISTS device_replacements_mode_check;
ALTER TABLE device_replacements ADD CONSTRAINT device_replacements_mode_check
  CHECK (mode IN ('SELF_SERVICE', 'APP_INSTALL', 'OWNER_LINK', 'ADMIN_APPROVED', 'ADMIN_REJECTED', 'PENDING'));

-- One-time pairing that hands access from the browser where the link was opened to the
-- home-screen app (iPhone keeps the app's storage separate from Safari).
CREATE TABLE app_pairings (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  customer_id     uuid NOT NULL REFERENCES customers(id) ON DELETE CASCADE,
  from_device_id  uuid NOT NULL REFERENCES registered_devices(id) ON DELETE CASCADE,
  token_hash      text NOT NULL UNIQUE,
  expires_at      timestamptz NOT NULL,
  used_at         timestamptz,
  used_by_device_id uuid REFERENCES registered_devices(id),
  created_at      timestamptz NOT NULL DEFAULT now()
);

-- The invitation message no longer asks the customer to verify a number.
UPDATE website_settings
   SET value = jsonb_set(value, '{invitationTemplate}', to_jsonb(replace(value->>'invitationTemplate',
     'Please open your private reading invitation below and verify your registered WhatsApp number to activate your access.',
     'Open your private link below on the phone or computer you will read on. The link opens only once.')))
 WHERE key = 'whatsapp';

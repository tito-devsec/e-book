-- WhatsApp verification codes are removed: the private link from the owner is the proof of
-- purchase. The link stays valid until the book is added to the device and the app opens.

-- One-time claim tokens carried by the app's start address (see services/access.js).
CREATE TABLE invitation_claims (
  id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  invitation_id uuid NOT NULL REFERENCES invitations(id) ON DELETE CASCADE,
  token_hash    text NOT NULL UNIQUE,
  expires_at    timestamptz NOT NULL,
  used_at       timestamptz,
  created_at    timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX invitation_claims_invitation_idx ON invitation_claims (invitation_id);

-- No longer used: codes, sign-in device moves and browser-to-app pairing.
DROP TABLE IF EXISTS otp_challenges;
DROP TABLE IF EXISTS pending_device_grants;
DROP TABLE IF EXISTS app_pairings;
DELETE FROM system_settings WHERE key IN (
  'require_whatsapp_code', 'otp_ttl_minutes', 'otp_max_attempts', 'otp_max_requests_per_hour',
  'otp_resend_cooldown_seconds', 'device_replacement_mode', 'max_self_replacements_per_30d');

-- Links stay open until the book is added, so give customers three days by default.
UPDATE system_settings SET value = '72' WHERE key = 'invitation_expiry_hours' AND value = '24';

-- Invitation message wording.
UPDATE website_settings
   SET value = jsonb_set(value, '{invitationTemplate}', to_jsonb(replace(replace(value->>'invitationTemplate',
     'Open your private link below on the phone or computer you will read on. The link opens only once.',
     'Open your private link below on the phone or computer you will read on, then add the book to your device.'),
     'Please open your private reading invitation below and verify your registered WhatsApp number to activate your access.',
     'Open your private link below on the phone or computer you will read on, then add the book to your device.')))
 WHERE key = 'whatsapp';

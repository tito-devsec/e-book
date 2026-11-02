-- Reading happens only in the installed app (PWA). A device records when the app was installed
-- on it; the download page expires once that happens.
ALTER TABLE registered_devices ADD COLUMN IF NOT EXISTS installed_at timestamptz;

-- Moving access from the browser to the app just installed on the same phone (iOS gives the
-- installed app its own storage) is recorded separately and does not count as a device change.
ALTER TABLE device_replacements DROP CONSTRAINT IF EXISTS device_replacements_mode_check;
ALTER TABLE device_replacements ADD CONSTRAINT device_replacements_mode_check
  CHECK (mode IN ('SELF_SERVICE', 'APP_INSTALL', 'ADMIN_APPROVED', 'ADMIN_REJECTED', 'PENDING'));

INSERT INTO system_settings (key, value) VALUES ('require_app_install', 'true') ON CONFLICT (key) DO NOTHING;

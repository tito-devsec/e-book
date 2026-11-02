-- The book owner's WhatsApp contact, shown to visitors without a link and on every page watermark.
-- Only fills in values that are empty, so a number set later is never overwritten.
UPDATE website_settings
   SET value = value
     || CASE WHEN COALESCE(value->>'contactName', '') = '' THEN jsonb_build_object('contactName', 'Kenedy Njume') ELSE '{}'::jsonb END
     || CASE WHEN COALESCE(value->>'number', '') = '' THEN jsonb_build_object('number', '+255746274010') ELSE '{}'::jsonb END
 WHERE key = 'whatsapp';

-- The separate marketing website was removed. Keep only the settings still in use:
-- `site` (which book the download page shows) and `whatsapp` (order link, invitation message).
DROP TABLE IF EXISTS testimonials;
DELETE FROM website_settings WHERE key NOT IN ('site', 'whatsapp');
UPDATE website_settings SET value = jsonb_build_object('featuredBookId', value->'featuredBookId') WHERE key = 'site';

-- PDF editions also store each page's extracted text (encrypted) for server-side search.
ALTER TABLE book_assets DROP CONSTRAINT IF EXISTS book_assets_kind_check;
ALTER TABLE book_assets ADD CONSTRAINT book_assets_kind_check CHECK (kind IN ('CHAPTER', 'PAGE_IMAGE', 'PAGE_TEXT', 'IMAGE'));

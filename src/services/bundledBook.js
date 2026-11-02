// Development convenience: the book file kept in content/ is loaded as the current edition of its
// book the first time the server sees it. Uploads made later in the dashboard are never replaced,
// because a file is only loaded once (matched by its checksum). Never runs in production.
import fs from 'node:fs/promises';
import path from 'node:path';
import { sha256Hex } from '../lib/crypto.js';

export const BUNDLED = { slug: '20-objections-that-cost-you-sales', file: path.resolve(import.meta.dirname, '..', '..', 'content', '20-objections-that-cost-you-sales.pdf') };

export async function loadBundledBook({ pool, ingest, logger }, { slug = BUNDLED.slug, file = BUNDLED.file } = {}) {
  let buffer;
  try { buffer = await fs.readFile(file); } catch { return null; }
  const { rows: [book] } = await pool.query('SELECT id FROM books WHERE slug=$1', [slug]);
  if (!book) return null;
  const { rowCount } = await pool.query(`SELECT 1 FROM book_editions WHERE book_id=$1 AND original_sha256=$2 AND status IN ('READY','ARCHIVED')`, [book.id, sha256Hex(buffer)]);
  if (rowCount) return null;
  const edition = await ingest.ingestEdition({ bookId: book.id, buffer, label: path.basename(file), adminId: null });
  await pool.query('UPDATE books SET current_edition_id=$2, preferred_format=$3, published=true, updated_at=now() WHERE id=$1', [book.id, edition.id, edition.format]);
  logger.info('bundled book loaded', { slug, pages: edition.page_count });
  return edition;
}

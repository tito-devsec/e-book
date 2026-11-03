// Creates the book (with its cover) and the owner's contact details. Used by `npm run load-book`
// (any environment) and by the development seed.
import fs from 'node:fs/promises';
import path from 'node:path';

const COVER = path.resolve(import.meta.dirname, '..', '..', 'public', 'assets', 'cover.png');
export const OWNER = { name: 'Kenedy Njume', number: '+255746274010' };

export async function ensureBook({ pool, storage }) {
  let { rows: [book] } = await pool.query(`SELECT * FROM books WHERE slug='20-objections-that-cost-you-sales'`);
  if (book) return book;
  ({ rows: [book] } = await pool.query(
    `INSERT INTO books (slug, title, subtitle, author, description, price_amount, currency, published, max_devices)
     VALUES ('20-objections-that-cost-you-sales','20 Objections That Cost You Sales','How to Handle Customer Objections and Close More Deals',
             'Kenedy Njume', $1, 15000, 'TZS', false, 1) RETURNING *`,
    ['Every lost sale starts with an objection that was not handled well. This practical guide walks through the twenty objections salespeople hear most and gives you clear, tested ways to respond.']));
  // The cover goes in first: it becomes the full-page front cover of the book.
  const key = `covers/${book.id}/seed`;
  await storage.put(key, await fs.readFile(COVER), 'image/png');
  await pool.query('UPDATE books SET cover_storage_key=$2, cover_mime=$3 WHERE id=$1', [book.id, key, 'image/png']);
  return book;
}

export async function setOwnerContact(pool, bookId, number = process.env.OWNER_WHATSAPP || OWNER.number) {
  await pool.query(`UPDATE website_settings SET value=$1 WHERE key='site'`, [{ featuredBookId: bookId }]);
  const { rows: [wa] } = await pool.query(`SELECT value FROM website_settings WHERE key='whatsapp'`);
  await pool.query(`UPDATE website_settings SET value=$1 WHERE key='whatsapp'`,
    [{ ...wa.value, contactName: OWNER.name, number, orderMessage: 'Hello, I would like to order {book_title}.' }]);
}

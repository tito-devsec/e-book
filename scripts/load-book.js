// Creates the book and loads the book file from content/ as its current edition. Safe to run in
// production and to run again (a file is only loaded once). Run after `npm run migrate`.
// Usage: npm run load-book      Optional: OWNER_WHATSAPP=+255... to change the WhatsApp number.
import { loadConfig } from '../src/config.js';
import { createContext } from '../src/app.js';
import { ensureBook, setOwnerContact } from '../src/services/bookSetup.js';
import { loadBundledBook, BUNDLED } from '../src/services/bundledBook.js';

const ctx = createContext(loadConfig());
try {
  const book = await ensureBook(ctx);
  const loaded = await loadBundledBook(ctx);
  if (loaded) console.log(`Loaded the book from content/ (${loaded.page_count} pages).`);
  const { rows: [cur] } = await ctx.pool.query('SELECT current_edition_id FROM books WHERE id=$1', [book.id]);
  if (!cur.current_edition_id) {
    console.error(`No book file found. Copy the PDF to ${BUNDLED.file} and run this again.`);
    process.exitCode = 1;
  } else {
    await setOwnerContact(ctx.pool, book.id);
    console.log('The book is ready and published. WhatsApp contact set.');
  }
} finally {
  await ctx.pool.end();
}

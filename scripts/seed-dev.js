// DEVELOPMENT ONLY. Creates an owner account and a sample book with the bundled cover and a
// generated sample EPUB. Options: --book <file.pdf|file.epub> to load your own book file,
// --demo to add sample customers and sales. Refuses to run in production.
import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import JSZip from 'jszip';
import { loadConfig } from '../src/config.js';
import { createContext } from '../src/app.js';
import { runMigrations } from '../src/migrate.js';
import { hashPassword } from '../src/lib/crypto.js';

const cfg = loadConfig();
if (cfg.isProd) {
  console.error('seed-dev refuses to run with NODE_ENV=production');
  process.exit(1);
}
const here = path.dirname(fileURLToPath(import.meta.url));
const ctx = createContext(cfg);
const { pool } = ctx;

async function sampleEpub() {
  const zip = new JSZip();
  zip.file('mimetype', 'application/epub+zip', { compression: 'STORE' });
  zip.file('META-INF/container.xml', '<?xml version="1.0"?><container version="1.0" xmlns="urn:oasis:names:tc:opendocument:xmlns:container"><rootfiles><rootfile full-path="OEBPS/content.opf" media-type="application/oebps-package+xml"/></rootfiles></container>');
  const lorem = 'This is development sample text used to exercise pagination, the page-flip effect, search and bookmarks. Replace this sample by uploading the real EPUB or PDF from the dashboard. ';
  const chapters = ['Introduction', 'Why objections happen', 'Listening before answering', 'Price objections', 'Timing objections'];
  const items = []; const spine = []; const nav = [];
  chapters.forEach((t, i) => {
    const body = Array.from({ length: 14 }, (_, k) => `<p>${k === 0 ? `<strong>${t}.</strong> ` : ''}${lorem.repeat(2)}</p>`).join('');
    zip.file(`OEBPS/c${i}.xhtml`, `<?xml version="1.0"?><html xmlns="http://www.w3.org/1999/xhtml"><head><title>${t}</title></head><body><h1 id="top">${t}</h1>${body}</body></html>`);
    items.push(`<item id="c${i}" href="c${i}.xhtml" media-type="application/xhtml+xml"/>`);
    spine.push(`<itemref idref="c${i}"/>`);
    nav.push(`<li><a href="c${i}.xhtml">${t}</a></li>`);
  });
  zip.file('OEBPS/nav.xhtml', `<html xmlns="http://www.w3.org/1999/xhtml" xmlns:epub="http://www.idpf.org/2007/ops"><body><nav epub:type="toc"><ol>${nav.join('')}</ol></nav></body></html>`);
  zip.file('OEBPS/content.opf', `<?xml version="1.0"?><package xmlns="http://www.idpf.org/2007/opf" version="3.0"><metadata xmlns:dc="http://purl.org/dc/elements/1.1/"><dc:title>Sample</dc:title></metadata><manifest>${items.join('')}<item id="nav" href="nav.xhtml" media-type="application/xhtml+xml" properties="nav"/></manifest><spine>${spine.join('')}</spine></package>`);
  return zip.generateAsync({ type: 'nodebuffer' });
}

try {
  await runMigrations(pool, { info() {} });
  const email = process.env.SEED_ADMIN_EMAIL || 'owner@example.com';
  const password = process.env.SEED_ADMIN_PASSWORD || 'change-me-please-123';
  await pool.query(
    `INSERT INTO administrators (email, full_name, password_hash, role_id)
     VALUES ($1,'Book Owner',$2,(SELECT id FROM roles WHERE name='OWNER')) ON CONFLICT DO NOTHING`,
    [email, await hashPassword(password)]);

  let { rows: [book] } = await pool.query(`SELECT * FROM books WHERE slug='20-objections-that-cost-you-sales'`);
  if (!book) {
    ({ rows: [book] } = await pool.query(
      `INSERT INTO books (slug, title, subtitle, author, description, price_amount, currency, published, max_devices)
       VALUES ('20-objections-that-cost-you-sales','20 Objections That Cost You Sales','How to Handle Customer Objections and Close More Deals',
               'Kenedy Njume', $1, 15000, 'TZS', false, 1) RETURNING *`,
      ['Every lost sale starts with an objection that was not handled well. This practical guide walks through the twenty objections salespeople hear most and gives you clear, tested ways to respond.']));
    const cover = await fs.readFile(path.join(here, '..', 'public', 'assets', 'cover.png'));
    const key = `covers/${book.id}/seed`;
    await ctx.storage.put(key, cover, 'image/png');
    const edition = await ctx.ingest.ingestEdition({ bookId: book.id, buffer: await sampleEpub(), label: 'Development sample', adminId: null });
    await pool.query('UPDATE books SET cover_storage_key=$2, cover_mime=$3, current_edition_id=$4, published=true WHERE id=$1', [book.id, key, 'image/png', edition.id]);
  }
  await pool.query(`UPDATE website_settings SET value=$1 WHERE key='site'`, [{ featuredBookId: book.id }]);
  const { rows: [wa] } = await pool.query(`SELECT value FROM website_settings WHERE key='whatsapp'`);
  await pool.query(`UPDATE website_settings SET value=$1 WHERE key='whatsapp'`,
    [{ ...wa.value, contactName: wa.value.contactName || 'Kenedy Njume', number: wa.value.number || process.env.SEED_WHATSAPP || '+255700000000', orderMessage: 'Hello, I would like to order {book_title}.' }]);

  // --book <file>: use your own EPUB or PDF as the sample book's current edition.
  const bi = process.argv.indexOf('--book');
  if (bi > 0 && process.argv[bi + 1]) {
    const file = path.resolve(process.argv[bi + 1]);
    const buffer = await fs.readFile(file);
    console.log(`Processing ${path.basename(file)}…`);
    const edition = await ctx.ingest.ingestEdition({ bookId: book.id, buffer, label: path.basename(file), adminId: null });
    await pool.query('UPDATE books SET current_edition_id=$2, preferred_format=$3 WHERE id=$1', [book.id, edition.id, edition.format]);
    console.log(`Book file loaded: ${edition.format}, ${edition.page_count} ${edition.format === 'PDF' ? 'pages' : 'chapters'} (encrypted in private storage).`);
  }
  if (process.argv.includes('--demo')) {
    // Sample sales history so the dashboard charts have something to show. Development only.
    const names = ['Amina Wanjiru', 'Brian Otieno', 'Grace Achieng', 'Kevin Mwangi', 'Faith Njeri', 'Dennis Kiprop', 'Mercy Atieno', 'John Kamau',
      'Lucy Wambui', 'Peter Omondi', 'Sharon Chebet', 'Victor Mutua', 'Diana Wairimu', 'Collins Ouma', 'Esther Moraa', 'Samuel Kibet',
      'Joy Nyambura', 'Moses Barasa', 'Ruth Akinyi', 'Daniel Kariuki', 'Mary Wanjiku', 'Felix Onyango', 'Agnes Jepkosgei', 'Tom Mbugua'];
    const day = 86400000;
    let made = 0;
    for (let i = 0; i < names.length; i += 1) {
      const phone = `+2557990${String(10000 + i).slice(1)}`;
      const { rowCount } = await pool.query('SELECT 1 FROM customers WHERE phone_e164=$1', [phone]);
      if (rowCount) continue;
      // Most sales in recent weeks, a tail over the last 7 months.
      const ageDays = i < 10 ? i % 7 : 7 + Math.floor(((i - 10) / (names.length - 10)) * 200);
      const at = new Date(Date.now() - ageDays * day - (i % 5) * 3600000);
      const state = i % 9 === 4 ? 'PENDING' : 'VERIFIED';
      const activated = state === 'VERIFIED' && i % 4 !== 1;
      const status = state === 'PENDING' ? 'PENDING_PAYMENT' : activated ? 'ACTIVE' : 'INVITED';
      const { rows: [c] } = await pool.query(
        `INSERT INTO customers (full_name, phone_e164, status, notes, created_at) VALUES ($1,$2,$3,'Demo data',$4) RETURNING id`, [names[i], phone, status, at]);
      const { rows: [o] } = await pool.query(
        `INSERT INTO orders (customer_id, reference, status, total_amount, currency, created_at) VALUES ($1,$2,$3,$4,'TZS',$5) RETURNING id`,
        [c.id, `DEMO-${1000 + i}`, state === 'PENDING' ? 'PENDING_PAYMENT' : 'PAID', book.price_amount, at]);
      await pool.query('INSERT INTO order_items (order_id, book_id, unit_price) VALUES ($1,$2,$3)', [o.id, book.id, book.price_amount]);
      await pool.query(
        `INSERT INTO payments (order_id, amount, currency, method, reference, status, verified_at, created_at) VALUES ($1,$2,'TZS',$3,$4,$5,$6,$7)`,
        [o.id, book.price_amount, ['M-Pesa', 'Tigo Pesa', 'Airtel Money', 'Bank transfer'][i % 4], `DEMO${100000 + i}`, state, state === 'VERIFIED' ? new Date(at.getTime() + 3600000) : null, at]);
      if (state === 'VERIFIED') {
        await pool.query(
          `INSERT INTO reading_licenses (customer_id, book_id, order_id, status, activated_at, created_at) VALUES ($1,$2,$3,$4,$5,$6)`,
          [c.id, book.id, o.id, activated ? (i === 11 ? 'SUSPENDED' : 'ACTIVE') : 'PENDING_ACTIVATION', activated ? new Date(at.getTime() + 7200000) : null, at]);
      }
      made += 1;
    }
    console.log(`Added ${made} demo customers with orders.`);
  }
  console.log(`Seeded. Admin: ${email} / ${password}`);
} finally {
  await pool.end();
}

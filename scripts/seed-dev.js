// DEVELOPMENT ONLY. Creates an owner account, a sample book with the bundled cover and a
// generated sample EPUB, and starter website content. Refuses to run in production.
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
               'Kenedy Njume', $1, 1500, 'KES', false, 1) RETURNING *`,
      ['Every lost sale starts with an objection that was not handled well. This practical guide walks through the twenty objections salespeople hear most and gives you clear, tested ways to respond.']));
    const cover = await fs.readFile(path.join(here, '..', 'public', 'assets', 'cover.png'));
    const key = `covers/${book.id}/seed`;
    await ctx.storage.put(key, cover, 'image/png');
    const edition = await ctx.ingest.ingestEdition({ bookId: book.id, buffer: await sampleEpub(), label: 'Development sample', adminId: null });
    await pool.query('UPDATE books SET cover_storage_key=$2, cover_mime=$3, current_edition_id=$4, published=true WHERE id=$1', [book.id, key, 'image/png', edition.id]);
  }
  const set = (k, v) => pool.query('UPDATE website_settings SET value=$2 WHERE key=$1', [k, v]);
  await set('site', { siteName: 'Kenedy Njume', tagline: '', featuredBookId: book.id, seoDescription: 'How to handle customer objections and close more deals.' });
  await set('hero', { headline: '20 Objections That Cost You Sales', subheadline: 'Practical responses to the objections you hear every week, so more conversations end in a sale.' });
  await set('learn', { heading: 'What you will learn', items: [
    { title: 'Why buyers object', text: 'Recognise what an objection is really asking for.' },
    { title: 'Price and budget', text: 'Answer “it is too expensive” without discounting.' },
    { title: 'Timing and trust', text: 'Move stalled deals forward with confidence.' }] });
  await set('author', { heading: 'About the author', name: 'Kenedy Njume', bio: 'Development sample biography. Edit this in the dashboard under Marketing Website Content.' });
  await set('faq', { heading: 'Frequently asked questions', items: [
    { question: 'How do I receive the book?', answer: 'After your payment is verified you receive a private link on WhatsApp. Open it, confirm your number, and read in the private reader.' },
    { question: 'Can I read on my phone?', answer: 'Yes. You can install the reader on your phone or computer.' }] });
  await set('whatsapp', { number: process.env.SEED_WHATSAPP || '+254700000000', orderMessage: 'Hello, I would like to order {book_title}.',
    invitationTemplate: (await pool.query(`SELECT value FROM website_settings WHERE key='whatsapp'`)).rows[0].value.invitationTemplate });
  console.log(`Seeded. Admin: ${email} / ${password}`);
} finally {
  await pool.end();
}

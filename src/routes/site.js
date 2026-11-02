// Public marketing website, server-rendered from database content with strict escaping.
// Exposes only published book metadata and covers; never reader routes, tokens or files.
import express from 'express';
import fs from 'node:fs/promises';
import path from 'node:path';
import { uuidParam, notFound } from '../lib/http.js';

export const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const para = (s) => String(s || '').split(/\n{2,}/).filter((p) => p.trim()).map((p) => `<p>${esc(p.trim()).replace(/\n/g, '<br>')}</p>`).join('');

export function formatPrice(amount, currency) {
  try {
    return new Intl.NumberFormat('en', { style: 'currency', currency, maximumFractionDigits: Number(amount) % 1 ? 2 : 0 }).format(Number(amount));
  } catch {
    return `${currency} ${amount}`;
  }
}

/** Cover images of published books are public marketing assets, served on every host. */
export function coverRoutes({ pool, storage }) {
  const r = express.Router();
  r.get('/media/covers/:bookId', async (req, res) => {
    const id = uuidParam(req.params.bookId);
    const { rows: [b] } = await pool.query('SELECT cover_storage_key, cover_mime FROM books WHERE id=$1 AND published AND cover_storage_key IS NOT NULL', [id]);
    if (!b) throw notFound();
    const body = await storage.get(b.cover_storage_key);
    res.set('Cache-Control', 'public, max-age=3600');
    res.type(b.cover_mime).send(body);
  });

  return r;
}

export function siteRoutes({ pool, settings, storage, publicDir }) {
  const r = express.Router();
  let template = null;

  async function featuredBook(content) {
    const id = content.site?.featuredBookId;
    const { rows } = id
      ? await pool.query('SELECT * FROM books WHERE id=$1 AND published', [id])
      : await pool.query('SELECT * FROM books WHERE published ORDER BY created_at LIMIT 1');
    return rows[0];
  }

  r.get('/', async (req, res) => {
    template ??= await fs.readFile(path.join(publicDir, 'site', 'index.html'), 'utf8');
    const c = await settings.website();
    const book = await featuredBook(c);
    const { rows: testimonials } = await pool.query(
      `SELECT author_name, author_title, quote, rating FROM testimonials WHERE published ORDER BY sort_order, created_at LIMIT 12`);
    const siteName = c.site?.siteName || book?.author || 'Books';
    const wa = c.whatsapp || {};
    const orderMsg = (wa.orderMessage || '').replaceAll('{book_title}', book?.title || '');
    const waUrl = wa.number ? `https://wa.me/${wa.number.replace(/^\+/, '')}?text=${encodeURIComponent(orderMsg)}` : '';
    const cta = (label, cls = 'btn btn-primary') => (waUrl
      ? `<a class="${cls}" href="${esc(waUrl)}" target="_blank" rel="noopener noreferrer">${esc(label)}</a>`
      : `<span class="btn btn-disabled" aria-disabled="true">Ordering opens soon</span>`);
    const list = (items, a, b) => (items || []).filter((i) => i[a]).map((i) => `<li><h3>${esc(i[a])}</h3>${i[b] ? `<p>${esc(i[b])}</p>` : ''}</li>`).join('');
    const section = (id, html) => (html ? html : '');

    const parts = {
      title: esc(book ? `${book.title} by ${book.author}` : siteName),
      description: esc(c.site?.seoDescription || book?.subtitle || ''),
      siteName: esc(siteName),
      canonical: esc(`${req.protocol}://${req.get('host')}/`),
      ogImage: book?.cover_storage_key ? esc(`${req.protocol}://${req.get('host')}/media/covers/${book.id}`) : '',
      headerCta: book ? cta('Order on WhatsApp', 'btn btn-small') : '',
      hero: book ? `
        <div class="hero-cover"><img src="/media/covers/${book.id}" alt="${esc(book.title)} book cover" width="420" height="504" fetchpriority="high"></div>
        <div class="hero-text">
          <p class="eyebrow">${esc(c.hero?.subheadline ? 'New book' : book.author)}</p>
          <h1>${esc(c.hero?.headline || book.title)}</h1>
          ${book.subtitle ? `<p class="lede">${esc(book.subtitle)}</p>` : ''}
          ${c.hero?.subheadline ? `<p class="hero-sub">${esc(c.hero.subheadline)}</p>` : ''}
          <p class="byline">by <strong>${esc(book.author)}</strong></p>
          <div class="price-row"><span class="price">${esc(formatPrice(book.price_amount, book.currency))}</span>
          ${book.availability === 'AVAILABLE' ? cta('Order on WhatsApp') : `<span class="btn btn-disabled">${book.availability === 'COMING_SOON' ? 'Coming soon' : 'Currently unavailable'}</span>`}</div>
          <p class="fine">Pay securely, then receive private reading access on your phone or computer.</p>
        </div>` : '<div class="hero-text"><h1>Coming soon</h1></div>',
      about: section('about', (c.about?.body || book?.description) ? `<section id="about" class="section narrow"><h2>${esc(c.about?.heading || 'About the book')}</h2>${para(c.about?.body || book?.description)}</section>` : ''),
      learn: section('learn', c.learn?.items?.length ? `<section id="learn" class="section alt"><div class="wrap"><h2>${esc(c.learn.heading)}</h2><ul class="grid">${list(c.learn.items, 'title', 'text')}</ul></div></section>` : ''),
      author: section('author', c.author?.bio ? `<section id="author" class="section narrow"><h2>${esc(c.author.heading || 'About the author')}</h2>${c.author.name ? `<p class="author-name">${esc(c.author.name)}</p>` : ''}${para(c.author.bio)}</section>` : ''),
      benefits: section('benefits', c.benefits?.items?.length ? `<section id="benefits" class="section alt"><div class="wrap"><h2>${esc(c.benefits.heading)}</h2><ul class="grid">${list(c.benefits.items, 'title', 'text')}</ul></div></section>` : ''),
      testimonials: testimonials.length ? `<section id="testimonials" class="section"><div class="wrap"><h2>What readers say</h2><div class="quotes">${testimonials.map((t) => `
        <figure class="quote">${t.rating ? `<div class="stars" aria-label="${t.rating} out of 5">${'★'.repeat(t.rating)}${'☆'.repeat(5 - t.rating)}</div>` : ''}
        <blockquote>${esc(t.quote)}</blockquote><figcaption><strong>${esc(t.author_name)}</strong>${t.author_title ? `<span>${esc(t.author_title)}</span>` : ''}</figcaption></figure>`).join('')}</div></div></section>` : '',
      faq: c.faq?.items?.length ? `<section id="faq" class="section narrow"><h2>${esc(c.faq.heading)}</h2>${c.faq.items.filter((i) => i.question).map((i) => `<details><summary>${esc(i.question)}</summary>${para(i.answer)}</details>`).join('')}</section>` : '',
      finalCta: book ? `<section class="final-cta"><div class="wrap"><h2>${esc(c.cta?.heading || `Get ${book.title} today`)}</h2>${c.cta?.body ? `<p>${esc(c.cta.body)}</p>` : ''}${cta('Order on WhatsApp', 'btn btn-light')}</div></section>` : '',
      footer: esc(c.footer?.copyright || `© ${new Date().getFullYear()} ${siteName}. All rights reserved.`),
      nav: [c.about?.body || book?.description ? '<a href="#about">About</a>' : '', c.learn?.items?.length ? '<a href="#learn">What you will learn</a>' : '',
        c.author?.bio ? '<a href="#author">Author</a>' : '', testimonials.length ? '<a href="#testimonials">Reviews</a>' : '', c.faq?.items?.length ? '<a href="#faq">FAQ</a>' : ''].join(''),
    };
    const html = template.replace(/\{\{(\w+)\}\}/g, (_, k) => parts[k] ?? '');
    res.set('Cache-Control', 'public, max-age=60');
    res.type('html').send(html);
  });

  r.get('/robots.txt', (req, res) => {
    res.type('text/plain').send('User-agent: *\nAllow: /$\nDisallow: /access/\nDisallow: /app\nDisallow: /read/\nDisallow: /library\nDisallow: /admin\nDisallow: /api/\n');
  });

  return r;
}

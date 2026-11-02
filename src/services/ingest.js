// Book ingestion: validates an uploaded original, encrypts it into private storage, and
// produces individually encrypted reading resources (sanitized chapters / page images).
//
// The reader never receives the original file. It receives one sanitized chapter (EPUB) or
// one rendered page image (PDF) per authorized request.
import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import JSZip from 'jszip';
import sanitizeHtml from 'sanitize-html';
import { parseDocument } from 'htmlparser2';
import * as du from 'domutils';
import { aesGcmEncrypt, aesGcmDecrypt, sha256Hex } from '../lib/crypto.js';
import { badRequest } from '../lib/http.js';

const execFileP = promisify(execFile);

// ---------------------------------------------------------------------------
// File type detection by content (magic bytes), never by extension or client MIME.
// ---------------------------------------------------------------------------
export async function detectBookFormat(buf) {
  if (buf.length > 5 && buf.subarray(0, 5).toString('latin1') === '%PDF-') return 'PDF';
  if (buf.length > 4 && buf.readUInt32BE(0) === 0x504b0304) {
    let zip;
    try { zip = await JSZip.loadAsync(buf); } catch { return null; }
    const mt = zip.file('mimetype');
    if (mt && (await mt.async('string')).trim() === 'application/epub+zip') return 'EPUB';
  }
  return null;
}

export function detectImageMime(buf) {
  if (buf.length > 8 && buf.subarray(0, 8).equals(Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]))) return 'image/png';
  if (buf.length > 3 && buf[0] === 0xff && buf[1] === 0xd8 && buf[2] === 0xff) return 'image/jpeg';
  if (buf.length > 12 && buf.subarray(0, 4).toString('latin1') === 'RIFF' && buf.subarray(8, 12).toString('latin1') === 'WEBP') return 'image/webp';
  return null;
}

// ---------------------------------------------------------------------------
// EPUB parsing helpers
// ---------------------------------------------------------------------------
const xml = (s) => parseDocument(s, { xmlMode: true });
const byLocal = (name) => (el) => el.type === 'tag' && (el.name === name || el.name.endsWith(':' + name));
const attr = (el, name) => el?.attribs?.[name] ?? el?.attribs?.[Object.keys(el?.attribs || {}).find((k) => k.endsWith(':' + name))];

function resolveHref(baseFile, href) {
  const clean = decodeURIComponent(href.split('#')[0]);
  return path.posix.normalize(path.posix.join(path.posix.dirname(baseFile), clean));
}

const MAX_ZIP_ENTRY = 50 * 1024 * 1024;
const MAX_ZIP_TOTAL = 400 * 1024 * 1024;
const MAX_ZIP_ENTRIES = 5000;

async function readZipText(zip, p) {
  const f = zip.file(p);
  if (!f) throw badRequest(`EPUB is missing ${p}`, 'INVALID_EPUB');
  return f.async('string');
}

const ALLOWED_TAGS = ['p', 'div', 'span', 'section', 'article', 'aside', 'header', 'footer', 'figure', 'figcaption',
  'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'em', 'strong', 'b', 'i', 'u', 's', 'small', 'sup', 'sub', 'br', 'hr',
  'blockquote', 'q', 'cite', 'pre', 'code', 'ul', 'ol', 'li', 'dl', 'dt', 'dd', 'a', 'img',
  'table', 'thead', 'tbody', 'tfoot', 'tr', 'th', 'td', 'caption', 'abbr', 'mark'];

export async function parseEpub(buf) {
  const zip = await JSZip.loadAsync(buf);
  const entries = Object.values(zip.files);
  if (entries.length > MAX_ZIP_ENTRIES) throw badRequest('EPUB has too many files', 'INVALID_EPUB');
  let total = 0;
  for (const e of entries) {
    // eslint-disable-next-line no-underscore-dangle
    const size = e._data?.uncompressedSize ?? 0;
    if (size > MAX_ZIP_ENTRY) throw badRequest('EPUB contains an oversized file', 'INVALID_EPUB');
    total += size;
    if (e.name.includes('..') || e.name.startsWith('/')) throw badRequest('EPUB contains an unsafe path', 'INVALID_EPUB');
  }
  if (total > MAX_ZIP_TOTAL) throw badRequest('EPUB is too large when unpacked', 'INVALID_EPUB');

  const container = xml(await readZipText(zip, 'META-INF/container.xml'));
  const rootfile = du.findOne(byLocal('rootfile'), container.children, true);
  const opfPath = attr(rootfile, 'full-path');
  if (!opfPath) throw badRequest('EPUB has no package document', 'INVALID_EPUB');
  const opf = xml(await readZipText(zip, opfPath));

  const manifest = new Map();
  for (const item of du.findAll(byLocal('item'), opf.children)) {
    manifest.set(attr(item, 'id'), {
      href: resolveHref(opfPath, attr(item, 'href') || ''),
      type: attr(item, 'media-type') || '',
      props: (attr(item, 'properties') || '').split(/\s+/),
    });
  }
  const spine = du.findAll(byLocal('itemref'), opf.children)
    .filter((r) => attr(r, 'linear') !== 'no')
    .map((r) => manifest.get(attr(r, 'idref')))
    .filter((m) => m && /x?html/.test(m.type));
  if (spine.length === 0) throw badRequest('EPUB has no readable chapters', 'INVALID_EPUB');

  const titleEl = du.findOne(byLocal('title'), opf.children, true);
  const creatorEl = du.findOne(byLocal('creator'), opf.children, true);
  const meta = { title: titleEl ? du.textContent(titleEl).trim() : '', author: creatorEl ? du.textContent(creatorEl).trim() : '' };

  // Collect image resources referenced by chapters.
  const images = new Map(); // zip path -> { id, mime, data }
  const chapterIndexByPath = new Map(spine.map((s, i) => [s.href, i]));

  const chapters = [];
  for (let i = 0; i < spine.length; i += 1) {
    const item = spine[i];
    const raw = await readZipText(zip, item.href);
    const doc = parseDocument(raw, { xmlMode: false, decodeEntities: true });
    const body = du.findOne(byLocal('body'), doc.children, true);
    const bodyHtml = body ? du.getInnerHTML(body) : raw;
    const headings = du.findAll((el) => el.type === 'tag' && /^h[1-3]$/.test(el.name), doc.children);
    const title = headings[0] ? du.textContent(headings[0]).trim().slice(0, 200) : '';

    const html = sanitizeHtml(bodyHtml, {
      allowedTags: ALLOWED_TAGS,
      allowedAttributes: {
        '*': ['id', 'title', 'lang', 'dir'],
        a: ['href', 'data-chapter', 'data-anchor'],
        img: ['alt', 'data-asset'],
        td: ['colspan', 'rowspan'], th: ['colspan', 'rowspan'],
      },
      allowedSchemes: ['https'],
      allowProtocolRelative: false,
      transformTags: {
        img: (tag, attribs) => {
          const out = { alt: attribs.alt || '' };
          if (attribs.src && !/^[a-z]+:/i.test(attribs.src)) {
            const p = resolveHref(item.href, attribs.src);
            const m = [...manifest.values()].find((x) => x.href === p);
            if (m && /^image\/(png|jpeg|gif|webp|svg\+xml)$/.test(m.type) && m.type !== 'image/svg+xml') {
              if (!images.has(p)) images.set(p, { id: crypto.randomUUID(), mime: m.type, path: p });
              out['data-asset'] = images.get(p).id;
            }
          }
          return { tagName: 'img', attribs: out };
        },
        a: (tag, attribs) => {
          const href = attribs.href || '';
          if (/^https:\/\//i.test(href)) return { tagName: 'a', attribs: { href } };
          if (href.startsWith('#')) return { tagName: 'a', attribs: { 'data-chapter': String(i), 'data-anchor': href.slice(1) } };
          if (href) {
            const target = chapterIndexByPath.get(resolveHref(item.href, href));
            if (target !== undefined) {
              const anchor = href.includes('#') ? href.split('#')[1] : '';
              return { tagName: 'a', attribs: { 'data-chapter': String(target), 'data-anchor': anchor } };
            }
          }
          return { tagName: 'span', attribs: {} };
        },
      },
      exclusiveFilter: (frame) => frame.tag === 'img' && !frame.attribs['data-asset'],
    });
    chapters.push({ index: i, title, html, sourcePath: item.href });
  }

  for (const img of images.values()) {
    const f = zip.file(img.path);
    img.data = f ? await f.async('nodebuffer') : null;
  }

  // Table of contents: EPUB 3 nav document, else EPUB 2 NCX, else chapter titles.
  let toc = [];
  const navItem = [...manifest.values()].find((m) => m.props.includes('nav'));
  const tocEntry = (href, label, level, base) => {
    const p = resolveHref(base, href);
    const chapter = chapterIndexByPath.get(p);
    if (chapter === undefined) return null;
    return { label: label.replace(/\s+/g, ' ').trim().slice(0, 200), chapter, anchor: href.includes('#') ? href.split('#')[1] : '', level };
  };
  if (navItem && zip.file(navItem.href)) {
    const nav = parseDocument(await readZipText(zip, navItem.href), { xmlMode: false });
    const tocNav = du.findAll(byLocal('nav'), nav.children).find((n) => /toc/.test(attr(n, 'type') || '')) || du.findOne(byLocal('nav'), nav.children, true);
    if (tocNav) {
      const walk = (ol, level) => {
        for (const li of (ol.children || []).filter(byLocal('li'))) {
          const a = (li.children || []).find(byLocal('a'));
          if (a && attr(a, 'href')) {
            const e = tocEntry(attr(a, 'href'), du.textContent(a), level, navItem.href);
            if (e) toc.push(e);
          }
          const sub = (li.children || []).find(byLocal('ol'));
          if (sub) walk(sub, level + 1);
        }
      };
      const ol = du.findOne(byLocal('ol'), tocNav.children, true);
      if (ol) walk(ol, 0);
    }
  }
  if (toc.length === 0) {
    const ncx = [...manifest.values()].find((m) => m.type === 'application/x-dtbncx+xml');
    if (ncx && zip.file(ncx.href)) {
      const doc = xml(await readZipText(zip, ncx.href));
      const walk = (parent, level) => {
        for (const np of (parent.children || []).filter(byLocal('navPoint'))) {
          const label = du.findOne(byLocal('text'), np.children, true);
          const content = (np.children || []).find(byLocal('content'));
          if (label && content) {
            const e = tocEntry(attr(content, 'src') || '', du.textContent(label), level, ncx.href);
            if (e) toc.push(e);
          }
          walk(np, level + 1);
        }
      };
      const navMap = du.findOne(byLocal('navMap'), doc.children, true);
      if (navMap) walk(navMap, 0);
    }
  }
  if (toc.length === 0) {
    toc = chapters.map((c) => ({ label: c.title || `Chapter ${c.index + 1}`, chapter: c.index, anchor: '', level: 0 }));
  }
  return { meta, chapters, images: [...images.values()].filter((i) => i.data), toc };
}

// ---------------------------------------------------------------------------
// PDF rendering with poppler's pdftoppm into per-page PNG images.
// ---------------------------------------------------------------------------
export async function renderPdf(buf, cfg) {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'pdf-'));
  try {
    const input = path.join(dir, 'in.pdf');
    await fs.writeFile(input, buf, { mode: 0o600 });
    await execFileP(cfg.pdftoppmPath, ['-png', '-r', String(cfg.pdfRenderDpi), input, path.join(dir, 'p')], {
      timeout: 10 * 60 * 1000, maxBuffer: 10 * 1024 * 1024,
    });
    const files = (await fs.readdir(dir)).filter((f) => /^p-\d+\.png$/.test(f))
      .sort((a, b) => Number(a.match(/\d+/)[0]) - Number(b.match(/\d+/)[0]));
    if (files.length === 0) throw badRequest('The PDF has no pages', 'INVALID_PDF');
    const pages = [];
    for (const f of files) pages.push(await fs.readFile(path.join(dir, f)));
    return pages;
  } catch (err) {
    if (err.status) throw err;
    throw badRequest('The PDF could not be processed', 'INVALID_PDF');
  } finally {
    await fs.rm(dir, { recursive: true, force: true });
  }
}

// ---------------------------------------------------------------------------
// Ingestion orchestration
// ---------------------------------------------------------------------------
export function createIngest({ pool, cfg, kms, storage, scanner, logger }) {
  async function putEncrypted(key, dataKey, plaintext, aad) {
    await storage.put(key, aesGcmEncrypt(dataKey, plaintext, aad));
  }

  return {
    /** Store and process a new edition. Returns the edition row. */
    async ingestEdition({ bookId, buffer, label, adminId }) {
      const format = await detectBookFormat(buffer);
      if (!format) throw badRequest('Upload a valid EPUB or PDF file', 'UNSUPPORTED_FILE');
      const scan = await scanner.scan(buffer);
      if (!scan.clean) throw badRequest('The file was rejected by the malware scanner', 'MALWARE_DETECTED');

      const editionId = crypto.randomUUID();
      const dk = await kms.generateDataKey(editionId);
      const originalKey = `books/${bookId}/${editionId}/original.bin`;
      await putEncrypted(originalKey, dk.plaintext, buffer, `${editionId}:original`);

      const { rows: [{ next }] } = await pool.query(
        'SELECT COALESCE(MAX(version),0)+1 AS next FROM book_editions WHERE book_id=$1', [bookId]);
      await pool.query(
        `INSERT INTO book_editions (id, book_id, version, label, format, status, original_storage_key, original_sha256,
           original_size, wrapped_key, uploaded_by)
         VALUES ($1,$2,$3,$4,$5,'PROCESSING',$6,$7,$8,$9,$10)`,
        [editionId, bookId, next, label || `Version ${next}`, format, originalKey, sha256Hex(buffer), buffer.length, dk.wrapped, adminId]);

      try {
        await this.processEdition(editionId, buffer, format, dk.plaintext, bookId);
      } catch (err) {
        logger.error('edition processing failed', { editionId, err });
        await pool.query(`UPDATE book_editions SET status='FAILED', error=$2 WHERE id=$1`,
          [editionId, (err.status ? err.message : 'Processing failed').slice(0, 500)]);
        throw err.status ? err : badRequest('The book could not be processed', 'PROCESSING_FAILED');
      }
      const { rows: [edition] } = await pool.query('SELECT * FROM book_editions WHERE id=$1', [editionId]);
      return edition;
    },

    async processEdition(editionId, buffer, format, dataKey, bookId) {
      const assets = [];
      let toc = [];
      if (format === 'EPUB') {
        const book = await parseEpub(buffer);
        for (const c of book.chapters) {
          const id = crypto.randomUUID();
          const key = `books/${bookId}/${editionId}/a/${id}.bin`;
          const body = Buffer.from(c.html, 'utf8');
          await putEncrypted(key, dataKey, body, `${editionId}:${id}`);
          assets.push([id, 'CHAPTER', c.index, c.title, c.sourcePath, 'text/html', key, body.length]);
        }
        for (const img of book.images) {
          const key = `books/${bookId}/${editionId}/a/${img.id}.bin`;
          await putEncrypted(key, dataKey, img.data, `${editionId}:${img.id}`);
          assets.push([img.id, 'IMAGE', 0, '', img.path, img.mime, key, img.data.length]);
        }
        toc = book.toc;
      } else {
        const pages = await renderPdf(buffer, cfg);
        for (let i = 0; i < pages.length; i += 1) {
          const id = crypto.randomUUID();
          const key = `books/${bookId}/${editionId}/a/${id}.bin`;
          await putEncrypted(key, dataKey, pages[i], `${editionId}:${id}`);
          assets.push([id, 'PAGE_IMAGE', i, `Page ${i + 1}`, '', 'image/png', key, pages[i].length]);
        }
        toc = pages.map((_, i) => ({ label: `Page ${i + 1}`, chapter: i, anchor: '', level: 0 })).filter((_, i) => i % 10 === 0);
      }
      const client = await pool.connect();
      try {
        await client.query('BEGIN');
        for (const a of assets) {
          await client.query(
            `INSERT INTO book_assets (id, edition_id, kind, ordinal, title, source_path, mime, storage_key, size)
             VALUES ($1,$9,$2,$3,$4,$5,$6,$7,$8)`, [...a, editionId]);
        }
        const count = assets.filter((a) => a[1] !== 'IMAGE').length;
        await client.query(`UPDATE book_editions SET status='READY', toc=$2, page_count=$3 WHERE id=$1`,
          [editionId, JSON.stringify(toc), count]);
        await client.query('COMMIT');
      } catch (e) {
        await client.query('ROLLBACK'); throw e;
      } finally { client.release(); }
    },

    /** Decrypt one asset of an edition. */
    async readAsset(edition, asset) {
      const dataKey = await kms.unwrap(edition.wrapped_key, edition.id);
      const blob = await storage.get(asset.storage_key);
      return aesGcmDecrypt(dataKey, blob, `${edition.id}:${asset.id}`);
    },
  };
}

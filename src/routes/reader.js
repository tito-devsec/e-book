// Reader API. Every route requires a live session, a valid device signature, and an
// active license for the requested book on this device. Responses are never cacheable.
import express from 'express';
import { validate, notFound, uuidParam, HttpError } from '../lib/http.js';
import { watermarkPage, traceCode, maskedPhone, formatPhone } from '../services/watermark.js';

export function readerRoutes({ pool, access, ingest, events, readerAuth, storage, cfg, settings }) {
  const r = express.Router();
  r.use((req, res, next) => { res.set('Cache-Control', 'no-store, private'); res.set('Pragma', 'no-cache'); next(); });
  r.use(readerAuth.sessionOnly(), readerAuth.signed());

  // Text of the tiled watermark: the author's name and number only, never the buyer's details.
  async function ownerMark() {
    const wa = (await settings.website()).whatsapp || {};
    return [wa.contactName, wa.number ? formatPhone(wa.number) : ''].filter(Boolean).join(' · ');
  }

  async function currentEdition(bookId) {
    const { rows: [e] } = await pool.query(
      `SELECT e.* FROM books b JOIN book_editions e ON e.id=b.current_edition_id WHERE b.id=$1 AND e.status='READY'`, [bookId]);
    return e;
  }

  // Book content is only served to the installed app (unless the owner turned this off).
  async function requireInstalled(req) {
    const policy = await settings.policy();
    if (policy.require_app_install !== false && !req.reader.device_installed_at) {
      throw new HttpError(403, 'APP_INSTALL_REQUIRED', 'Add the book to your device to start reading.');
    }
  }

  // Called by the installed app the first time it opens on this device. From then on the
  // download page for this device is expired and reading happens only in the app.
  r.post('/app-installed', async (req, res) => {
    const { rowCount } = await pool.query('UPDATE registered_devices SET installed_at=now() WHERE id=$1 AND installed_at IS NULL', [req.reader.device_id]);
    if (rowCount) await events.reading(null, { type: 'APP_INSTALLED', customerId: req.reader.customer_id, deviceId: req.reader.device_id });
    res.json({ ok: true });
  });

  r.get('/library', async (req, res) => {
    const books = await access.libraryFor(req.reader);
    res.json({
      customer: { name: req.reader.full_name },
      books: books.map((b) => ({
        id: b.id, title: b.title, subtitle: b.subtitle, author: b.author, description: b.description,
        hasCover: b.has_cover, ready: b.edition_status === 'READY', format: b.format,
        progress: b.percent ? Number(b.percent) : 0, expiresAt: b.expires_at,
      })),
    });
  });

  r.get('/books/:bookId', async (req, res) => {
    const bookId = uuidParam(req.params.bookId);
    const lic = await access.requireBookAccess(req.reader, bookId, req.ip);
    const { rows: [b] } = await pool.query('SELECT id, title, subtitle, author, description, (cover_storage_key IS NOT NULL) AS has_cover FROM books WHERE id=$1', [bookId]);
    const e = await currentEdition(bookId);
    res.json({
      book: { id: b.id, title: b.title, subtitle: b.subtitle, author: b.author, description: b.description, hasCover: b.has_cover },
      access: { status: 'ACTIVE', activatedAt: lic.activated_at, expiresAt: lic.expires_at },
      preparation: e ? 'READY' : 'PREPARING',
      installedOnThisDevice: Boolean(req.reader.device_installed_at),
    });
  });

  r.get('/books/:bookId/cover', async (req, res) => {
    const bookId = uuidParam(req.params.bookId);
    await access.requireBookAccess(req.reader, bookId, req.ip);
    const { rows: [b] } = await pool.query('SELECT cover_storage_key, cover_mime FROM books WHERE id=$1', [bookId]);
    if (!b?.cover_storage_key) throw notFound();
    res.type(b.cover_mime).send(await storage.get(b.cover_storage_key));
  });

  r.get('/books/:bookId/manifest', async (req, res) => {
    const bookId = uuidParam(req.params.bookId);
    await access.requireBookAccess(req.reader, bookId, req.ip);
    await requireInstalled(req);
    const e = await currentEdition(bookId);
    if (!e) return res.status(409).json({ code: 'NOT_READY', message: 'This book is being prepared. Please check back shortly.' });
    const { rows } = await pool.query(
      `SELECT id, ordinal, title FROM book_assets WHERE edition_id=$1 AND kind = ANY($2) ORDER BY ordinal`,
      [e.id, e.format === 'PDF' ? ['PAGE_IMAGE'] : ['CHAPTER']]);
    await events.reading(null, { type: 'READER_OPENED', customerId: req.reader.customer_id, bookId, deviceId: req.reader.device_id });
    // Customer is fully onboarded once they open the reader.
    await pool.query(`UPDATE customers SET status='ACTIVE', updated_at=now() WHERE id=$1 AND status='ACTIVATED'`, [req.reader.customer_id]);
    res.json({
      format: e.format,
      edition: e.version,
      toc: e.toc,
      items: rows.map((a) => ({ id: a.id, index: a.ordinal, title: a.title })),
      watermark: await ownerMark(),
    });
  });

  r.get('/books/:bookId/content/:resourceId', async (req, res) => {
    const bookId = uuidParam(req.params.bookId);
    const resourceId = uuidParam(req.params.resourceId);
    const lic = await access.requireBookAccess(req.reader, bookId, req.ip);
    await requireInstalled(req);
    const e = await currentEdition(bookId);
    if (!e) throw notFound();
    // Extracted page text is only used by server-side search; it is never handed out whole.
    const { rows: [asset] } = await pool.query(`SELECT * FROM book_assets WHERE id=$1 AND edition_id=$2 AND kind <> 'PAGE_TEXT'`, [resourceId, e.id]);
    if (!asset) throw notFound();
    let body = await ingest.readAsset(e, asset);
    let mime = asset.mime === 'text/html' ? 'text/html; charset=utf-8' : asset.mime;
    if (asset.kind === 'PAGE_IMAGE') {
      // Burn the buyer's identity into the page pixels for this request.
      const wa = (await settings.website()).whatsapp || {};
      body = await watermarkPage(body, {
        name: req.reader.full_name, phone: maskedPhone(req.reader.phone_e164), code: traceCode(cfg.hashPepper, lic.id),
        owner: wa.contactName ? { name: wa.contactName, phone: formatPhone(wa.number) } : null,
        dark: asset.title === 'Front cover',
      });
      mime = 'image/webp';
    }
    if (asset.kind !== 'IMAGE') {
      await events.reading(null, { type: 'CHAPTER_ACCESSED', customerId: req.reader.customer_id, bookId, deviceId: req.reader.device_id, details: { index: asset.ordinal } });
    }
    res.set('Content-Type', mime);
    res.set('Content-Disposition', 'inline');
    res.set('Content-Security-Policy', "default-src 'none'; sandbox");
    res.send(body);
  });

  // Full-text search runs on the server and returns short snippets only, so the client never
  // needs to download every chapter to search.
  r.get('/books/:bookId/search', async (req, res) => {
    const bookId = uuidParam(req.params.bookId);
    const q = String(req.query.q || '').trim();
    if (q.length < 2 || q.length > 100) return res.json({ results: [] });
    await access.requireBookAccess(req.reader, bookId, req.ip);
    await requireInstalled(req);
    const e = await currentEdition(bookId);
    if (!e) return res.json({ results: [], supported: false });
    const { rows } = await pool.query(`SELECT * FROM book_assets WHERE edition_id=$1 AND kind=$2 ORDER BY ordinal`, [e.id, e.format === 'PDF' ? 'PAGE_TEXT' : 'CHAPTER']);
    if (!rows.length) return res.json({ results: [], supported: false });
    const needle = q.toLowerCase();
    const results = [];
    for (const a of rows) {
      const text = (await ingest.readAsset(e, a)).toString('utf8').replace(/<[^>]+>/g, ' ').replace(/&nbsp;/g, ' ').replace(/&amp;/g, '&').replace(/\s+/g, ' ');
      const lower = text.toLowerCase();
      let from = 0; let count = 0;
      while (count < 3 && results.length < 30) {
        const at = lower.indexOf(needle, from);
        if (at < 0) break;
        results.push({ index: a.ordinal, chapter: a.title, snippet: text.slice(Math.max(0, at - 50), at + needle.length + 50).trim(), offset: at });
        from = at + needle.length; count += 1;
      }
      if (results.length >= 30) break;
    }
    res.json({ results, supported: true });
  });

  r.get('/progress/:bookId', async (req, res) => {
    const bookId = uuidParam(req.params.bookId);
    await access.requireBookAccess(req.reader, bookId, req.ip);
    const { rows: [p] } = await pool.query('SELECT location, percent, updated_at FROM reading_progress WHERE customer_id=$1 AND book_id=$2', [req.reader.customer_id, bookId]);
    res.json({ progress: p ? { location: p.location, percent: Number(p.percent), updatedAt: p.updated_at } : null });
  });

  const locationSchema = (loc) => {
    const l = validate(loc, { index: { type: 'int', required: true, min: 0, max: 100000 }, page: { type: 'int', min: 0, max: 100000, default: 0 } });
    return l;
  };

  r.post('/progress', async (req, res) => {
    const b = validate(req.body, {
      bookId: { type: 'uuid', required: true },
      location: { type: 'object', required: true },
      percent: { type: 'int', required: true, min: 0, max: 100 },
    });
    await access.requireBookAccess(req.reader, b.bookId, req.ip);
    const loc = locationSchema(b.location);
    await pool.query(
      `INSERT INTO reading_progress (customer_id, book_id, location, percent) VALUES ($1,$2,$3,$4)
       ON CONFLICT (customer_id, book_id) DO UPDATE SET location=$3, percent=$4, updated_at=now()`,
      [req.reader.customer_id, b.bookId, loc, b.percent]);
    res.json({ ok: true });
  });

  r.get('/bookmarks/:bookId', async (req, res) => {
    const bookId = uuidParam(req.params.bookId);
    await access.requireBookAccess(req.reader, bookId, req.ip);
    const { rows } = await pool.query(
      'SELECT id, location, label, created_at FROM bookmarks WHERE customer_id=$1 AND book_id=$2 ORDER BY created_at', [req.reader.customer_id, bookId]);
    res.json({ bookmarks: rows });
  });

  r.post('/bookmarks', async (req, res) => {
    const b = validate(req.body, {
      bookId: { type: 'uuid', required: true },
      location: { type: 'object', required: true },
      label: { type: 'string', max: 200, default: '' },
    });
    await access.requireBookAccess(req.reader, b.bookId, req.ip);
    const { rows: [{ n }] } = await pool.query('SELECT count(*)::int AS n FROM bookmarks WHERE customer_id=$1 AND book_id=$2', [req.reader.customer_id, b.bookId]);
    if (n >= 500) return res.status(400).json({ code: 'TOO_MANY_BOOKMARKS', message: 'Bookmark limit reached' });
    const { rows: [bm] } = await pool.query(
      'INSERT INTO bookmarks (customer_id, book_id, location, label) VALUES ($1,$2,$3,$4) RETURNING id, location, label, created_at',
      [req.reader.customer_id, b.bookId, locationSchema(b.location), b.label]);
    res.status(201).json({ bookmark: bm });
  });

  r.delete('/bookmarks/:id', async (req, res) => {
    const id = uuidParam(req.params.id);
    const { rowCount } = await pool.query('DELETE FROM bookmarks WHERE id=$1 AND customer_id=$2', [id, req.reader.customer_id]);
    if (!rowCount) throw notFound();
    res.json({ ok: true });
  });

  return r;
}

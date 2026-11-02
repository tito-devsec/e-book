// Management dashboard API. Every route requires an authenticated administrator with the
// listed permission; every state change writes an audit log entry in the same transaction.
import express from 'express';
import multer from 'multer';
import crypto from 'node:crypto';
import { tx } from '../db.js';
import {
  validate, badRequest, notFound, conflict, uuidParam, pageParams, normalizePhone,
} from '../lib/http.js';
import { hashPassword } from '../lib/crypto.js';
import { detectImageMime } from '../services/ingest.js';
import { traceCode } from '../services/watermark.js';
import { POLICY_SCHEMA, WEBSITE_KEYS } from '../services/settings.js';
import { validatePasswordStrength } from './adminAuth.js';

const CUSTOMER_STATUSES = ['PENDING_PAYMENT', 'PAID', 'INVITED', 'ACTIVATED', 'ACTIVE', 'SUSPENDED', 'REVOKED', 'EXPIRED'];
const like = (q) => `%${String(q).replace(/[\\%_]/g, (m) => '\\' + m)}%`;

export function adminRoutes(ctx) {
  const { pool, cfg, adminAuth, events, access, ingest, storage, settings, scanner } = ctx;
  const r = express.Router();
  const can = (...p) => adminAuth.require(...p);
  r.use((req, res, next) => { res.set('Cache-Control', 'no-store'); next(); });

  const audit = (db, req, action, entityType, entityId, details) =>
    events.audit(db, { adminId: req.admin.id, action, entityType, entityId, details, ip: req.ip });

  const bookUpload = multer({ storage: multer.memoryStorage(), limits: { fileSize: cfg.maxBookUploadMb * 1024 * 1024, files: 1, fields: 5 } });
  const coverUpload = multer({ storage: multer.memoryStorage(), limits: { fileSize: cfg.maxCoverUploadMb * 1024 * 1024, files: 1, fields: 2 } });

  // =========================================================================
  // Overview
  // =========================================================================
  r.get('/overview', can('dashboard.view'), async (req, res) => {
    const { rows: [m] } = await pool.query(`SELECT
      (SELECT count(*) FROM books)::int AS total_books,
      (SELECT count(*) FROM orders)::int AS total_orders,
      (SELECT count(*) FROM payments WHERE status='VERIFIED')::int AS verified_payments,
      (SELECT count(*) FROM payments WHERE status='PENDING')::int AS pending_payments,
      (SELECT count(*) FROM customers)::int AS registered_customers,
      (SELECT count(*) FROM invitations WHERE status='PENDING' AND expires_at > now())::int AS active_invitations,
      (SELECT count(*) FROM customers WHERE status IN ('ACTIVATED','ACTIVE'))::int AS activated_customers,
      (SELECT count(*) FROM reading_licenses WHERE status='ACTIVE' AND (expires_at IS NULL OR expires_at > now()))::int AS active_licenses,
      (SELECT count(*) FROM customers WHERE status='SUSPENDED')::int AS suspended_accounts,
      (SELECT count(*) FROM customers WHERE status='REVOKED')::int + (SELECT count(*) FROM reading_licenses WHERE status='REVOKED')::int AS revoked_access,
      (SELECT count(*) FROM security_events WHERE resolved_at IS NULL)::int AS open_security_events`);
    const { rows: security } = await pool.query(
      `SELECT s.id, s.event_type, s.severity, s.created_at, c.full_name AS customer
         FROM security_events s LEFT JOIN customers c ON c.id=s.customer_id ORDER BY s.created_at DESC LIMIT 8`);
    const { rows: activity } = await pool.query(
      `SELECT e.id, e.event_type, e.created_at, c.full_name AS customer, b.title AS book
         FROM reading_events e LEFT JOIN customers c ON c.id=e.customer_id LEFT JOIN books b ON b.id=e.book_id
        ORDER BY e.created_at DESC LIMIT 8`);
    // Chart data. Money is summed per currency; charts use the currency with the most revenue.
    const { rows: revenue } = await pool.query(
      `SELECT currency, sum(amount) FILTER (WHERE status='VERIFIED')::text AS verified, sum(amount) FILTER (WHERE status='PENDING')::text AS pending,
              count(*) FILTER (WHERE status='PENDING')::int AS pending_count
         FROM payments GROUP BY currency ORDER BY sum(amount) FILTER (WHERE status='VERIFIED') DESC NULLS LAST`);
    const currency = revenue[0]?.currency || 'KES';
    const { rows: weekly } = await pool.query(
      `SELECT to_char(d, 'YYYY-MM-DD') AS day,
              (SELECT count(*) FROM orders o WHERE o.created_at >= d AND o.created_at < d + interval '1 day')::int AS orders,
              (SELECT count(*) FROM payments p WHERE p.status='VERIFIED' AND p.verified_at >= d AND p.verified_at < d + interval '1 day')::int AS verified,
              (SELECT count(*) FROM reading_licenses l WHERE l.activated_at >= d AND l.activated_at < d + interval '1 day')::int AS activations
         FROM generate_series(date_trunc('day', now()) - interval '6 days', date_trunc('day', now()), interval '1 day') d ORDER BY d`);
    const { rows: monthly } = await pool.query(
      `SELECT to_char(m, 'YYYY-MM') AS month,
              COALESCE((SELECT sum(amount) FROM payments p WHERE p.status='VERIFIED' AND p.currency=$1
                         AND p.verified_at >= m AND p.verified_at < m + interval '1 month'), 0)::text AS amount
         FROM generate_series(date_trunc('month', now()) - interval '7 months', date_trunc('month', now()), interval '1 month') m ORDER BY m`, [currency]);
    const { rows: licenseStatus } = await pool.query(`SELECT status, count(*)::int AS n FROM reading_licenses GROUP BY status`);
    const { rows: recentPayments } = await pool.query(
      `SELECT p.id, p.amount, p.currency, p.method, p.reference, p.status, COALESCE(p.verified_at, p.created_at) AS at,
              o.id AS order_id, c.full_name
         FROM payments p JOIN orders o ON o.id=p.order_id JOIN customers c ON c.id=o.customer_id
        ORDER BY COALESCE(p.verified_at, p.created_at) DESC LIMIT 5`);
    const { rows: recentCustomers } = await pool.query(
      `SELECT id, full_name, status FROM customers ORDER BY created_at DESC LIMIT 4`);
    res.json({
      metrics: m, recentSecurity: security, recentActivity: activity,
      revenue, currency, weekly, monthly, licenseStatus, recentPayments, recentCustomers,
    });
  });

  // =========================================================================
  // Books and editions
  // =========================================================================
  const bookSchema = (partial) => ({
    title: { type: 'string', required: !partial, max: 300 },
    subtitle: { type: 'string', max: 300 },
    author: { type: 'string', required: !partial, max: 200 },
    description: { type: 'string', max: 10000, trim: false },
    priceAmount: { type: 'money', required: !partial },
    currency: { type: 'string', pattern: /^[A-Z]{3}$/, required: !partial },
    availability: { type: 'string', enum: ['AVAILABLE', 'COMING_SOON', 'UNAVAILABLE'] },
    preferredFormat: { type: 'string', enum: ['EPUB', 'PDF'] },
    licenseDurationDays: { type: 'int', min: 1, max: 36500, nullable: true },
    maxDevices: { type: 'int', min: 1, max: 10 },
  });
  const slugify = (s) => s.toLowerCase().normalize('NFKD').replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '').slice(0, 80) || 'book';

  r.get('/books', can('books.manage'), async (req, res) => {
    const { rows } = await pool.query(
      `SELECT b.*, e.version AS current_version, e.format AS current_format, e.status AS current_status,
              (SELECT count(*) FROM reading_licenses l WHERE l.book_id=b.id AND l.status='ACTIVE')::int AS active_licenses
         FROM books b LEFT JOIN book_editions e ON e.id=b.current_edition_id ORDER BY b.created_at DESC`);
    res.json({ books: rows.map(({ cover_storage_key, ...b }) => ({ ...b, has_cover: Boolean(cover_storage_key) })) });
  });

  r.post('/books', can('books.manage'), async (req, res) => {
    const b = validate(req.body, bookSchema(false));
    const policy = await settings.policy();
    const book = await tx(pool, async (db) => {
      let slug = slugify(b.title);
      const { rowCount } = await db.query('SELECT 1 FROM books WHERE slug=$1', [slug]);
      if (rowCount) slug = `${slug}-${crypto.randomBytes(3).toString('hex')}`;
      const { rows: [row] } = await db.query(
        `INSERT INTO books (slug, title, subtitle, author, description, price_amount, currency, availability, preferred_format, license_duration_days, max_devices)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) RETURNING *`,
        [slug, b.title, b.subtitle || '', b.author, b.description || '', b.priceAmount, b.currency, b.availability || 'AVAILABLE',
          b.preferredFormat || 'EPUB', b.licenseDurationDays ?? policy.default_license_duration_days ?? null, b.maxDevices || policy.default_max_devices || 1]);
      await audit(db, req, 'book.create', 'book', row.id, { title: row.title });
      return row;
    });
    res.status(201).json({ book });
  });

  r.get('/books/:id', can('books.manage'), async (req, res) => {
    const id = uuidParam(req.params.id);
    const { rows: [book] } = await pool.query('SELECT * FROM books WHERE id=$1', [id]);
    if (!book) throw notFound();
    const { rows: editions } = await pool.query(
      `SELECT e.id, e.version, e.label, e.format, e.status, e.original_size, e.original_sha256, e.page_count, e.error, e.created_at,
              a.full_name AS uploaded_by_name
         FROM book_editions e LEFT JOIN administrators a ON a.id=e.uploaded_by WHERE e.book_id=$1 ORDER BY e.version DESC`, [id]);
    const { cover_storage_key: ck, ...rest } = book;
    res.json({ book: { ...rest, has_cover: Boolean(ck) }, editions });
  });

  r.patch('/books/:id', can('books.manage'), async (req, res) => {
    const id = uuidParam(req.params.id);
    const b = validate(req.body, bookSchema(true));
    const cols = { title: 'title', subtitle: 'subtitle', author: 'author', description: 'description', priceAmount: 'price_amount', currency: 'currency',
      availability: 'availability', preferredFormat: 'preferred_format', licenseDurationDays: 'license_duration_days', maxDevices: 'max_devices' };
    const sets = []; const vals = [id];
    for (const [k, col] of Object.entries(cols)) {
      if (k in b) { vals.push(b[k]); sets.push(`${col}=$${vals.length}`); }
    }
    if (!sets.length) throw badRequest('Nothing to update');
    const book = await tx(pool, async (db) => {
      const { rows: [row] } = await db.query(`UPDATE books SET ${sets.join(', ')}, updated_at=now() WHERE id=$1 RETURNING *`, vals);
      if (!row) throw notFound();
      await audit(db, req, 'book.update', 'book', id, b);
      return row;
    });
    res.json({ book });
  });

  r.post('/books/:id/cover', can('books.manage'), coverUpload.single('file'), async (req, res) => {
    const id = uuidParam(req.params.id);
    if (!req.file) throw badRequest('Choose an image file');
    const mime = detectImageMime(req.file.buffer);
    if (!mime) throw badRequest('Cover must be a PNG, JPEG or WebP image', 'UNSUPPORTED_FILE');
    const scan = await scanner.scan(req.file.buffer);
    if (!scan.clean) throw badRequest('The file was rejected by the malware scanner', 'MALWARE_DETECTED');
    const key = `covers/${id}/${crypto.randomUUID()}`;
    await storage.put(key, req.file.buffer, mime);
    await tx(pool, async (db) => {
      const { rowCount } = await db.query('UPDATE books SET cover_storage_key=$2, cover_mime=$3, updated_at=now() WHERE id=$1', [id, key, mime]);
      if (!rowCount) throw notFound();
      await audit(db, req, 'book.cover_upload', 'book', id, { mime, size: req.file.size });
    });
    res.json({ ok: true });
  });

  r.post('/books/:id/upload', can('books.manage'), bookUpload.single('file'), async (req, res) => {
    const id = uuidParam(req.params.id);
    if (!req.file) throw badRequest('Choose an EPUB or PDF file');
    const { rows: [book] } = await pool.query('SELECT id, current_edition_id FROM books WHERE id=$1', [id]);
    if (!book) throw notFound();
    const label = typeof req.body?.label === 'string' ? req.body.label.trim().slice(0, 120) : '';
    const makeCurrent = req.body?.makeCurrent !== 'false';
    const edition = await ingest.ingestEdition({ bookId: id, buffer: req.file.buffer, label, adminId: req.admin.id });
    await tx(pool, async (db) => {
      // Existing licenses reference the book, not the edition, so swapping the current edition
      // never changes who may read it.
      if (makeCurrent || !book.current_edition_id) {
        await db.query('UPDATE books SET current_edition_id=$2, updated_at=now() WHERE id=$1', [id, edition.id]);
      }
      await audit(db, req, 'book.edition_upload', 'book_edition', edition.id, {
        bookId: id, format: edition.format, size: edition.original_size, sha256: edition.original_sha256, malwareScanned: scanner.enabled, makeCurrent,
      });
    });
    res.status(201).json({ edition: { id: edition.id, version: edition.version, format: edition.format, status: edition.status, pageCount: edition.page_count } });
  });

  r.post('/books/:id/editions/:editionId/activate', can('books.manage'), async (req, res) => {
    const id = uuidParam(req.params.id); const eid = uuidParam(req.params.editionId);
    await tx(pool, async (db) => {
      const { rows: [e] } = await db.query(`SELECT * FROM book_editions WHERE id=$1 AND book_id=$2`, [eid, id]);
      if (!e) throw notFound();
      if (e.status !== 'READY') throw badRequest('Only a ready edition can be made current');
      await db.query('UPDATE books SET current_edition_id=$2, updated_at=now() WHERE id=$1', [id, eid]);
      await audit(db, req, 'book.edition_activate', 'book_edition', eid, { bookId: id, version: e.version });
    });
    res.json({ ok: true });
  });

  r.post('/books/:id/editions/:editionId/archive', can('books.manage'), async (req, res) => {
    const id = uuidParam(req.params.id); const eid = uuidParam(req.params.editionId);
    await tx(pool, async (db) => {
      const { rows: [b] } = await db.query('SELECT current_edition_id FROM books WHERE id=$1', [id]);
      if (!b) throw notFound();
      if (b.current_edition_id === eid) throw badRequest('Make another edition current before archiving this one');
      const { rowCount } = await db.query(`UPDATE book_editions SET status='ARCHIVED' WHERE id=$1 AND book_id=$2`, [eid, id]);
      if (!rowCount) throw notFound();
      await audit(db, req, 'book.edition_archive', 'book_edition', eid, { bookId: id });
    });
    res.json({ ok: true });
  });

  for (const [path, published] of [['publish', true], ['unpublish', false]]) {
    r.post(`/books/:id/${path}`, can('books.manage'), async (req, res) => {
      const id = uuidParam(req.params.id);
      await tx(pool, async (db) => {
        const { rows: [b] } = await db.query('SELECT * FROM books WHERE id=$1 FOR UPDATE', [id]);
        if (!b) throw notFound();
        if (published && !b.cover_storage_key) throw badRequest('Upload a cover before publishing');
        await db.query('UPDATE books SET published=$2, updated_at=now() WHERE id=$1', [id, published]);
        await audit(db, req, `book.${path}`, 'book', id, {});
      });
      res.json({ ok: true });
    });
  }

  // =========================================================================
  // Customers
  // =========================================================================
  r.get('/customers', can('customers.view'), async (req, res) => {
    const { limit, offset, page } = pageParams(req.query);
    const where = []; const vals = [];
    if (req.query.q) { vals.push(like(req.query.q)); where.push(`(c.full_name ILIKE $${vals.length} OR c.phone_e164 ILIKE $${vals.length} OR c.email ILIKE $${vals.length})`); }
    if (CUSTOMER_STATUSES.includes(req.query.status)) { vals.push(req.query.status); where.push(`c.status=$${vals.length}`); }
    const sorts = { name: 'c.full_name', created: 'c.created_at', status: 'c.status' };
    const sort = sorts[req.query.sort] || 'c.created_at';
    const dir = req.query.dir === 'asc' ? 'ASC' : 'DESC';
    const w = where.length ? `WHERE ${where.join(' AND ')}` : '';
    const { rows: [{ total }] } = await pool.query(`SELECT count(*)::int AS total FROM customers c ${w}`, vals);
    const { rows } = await pool.query(
      `SELECT c.id, c.full_name, c.phone_e164, c.email, c.status, c.created_at,
              (SELECT count(*) FROM orders o WHERE o.customer_id=c.id)::int AS orders,
              (SELECT count(*) FROM reading_licenses l WHERE l.customer_id=c.id AND l.status='ACTIVE')::int AS active_licenses
         FROM customers c ${w} ORDER BY ${sort} ${dir}, c.id LIMIT ${limit} OFFSET ${offset}`, vals);
    res.json({ customers: rows, total, page, limit });
  });

  r.get('/customers/:id', can('customers.view'), async (req, res) => {
    const id = uuidParam(req.params.id);
    const { rows: [customer] } = await pool.query('SELECT * FROM customers WHERE id=$1', [id]);
    if (!customer) throw notFound();
    const q = (sql) => pool.query(sql, [id]).then((x) => x.rows);
    const [orders, licenses, invitations, devices, activity, security] = await Promise.all([
      q(`SELECT o.*, (SELECT json_agg(json_build_object('bookId', b.id, 'title', b.title)) FROM order_items i JOIN books b ON b.id=i.book_id WHERE i.order_id=o.id) AS books,
                (SELECT json_agg(p ORDER BY p.created_at) FROM payments p WHERE p.order_id=o.id) AS payments
           FROM orders o WHERE o.customer_id=$1 ORDER BY o.created_at DESC`),
      q(`SELECT l.*, b.title AS book_title, o.reference AS order_reference,
                (SELECT count(*) FROM device_authorizations da JOIN registered_devices dv ON dv.id=da.device_id WHERE da.license_id=l.id AND da.status='ACTIVE' AND dv.status='ACTIVE')::int AS active_devices
           FROM reading_licenses l JOIN books b ON b.id=l.book_id JOIN orders o ON o.id=l.order_id WHERE l.customer_id=$1 ORDER BY l.created_at DESC`),
      q(`SELECT i.id, i.status, i.token_hint, i.expires_at, i.opened_at, i.consumed_at, i.created_at, i.license_id, b.title AS book_title
           FROM invitations i JOIN books b ON b.id=i.book_id WHERE i.customer_id=$1 ORDER BY i.created_at DESC`),
      q(`SELECT d.id, d.browser, d.os, d.device_category, d.status, d.registered_at, d.last_seen_at, d.installed_at, d.revoked_at, d.revoked_reason,
                (SELECT string_agg(b.title, ', ') FROM device_authorizations da JOIN reading_licenses l ON l.id=da.license_id JOIN books b ON b.id=l.book_id
                  WHERE da.device_id=d.id AND da.status='ACTIVE') AS books,
                (SELECT count(*) FROM reading_sessions s WHERE s.device_id=d.id AND s.ended_at IS NULL AND s.expires_at > now())::int AS active_sessions
           FROM registered_devices d WHERE d.customer_id=$1 ORDER BY d.registered_at DESC`),
      q(`SELECT e.event_type, e.created_at, e.details, b.title AS book FROM reading_events e LEFT JOIN books b ON b.id=e.book_id
          WHERE e.customer_id=$1 ORDER BY e.created_at DESC LIMIT 100`),
      q(`SELECT id, event_type, severity, created_at, resolved_at FROM security_events WHERE customer_id=$1 ORDER BY created_at DESC LIMIT 50`),
    ]);
    res.json({ customer, orders, licenses: licenses.map((l) => ({ ...l, trace_code: traceCode(cfg.hashPepper, l.id) })), invitations, devices, activity, security });
  });

  r.patch('/customers/:id', can('customers.manage'), async (req, res) => {
    const id = uuidParam(req.params.id);
    const b = validate(req.body, { fullName: { type: 'string', max: 200 }, email: { type: 'string', max: 200, nullable: true }, notes: { type: 'string', max: 5000, trim: false }, phone: { type: 'string', max: 32 } });
    const customer = await tx(pool, async (db) => {
      const { rows: [c] } = await db.query('SELECT * FROM customers WHERE id=$1 FOR UPDATE', [id]);
      if (!c) throw notFound();
      let phone = c.phone_e164;
      if (b.phone) {
        phone = normalizePhone(b.phone, process.env.DEFAULT_COUNTRY_CODE || '');
        if (!phone) throw badRequest('Enter the phone number in international format, e.g. +254712345678');
        // Changing the number moves OTP delivery: pending invitations must be reissued.
        if (phone !== c.phone_e164) {
          await db.query(`UPDATE invitations SET status='REVOKED', revoked_at=now() WHERE customer_id=$1 AND status='PENDING'`, [id]);
        }
      }
      const { rows: [u] } = await db.query(
        `UPDATE customers SET full_name=COALESCE($2, full_name), email=$3, notes=COALESCE($4, notes), phone_e164=$5, updated_at=now() WHERE id=$1 RETURNING *`,
        [id, b.fullName || null, b.email !== undefined ? b.email : c.email, b.notes ?? null, phone]).catch((e) => {
        if (e.code === '23505') throw conflict('Another customer already uses this phone number');
        throw e;
      });
      await audit(db, req, 'customer.update', 'customer', id, { ...b, phoneChanged: phone !== c.phone_e164 });
      return u;
    });
    res.json({ customer });
  });

  async function setCustomerAccess(req, id, status, reason) {
    return tx(pool, async (db) => {
      const { rows: [c] } = await db.query('SELECT * FROM customers WHERE id=$1 FOR UPDATE', [id]);
      if (!c) throw notFound();
      await db.query('UPDATE customers SET status=$2, updated_at=now() WHERE id=$1', [id, status]);
      const endReason = status === 'REVOKED' ? 'ACCESS_REVOKED' : 'ACCOUNT_SUSPENDED';
      await db.query(`UPDATE reading_sessions SET ended_at=now(), end_reason=$2 WHERE customer_id=$1 AND ended_at IS NULL`, [id, endReason]);
      await db.query(`UPDATE invitations SET status='REVOKED', revoked_at=now() WHERE customer_id=$1 AND status='PENDING'`, [id]);
      if (status === 'REVOKED') {
        await db.query(`UPDATE reading_licenses SET status='REVOKED', status_reason=$2, updated_at=now() WHERE customer_id=$1 AND status IN ('ACTIVE','PENDING_ACTIVATION','SUSPENDED')`, [id, reason || 'Access revoked']);
      }
      await events.reading(db, { type: status === 'REVOKED' ? 'LICENSE_REVOKED' : 'ACCOUNT_SUSPENDED', customerId: id });
      await audit(db, req, status === 'REVOKED' ? 'customer.revoke_access' : 'customer.suspend', 'customer', id, { reason, previousStatus: c.status });
    });
  }

  r.post('/customers/:id/suspend', can('access.manage'), async (req, res) => {
    const b = validate(req.body, { reason: { type: 'string', max: 500 } });
    await setCustomerAccess(req, uuidParam(req.params.id), 'SUSPENDED', b.reason);
    res.json({ ok: true });
  });

  r.post('/customers/:id/revoke-access', can('access.manage'), async (req, res) => {
    const b = validate(req.body, { reason: { type: 'string', max: 500 } });
    await setCustomerAccess(req, uuidParam(req.params.id), 'REVOKED', b.reason);
    res.json({ ok: true });
  });

  r.post('/customers/:id/reactivate', can('access.manage'), async (req, res) => {
    const id = uuidParam(req.params.id);
    await tx(pool, async (db) => {
      const { rows: [c] } = await db.query('SELECT * FROM customers WHERE id=$1 FOR UPDATE', [id]);
      if (!c) throw notFound();
      if (c.status !== 'SUSPENDED') throw badRequest('Only suspended customers can be reactivated. Revoked access needs a new order.');
      const { rows: [{ n }] } = await db.query(`SELECT count(*)::int AS n FROM reading_licenses WHERE customer_id=$1 AND status='ACTIVE'`, [id]);
      const { rows: [{ p }] } = await db.query(`SELECT count(*)::int AS p FROM reading_licenses WHERE customer_id=$1 AND status='PENDING_ACTIVATION'`, [id]);
      const next = n > 0 ? 'ACTIVE' : p > 0 ? 'PAID' : 'EXPIRED';
      await db.query('UPDATE customers SET status=$2, updated_at=now() WHERE id=$1', [id, next]);
      await audit(db, req, 'customer.reactivate', 'customer', id, { status: next });
    });
    res.json({ ok: true });
  });

  r.post('/customers/:id/revoke-sessions', can('access.manage'), async (req, res) => {
    const id = uuidParam(req.params.id);
    await tx(pool, async (db) => {
      const { rowCount } = await db.query(`UPDATE reading_sessions SET ended_at=now(), end_reason='ADMIN_REVOKED' WHERE customer_id=$1 AND ended_at IS NULL`, [id]);
      await audit(db, req, 'customer.revoke_sessions', 'customer', id, { sessions: rowCount });
    });
    res.json({ ok: true });
  });

  // =========================================================================
  // Orders and payments
  // =========================================================================
  async function verifyPaymentTx(db, req, orderId, reference) {
    const { rows: [o] } = await db.query('SELECT * FROM orders WHERE id=$1 FOR UPDATE', [orderId]);
    if (!o) throw notFound();
    if (o.status !== 'PENDING_PAYMENT') throw badRequest(`Order is already ${o.status.toLowerCase().replace('_', ' ')}`, 'ORDER_NOT_PENDING');
    const { rows: [p] } = await db.query(`SELECT * FROM payments WHERE order_id=$1 AND status='PENDING' ORDER BY created_at DESC LIMIT 1 FOR UPDATE`, [orderId]);
    if (!p) throw badRequest('There is no pending payment on this order');
    const ref = reference ?? p.reference;
    if (!ref) throw badRequest('Enter the payment reference before verifying', 'REFERENCE_REQUIRED');
    await db.query(`UPDATE payments SET status='VERIFIED', reference=$2, verified_by=$3, verified_at=now() WHERE id=$1`, [p.id, ref, req.admin.id])
      .catch((e) => { if (e.code === '23505') throw conflict('This payment reference has already verified another order'); throw e; });
    await db.query(`UPDATE orders SET status='PAID', updated_at=now() WHERE id=$1`, [orderId]);
    const { rows: items } = await db.query(
      `SELECT i.book_id, b.max_devices, b.license_duration_days FROM order_items i JOIN books b ON b.id=i.book_id WHERE i.order_id=$1`, [orderId]);
    const licenses = [];
    for (const it of items) {
      const { rows: [l] } = await db.query(
        `INSERT INTO reading_licenses (customer_id, book_id, order_id, max_devices, duration_days)
         VALUES ($1,$2,$3,$4,$5) ON CONFLICT (order_id, book_id) DO NOTHING RETURNING id`,
        [o.customer_id, it.book_id, orderId, it.max_devices, it.license_duration_days]);
      if (l) licenses.push(l.id);
    }
    await db.query(`UPDATE customers SET status='PAID', updated_at=now() WHERE id=$1 AND status IN ('PENDING_PAYMENT','EXPIRED')`, [o.customer_id]);
    await audit(db, req, 'payment.verify', 'order', orderId, { paymentId: p.id, amount: p.amount, currency: p.currency, method: p.method, reference: ref, licenses });
    return { licenses };
  }

  r.post('/orders', can('customers.manage'), async (req, res) => {
    const b = validate(req.body, {
      customerId: { type: 'uuid' },
      fullName: { type: 'string', max: 200 },
      phone: { type: 'string', max: 32 },
      email: { type: 'string', max: 200, pattern: /^[^\s@]+@[^\s@]+\.[^\s@]+$/ },
      bookIds: { type: 'array', required: true, max: 20 },
      reference: { type: 'string', max: 80, pattern: /^[A-Za-z0-9._\-/#]+$/ },
      amount: { type: 'money', required: true },
      currency: { type: 'string', pattern: /^[A-Z]{3}$/ },
      paymentMethod: { type: 'string', required: true, max: 60 },
      paymentReference: { type: 'string', max: 120, default: '' },
      paymentStatus: { type: 'string', enum: ['PENDING', 'VERIFIED'], default: 'PENDING' },
      notes: { type: 'string', max: 5000, trim: false, default: '' },
    });
    if (b.paymentStatus === 'VERIFIED' && !req.admin.permissions.includes('payments.verify')) {
      throw badRequest('You do not have permission to verify payments', 'PERMISSION_DENIED');
    }
    for (const id of b.bookIds) uuidParam(id);
    const result = await tx(pool, async (db) => {
      let customerId = b.customerId;
      if (!customerId) {
        if (!b.fullName || !b.phone) throw badRequest('Customer name and WhatsApp number are required');
        const phone = normalizePhone(b.phone, process.env.DEFAULT_COUNTRY_CODE || '');
        if (!phone) throw badRequest('Enter the WhatsApp number in international format, e.g. +254712345678');
        const { rows: [existing] } = await db.query('SELECT id FROM customers WHERE phone_e164=$1', [phone]);
        if (existing) customerId = existing.id;
        else {
          const { rows: [c] } = await db.query(
            `INSERT INTO customers (full_name, phone_e164, email, notes) VALUES ($1,$2,$3,$4) RETURNING id`,
            [b.fullName, phone, b.email || null, b.notes]);
          customerId = c.id;
          await audit(db, req, 'customer.create', 'customer', c.id, { fullName: b.fullName });
        }
      } else {
        const { rowCount } = await db.query('SELECT 1 FROM customers WHERE id=$1', [customerId]);
        if (!rowCount) throw notFound('Customer not found');
      }
      const { rows: books } = await db.query('SELECT id, price_amount, currency FROM books WHERE id = ANY($1::uuid[])', [b.bookIds]);
      if (books.length !== new Set(b.bookIds).size || books.length === 0) throw badRequest('Select at least one valid book');
      const currency = b.currency || books[0].currency;
      const reference = b.reference || `ORD-${new Date().toISOString().slice(0, 10).replace(/-/g, '')}-${crypto.randomBytes(3).toString('hex').toUpperCase()}`;
      const { rows: [o] } = await db.query(
        `INSERT INTO orders (customer_id, reference, total_amount, currency, notes, created_by) VALUES ($1,$2,$3,$4,$5,$6) RETURNING *`,
        [customerId, reference, b.amount, currency, b.notes, req.admin.id]).catch((e) => {
        if (e.code === '23505') throw conflict('An order with this reference already exists');
        throw e;
      });
      for (const bk of books) await db.query('INSERT INTO order_items (order_id, book_id, unit_price) VALUES ($1,$2,$3)', [o.id, bk.id, bk.price_amount]);
      await db.query(`INSERT INTO payments (order_id, amount, currency, method, reference) VALUES ($1,$2,$3,$4,$5)`,
        [o.id, b.amount, currency, b.paymentMethod, b.paymentReference]);
      await db.query(`UPDATE customers SET status='PENDING_PAYMENT', updated_at=now() WHERE id=$1 AND status='EXPIRED'`, [customerId]);
      await audit(db, req, 'order.create', 'order', o.id, { reference, amount: b.amount, currency, books: b.bookIds, method: b.paymentMethod });
      let licenses = [];
      if (b.paymentStatus === 'VERIFIED') ({ licenses } = await verifyPaymentTx(db, req, o.id, b.paymentReference || undefined));
      return { orderId: o.id, customerId, reference, licenses };
    });
    res.status(201).json(result);
  });

  r.get('/orders', can('customers.view'), async (req, res) => {
    const { limit, offset, page } = pageParams(req.query);
    const where = []; const vals = [];
    if (['PENDING_PAYMENT', 'PAID', 'REJECTED', 'CANCELLED'].includes(req.query.status)) { vals.push(req.query.status); where.push(`o.status=$${vals.length}`); }
    if (req.query.q) { vals.push(like(req.query.q)); where.push(`(o.reference ILIKE $${vals.length} OR c.full_name ILIKE $${vals.length} OR c.phone_e164 ILIKE $${vals.length})`); }
    const w = where.length ? `WHERE ${where.join(' AND ')}` : '';
    const { rows: [{ total }] } = await pool.query(`SELECT count(*)::int AS total FROM orders o JOIN customers c ON c.id=o.customer_id ${w}`, vals);
    const { rows } = await pool.query(
      `SELECT o.id, o.reference, o.status, o.total_amount, o.currency, o.created_at, c.id AS customer_id, c.full_name, c.phone_e164,
              (SELECT string_agg(b.title, ', ') FROM order_items i JOIN books b ON b.id=i.book_id WHERE i.order_id=o.id) AS books,
              (SELECT p.method || ' ' || p.reference FROM payments p WHERE p.order_id=o.id ORDER BY p.created_at DESC LIMIT 1) AS payment
         FROM orders o JOIN customers c ON c.id=o.customer_id ${w} ORDER BY o.created_at DESC LIMIT ${limit} OFFSET ${offset}`, vals);
    res.json({ orders: rows, total, page, limit });
  });

  r.get('/orders/:id', can('customers.view'), async (req, res) => {
    const id = uuidParam(req.params.id);
    const { rows: [order] } = await pool.query(
      `SELECT o.*, c.full_name, c.phone_e164, c.email, c.status AS customer_status FROM orders o JOIN customers c ON c.id=o.customer_id WHERE o.id=$1`, [id]);
    if (!order) throw notFound();
    const { rows: items } = await pool.query(`SELECT i.*, b.title FROM order_items i JOIN books b ON b.id=i.book_id WHERE i.order_id=$1`, [id]);
    const { rows: payments } = await pool.query(
      `SELECT p.*, a.full_name AS verified_by_name FROM payments p LEFT JOIN administrators a ON a.id=p.verified_by WHERE p.order_id=$1 ORDER BY p.created_at`, [id]);
    const { rows: licenses } = await pool.query(
      `SELECT l.id, l.status, l.book_id, b.title,
              (SELECT json_build_object('id', i.id, 'status', i.status, 'expires_at', i.expires_at) FROM invitations i WHERE i.license_id=l.id ORDER BY i.created_at DESC LIMIT 1) AS latest_invitation
         FROM reading_licenses l JOIN books b ON b.id=l.book_id WHERE l.order_id=$1`, [id]);
    const { rows: trail } = await pool.query(
      `SELECT al.action, al.details, al.created_at, a.full_name AS admin FROM audit_logs al LEFT JOIN administrators a ON a.id=al.admin_id
        WHERE al.entity_type='order' AND al.entity_id=$1 ORDER BY al.created_at`, [id]);
    res.json({ order, items, payments, licenses, auditTrail: trail });
  });

  r.post('/orders/:id/verify-payment', can('payments.verify'), async (req, res) => {
    const b = validate(req.body, { reference: { type: 'string', max: 120 } });
    const id = uuidParam(req.params.id);
    const result = await tx(pool, (db) => verifyPaymentTx(db, req, id, b.reference));
    res.json({ ok: true, ...result });
  });

  r.post('/orders/:id/reject-payment', can('payments.verify'), async (req, res) => {
    const b = validate(req.body, { reason: { type: 'string', required: true, max: 500 } });
    const id = uuidParam(req.params.id);
    await tx(pool, async (db) => {
      const { rows: [o] } = await db.query('SELECT * FROM orders WHERE id=$1 FOR UPDATE', [id]);
      if (!o) throw notFound();
      if (o.status !== 'PENDING_PAYMENT') throw badRequest('Only pending orders can be rejected', 'ORDER_NOT_PENDING');
      await db.query(`UPDATE payments SET status='REJECTED', rejection_reason=$2, verified_by=$3, verified_at=now() WHERE order_id=$1 AND status='PENDING'`, [id, b.reason, req.admin.id]);
      await db.query(`UPDATE orders SET status='REJECTED', updated_at=now() WHERE id=$1`, [id]);
      await audit(db, req, 'payment.reject', 'order', id, { reason: b.reason });
    });
    res.json({ ok: true });
  });

  // =========================================================================
  // Invitations
  // =========================================================================
  r.get('/invitations', can('customers.view'), async (req, res) => {
    const { limit, offset, page } = pageParams(req.query);
    const vals = []; let w = '';
    if (['PENDING', 'CONSUMED', 'REVOKED', 'EXPIRED', 'REPLACED'].includes(req.query.status)) { vals.push(req.query.status); w = `WHERE i.status=$1`; }
    await pool.query(`UPDATE invitations SET status='EXPIRED' WHERE status='PENDING' AND expires_at <= now()`);
    const { rows } = await pool.query(
      `SELECT i.id, i.status, i.token_hint, i.expires_at, i.opened_at, i.consumed_at, i.created_at, i.license_id,
              c.id AS customer_id, c.full_name, c.phone_e164, b.title AS book_title, o.reference AS order_reference
         FROM invitations i JOIN customers c ON c.id=i.customer_id JOIN books b ON b.id=i.book_id JOIN orders o ON o.id=i.order_id
         ${w} ORDER BY i.created_at DESC LIMIT ${limit} OFFSET ${offset}`, vals);
    res.json({ invitations: rows, page, limit });
  });

  r.post('/invitations', can('invitations.manage'), async (req, res) => {
    const b = validate(req.body, { licenseId: { type: 'uuid', required: true }, expiryHours: { type: 'int', min: 1, max: 720 } });
    const result = await access.createInvitation({ licenseId: b.licenseId, adminId: req.admin.id, expiryHours: b.expiryHours, ip: req.ip });
    res.status(201).json(result);
  });

  r.post('/invitations/:id/revoke', can('invitations.manage'), async (req, res) => {
    const id = uuidParam(req.params.id);
    await tx(pool, async (db) => {
      const { rows: [i] } = await db.query(`UPDATE invitations SET status='REVOKED', revoked_at=now() WHERE id=$1 AND status='PENDING' RETURNING id`, [id]);
      if (!i) throw badRequest('Only pending invitations can be revoked');
      await audit(db, req, 'invitation.revoke', 'invitation', id, {});
    });
    res.json({ ok: true });
  });

  // Resend = secure reissue: the old link stops working and a new random token is generated.
  r.post('/invitations/:id/resend', can('invitations.manage'), async (req, res) => {
    const id = uuidParam(req.params.id);
    const b = validate(req.body, { expiryHours: { type: 'int', min: 1, max: 720 } });
    const { rows: [i] } = await pool.query('SELECT license_id, status FROM invitations WHERE id=$1', [id]);
    if (!i) throw notFound();
    const result = await access.createInvitation({ licenseId: i.license_id, adminId: req.admin.id, expiryHours: b.expiryHours, ip: req.ip });
    res.status(201).json(result);
  });

  // =========================================================================
  // Devices
  // =========================================================================
  r.get('/devices', can('customers.view'), async (req, res) => {
    const { limit, offset, page } = pageParams(req.query);
    const vals = []; const where = [];
    if (['ACTIVE', 'PENDING_APPROVAL', 'REVOKED', 'REPLACED', 'REJECTED'].includes(req.query.status)) { vals.push(req.query.status); where.push(`d.status=$${vals.length}`); }
    if (req.query.customerId) { vals.push(uuidParam(req.query.customerId)); where.push(`d.customer_id=$${vals.length}`); }
    const w = where.length ? `WHERE ${where.join(' AND ')}` : '';
    const { rows } = await pool.query(
      `SELECT d.id, d.browser, d.os, d.device_category, d.status, d.registered_at, d.last_seen_at, d.installed_at, d.revoked_at, d.revoked_reason, d.transition_until,
              c.id AS customer_id, c.full_name,
              (SELECT string_agg(b.title, ', ') FROM device_authorizations da JOIN reading_licenses l ON l.id=da.license_id JOIN books b ON b.id=l.book_id
                WHERE da.device_id=d.id AND da.status='ACTIVE') AS books,
              (SELECT count(*) FROM reading_sessions s WHERE s.device_id=d.id AND s.ended_at IS NULL AND s.expires_at > now())::int AS active_sessions
         FROM registered_devices d JOIN customers c ON c.id=d.customer_id ${w}
        ORDER BY d.registered_at DESC LIMIT ${limit} OFFSET ${offset}`, vals);
    res.json({ devices: rows, page, limit });
  });

  r.post('/devices/:id/revoke', can('access.manage'), async (req, res) => {
    const id = uuidParam(req.params.id);
    const b = validate(req.body, { reason: { type: 'string', max: 300, default: 'Revoked by administrator' } });
    await tx(pool, async (db) => {
      const { rows: [d] } = await db.query(
        `UPDATE registered_devices SET status='REVOKED', revoked_at=now(), revoked_reason=$2, transition_until=NULL
          WHERE id=$1 AND status IN ('ACTIVE','PENDING_APPROVAL') RETURNING *`, [id, b.reason]);
      if (!d) throw badRequest('Device is not active');
      await db.query(`UPDATE device_authorizations SET status='REVOKED', revoked_at=now() WHERE device_id=$1 AND status='ACTIVE'`, [id]);
      await access.endDeviceSessions(db, id, 'DEVICE_REVOKED');
      await audit(db, req, 'device.revoke', 'device', id, { customerId: d.customer_id, reason: b.reason });
    });
    res.json({ ok: true });
  });

  r.get('/device-replacements', can('customers.view'), async (req, res) => {
    const { rows } = await pool.query(
      `SELECT r.*, c.full_name, nd.browser AS new_browser, nd.os AS new_os, od.browser AS old_browser, od.os AS old_os, a.full_name AS decided_by_name
         FROM device_replacements r JOIN customers c ON c.id=r.customer_id
         JOIN registered_devices nd ON nd.id=r.new_device_id LEFT JOIN registered_devices od ON od.id=r.old_device_id
         LEFT JOIN administrators a ON a.id=r.decided_by
        ORDER BY (r.mode='PENDING') DESC, r.created_at DESC LIMIT 200`);
    res.json({ replacements: rows });
  });

  r.post('/device-replacements/:id/approve', can('access.manage'), async (req, res) => {
    const id = uuidParam(req.params.id);
    const b = validate(req.body, { transitionHours: { type: 'int', min: 0, max: 168, default: 0 } });
    await tx(pool, async (db) => {
      const { rows: [rep] } = await db.query(`SELECT * FROM device_replacements WHERE id=$1 AND mode='PENDING' FOR UPDATE`, [id]);
      if (!rep) throw badRequest('This request was already decided');
      const { rows: [nd] } = await db.query(`SELECT * FROM registered_devices WHERE id=$1 AND status='PENDING_APPROVAL' FOR UPDATE`, [rep.new_device_id]);
      if (!nd) throw badRequest('The new device is no longer pending');
      const { rows: licenses } = await db.query(
        `SELECT l.* FROM reading_licenses l JOIN orders o ON o.id=l.order_id AND o.status='PAID'
          WHERE l.customer_id=$1 AND l.status='ACTIVE' FOR UPDATE OF l`, [rep.customer_id]);
      const oldIds = new Set();
      for (const l of licenses) {
        const { rows: actives } = await db.query(
          `SELECT da.device_id FROM device_authorizations da JOIN registered_devices d ON d.id=da.device_id
            WHERE da.license_id=$1 AND da.status='ACTIVE' AND d.status='ACTIVE' ORDER BY d.last_seen_at NULLS FIRST`, [l.id]);
        if (actives.length >= l.max_devices) {
          const old = actives[0].device_id;
          oldIds.add(old);
          if (b.transitionHours === 0) {
            await db.query(`UPDATE device_authorizations SET status='REVOKED', revoked_at=now() WHERE device_id=$1 AND license_id=$2`, [old, l.id]);
          }
        }
        await access.authorize(db, nd.id, l.id);
      }
      await db.query(`UPDATE registered_devices SET status='ACTIVE' WHERE id=$1`, [nd.id]);
      for (const old of oldIds) {
        if (b.transitionHours > 0) {
          // Temporary transition: old device keeps working until the deadline, then stops.
          await db.query(`UPDATE registered_devices SET status='REPLACED', revoked_at=now(), revoked_reason='Replaced (transition)',
                            transition_until=now() + make_interval(hours => $2) WHERE id=$1`, [old, b.transitionHours]);
        } else {
          await db.query(`UPDATE registered_devices SET status='REPLACED', revoked_at=now(), revoked_reason='Replaced (approved by owner)' WHERE id=$1`, [old]);
          await access.endDeviceSessions(db, old, 'DEVICE_REPLACED');
        }
      }
      await db.query(`UPDATE device_replacements SET mode='ADMIN_APPROVED', old_device_id=$2, decided_by=$3, decided_at=now() WHERE id=$1`,
        [id, [...oldIds][0] || null, req.admin.id]);
      await events.reading(db, { type: 'DEVICE_REPLACED', customerId: rep.customer_id, deviceId: nd.id, details: { approvedBy: req.admin.id } });
      await audit(db, req, 'device.replacement_approve', 'device', nd.id, { replacementId: id, oldDevices: [...oldIds], transitionHours: b.transitionHours });
    });
    res.json({ ok: true });
  });

  r.post('/device-replacements/:id/reject', can('access.manage'), async (req, res) => {
    const id = uuidParam(req.params.id);
    await tx(pool, async (db) => {
      const { rows: [rep] } = await db.query(`SELECT * FROM device_replacements WHERE id=$1 AND mode='PENDING' FOR UPDATE`, [id]);
      if (!rep) throw badRequest('This request was already decided');
      await db.query(`UPDATE registered_devices SET status='REJECTED', revoked_at=now(), revoked_reason='Replacement rejected' WHERE id=$1`, [rep.new_device_id]);
      await db.query(`UPDATE device_replacements SET mode='ADMIN_REJECTED', decided_by=$2, decided_at=now() WHERE id=$1`, [id, req.admin.id]);
      await audit(db, req, 'device.replacement_reject', 'device', rep.new_device_id, { replacementId: id });
    });
    res.json({ ok: true });
  });

  // =========================================================================
  // Licenses
  // =========================================================================
  r.get('/licenses', can('customers.view'), async (req, res) => {
    const { limit, offset, page } = pageParams(req.query);
    await pool.query(`UPDATE reading_licenses SET status='EXPIRED', updated_at=now() WHERE status='ACTIVE' AND expires_at IS NOT NULL AND expires_at <= now()`);
    const vals = []; const where = [];
    if (['PENDING_ACTIVATION', 'ACTIVE', 'SUSPENDED', 'REVOKED', 'EXPIRED'].includes(req.query.status)) { vals.push(req.query.status); where.push(`l.status=$${vals.length}`); }
    if (req.query.customerId) { vals.push(uuidParam(req.query.customerId)); where.push(`l.customer_id=$${vals.length}`); }
    // Find the license behind a watermark reference seen on a leaked page.
    if (req.query.ref) {
      const ref = String(req.query.ref).trim().toUpperCase();
      const { rows: all } = await pool.query('SELECT id FROM reading_licenses');
      const hit = all.find((l) => traceCode(cfg.hashPepper, l.id) === ref);
      vals.push(hit ? hit.id : '00000000-0000-0000-0000-000000000000'); where.push(`l.id=$${vals.length}`);
    }
    const w = where.length ? `WHERE ${where.join(' AND ')}` : '';
    const { rows } = await pool.query(
      `SELECT l.*, c.full_name, c.phone_e164, b.title AS book_title, o.reference AS order_reference,
              (SELECT count(*) FROM device_authorizations da JOIN registered_devices d ON d.id=da.device_id WHERE da.license_id=l.id AND da.status='ACTIVE' AND d.status='ACTIVE')::int AS active_devices
         FROM reading_licenses l JOIN customers c ON c.id=l.customer_id JOIN books b ON b.id=l.book_id JOIN orders o ON o.id=l.order_id
         ${w} ORDER BY l.created_at DESC LIMIT ${limit} OFFSET ${offset}`, vals);
    res.json({ licenses: rows.map((l) => ({ ...l, trace_code: traceCode(cfg.hashPepper, l.id) })), page, limit });
  });

  async function licenseAction(req, id, fn) {
    return tx(pool, async (db) => {
      const { rows: [l] } = await db.query('SELECT * FROM reading_licenses WHERE id=$1 FOR UPDATE', [id]);
      if (!l) throw notFound();
      return fn(db, l);
    });
  }

  r.post('/licenses/:id/suspend', can('access.manage'), async (req, res) => {
    const b = validate(req.body, { reason: { type: 'string', max: 500 } });
    await licenseAction(req, uuidParam(req.params.id), async (db, l) => {
      if (l.status !== 'ACTIVE') throw badRequest('Only active licenses can be suspended');
      await db.query(`UPDATE reading_licenses SET status='SUSPENDED', status_reason=$2, updated_at=now() WHERE id=$1`, [l.id, b.reason || null]);
      await audit(db, req, 'license.suspend', 'license', l.id, { reason: b.reason });
    });
    res.json({ ok: true });
  });

  r.post('/licenses/:id/revoke', can('access.manage'), async (req, res) => {
    const b = validate(req.body, { reason: { type: 'string', max: 500 } });
    await licenseAction(req, uuidParam(req.params.id), async (db, l) => {
      if (l.status === 'REVOKED') throw badRequest('License is already revoked');
      await db.query(`UPDATE reading_licenses SET status='REVOKED', status_reason=$2, updated_at=now() WHERE id=$1`, [l.id, b.reason || null]);
      await db.query(`UPDATE invitations SET status='REVOKED', revoked_at=now() WHERE license_id=$1 AND status='PENDING'`, [l.id]);
      await db.query(`UPDATE device_authorizations SET status='REVOKED', revoked_at=now() WHERE license_id=$1 AND status='ACTIVE'`, [l.id]);
      await events.reading(db, { type: 'LICENSE_REVOKED', customerId: l.customer_id, bookId: l.book_id });
      await audit(db, req, 'license.revoke', 'license', l.id, { reason: b.reason });
    });
    res.json({ ok: true });
  });

  r.post('/licenses/:id/reactivate', can('access.manage'), async (req, res) => {
    await licenseAction(req, uuidParam(req.params.id), async (db, l) => {
      if (l.status !== 'SUSPENDED') throw badRequest('Only suspended licenses can be reactivated');
      const next = l.activated_at ? 'ACTIVE' : 'PENDING_ACTIVATION';
      await db.query(`UPDATE reading_licenses SET status=$2, status_reason=NULL, updated_at=now() WHERE id=$1`, [l.id, next]);
      await audit(db, req, 'license.reactivate', 'license', l.id, { status: next });
    });
    res.json({ ok: true });
  });

  r.post('/licenses/:id/renew', can('access.manage'), async (req, res) => {
    const b = validate(req.body, { days: { type: 'int', min: 1, max: 36500, nullable: true } });
    await licenseAction(req, uuidParam(req.params.id), async (db, l) => {
      if (l.status === 'REVOKED') throw badRequest('Revoked licenses cannot be renewed');
      if (!l.activated_at) throw badRequest('License has not been activated yet');
      const expires = b.days ? `GREATEST(now(), COALESCE(expires_at, now())) + make_interval(days => ${Number(b.days)})` : 'NULL';
      await db.query(`UPDATE reading_licenses SET status='ACTIVE', status_reason=NULL, expires_at=${expires}, updated_at=now() WHERE id=$1`, [l.id]);
      await db.query(`UPDATE customers SET status='ACTIVE', updated_at=now() WHERE id=$1 AND status='EXPIRED'`, [l.customer_id]);
      await audit(db, req, 'license.renew', 'license', l.id, { days: b.days ?? 'unlimited' });
    });
    res.json({ ok: true });
  });

  r.patch('/licenses/:id', can('access.manage'), async (req, res) => {
    const b = validate(req.body, { maxDevices: { type: 'int', min: 1, max: 10, required: true } });
    await licenseAction(req, uuidParam(req.params.id), async (db, l) => {
      await db.query('UPDATE reading_licenses SET max_devices=$2, updated_at=now() WHERE id=$1', [l.id, b.maxDevices]);
      await audit(db, req, 'license.update', 'license', l.id, { maxDevices: b.maxDevices, previous: l.max_devices });
    });
    res.json({ ok: true });
  });

  // =========================================================================
  // Activity, security, audit
  // =========================================================================
  r.get('/reading-events', can('security.view'), async (req, res) => {
    const { limit, offset, page } = pageParams(req.query, { maxLimit: 200, defaultLimit: 50 });
    const vals = []; const where = [];
    if (req.query.type) { vals.push(String(req.query.type).slice(0, 60)); where.push(`e.event_type=$${vals.length}`); }
    if (req.query.customerId) { vals.push(uuidParam(req.query.customerId)); where.push(`e.customer_id=$${vals.length}`); }
    const w = where.length ? `WHERE ${where.join(' AND ')}` : '';
    const { rows } = await pool.query(
      `SELECT e.id, e.event_type, e.details, e.created_at, c.id AS customer_id, c.full_name, b.title AS book
         FROM reading_events e LEFT JOIN customers c ON c.id=e.customer_id LEFT JOIN books b ON b.id=e.book_id
         ${w} ORDER BY e.created_at DESC LIMIT ${limit} OFFSET ${offset}`, vals);
    res.json({ events: rows, page, limit });
  });

  r.get('/security-events', can('security.view'), async (req, res) => {
    const { limit, offset, page } = pageParams(req.query, { maxLimit: 200, defaultLimit: 50 });
    const where = []; const vals = [];
    if (req.query.open === 'true') where.push('s.resolved_at IS NULL');
    if (['LOW', 'MEDIUM', 'HIGH'].includes(req.query.severity)) { vals.push(req.query.severity); where.push(`s.severity=$${vals.length}`); }
    const w = where.length ? `WHERE ${where.join(' AND ')}` : '';
    const { rows } = await pool.query(
      `SELECT s.*, c.full_name, a.full_name AS resolved_by_name FROM security_events s
         LEFT JOIN customers c ON c.id=s.customer_id LEFT JOIN administrators a ON a.id=s.resolved_by
         ${w} ORDER BY s.created_at DESC LIMIT ${limit} OFFSET ${offset}`, vals);
    res.json({ events: rows, page, limit });
  });

  r.post('/security-events/:id/resolve', can('security.manage'), async (req, res) => {
    const id = Number.parseInt(req.params.id, 10);
    if (!Number.isInteger(id)) throw notFound();
    const b = validate(req.body, { resolution: { type: 'string', required: true, max: 500 } });
    await tx(pool, async (db) => {
      const { rowCount } = await db.query(
        `UPDATE security_events SET resolved_at=now(), resolved_by=$2, resolution=$3 WHERE id=$1 AND resolved_at IS NULL`, [id, req.admin.id, b.resolution]);
      if (!rowCount) throw badRequest('Event not found or already resolved');
      await audit(db, req, 'security_event.resolve', 'security_event', id, { resolution: b.resolution });
    });
    res.json({ ok: true });
  });

  r.get('/audit-logs', can('audit.view'), async (req, res) => {
    const { limit, offset, page } = pageParams(req.query, { maxLimit: 200, defaultLimit: 50 });
    const vals = []; const where = [];
    if (req.query.entityType) { vals.push(String(req.query.entityType).slice(0, 40)); where.push(`l.entity_type=$${vals.length}`); }
    if (req.query.action) { vals.push(like(req.query.action)); where.push(`l.action ILIKE $${vals.length}`); }
    const w = where.length ? `WHERE ${where.join(' AND ')}` : '';
    const { rows } = await pool.query(
      `SELECT l.*, a.full_name AS admin_name FROM audit_logs l LEFT JOIN administrators a ON a.id=l.admin_id
        ${w} ORDER BY l.created_at DESC LIMIT ${limit} OFFSET ${offset}`, vals);
    res.json({ logs: rows, page, limit });
  });

  // =========================================================================
  // Download page and WhatsApp settings
  // =========================================================================
  r.get('/website', can('content.manage'), async (req, res) => {
    res.json({ content: await settings.website() });
  });

  r.put('/website/:key', can('content.manage'), async (req, res) => {
    const key = req.params.key;
    if (!WEBSITE_KEYS.includes(key)) throw notFound();
    const v = req.body || {};
    const str = (x, max = 5000) => (typeof x === 'string' ? x.slice(0, max) : '');
    let value;
    if (key === 'site') {
      value = { featuredBookId: v.featuredBookId ? uuidParam(v.featuredBookId) : null };
    } else {
      const number = v.number ? normalizePhone(String(v.number), '') : '';
      if (v.number && !number) throw badRequest('Enter the WhatsApp number in international format, e.g. +254712345678');
      const invitationTemplate = str(v.invitationTemplate, 2000);
      if (!invitationTemplate.includes('{invitation_link}')) throw badRequest('The invitation message must contain {invitation_link}');
      value = { contactName: str(v.contactName, 120).trim(), number, orderMessage: str(v.orderMessage, 1000), invitationTemplate };
    }
    await tx(pool, async (db) => {
      await db.query(`INSERT INTO website_settings (key, value, updated_by) VALUES ($1,$2,$3)
                      ON CONFLICT (key) DO UPDATE SET value=$2, updated_by=$3, updated_at=now()`, [key, value, req.admin.id]);
      await audit(db, req, 'website.update', 'website_settings', key, value);
    });
    res.json({ ok: true, value });
  });

  // =========================================================================
  // System settings
  // =========================================================================
  r.get('/settings', can('settings.manage'), async (req, res) => {
    res.json({ settings: await settings.policy(), schema: Object.fromEntries(Object.entries(POLICY_SCHEMA).map(([k, v]) => [k, { type: v.type, min: v.min, max: v.max, enum: v.enum, nullable: v.nullable }])) });
  });

  r.put('/settings', can('settings.manage'), async (req, res) => {
    const partial = Object.fromEntries(Object.entries(POLICY_SCHEMA).map(([k, v]) => [k, { ...v, required: false }]));
    const input = req.body || {};
    const b = validate(input, partial);
    // validate() drops explicit nulls unless nullable; keep them for nullable keys.
    for (const k of Object.keys(input)) if (input[k] === null && POLICY_SCHEMA[k]?.nullable) b[k] = null;
    await tx(pool, async (db) => {
      for (const [k, v] of Object.entries(b)) {
        await db.query(`UPDATE system_settings SET value=$2, updated_by=$3, updated_at=now() WHERE key=$1`, [k, JSON.stringify(v), req.admin.id]);
      }
      await audit(db, req, 'settings.update', 'system_settings', null, b);
    });
    settings.invalidate();
    res.json({ settings: await settings.policy() });
  });

  // =========================================================================
  // Administrators
  // =========================================================================
  r.get('/administrators', can('admins.manage'), async (req, res) => {
    const { rows } = await pool.query(
      `SELECT a.id, a.email, a.full_name, a.status, a.mfa_enabled, a.last_login_at, a.created_at, r.name AS role
         FROM administrators a JOIN roles r ON r.id=a.role_id ORDER BY a.created_at`);
    const { rows: roles } = await pool.query('SELECT name, description FROM roles ORDER BY name');
    res.json({ administrators: rows, roles });
  });

  r.post('/administrators', can('admins.manage'), async (req, res) => {
    const b = validate(req.body, {
      email: { type: 'string', required: true, max: 200, pattern: /^[^\s@]+@[^\s@]+\.[^\s@]+$/ },
      fullName: { type: 'string', required: true, max: 200 },
      role: { type: 'string', required: true, enum: ['OWNER', 'MANAGER', 'SUPPORT'] },
      password: { type: 'string', required: true, trim: false },
    });
    validatePasswordStrength(b.password);
    const a = await tx(pool, async (db) => {
      const { rows: [row] } = await db.query(
        `INSERT INTO administrators (email, full_name, password_hash, role_id)
         VALUES ($1,$2,$3,(SELECT id FROM roles WHERE name=$4)) RETURNING id, email, full_name`,
        [b.email, b.fullName, await hashPassword(b.password), b.role]).catch((e) => {
        if (e.code === '23505') throw conflict('An administrator with this email already exists');
        throw e;
      });
      await audit(db, req, 'admin.create', 'administrator', row.id, { email: b.email, role: b.role });
      return row;
    });
    res.status(201).json({ administrator: a });
  });

  r.patch('/administrators/:id', can('admins.manage'), async (req, res) => {
    const id = uuidParam(req.params.id);
    const b = validate(req.body, { role: { type: 'string', enum: ['OWNER', 'MANAGER', 'SUPPORT'] }, status: { type: 'string', enum: ['ACTIVE', 'DISABLED'] } });
    if (id === req.admin.id) throw badRequest('You cannot change your own role or status');
    await tx(pool, async (db) => {
      const { rows: [a] } = await db.query('SELECT a.*, r.name AS role FROM administrators a JOIN roles r ON r.id=a.role_id WHERE a.id=$1 FOR UPDATE', [id]);
      if (!a) throw notFound();
      if (b.role) await db.query('UPDATE administrators SET role_id=(SELECT id FROM roles WHERE name=$2), updated_at=now() WHERE id=$1', [id, b.role]);
      if (b.status) await db.query('UPDATE administrators SET status=$2, updated_at=now() WHERE id=$1', [id, b.status]);
      const { rows: [{ owners }] } = await db.query(
        `SELECT count(*)::int AS owners FROM administrators a JOIN roles r ON r.id=a.role_id WHERE r.name='OWNER' AND a.status='ACTIVE'`);
      if (owners === 0) throw badRequest('At least one active owner is required');
      if (b.status === 'DISABLED' || b.role) await db.query('UPDATE admin_sessions SET revoked_at=now() WHERE admin_id=$1 AND revoked_at IS NULL', [id]);
      await audit(db, req, 'admin.update', 'administrator', id, b);
    });
    res.json({ ok: true });
  });

  r.get('/books-options', can('customers.view'), async (req, res) => {
    const { rows } = await pool.query('SELECT id, title, price_amount, currency FROM books ORDER BY title');
    res.json({ books: rows });
  });

  return r;
}

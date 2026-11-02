// Public cover images of published books (used by the download page and invitation page).
import express from 'express';
import { uuidParam, notFound } from '../lib/http.js';

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

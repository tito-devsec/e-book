// Per-buyer watermark burned into every PDF page image at delivery time.
//
// The page stored on the server is clean; each request produces an image that carries the
// author's name and number across the page, and a footer line with the buyer's name, a masked
// phone number and a trace code derived from their license, so a leaked page can be traced.
// Both are part of the pixels, so they cannot be removed by editing the web page or a CSS overlay.
import { createCanvas, loadImage } from '@napi-rs/canvas';
import { keyedHash } from '../lib/crypto.js';

const FONT = 'Arial, "Liberation Sans", "DejaVu Sans", Helvetica, sans-serif';

/** Short, stable code that identifies a license (shown in the dashboard to trace leaks). */
export function traceCode(pepper, licenseId) {
  return keyedHash(pepper, licenseId, 'watermark').slice(0, 8).toUpperCase();
}

export function maskedPhone(e164) {
  return `${e164.slice(0, 4)}•••${e164.slice(-3)}`;
}

/** +255746274010 -> "+255 746 274 010" (Tanzanian numbers); other numbers are shown as they are. */
export function formatPhone(e164) {
  const m = String(e164 || '').match(/^\+255(\d{3})(\d{3})(\d{3})$/);
  return m ? `+255 ${m[1]} ${m[2]} ${m[3]}` : String(e164 || '');
}

/**
 * @param {Buffer} png  clean page image
 * @param {{name: string, phone: string, code: string, date?: Date, owner?: {name: string, phone: string}, dark?: boolean}} who
 *   `owner` is the author's name and number, the only text in the tiled pattern;
 *   `dark` is for the front cover (light marks on a dark page).
 * @returns {Promise<Buffer>} watermarked WebP
 */
export async function watermarkPage(png, who) {
  const img = await loadImage(png);
  const w = img.width; const h = img.height;
  const canvas = createCanvas(w, h);
  const ctx = canvas.getContext('2d');
  ctx.drawImage(img, 0, 0, w, h);

  // The tiled watermark is the author's name and number only. The buyer's details are never part
  // of the pattern: they appear only in the footer line below.
  const ownerLabel = who.owner?.name ? [who.owner.name, who.owner.phone].filter(Boolean).join(' · ') : '';
  const dark = Boolean(who.dark);

  // 1. Diagonal tiled pattern across the whole page (faint, so the page stays readable).
  if (ownerLabel) {
    const size = Math.max(14, Math.round(w / 36));
    ctx.save();
    ctx.translate(w / 2, h / 2);
    ctx.rotate(-Math.PI / 6);
    ctx.font = `700 ${size}px ${FONT}`;
    ctx.fillStyle = dark ? 'rgba(255, 255, 255, 0.12)' : 'rgba(20, 24, 40, 0.10)';
    ctx.textAlign = 'center';
    ctx.textBaseline = 'middle';
    const diag = Math.hypot(w, h);
    const stepY = size * 4.6;
    const textW = ctx.measureText(ownerLabel).width + size * 3;
    let row = 0;
    for (let y = -diag / 2; y < diag / 2; y += stepY) {
      const offset = (row % 2) * (textW / 2);
      for (let x = -diag / 2 - offset; x < diag / 2 + textW; x += textW) ctx.fillText(ownerLabel, x, y);
      row += 1;
    }
    ctx.restore();
  }

  // 2. Footer line on every page.
  const fs = Math.max(11, Math.round(w / 78));
  const barH = Math.round(fs * 2.1);
  ctx.fillStyle = dark ? 'rgba(0, 0, 0, 0.62)' : 'rgba(255, 255, 255, 0.82)';
  ctx.fillRect(0, h - barH, w, barH);
  ctx.font = `500 ${fs}px ${FONT}`;
  ctx.fillStyle = dark ? 'rgba(255, 255, 255, 0.7)' : 'rgba(30, 34, 48, 0.72)';
  ctx.textAlign = 'center';
  ctx.textBaseline = 'middle';
  const date = (who.date || new Date()).toISOString().slice(0, 10);
  ctx.fillText(`Licensed to ${who.name} · ${who.phone} · Ref ${who.code} · ${date} · Personal copy, sharing prohibited`, w / 2, h - barH / 2);

  return canvas.encode('webp', 82);
}

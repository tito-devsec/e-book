// Per-buyer watermark burned into every PDF page image at delivery time.
//
// The page stored on the server is clean; each request produces an image that carries the
// buyer's name, a masked phone number and a trace code derived from their license. A leaked
// screenshot or photo of a page therefore identifies whose copy it came from. The watermark is
// part of the pixels, so it cannot be removed by editing the web page or blocking a CSS overlay.
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
 *   `owner` is the book owner's name and number, shown on every other row of the pattern;
 *   `dark` is for the front cover (light marks on a dark page).
 * @returns {Promise<Buffer>} watermarked WebP
 */
export async function watermarkPage(png, who) {
  const img = await loadImage(png);
  const w = img.width; const h = img.height;
  const canvas = createCanvas(w, h);
  const ctx = canvas.getContext('2d');
  ctx.drawImage(img, 0, 0, w, h);

  const buyerLabel = `${who.name} · ${who.phone} · ${who.code}`;
  const ownerLabel = who.owner?.name ? [who.owner.name, who.owner.phone].filter(Boolean).join(' · ') : '';
  const dark = Boolean(who.dark);

  // 1. Diagonal tiled pattern across the whole page (faint, so the page stays readable).
  //    Rows alternate: the owner's name and number, then this buyer's trace line.
  const size = Math.max(14, Math.round(w / 36));
  ctx.save();
  ctx.translate(w / 2, h / 2);
  ctx.rotate(-Math.PI / 6);
  ctx.textAlign = 'center';
  ctx.textBaseline = 'middle';
  const diag = Math.hypot(w, h);
  const stepY = size * 3.4;
  let row = 0;
  for (let y = -diag / 2; y < diag / 2; y += stepY) {
    const isOwner = ownerLabel && row % 2 === 0;
    const label = isOwner ? ownerLabel : buyerLabel;
    ctx.font = `${isOwner ? 700 : 600} ${size}px ${FONT}`;
    ctx.fillStyle = dark
      ? `rgba(255, 255, 255, ${isOwner ? 0.14 : 0.09})`
      : `rgba(20, 24, 40, ${isOwner ? 0.12 : 0.075})`;
    const textW = ctx.measureText(label).width + size * 3;
    const offset = (Math.floor(row / 2) % 2) * (textW / 2);
    for (let x = -diag / 2 - offset; x < diag / 2 + textW; x += textW) ctx.fillText(label, x, y);
    row += 1;
  }
  ctx.restore();

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

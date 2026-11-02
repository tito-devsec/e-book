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

/**
 * @param {Buffer} png  clean page image
 * @param {{name: string, phone: string, code: string, date?: Date}} who
 * @returns {Promise<Buffer>} watermarked WebP
 */
export async function watermarkPage(png, who) {
  const img = await loadImage(png);
  const w = img.width; const h = img.height;
  const canvas = createCanvas(w, h);
  const ctx = canvas.getContext('2d');
  ctx.drawImage(img, 0, 0, w, h);

  const label = `${who.name} · ${who.phone} · ${who.code}`;

  // 1. Diagonal tiled pattern across the whole page (faint, so the page stays readable).
  const size = Math.max(14, Math.round(w / 36));
  ctx.save();
  ctx.translate(w / 2, h / 2);
  ctx.rotate(-Math.PI / 6);
  ctx.font = `600 ${size}px ${FONT}`;
  ctx.fillStyle = 'rgba(20, 24, 40, 0.075)';
  ctx.textAlign = 'center';
  ctx.textBaseline = 'middle';
  const diag = Math.hypot(w, h);
  const stepY = size * 5.2;
  const textW = ctx.measureText(label).width + size * 3;
  let row = 0;
  for (let y = -diag / 2; y < diag / 2; y += stepY) {
    const offset = (row % 2) * (textW / 2);
    for (let x = -diag / 2 - offset; x < diag / 2 + textW; x += textW) ctx.fillText(label, x, y);
    row += 1;
  }
  ctx.restore();

  // 2. Footer line on every page.
  const fs = Math.max(11, Math.round(w / 78));
  const barH = Math.round(fs * 2.1);
  ctx.fillStyle = 'rgba(255, 255, 255, 0.82)';
  ctx.fillRect(0, h - barH, w, barH);
  ctx.font = `500 ${fs}px ${FONT}`;
  ctx.fillStyle = 'rgba(30, 34, 48, 0.72)';
  ctx.textAlign = 'center';
  ctx.textBaseline = 'middle';
  const date = (who.date || new Date()).toISOString().slice(0, 10);
  ctx.fillText(`Licensed to ${who.name} · ${who.phone} · Ref ${who.code} · ${date} · Personal copy, sharing prohibited`, w / 2, h - barH / 2);

  return canvas.encode('webp', 82);
}

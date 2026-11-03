// PDF page delivery: the stored page image is converted to WebP for the reader. Pages are sent
// clean, with no watermark.
import { createCanvas, loadImage } from '@napi-rs/canvas';

/** @param {Buffer} png  stored page image  @returns {Promise<Buffer>} WebP */
export async function toWebp(png) {
  const img = await loadImage(png);
  const canvas = createCanvas(img.width, img.height);
  canvas.getContext('2d').drawImage(img, 0, 0, img.width, img.height);
  return canvas.encode('webp', 86);
}

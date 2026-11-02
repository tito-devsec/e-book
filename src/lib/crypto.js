import crypto from 'node:crypto';
import { promisify } from 'node:util';

const scrypt = promisify(crypto.scrypt);

/** 256-bit URL-safe random token. */
export function randomToken(bytes = 32) {
  return crypto.randomBytes(bytes).toString('base64url');
}

/** Keyed hash for tokens, OTP codes, IPs. Pepper is server-side only. */
export function keyedHash(pepper, value, purpose) {
  return crypto.createHmac('sha256', pepper).update(`${purpose}:${value}`).digest('hex');
}

export function sha256Hex(buf) {
  return crypto.createHash('sha256').update(buf).digest('hex');
}

export function timingSafeEqualHex(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string' || a.length !== b.length) return false;
  return crypto.timingSafeEqual(Buffer.from(a, 'hex'), Buffer.from(b, 'hex'));
}

/** Numeric OTP with uniform distribution. */
export function randomOtp(digits = 6) {
  return String(crypto.randomInt(0, 10 ** digits)).padStart(digits, '0');
}

// ---------------------------------------------------------------------------
// Password hashing (scrypt, N=2^15, r=8, p=1, 64-byte key)
// ---------------------------------------------------------------------------
const SCRYPT = { N: 32768, r: 8, p: 1, maxmem: 64 * 1024 * 1024 };

export async function hashPassword(password) {
  const salt = crypto.randomBytes(16);
  const key = await scrypt(password, salt, 64, SCRYPT);
  return `scrypt$${SCRYPT.N}$${SCRYPT.r}$${SCRYPT.p}$${salt.toString('base64')}$${key.toString('base64')}`;
}

export async function verifyPassword(password, stored) {
  const parts = String(stored).split('$');
  if (parts.length !== 6 || parts[0] !== 'scrypt') return false;
  const [, N, r, p, saltB64, keyB64] = parts;
  const expected = Buffer.from(keyB64, 'base64');
  const key = await scrypt(password, Buffer.from(saltB64, 'base64'), expected.length, {
    N: Number(N), r: Number(r), p: Number(p), maxmem: 64 * 1024 * 1024,
  });
  return crypto.timingSafeEqual(key, expected);
}

// A fixed hash used to equalize timing when the account does not exist.
export const DUMMY_PASSWORD_HASH =
  'scrypt$32768$8$1$AAAAAAAAAAAAAAAAAAAAAA==$' + Buffer.alloc(64).toString('base64');

// ---------------------------------------------------------------------------
// AES-256-GCM authenticated encryption for content and small secrets
// ---------------------------------------------------------------------------
export function aesGcmEncrypt(key, plaintext, aad) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  if (aad) cipher.setAAD(Buffer.from(aad));
  const ct = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  // Layout: version(1) | iv(12) | tag(16) | ciphertext
  return Buffer.concat([Buffer.from([1]), iv, cipher.getAuthTag(), ct]);
}

export function aesGcmDecrypt(key, blob, aad) {
  if (blob[0] !== 1) throw new Error('Unknown ciphertext version');
  const iv = blob.subarray(1, 13);
  const tag = blob.subarray(13, 29);
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  if (aad) decipher.setAAD(Buffer.from(aad));
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(blob.subarray(29)), decipher.final()]);
}

// ---------------------------------------------------------------------------
// TOTP (RFC 6238) for administrator MFA
// ---------------------------------------------------------------------------
const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

export function base32Encode(buf) {
  let bits = 0, value = 0, out = '';
  for (const byte of buf) {
    value = (value << 8) | byte; bits += 8;
    while (bits >= 5) { out += B32[(value >>> (bits - 5)) & 31]; bits -= 5; }
  }
  if (bits > 0) out += B32[(value << (5 - bits)) & 31];
  return out;
}

export function base32Decode(str) {
  const clean = str.replace(/=+$/, '').toUpperCase().replace(/\s/g, '');
  let bits = 0, value = 0; const out = [];
  for (const ch of clean) {
    const idx = B32.indexOf(ch);
    if (idx < 0) throw new Error('Invalid base32');
    value = (value << 5) | idx; bits += 5;
    if (bits >= 8) { out.push((value >>> (bits - 8)) & 255); bits -= 8; }
  }
  return Buffer.from(out);
}

export function totpAt(secretB32, step) {
  const msg = Buffer.alloc(8);
  msg.writeBigUInt64BE(BigInt(step));
  const h = crypto.createHmac('sha1', base32Decode(secretB32)).update(msg).digest();
  const off = h[h.length - 1] & 0xf;
  const code = ((h.readUInt32BE(off) & 0x7fffffff) % 1_000_000);
  return String(code).padStart(6, '0');
}

/** Returns the matched time step, or null. Accepts +/-1 step of clock drift. */
export function verifyTotp(secretB32, code, now = Date.now()) {
  if (!/^\d{6}$/.test(String(code))) return null;
  const step = Math.floor(now / 30000);
  for (const s of [step, step - 1, step + 1]) {
    const expected = totpAt(secretB32, s);
    if (crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(String(code)))) return s;
  }
  return null;
}

// ---------------------------------------------------------------------------
// Device keys: ECDSA P-256 public keys registered by the browser (WebCrypto).
// ---------------------------------------------------------------------------
export function importDevicePublicKey(jwk) {
  if (!jwk || jwk.kty !== 'EC' || jwk.crv !== 'P-256' || typeof jwk.x !== 'string' || typeof jwk.y !== 'string' || jwk.d) {
    throw new Error('Invalid device public key');
  }
  return crypto.createPublicKey({ key: { kty: 'EC', crv: 'P-256', x: jwk.x, y: jwk.y }, format: 'jwk' });
}

/** RFC 7638 JWK thumbprint. */
export function jwkThumbprint(jwk) {
  const canonical = JSON.stringify({ crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y });
  return crypto.createHash('sha256').update(canonical).digest('base64url');
}

/** Verify a WebCrypto ECDSA P-256/SHA-256 signature (IEEE P1363 r||s encoding). */
export function verifyDeviceSignature(publicKey, message, signatureB64url) {
  try {
    const sig = Buffer.from(signatureB64url, 'base64url');
    if (sig.length !== 64) return false;
    return crypto.verify('sha256', Buffer.from(message), { key: publicKey, dsaEncoding: 'ieee-p1363' }, sig);
  } catch {
    return false;
  }
}

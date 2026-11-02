// HTTP helpers: typed errors, validation and async route wrapping.

export class HttpError extends Error {
  constructor(status, code, message, extra) {
    super(message || code);
    this.status = status;
    this.code = code;
    this.extra = extra;
  }
}

export const badRequest = (msg, code = 'BAD_REQUEST') => new HttpError(400, code, msg);
export const unauthorized = (code = 'UNAUTHORIZED', msg = 'Authentication required') => new HttpError(401, code, msg);
export const forbidden = (code = 'FORBIDDEN', msg = 'Access denied') => new HttpError(403, code, msg);
export const notFound = (msg = 'Not found') => new HttpError(404, 'NOT_FOUND', msg);
export const conflict = (msg, code = 'CONFLICT') => new HttpError(409, code, msg);
export const tooMany = (msg = 'Too many requests', code = 'RATE_LIMITED') => new HttpError(429, code, msg);

/** Wrap an async handler so rejections reach the error middleware (Express 5 also does this). */
export const ah = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);

// ---------------------------------------------------------------------------
// Minimal schema validation. Each field: { type, required, max, min, pattern, enum, trim }
// Unknown fields are dropped.
// ---------------------------------------------------------------------------
export function validate(input, schema) {
  const src = input && typeof input === 'object' ? input : {};
  const out = {};
  for (const [key, rule] of Object.entries(schema)) {
    let v = src[key];
    if (v === undefined || v === null || v === '') {
      if (rule.required) throw badRequest(`${key} is required`, 'VALIDATION');
      if (rule.default !== undefined) out[key] = rule.default;
      else if (v === null && rule.nullable) out[key] = null;
      continue;
    }
    switch (rule.type) {
      case 'string': {
        if (typeof v !== 'string') throw badRequest(`${key} must be text`, 'VALIDATION');
        if (rule.trim !== false) v = v.trim();
        if (rule.required && v === '') throw badRequest(`${key} is required`, 'VALIDATION');
        if (rule.max && v.length > rule.max) throw badRequest(`${key} is too long`, 'VALIDATION');
        if (rule.min && v.length < rule.min) throw badRequest(`${key} is too short`, 'VALIDATION');
        if (rule.pattern && !rule.pattern.test(v)) throw badRequest(`${key} is invalid`, 'VALIDATION');
        if (rule.enum && !rule.enum.includes(v)) throw badRequest(`${key} is invalid`, 'VALIDATION');
        break;
      }
      case 'int': {
        const n = typeof v === 'number' ? v : Number(v);
        if (!Number.isInteger(n)) throw badRequest(`${key} must be a whole number`, 'VALIDATION');
        if (rule.min !== undefined && n < rule.min) throw badRequest(`${key} is too small`, 'VALIDATION');
        if (rule.max !== undefined && n > rule.max) throw badRequest(`${key} is too large`, 'VALIDATION');
        v = n; break;
      }
      case 'money': {
        const s = String(v).trim();
        if (!/^\d{1,10}(\.\d{1,2})?$/.test(s)) throw badRequest(`${key} must be an amount like 1500 or 1500.00`, 'VALIDATION');
        v = s; break;
      }
      case 'bool':
        if (typeof v === 'string') v = ['true', '1', 'on', 'yes'].includes(v.toLowerCase());
        else v = Boolean(v);
        break;
      case 'uuid':
        if (typeof v !== 'string' || !UUID_RE.test(v)) throw badRequest(`${key} is invalid`, 'VALIDATION');
        break;
      case 'object':
        if (typeof v !== 'object' || Array.isArray(v)) throw badRequest(`${key} is invalid`, 'VALIDATION');
        break;
      case 'array':
        if (!Array.isArray(v)) throw badRequest(`${key} must be a list`, 'VALIDATION');
        if (rule.max && v.length > rule.max) throw badRequest(`${key} has too many items`, 'VALIDATION');
        break;
      case 'any':
        break;
      default:
        throw new Error(`Unknown rule type ${rule.type}`);
    }
    out[key] = v;
  }
  return out;
}

export const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export function uuidParam(v) {
  if (typeof v !== 'string' || !UUID_RE.test(v)) throw notFound();
  return v;
}

/** Normalize a phone number to E.164. Accepts +<digits> or local digits with a default country code. */
export function normalizePhone(raw, defaultCountryCode = '') {
  if (typeof raw !== 'string') return null;
  let s = raw.replace(/[\s().-]/g, '');
  if (s.startsWith('00')) s = '+' + s.slice(2);
  if (!s.startsWith('+')) {
    if (!defaultCountryCode) return null;
    s = '+' + defaultCountryCode + s.replace(/^0+/, '');
  }
  return /^\+[1-9]\d{7,14}$/.test(s) ? s : null;
}

export function maskPhone(e164) {
  if (!e164) return '';
  return e164.slice(0, 4) + ' ••• ••' + e164.slice(-3);
}

export function pageParams(query, { maxLimit = 100, defaultLimit = 25 } = {}) {
  const limit = Math.min(maxLimit, Math.max(1, Number.parseInt(query.limit, 10) || defaultLimit));
  const page = Math.max(1, Number.parseInt(query.page, 10) || 1);
  return { limit, offset: (page - 1) * limit, page };
}

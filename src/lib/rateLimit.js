// Fixed-window in-memory rate limiter keyed by an arbitrary string.
// Per-instance: when running multiple instances, the per-customer OTP limits that matter for
// security are additionally enforced in the database (otp_challenges counts).
import { tooMany } from './http.js';

export function createRateLimiter() {
  const buckets = new Map();
  setInterval(() => {
    const now = Date.now();
    for (const [k, b] of buckets) if (b.reset < now) buckets.delete(k);
  }, 60000).unref();

  function hit(key, limit, windowMs) {
    const now = Date.now();
    let b = buckets.get(key);
    if (!b || b.reset < now) { b = { count: 0, reset: now + windowMs }; buckets.set(key, b); }
    b.count += 1;
    return { allowed: b.count <= limit, count: b.count, retryAfter: Math.ceil((b.reset - now) / 1000) };
  }

  /** Express middleware limiting by client IP and route group. */
  function middleware(group, limit, windowMs) {
    return (req, res, next) => {
      const r = hit(`${group}:${req.ip}`, limit, windowMs);
      if (!r.allowed) {
        res.set('Retry-After', String(r.retryAfter));
        return next(tooMany());
      }
      next();
    };
  }

  return { hit, middleware, reset: () => buckets.clear() };
}

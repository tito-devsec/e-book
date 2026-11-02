// Structured JSON logger with redaction of secrets (invitation tokens, cookies, OTP codes).
const LEVELS = { debug: 10, info: 20, warn: 30, error: 40 };

export function redactPath(path) {
  // Never log full invitation tokens.
  return String(path).replace(/(\/access\/)([A-Za-z0-9_-]{6})[A-Za-z0-9_-]*/g, '$1$2…');
}

const SENSITIVE_KEYS = /token|password|code|otp|cookie|authorization|secret|signature|key/i;

function redact(value, depth = 0) {
  if (value === null || typeof value !== 'object' || depth > 4) return value;
  if (value instanceof Error) return { name: value.name, message: value.message, stack: value.stack };
  const out = Array.isArray(value) ? [] : {};
  for (const [k, v] of Object.entries(value)) {
    out[k] = SENSITIVE_KEYS.test(k) && typeof v === 'string' ? '[redacted]' : redact(v, depth + 1);
  }
  return out;
}

export function createLogger(level = 'info', sink = process.stdout) {
  const min = LEVELS[level] ?? 20;
  const write = (lvl, msg, fields) => {
    if (LEVELS[lvl] < min) return;
    sink.write(JSON.stringify({ t: new Date().toISOString(), level: lvl, msg, ...redact(fields || {}) }) + '\n');
  };
  return {
    debug: (m, f) => write('debug', m, f),
    info: (m, f) => write('info', m, f),
    warn: (m, f) => write('warn', m, f),
    error: (m, f) => write('error', m, f),
  };
}

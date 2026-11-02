# Security

## Reporting a vulnerability

Please report security issues privately to the repository owner (tito-devsec) through GitHub's
private vulnerability reporting ("Security" tab, "Report a vulnerability"). Do not open public
issues for vulnerabilities. Include steps to reproduce and the impact you observed. You will get
an acknowledgement within 5 working days.

## Supported versions

Only the latest release on `main` receives security fixes.

## Controls in place

| Area | Control |
|---|---|
| Transport | HTTPS required in production (`COOKIE_SECURE`, HSTS) |
| Admin auth | scrypt password hashing, lockout after 5 failures, optional/mandatory TOTP MFA, session rotation, idle timeout, RBAC (Owner/Manager/Support) |
| Customer auth | WhatsApp OTP to the stored number only, 6 digits, expiry, attempt limit, hourly cap, resend cooldown |
| Invitations | 256-bit random tokens, stored as keyed hashes, single use, expiring, revocable, reissue invalidates the old link |
| Devices | Non-extractable ECDSA P-256 key per browser; every reader request signed (method, URL, timestamp, nonce, body hash); replay protection |
| Content | Originals encrypted at rest (AES-256-GCM, per-edition data key wrapped by KMS); PDFs rendered to images server-side and never sent as PDF; each PDF page watermarked per buyer with a traceable ref; served one sanitized chapter or page at a time after session, device and license checks; `no-store` |
| Web | Strict CSP (no inline script), `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, `nosniff`, SameSite=Strict HttpOnly cookies, CSRF tokens, origin checks, JSON-only state changes |
| Input | Schema validation, parameterized SQL, HTML sanitization of book content, magic-byte file validation, upload size limits, optional ClamAV scanning, zip-bomb limits |
| Abuse | Per-IP rate limits, per-customer OTP limits, per-session content rate limit with alerts |
| Audit | Append-only audit log (database trigger), security events, reading events |

Details and the threat model: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).
Known limits of browser-based protection: [docs/SECURITY_LIMITATIONS.md](docs/SECURITY_LIMITATIONS.md).

## Operational checklist

- Set `REQUIRE_ADMIN_MFA=true`.
- Keep `HASH_PEPPER`, `LOCAL_MASTER_KEY` and WhatsApp tokens in a secret manager. Rotating
  `HASH_PEPPER` invalidates all sessions and pending invitations.
- Use `KMS_PROVIDER=aws` and a private S3 bucket with Block Public Access in production.
- Run `npm run audit` regularly (CI does this on every push).
- Review **Security Events** in the dashboard weekly.

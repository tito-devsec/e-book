# Architecture

## Components

```
                 ┌──────────────── one Node.js service (Express 5) ────────────────┐
 admin.*     ───▶│ /admin SPA       + /api/admin/*   (admin session, RBAC, CSRF)    │
 books.*     ───▶│ contact page + reader PWA, /api/public/contact, /api/access/*,  │
                 │                    /api/auth/*  (link claim, session), covers    │
                 │                  + /api/reader/*  (session + device signature)   │
                 └───────┬───────────────────────┬────────────────────┬────────────┘
                         │                       │                    │
                    PostgreSQL            Private storage         KMS (AWS KMS or
                 (all state, audit)    (S3 bucket or local dir)   local master key)
                                                                       │
```

- **Host gating** (`src/app.js`): when `ADMIN_BASE_URL` / `READER_BASE_URL` name different hosts,
  each app is served only on its host. Cookies are host-only, so an admin cookie never reaches the
  reader host and vice versa. With one host, everything is path-based.
- **No build step.** Browser code is plain ES modules served from `public/`.

## Source layout

| Path | Responsibility |
|---|---|
| `src/config.js` | Environment parsing and startup validation (refuses unsafe production config) |
| `src/app.js` | Wiring, security headers, host gating, static files, error handling |
| `src/middleware.js` | Cookies, CSP, origin check, admin auth + RBAC + CSRF, reader session + device signature + replay + rate limit |
| `src/services/access.js` | Private links, claim tokens, activation, device registration, sessions, license checks |
| `src/services/ingest.js` | Upload validation, EPUB parsing + sanitization, PDF rendering, encryption, asset reads |
| `src/services/kms.js` | Envelope encryption (AWS KMS or local KEK) |
| `src/services/storage.js` | Private storage (S3 or local) |
| `src/services/malwareScan.js` | ClamAV INSTREAM client |
| `src/services/events.js` | Audit, security and reading events |
| `src/routes/*.js` | HTTP routes |

## Key flows

### Payment → license → invitation

1. `POST /api/admin/orders` creates the customer (or reuses one with the same phone), order,
   order items and a `PENDING` payment.
2. `POST /api/admin/orders/:id/verify-payment` runs **one transaction**: lock order, mark the
   payment `VERIFIED` (a partial unique index stops one payment reference verifying two orders),
   mark the order `PAID`, create one `reading_licenses` row per book (`PENDING_ACTIVATION`).
3. `POST /api/admin/invitations` requires a `PENDING_ACTIVATION` license on a `PAID` order.
   It generates 32 random bytes (256 bits), stores `HMAC-SHA256(pepper, token)` and a 6-character
   hint, replaces any earlier pending invitation, and returns the link once.

### Private link → app (no codes)

The private link is the proof of purchase. `/access/<token>` moves the token out of the address
bar, validates it (`POST /api/access/validate-invitation`) and asks for a one-time **claim token**
(`POST /api/access/prepare-app`). The page points its manifest at
`/manifest.webmanifest?claim=…`, so the app added from this page starts at `/app?claim=…`.
Opening or refreshing the link page does not use up the link. Android and computers see the
download page with an **Add to your device** button; iPhones see the Add to Home Screen steps.

The first time the added app opens, `POST /api/access/claim` runs one transaction with row locks:
invitation `PENDING → CONSUMED`, claim used, license `→ ACTIVE`, device registered and marked as
having the app, older devices beyond `max_devices` revoked (a new link from the owner is their
approval to move the book), session created. This works the same on iPhone, where the home-screen
app has storage separate from Safari. Sessions renew themselves while in use.

### Device identity

At activation or sign-in the browser generates a **non-extractable** ECDSA P-256 key with
WebCrypto and stores the `CryptoKey` in IndexedDB. Only the public JWK goes to the server.
Every `/api/reader/*` request carries `x-sig-ts`, `x-sig-nonce`, `x-sig`: a signature over
`METHOD \n URL \n timestamp \n nonce \n sha256(body)`. The server checks the timestamp window
(±2 min), the signature against the session's device key, and inserts the nonce into
`request_nonces` (primary key) to reject replays.

This is an additional authorization signal. A stolen session cookie alone cannot read content,
but a fully compromised browser profile can still use its own key. It is not equivalent to a
hardware-backed key (Android Keystore / Secure Enclave). See SECURITY_LIMITATIONS.md.

### Devices per license

`device_authorizations` links devices to licenses. `max_devices` (default 1) caps active
authorizations per license. Moving to a new phone is done by the owner: a new link for the same
license, claimed on the new phone, revokes the least recently used older device and ends its
sessions (`device_replacements.mode = OWNER_LINK`).

### Protected content pipeline

1. Upload → magic-byte check (EPUB = zip with `mimetype` entry; PDF = `%PDF-`), size limit,
   optional ClamAV scan.
2. A per-edition 256-bit data key is generated by the KMS (`GenerateDataKey`) and stored only
   wrapped (`book_editions.wrapped_key`).
3. The original is encrypted with AES-256-GCM (AAD = edition id) into private storage.
4. EPUB: spine chapters are sanitized (allow-list of tags/attributes, scripts, handlers, iframes,
   forms, styles and non-https links removed; internal links and images rewritten to opaque asset
   ids) and each chapter/image is encrypted separately. PDF: pdf.js renders every page to a PNG
   **in memory** (the original is never written to disk unencrypted; eval, scripting and XFA are
   disabled), extracts each page's text for server-side search, reads the PDF outline for the
   table of contents, and encrypts each page image and text separately.
5. `GET /api/reader/books/:id/content/:resourceId` checks session → device → signature → nonce →
   rate limit → license (customer + book + device authorization + paid order + not expired) and
   returns one decrypted chapter or page with `Cache-Control: no-store` and a sandbox CSP.
   PDF pages are re-encoded as WebP per request (`src/services/watermark.js`) and sent clean: no
   watermark is applied, by the owner's choice. Page text is never served, only searched.
   The reader decodes pages into `ImageBitmap`s drawn on `<canvas>` (no image URL to save).
6. The reader keeps at most a few chapters in memory, never in Cache Storage, localStorage or
   IndexedDB.

Editions belong to the book, licenses to the book, so replacing an edition never changes who can
read.

### Sessions

Opaque 256-bit tokens in `HttpOnly; Secure; SameSite=Strict` cookies, stored hashed. Customer
sessions: absolute TTL (`session_ttl_hours`) and idle timeout, one per device (rotated on sign-in).
Admin sessions: 12 h absolute, 60 min idle, rotated after MFA, revoked on password change, role
change or disable. Every request re-checks device status, customer status and license status in
the database, so revocation takes effect on the next request.

## Threat model

| Threat | Mitigation | Residual risk |
|---|---|---|
| Link forwarded before the book is added | Whoever adds the book first with the link gets it; the link is then used up. The owner sees the device and can revoke it and send a new link | If the buyer forwards both the link and the code, the recipient can activate. That is the buyer giving their purchase away. |
| Invitation reused after activation | `CONSUMED` state; shows "already activated" without customer data; security event | none |
| Token leakage via logs/referrer/history | Tokens hashed in DB; logs redact `/access/` paths; `Referrer-Policy: no-referrer`; token removed from URL bar; no third-party resources | Token visible in the WhatsApp chat itself until the book is added |
| Guessing links | 256-bit tokens; per-IP rate limits on link pages | Infeasible |
| Account enumeration via sign-in | Identical responses for unknown numbers | Timing differences are small but non-zero |
| Reader URL shared | Shell contains no content; APIs require session + device signature + license → 401/404 | none |
| Session cookie theft | HttpOnly cookie is useless without the device private key (non-extractable) | Malware on the device itself |
| Replay of captured requests | Timestamp window + unique nonce per device | none within design |
| Account sharing (giving someone your phone) | One device per license, replacement limits, alerts on multiple sessions and new devices, owner can revoke | A buyer can always show their own screen to someone |
| Bulk scraping by a legitimate buyer | Per-session rate limit with alert; one chapter per request | A determined buyer can copy text they can see (see SECURITY_LIMITATIONS.md) |
| Malicious upload (XSS, zip bomb, malware) | Admin-only; magic bytes; entry count/size limits; path traversal check; sanitization; ClamAV; sandbox CSP on content | Zero-day in parser libraries |
| SQL injection | Parameterized queries only | none known |
| XSS | Strict CSP without inline scripts; `textContent` everywhere; sanitized chapters | none known |
| CSRF | SameSite=Strict, CSRF token, Origin check, JSON-only bodies | none known |
| Admin account takeover | scrypt, lockout, TOTP MFA (can be mandatory), short idle timeout, audit | Phishing of both password and code |
| Insider misuse | RBAC; append-only audit log | Owners can do anything by design |
| Storage leak | Originals and assets encrypted; key wrapped by KMS; bucket private | Attacker with both DB and KMS access |

## Decisions

- **Custom reader instead of EPUB.js / Readium in the browser.** Both libraries expect the browser
  to fetch the full EPUB container or unpacked resources by URL, which undercuts "one authorized
  chapter per request" and makes signing every request awkward. Parsing on the server lets us
  sanitize once, encrypt per chapter, and render with CSS columns plus the page-flip effect.
  Trade-off: complex EPUB CSS and fixed-layout EPUBs are not reproduced; the reader applies its
  own typography. Fixed-layout books should be uploaded as PDF.
- **PDF as page images.** Avoids shipping the PDF to the browser. Trade-off: no text selection or
  search for PDF editions, and dark mode inverts the image.
- **Encryption.** AES-256-GCM with per-edition data keys from AWS KMS (envelope encryption), a
  standard reviewed construction. No custom cryptographic protocol. Content travels to the browser
  over TLS and is not re-encrypted for the client: client-side decryption keys would be visible to
  the same user anyway (see SECURITY_LIMITATIONS.md).
- **No WhatsApp codes.** The owner verifies each payment and sends a private link; the link is the
  proof of purchase. This removes the WhatsApp Business API dependency entirely.

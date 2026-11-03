# API reference

All endpoints are under `/api`, accept and return JSON (uploads use `multipart/form-data`),
and are never cached. Errors have the shape:

```json
{ "code": "CLAIM_INVALID", "message": "This link has already been used or is no longer valid." }
```

| Status | Meaning |
|---|---|
| 400 | Validation or business-rule failure (`code` explains) |
| 401 | Not signed in, session expired, or request signature invalid |
| 403 | Signed in but not allowed (`PERMISSION_DENIED`, `CSRF`, `DEVICE_REVOKED`, `ACCOUNT_SUSPENDED`, `BAD_ORIGIN`) |
| 404 | Not found, or not yours (the API does not reveal which) |
| 409 | Conflict (`DEVICE_LIMIT`, duplicate reference, `NOT_READY`) |
| 413 / 415 | Too large / not JSON |
| 429 | Rate limited (`Retry-After` header) |

State-changing requests must send `Content-Type: application/json` (or multipart) and, when a
session exists, `X-CSRF-Token`. Cross-origin requests are rejected.

## Public (customer site)

| Method & path | Result |
|---|---|
| `GET /public/contact` | Contact name, WhatsApp chat link and sign-in mode for visitors without a private link (no book information) |

## Customer access (reader host)

| Method & path | Body | Result |
|---|---|---|
| `POST /access/validate-invitation` | `{token}` | `{state: VALID\|CONSUMED\|EXPIRED\|REVOKED\|INVALID, book?, expiresAt?}`. Does not use up the link |
| `POST /access/prepare-app` | `{token}` | `{claim}`: one-time token for the app's start address (`/manifest.webmanifest?claim=…`). Each call replaces the previous claim |
| `POST /access/claim` | `{claim, deviceKey}` | First open of the added app: uses up the link, registers the device (marked as having the app), sets the session cookie. `{ok, bookId, csrf}` |
| `GET /auth/session` | — | `{authenticated, csrf, customer, books[]}` or 401/403 with `code` |
| `POST /auth/logout` | — | Ends session, clears cookie, `Clear-Site-Data` |
| `POST /access/validate-license` | `{bookId}` | `{valid, expiresAt}` (session required) |

`deviceKey` is a public EC P-256 JWK: `{kty:"EC", crv:"P-256", x, y}`.

## Reader (session + signed requests)

Every request needs the session cookie and these headers:

| Header | Value |
|---|---|
| `x-sig-ts` | Milliseconds since epoch (must be within ±120 s) |
| `x-sig-nonce` | 16–64 URL-safe random characters, never reused |
| `x-sig` | base64url ECDSA P-256 SHA-256 signature (64-byte r‖s) over `METHOD\nURL\nts\nnonce\nsha256hex(body)` |

`URL` is the path plus query string exactly as sent.

| Method & path | Notes |
|---|---|
| `GET /reader/library` | Books this device may read, with progress |
| `GET /reader/books/:bookId` | Book details, access and preparation status |
| `GET /reader/books/:bookId/cover` | Cover image |
| `GET /reader/books/:bookId/manifest` | `{format, edition, toc[], items[{id,index,title}]}` |
| `GET /reader/books/:bookId/content/:resourceId` | One sanitized chapter (`text/html`), an EPUB image, or a PDF page as `image/webp` (no watermark) |
| `GET /reader/books/:bookId/search?q=` | `{results:[{index, chapter, snippet, offset}], supported}` (EPUB chapters and PDF page text) |
| `GET /reader/progress/:bookId` | `{progress: {location, percent, updatedAt} \| null}` |
| `POST /reader/progress` | `{bookId, location:{index, page}, percent}` |
| `GET /reader/bookmarks/:bookId` | `{bookmarks[]}` |
| `POST /reader/bookmarks` | `{bookId, location, label}` |
| `DELETE /reader/bookmarks/:id` | — |

## Admin authentication (admin host)

| Method & path | Body | Notes |
|---|---|---|
| `POST /admin/auth/login` | `{email, password}` | `{mfaRequired, csrf}` |
| `POST /admin/auth/mfa` | `{code}` | Completes sign-in when MFA is on |
| `GET /admin/auth/session` | — | `{authenticated, csrf, admin{permissions,…}}` |
| `POST /admin/auth/logout` | — | |
| `POST /admin/auth/mfa/setup` | — | `{secret, uri}` |
| `POST /admin/auth/mfa/enable` | `{code}` | |
| `POST /admin/auth/password` | `{current, next}` | Signs out other sessions |

## Admin API

Permission in brackets. All changes are written to the audit log.

**Overview** — `GET /admin/overview` [dashboard.view]

**Books** [books.manage]
- `GET /admin/books`, `POST /admin/books` `{title, author, priceAmount, currency, subtitle?, description?, availability?, preferredFormat?, maxDevices?, licenseDurationDays?}`
- `GET /admin/books/:id` (with editions), `PATCH /admin/books/:id`
- `POST /admin/books/:id/cover` (multipart `file`: PNG/JPEG/WebP)
- `POST /admin/books/:id/upload` (multipart `file`: EPUB/PDF, `label?`, `makeCurrent?`)
- `POST /admin/books/:id/editions/:editionId/activate`, `.../archive`
- `POST /admin/books/:id/publish`, `POST /admin/books/:id/unpublish`

**Customers** — `GET /admin/customers?q=&status=&sort=name|created|status&dir=&page=&limit=` [customers.view], `GET /admin/customers/:id` [customers.view], `PATCH /admin/customers/:id` [customers.manage], `POST /admin/customers/:id/suspend|reactivate|revoke-access|revoke-sessions` [access.manage]

**Orders and payments**
- `POST /admin/orders` [customers.manage] `{customerId? | fullName+phone, email?, bookIds[], reference?, amount, currency?, paymentMethod, paymentReference?, paymentStatus?: PENDING|VERIFIED, notes?}` (`VERIFIED` also needs payments.verify)
- `GET /admin/orders?status=&q=&page=`, `GET /admin/orders/:id` (with payments, licenses, audit trail) [customers.view]
- `POST /admin/orders/:id/verify-payment` `{reference?}`, `POST /admin/orders/:id/reject-payment` `{reason}` [payments.verify]

**Invitations** — `GET /admin/invitations?status=` [customers.view]; `POST /admin/invitations` `{licenseId, expiryHours?}` → `{invitation, link, message, whatsappUrl}`; `POST /admin/invitations/:id/revoke`; `POST /admin/invitations/:id/resend` `{expiryHours?}` (reissue with a new token) [invitations.manage]

**Devices** — `GET /admin/devices?status=&customerId=` [customers.view]; `POST /admin/devices/:id/revoke` `{reason?}` [access.manage]; `GET /admin/device-replacements`; `POST /admin/device-replacements/:id/approve` `{transitionHours}`; `POST /admin/device-replacements/:id/reject` [access.manage]

**Licenses** — `GET /admin/licenses?status=&customerId=` [customers.view]; `POST /admin/licenses/:id/suspend|reactivate|revoke`; `POST /admin/licenses/:id/renew` `{days|null}`; `PATCH /admin/licenses/:id` `{maxDevices}` [access.manage]

**Monitoring** — `GET /admin/reading-events?type=&customerId=`, `GET /admin/security-events?open=true&severity=` [security.view]; `POST /admin/security-events/:id/resolve` `{resolution}` [security.manage]; `GET /admin/audit-logs?action=&entityType=` [audit.view]

**Download page & WhatsApp** [content.manage] — `GET /admin/website`; `PUT /admin/website/site` `{featuredBookId}`; `PUT /admin/website/whatsapp` `{number, orderMessage, invitationTemplate}`

**Settings** [settings.manage] — `GET /admin/settings`, `PUT /admin/settings` (any subset of policy keys)

**Administrators** [admins.manage] — `GET /admin/administrators`, `POST /admin/administrators` `{email, fullName, role, password}`, `PATCH /admin/administrators/:id` `{role?, status?}`

## Mapping to the original route contract

| Requested | Implemented as |
|---|---|
| `POST /api/access/activate`, `register-device` | `POST /api/access/claim`: the device is registered when the added app first opens with its claim token. There are no WhatsApp codes |
| `POST /api/admin/invitations/:id/resend` | Reissue: generates a new token and invalidates the old one (old tokens cannot be recovered because only hashes are stored) |
| `POST /api/admin/devices/:id/revoke` etc. | As specified, plus device-replacement approval endpoints |

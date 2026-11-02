# Database schema

PostgreSQL 14+. Defined in `migrations/001_initial_schema.sql`; applied by `npm run migrate`,
which records applied files in `schema_migrations` and holds an advisory lock so concurrent
deploys don't race. UUID primary keys (`gen_random_uuid()`), `timestamptz` everywhere, money as
`numeric(12,2)`.

## Entity overview

```
roles ─< role_permissions >─ permissions
roles ─< administrators ─< admin_sessions

books ─< book_editions ─< book_assets           books.current_edition_id → book_editions
customers ─< orders ─< order_items >─ books
                orders ─< payments
orders ─< reading_licenses >─ books, customers   (one per order × book)
reading_licenses ─< invitations
customers ─< otp_challenges
customers ─< registered_devices ─< device_authorizations >─ reading_licenses
customers ─< device_replacements, pending_device_grants
registered_devices ─< reading_sessions, request_nonces
customers ─< reading_progress, bookmarks, reading_events, security_events
audit_logs, website_settings, testimonials, system_settings
```

## Tables

| Table | Purpose and key rules |
|---|---|
| `roles`, `permissions`, `role_permissions` | RBAC. Seeded roles: OWNER (all), MANAGER (no admin/settings management), SUPPORT (read-only views) |
| `administrators` | Email (case-insensitive unique), scrypt hash, role, status, encrypted TOTP secret, lockout counters |
| `admin_sessions` | Hashed token, CSRF token, `mfa_pending`, expiry, revocation |
| `books` | Title, author, price, currency, availability, published flag, private cover key, current edition, default `max_devices` and license duration |
| `book_editions` | Versioned uploads: format, status (PROCESSING/READY/FAILED/ARCHIVED), encrypted original location, SHA-256, size, **wrapped data key**, TOC |
| `book_assets` | Individually encrypted chapters, page images and images with opaque ids |
| `customers` | Name, **unique E.164 WhatsApp number**, optional email, status (PENDING_PAYMENT, PAID, INVITED, ACTIVATED, ACTIVE, SUSPENDED, REVOKED, EXPIRED), notes |
| `orders`, `order_items` | Unique reference; status PENDING_PAYMENT/PAID/REJECTED/CANCELLED; one or more books |
| `payments` | Amount, method, reference, status PENDING/VERIFIED/REJECTED, verifier, reason. **Partial unique index**: a `(method, reference)` can verify only one payment |
| `reading_licenses` | The entitlement: customer × book × order, status PENDING_ACTIVATION/ACTIVE/SUSPENDED/REVOKED/EXPIRED, `max_devices`, `duration_days`, `expires_at`. Unique `(order_id, book_id)` |
| `invitations` | Tied to license, customer, book, order and phone. Token stored as keyed hash (unique) + 6-char hint. **Partial unique indexes**: one PENDING and one CONSUMED per license |
| `otp_challenges` | Hashed code (bound to challenge id), purpose, attempts/max, expiry, consumed time |
| `registered_devices` | Public key JWK + RFC 7638 thumbprint (unique per customer while active), display-only browser/OS/category, status, replacement link, `transition_until` |
| `device_authorizations` | Device ↔ license, ACTIVE/REVOKED |
| `device_replacements` | History: old → new device, SELF_SERVICE / PENDING / ADMIN_APPROVED / ADMIN_REJECTED |
| `pending_device_grants` | 15-minute grants created after OTP when a new device needs a slot |
| `reading_sessions` | Hashed token, device, CSRF token, expiry, last seen, end reason |
| `request_nonces` | Replay protection for signed requests (primary key device + nonce), swept after 5 min |
| `reading_progress`, `bookmarks` | Per customer and book |
| `reading_events` | INVITATION_OPENED, OTP_REQUESTED, OTP_VERIFIED, DEVICE_REGISTERED, LICENSE_ACTIVATED, READER_OPENED, CHAPTER_ACCESSED, READING_SESSION_ENDED, ACCESS_DENIED, SESSION_EXPIRED, DEVICE_REPLACED, ACCOUNT_SUSPENDED, LICENSE_REVOKED |
| `security_events` | Typed alerts with severity, hashed IP, resolution |
| `audit_logs` | Every admin action. **Append-only**: a trigger rejects UPDATE and DELETE |
| `website_settings` | JSON content blocks for the marketing site and WhatsApp templates |
| `testimonials` | Quotes shown on the site |
| `system_settings` | Access policy values (see Admin manual → System Settings) |

## Transactions

Payment verification, invitation creation, activation, sign-in, device replacement, approvals and
every admin change run in a single transaction with `SELECT … FOR UPDATE` on the rows they change.

## Privacy

The database stores no OTP codes, invitation tokens or session tokens in clear. IP addresses are
stored only as keyed hashes in event tables. Reading events record access, not reading behaviour
beyond chapter opens.

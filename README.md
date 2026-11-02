# Private Book Distribution Platform

Sell a digital book, verify payments by hand, and give each paying customer private reading
access in an installable web app, without ever handing out a PDF or EPUB file.

The platform has four parts in one Node.js service:

| Part | Default path | Purpose |
|---|---|---|
| Marketing website | `/` | Sales page with WhatsApp ordering, edited from the dashboard |
| Management dashboard | `/admin` | Books, customers, orders, payment verification, invitations, devices, licenses, monitoring |
| Reader PWA | `/app`, `/access/<token>`, `/read/<id>` | Invitation activation, OTP sign-in, installable reader with page-flip |
| API | `/api/...` | Authenticated, validated JSON API ([docs/API.md](docs/API.md)) |

Each part can run on its own domain (`example.com`, `admin.example.com`, `reader.example.com`)
or together on one domain.

## How it works

1. A customer finds the book on the website and orders on WhatsApp.
2. The customer pays (for example M-PESA or a bank transfer).
3. The owner registers the order in the dashboard and verifies the payment reference.
4. The owner clicks **Generate Access Link** and sends the private link on WhatsApp.
5. The customer opens the link and confirms their WhatsApp number with a one-time code.
6. The invitation is consumed, this browser is registered, and the book page opens.
7. **DOWNLOAD BOOK** installs the reader app; **START READING** opens the book (offering installation first).
8. The installed app opens straight to the book. The original file never leaves private storage.

Sharing the invitation or a reader URL does not give anyone else access: activation needs a code
sent to the buyer's own number, and every content request must come from a registered device with
an active license. See [docs/SECURITY_LIMITATIONS.md](docs/SECURITY_LIMITATIONS.md) for what
browser-based protection can and cannot do.

## Requirements

- Node.js 22.9 or newer
- PostgreSQL 14 or newer
- `pdftoppm` (poppler-utils) for PDF editions
- For production: HTTPS reverse proxy, WhatsApp Business Cloud API, AWS KMS + S3 (or the local alternatives), optionally ClamAV

## Quick start (development)

Install Node.js 22.9+ and PostgreSQL (on Windows, use the installer from postgresql.org and note
the password you choose for the `postgres` user). Then, in the project folder:

```bash
npm install
npm run setup -- --db-password YOUR_POSTGRES_PASSWORD
npm run migrate
npm run seed:dev
npm run dev
```

`npm run setup` writes a development `.env` with random local secrets and creates the database.
`npm run seed:dev` adds a sample book and the owner account `owner@example.com` /
`change-me-please-123`. Verification codes are printed in the terminal running `npm run dev`.

Open http://localhost:3000 (website) and http://localhost:3000/admin (dashboard).
PDF uploads need `pdftoppm` (poppler) on the PATH; EPUB works without it.

## Production

```bash
npm ci --omit=dev
npm run migrate
npm run admin:create -- --email you@example.com --name "Your Name"
npm start
```

Or use the included `Dockerfile` / `docker-compose.yml`. Full steps, DNS, TLS and WhatsApp setup:
[docs/DEPLOYMENT.md](docs/DEPLOYMENT.md). Every environment variable is documented in
[.env.example](.env.example).

Health checks: `GET /healthz` (process up) and `GET /readyz` (database reachable).

## Tests

The suite runs against a real PostgreSQL database and a real HTTP server with WebCrypto device keys.

```bash
createdb bookapp_test
TEST_DATABASE_URL=postgres://user:pass@localhost:5432/bookapp_test npm test
npm run audit           # dependency vulnerability scan
```

It covers payment and invitation rules, OTP limits, every shared-link scenario, device replacement,
revocation, content protection, admin RBAC/CSRF/MFA, audit logging and separate-domain hosting.

## Documentation

| Document | For |
|---|---|
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | System design, threat model, decisions |
| [docs/API.md](docs/API.md) | API reference |
| [docs/DATABASE.md](docs/DATABASE.md) | Schema reference |
| [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) | Production deployment |
| [docs/BACKUP_RECOVERY.md](docs/BACKUP_RECOVERY.md) | Backups and restore |
| [docs/ADMIN_MANUAL.md](docs/ADMIN_MANUAL.md) | Book owner's guide to the dashboard |
| [docs/CUSTOMER_GUIDE.md](docs/CUSTOMER_GUIDE.md) | Reader instructions to share with customers |
| [docs/PWA_INSTALL.md](docs/PWA_INSTALL.md) | Installing the reader on each platform |
| [docs/SECURITY_LIMITATIONS.md](docs/SECURITY_LIMITATIONS.md) | What protection is and is not provided |
| [SECURITY.md](SECURITY.md) | Reporting vulnerabilities, security controls |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Development workflow |

## Project layout

```
src/            server: config, app, middleware, routes, services
migrations/     SQL migrations (applied in order, once)
public/site     marketing page template and styles
public/admin    dashboard SPA
public/reader   reader PWA, manifest, service worker
public/shared   shared design tokens
scripts/        migrate, create-admin, seed-dev
test/           acceptance tests
docs/           documentation
```

## License

Proprietary. See [LICENSE](LICENSE).

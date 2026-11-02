# Deployment guide

This guide deploys the platform on one Linux server with Docker, behind Caddy for HTTPS, with
AWS KMS and S3 for keys and storage. Alternatives are noted where they differ.

## 1. What you need

| Item | Notes |
|---|---|
| Server | 2 vCPU, 2–4 GB RAM is enough to start. Docker + Docker Compose. |
| Domains | `books.example.com` (customer site) and `admin.example.com` pointing (A/AAAA) to the server |
| AWS | One KMS symmetric key and one private S3 bucket (or use `KMS_PROVIDER=local` / `STORAGE_DRIVER=local`) |

## 2. Prepare AWS (recommended)

1. **S3 bucket**: create a bucket, keep *Block all public access* **on**, enable default
   encryption (SSE-KMS with your key) and versioning.
2. **KMS key**: create a symmetric key (`ENCRYPT_DECRYPT`).
3. **IAM**: create a user or instance role allowed only:
   - `s3:GetObject`, `s3:PutObject`, `s3:DeleteObject` on `arn:aws:s3:::BUCKET/*`
   - `kms:GenerateDataKey`, `kms:Decrypt` on the key ARN
4. Provide credentials via an instance role, or `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` in `.env`.

Without AWS: `KMS_PROVIDER=local` with `LOCAL_MASTER_KEY=$(openssl rand -hex 32)` stored in a secret
manager, and `STORAGE_DRIVER=local` on an encrypted disk volume. Back up the key separately from
the data: without it, stored books cannot be decrypted.

## 3. Configure

```bash
git clone <repository> bookapp && cd bookapp
cp .env.example .env
openssl rand -base64 48      # → HASH_PEPPER
echo "POSTGRES_PASSWORD=$(openssl rand -hex 24)" >> .env
```

Edit `.env`: domains, `HASH_PEPPER`, KMS/S3, `REQUIRE_ADMIN_MFA=true`,
`DEFAULT_COUNTRY_CODE`. Every variable is explained in `.env.example`. The server refuses to
start with insecure production settings (non-secure cookies, short pepper, missing key).

## 4. Start

```bash
docker compose up -d --build
docker compose logs -f app          # wait for "server listening"
docker compose exec app node scripts/create-admin.js --email you@example.com --name "Your Name"
```

`MIGRATE_ON_START=true` in the compose file applies migrations at startup. Without Docker:

```bash
npm ci --omit=dev
npm run migrate
npm run admin:create -- --email you@example.com --name "Your Name"
NODE_ENV=production npm start       # run under systemd or a process manager
```

## 5. HTTPS reverse proxy (Caddy)

`/etc/caddy/Caddyfile`:

```
books.example.com, admin.example.com {
    encode gzip
    request_body {
        max_size 110MB
    }
    reverse_proxy 127.0.0.1:3000 {
        transport http {
            read_timeout 15m
        }
    }
}
```

Caddy obtains certificates automatically. With nginx, set `client_max_body_size 110m;`,
`proxy_read_timeout 900s;`, and forward `Host`, `X-Forwarded-For` and `X-Forwarded-Proto`.
Keep `TRUST_PROXY=1` (one proxy hop).

## 6. Verify

```bash
curl -fsS https://books.example.com/readyz
curl -sI https://books.example.com/app | grep -i content-security-policy
```

Then in the dashboard (`https://admin.example.com`):

1. Sign in and set up two-factor authentication (My Account).
2. Books → create the book, upload the cover and the EPUB/PDF, publish.
3. Download Page & WhatsApp → choose the book and enter your business number.
4. Register a test order with your own number, verify it, generate an access link, open it on your
   phone and complete activation.

## 7. Updating

```bash
git pull
docker compose up -d --build      # migrations run on start
```

Migrations are forward-only and additive; take a database backup before each update
(see BACKUP_RECOVERY.md).

## 8. Logging and monitoring

- Logs are JSON lines on stdout (`docker compose logs app`). Invitation tokens, cookies and
  codes are redacted.
- Point an uptime monitor at `/readyz`.
- The dashboard's **Security Events** page lists alerts; review it regularly.
- CI runs `npm audit`; also enable GitHub Dependabot alerts on the repository.

## Single-domain mode

Leave `ADMIN_BASE_URL` empty (or equal to `READER_BASE_URL`). The dashboard
is at `/admin` and the reader at `/app` on the same domain.

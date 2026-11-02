# Backup and recovery

Three things must be backed up. Losing any one of them can make the books unreadable.

| What | Where | Why it matters |
|---|---|---|
| PostgreSQL database | `bookapp` database | Customers, orders, licenses, devices, **wrapped data keys**, audit log |
| Private storage | S3 bucket or `STORAGE_LOCAL_DIR` | Encrypted originals, chapters and covers |
| Keys and secrets | KMS key (AWS) or `LOCAL_MASTER_KEY`; `HASH_PEPPER`; WhatsApp token | Needed to decrypt books and to keep sessions/invitations valid |

## Database

Daily logical backup, kept 30 days:

```bash
# /etc/cron.d/bookapp-backup
15 2 * * * root docker compose -f /srv/bookapp/docker-compose.yml exec -T db \
  pg_dump -U bookapp -Fc bookapp > /backups/bookapp-$(date +\%F).dump && \
  find /backups -name 'bookapp-*.dump' -mtime +30 -delete
```

Copy `/backups` off the server (for example to a separate S3 bucket with object lock). With a
managed database (RDS, Cloud SQL, Neon…), enable automated backups and point-in-time recovery.

## Storage

- **S3**: enable bucket versioning and replication to a second region, or a lifecycle rule that
  keeps non-current versions for 30 days.
- **Local**: back up the storage volume daily, for example
  `restic backup /var/lib/docker/volumes/bookapp_storage`.

## Keys

- **AWS KMS**: never schedule key deletion while any edition still uses it. KMS keys are durable
  and region-replicated by AWS; enable automatic key rotation (old versions keep decrypting).
- **Local master key**: store `LOCAL_MASTER_KEY` in a password manager or secret manager **and**
  an offline copy. It is not in the database backup on purpose.
- Keep `HASH_PEPPER` with the same care. Restoring with a different pepper signs everyone out
  and invalidates pending invitations; licenses and books are unaffected.

## Restore

1. Provision the server and `.env` with the **same** `HASH_PEPPER` and key settings.
2. Restore storage (S3 versions or the volume backup).
3. Restore the database:
   ```bash
   docker compose up -d db
   docker compose exec -T db createdb -U bookapp bookapp_restore
   docker compose exec -T db pg_restore -U bookapp -d bookapp_restore < bookapp-YYYY-MM-DD.dump
   ```
   Check it, then rename it to `bookapp` (or point `DATABASE_URL` at it).
4. Start the app: `docker compose up -d`. Check `/readyz`, sign in to the dashboard, and open a
   book as a test customer.

## Test the restore

Every quarter, restore the latest backup into a staging environment and open one book from each
edition. An untested backup is not a backup.

## Disaster scenarios

| Scenario | Action |
|---|---|
| Server lost | Restore as above on a new server |
| Database corrupted | Restore last dump or point-in-time; customers who activated after the backup sign in again with their number (their license comes back only if the order is in the restored data; re-enter recent orders from the audit trail or your payment records) |
| Storage object deleted | Restore from S3 versioning / volume backup. If unrecoverable, re-upload the book as a new edition; licenses are unaffected |
| `HASH_PEPPER` leaked | Rotate it and restart; all sessions end and pending invitations stop working; reissue invitations |
| WhatsApp token leaked | Revoke it in Meta Business settings, create a new one, update `.env`, restart |
| Admin account compromised | Disable it from another owner account (Administrators), review Audit Logs, rotate its password and MFA |

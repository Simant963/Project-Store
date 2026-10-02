# Appora production deployment

## Prerequisites

- A Linux server with Docker Engine and Docker Compose.
- A domain whose DNS points to the server.
- TLS files at `deployment/certs/fullchain.pem` and `deployment/certs/privkey.pem`.
- No email service is required with `PASSWORD_RESET_MODE=manual`. SMTP is optional when email recovery is enabled.
- A Supabase PostgreSQL session-pooler connection string.

## First deployment

1. Copy `.env.production.example` to `.env.production` and replace every placeholder.
2. Set `PUBLIC_BASE_URL`, the administrator email, legal contacts, and `PASSWORD_RESET_MODE=manual`. SMTP values may remain empty in manual mode.
3. Add the TLS certificate and private key under `deployment/certs`.
4. Run the local release preflight. It validates settings without displaying secret values:

   ```text
   powershell -NoProfile -ExecutionPolicy Bypass -File deployment/preflight.ps1
   ```

5. Build and start the stack:

   ```text
   docker compose --env-file .env.production -f docker-compose.production.yml up -d --build
   ```

6. Verify migrations, service health, and application readiness:

   ```text
   docker compose --env-file .env.production -f docker-compose.production.yml ps
   docker compose --env-file .env.production -f docker-compose.production.yml exec web flask --app app production-check
   ```

7. Before opening public traffic, verify authenticated workflows for admin,
   co-admin, developer, and user in a separate staging environment. Verify
   sustained traffic, uploads, downloads, and backup recovery with privately
   maintained test tools; local test scripts are no longer included here.

The proxy redirects HTTP traffic to HTTPS. Only ports 80 and 443 are exposed;
Redis and Gunicorn remain on the private container network. PostgreSQL is
provided by Supabase over an SSL connection.

## Backups

Back up the PostgreSQL database and private uploads together:

```text
powershell -File deployment/backup.ps1
```

Copy the resulting `backups` directory to encrypted off-server storage. A
backup is not considered valid until it has been restored successfully in a
separate staging environment.

## Restore drill

Stop public traffic before restoring. The restore command replaces the active
database and upload volume and therefore requires an explicit confirmation:

```text
powershell -File deployment/restore.ps1 -DatabaseBackup backups/appora-TIMESTAMP.dump -UploadsBackup backups/appora-uploads-TIMESTAMP.tar.gz -Confirmation RESTORE-APPORA
```

After restoration, run the migration and production preflight commands before
reopening traffic.

## Updates and rollback

Create a fresh backup before every deployment. Rebuild the stack, allow the
one-shot `migrate` service to finish, and verify `/ready`. Roll back application
images only when the corresponding database migration has a reviewed downgrade;
otherwise restore the paired database and upload backup.

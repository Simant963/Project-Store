# Appora

Appora is a Flask marketplace where approved developers publish Android apps and users can discover, download, save, rate, review, and report them. Administrators approve developer identities and releases, moderate accounts and community content, and can block or remove unsafe entries.

## Local setup

1. Create and activate a virtual environment.
2. Install packages with `pip install -r requirements.txt`.
3. Copy `.env.example` to `.env` and set a strong `SECRET_KEY` and `ADMIN_PASSWORD`.
4. Apply the database migrations with `flask --app app db upgrade`.
5. Start the app with `flask --app app run --port 5001`.

The default local database is SQLite. Uploaded identity documents, screenshots, icons, and APKs are stored below the configured private upload directory and are served only through permission-checked routes.

## Production checklist

- Use PostgreSQL by setting `DATABASE_URL`, run `flask --app app db upgrade` as a deployment/release step, and run the site with the included `Procfile`.
- Set `APP_ENV=production`, `FLASK_DEBUG=false`, `SESSION_COOKIE_SECURE=true`, `TRUST_PROXY=true`, and a unique high-entropy `SECRET_KEY`. Startup rejects unsafe production values.
- Set `PUBLIC_BASE_URL` to the HTTPS domain and configure all SMTP values so password-reset links are emailed.
- Mount durable private storage or replace local uploads with private object storage. The web filesystem must not be ephemeral.
- Back up the database and private uploads together, and test restoration before launch.
- Appora tracks schema revisions with Alembic's `alembic_version` table. Review generated migrations, back up production, and apply `flask --app app db upgrade` before starting a new release.
- Install ClamAV, keep signatures current with `freshclam`, and set `CLAMAV_COMMAND`. APK submission fails closed if ClamAV is unavailable, reports a threat, or times out. Structural APK validation runs separately.
- Configure the platform liveness check at `/health` and readiness check at `/ready`, then enforce HTTPS at the load balancer.

## Production services

Use `.env.production.example` as the deployment configuration checklist. Store
the real values in the hosting provider's encrypted environment settings, not
in a committed file.

Required production services:

- PostgreSQL through `DATABASE_URL`.
- A persistent mounted disk for `PRIVATE_UPLOAD_ROOT`.
- An SMTP provider for password-reset messages.
- ClamAV installed in the application image with current signatures.
- An HTTPS reverse proxy with `TRUST_PROXY=true`.

Deploy in this order:

```text
flask --app app db upgrade
flask --app app production-check
gunicorn --workers 3 --bind 0.0.0.0:$PORT app:app
```

The included `Procfile` runs the database migration as its release command.
Production startup rejects SQLite, insecure cookies, HTTP public URLs,
automatic migrations, relative upload paths, missing mail settings, and a
missing ClamAV executable.

For a complete self-hosted deployment with PostgreSQL, Gunicorn, Nginx,
ClamAV signature updates, persistent volumes, health checks, and backup/restore
commands, follow `deployment/DEPLOYMENT.md` and use
`docker-compose.production.yml`.

Before a release, create the private `.env.production` file and TLS files, then
run `powershell -File deployment/preflight.ps1`. The checker does not display
secret values and fails when required configuration, certificates, regression
tests, migrations, Docker, or the Compose configuration are not ready.

## Verification

Run the two regression scripts:

```text
python _apk_security_test.py
python _marketplace_workflow_test.py
```

They use isolated temporary databases and do not alter local marketplace data.

The suites cover registration and login flows, password recovery, downloads,
reviews and reports, developer/app approvals, admin and co-admin permission
boundaries, APK structure and malware rejection, soft deletion and restore,
protected permanent deletion, realtime state changes, and logout confirmation.

## Database migrations

Create a migration after changing a SQLAlchemy model:

```text
flask --app app db migrate -m "describe the schema change"
flask --app app db upgrade
flask --app app db check
```

Review every generated file under `migrations/versions` before applying it.
`AUTO_MIGRATE=true` is reserved for isolated automated tests; keep it `false`
in production so schema changes happen as an explicit release step.

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
- Set `PASSWORD_RESET_MODE=manual` for administrator-approved recovery without an email service. Use `email` and configure SMTP only if emailed reset links are wanted.
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

- Supabase PostgreSQL through its session-pooler `DATABASE_URL`.
- Redis through `REDIS_URL` for live updates across web workers.
- A persistent mounted disk for `PRIVATE_UPLOAD_ROOT`.
- No mail service is required in manual reset mode. An SMTP provider is optional for emailed reset links.
- ClamAV installed in the application image with current signatures.
- An HTTPS reverse proxy with `TRUST_PROXY=true`.

Deploy in this order:

```text
flask --app app db upgrade
flask --app app production-check
gunicorn --workers 4 --worker-class gevent --worker-connections 1200 --keep-alive 5 --timeout 300 --bind 0.0.0.0:$PORT app:app
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
run `powershell -NoProfile -ExecutionPolicy Bypass -File deployment/preflight.ps1`.
The checker does not display
secret values and fails when required configuration, certificates,
migrations, Docker, or the Compose configuration are not ready.

## Verification

Earlier local test scripts, saved test credentials, and generated verification reports
have been removed from this repository. Before launch, verify registration,
login, password recovery, developer/app approvals, uploads, downloads, role
permissions, malware rejection, and backup recovery in a separate staging
environment. Check `/health` and `/ready` after every deployment.

Keep private environment files, runtime data, backups, and installed
dependencies out of Git. Only placeholder environment examples are committed.

## App submission progress

Developer My Apps and the administrator overview/review queue share a four-stage
tracker: uploaded, security checks, admin verification, and published/live.
Developers can open `/developer/apps/<id>` for private progress, feedback, and
status history. Administrators use the existing `/admin/apps` queue and detail
pages; authorized co-admin reviewers use the same controls.

Uploads retain the existing fail-closed structural and ClamAV checks. The deeper
60-point check is queued for the administrator's **Run security check** action.
A successful scan moves the submission to admin review automatically. **Approve
App** verifies the build but does not make it downloadable. **Publish App** is a
separate confirmed action. Rejection and requested changes require a reason.
Resubmission restarts security review; the previous published version stays live
while a replacement is reviewed. Published builds cannot be rescanned through
this workflow; submit a new version instead.

Review states are enforced on the backend, with transactional notifications,
per-build transition history, row locking, optimistic revision checks, and
idempotent approval/publication. The read-only `/submission-status?ids=1,2`
snapshot and `/apps/<id>/status-history` enforce submission ownership or staff
access. Existing SSE streams refresh visible progress, with a 15-second polling
fallback; status updates never require a manual page reload.

The isolated verification runner creates disposable accounts and storage, applies
all migrations, and checks both roles without accessing the configured database:

```text
env/Scripts/python.exe verification/submission_workflow_checks.py
```

This default run uses real static analysis and a mocked antivirus result. Its
`--postgres --real-antivirus` mode requires a disposable Docker database named
`appora_submission` on host `appora-submission-db`, the private fixture connection
in `APPORA_VERIFY_DATABASE_URL`, and a real ClamAV signature volume. Never point
verification tools at production. No clean scan guarantees an APK is safe;
review warnings and perform isolated Android installation/runtime testing.

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

# Appora

Appora is a Flask marketplace where approved developers publish Android apps and users can discover, download, save, rate, review, and report them. Administrators approve developer identities and releases, moderate accounts and community content, and can block or remove unsafe entries.

## Local setup

1. Create and activate a virtual environment.
2. Install packages with `pip install -r requirements.txt`.
3. Copy `.env.example` to `.env` and set a strong `SECRET_KEY` and `ADMIN_PASSWORD`.
4. Start the app with `flask --app app run --port 5001`.

The default local database is SQLite. Uploaded identity documents, screenshots, icons, and APKs are stored below the configured private upload directory and are served only through permission-checked routes.

## Production checklist

- Use PostgreSQL by setting `DATABASE_URL` and run the site with the included `Procfile`.
- Set `APP_ENV=production`, `FLASK_DEBUG=false`, `SESSION_COOKIE_SECURE=true`, `TRUST_PROXY=true`, and a unique high-entropy `SECRET_KEY`. Startup rejects unsafe production values.
- Set `PUBLIC_BASE_URL` to the HTTPS domain and configure all SMTP values so password-reset links are emailed.
- Mount durable private storage or replace local uploads with private object storage. The web filesystem must not be ephemeral.
- Back up the database and private uploads together, and test restoration before launch.
- Appora records the applied local schema level in `schema_version`; never deploy an older application build over a newer recorded schema without a tested rollback.
- Install ClamAV, keep signatures current with `freshclam`, and set `CLAMAV_COMMAND`. APK submission fails closed if ClamAV is unavailable, reports a threat, or times out. Structural APK validation runs separately.
- Configure the platform liveness check at `/health` and readiness check at `/ready`, then enforce HTTPS at the load balancer.

## Verification

Run the two regression scripts:

```text
python _apk_security_test.py
python _marketplace_workflow_test.py
```

They use isolated temporary databases and do not alter local marketplace data.

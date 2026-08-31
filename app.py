import os
import secrets
from datetime import timedelta
from pathlib import Path

from dotenv import load_dotenv
from flask import Flask, abort, jsonify, render_template, request
from sqlalchemy import inspect, text
from werkzeug.middleware.proxy_fix import ProxyFix

from application.database import db

load_dotenv()


def upgrade_existing_user_table():
    """Add new account fields without deleting existing local data."""
    inspector = inspect(db.engine)
    if "user" not in inspector.get_table_names():
        return

    columns = {column["name"] for column in inspector.get_columns("user")}
    datetime_type = "TIMESTAMP WITH TIME ZONE" if db.engine.dialect.name == "postgresql" else "DATETIME"
    additions = {
        "status": "ALTER TABLE user ADD COLUMN status VARCHAR(20) NOT NULL DEFAULT 'approved'",
        "company_name": "ALTER TABLE user ADD COLUMN company_name VARCHAR(120)",
        "created_at": f"ALTER TABLE user ADD COLUMN created_at {datetime_type}",
        "approved_at": f"ALTER TABLE user ADD COLUMN approved_at {datetime_type}",
        "last_login_at": f"ALTER TABLE user ADD COLUMN last_login_at {datetime_type}",
    }

    for name, statement in additions.items():
        if name not in columns:
            db.session.execute(text(statement))

    db.session.execute(
        text("UPDATE user SET created_at = CURRENT_TIMESTAMP WHERE created_at IS NULL")
    )
    db.session.execute(
        text(
            "CREATE INDEX IF NOT EXISTS idx_user_role_status "
            "ON user (role, status)"
        )
    )
    if db.engine.dialect.name == "sqlite":
        db.session.execute(text("PRAGMA optimize"))


def upgrade_existing_store_app_table():
    """Add release-review fields without replacing existing app records."""
    inspector = inspect(db.engine)
    if "store_app" not in inspector.get_table_names():
        return

    columns = {column["name"] for column in inspector.get_columns("store_app")}
    datetime_type = "TIMESTAMP WITH TIME ZONE" if db.engine.dialect.name == "postgresql" else "DATETIME"
    additions = {
        "pending_version": "ALTER TABLE store_app ADD COLUMN pending_version VARCHAR(40)",
        "pending_min_android_version": "ALTER TABLE store_app ADD COLUMN pending_min_android_version VARCHAR(40)",
        "pending_changelog": "ALTER TABLE store_app ADD COLUMN pending_changelog TEXT",
        "pending_apk_file": "ALTER TABLE store_app ADD COLUMN pending_apk_file VARCHAR(255)",
        "pending_apk_original_name": "ALTER TABLE store_app ADD COLUMN pending_apk_original_name VARCHAR(255)",
        "pending_apk_size": "ALTER TABLE store_app ADD COLUMN pending_apk_size INTEGER",
        "pending_apk_sha256": "ALTER TABLE store_app ADD COLUMN pending_apk_sha256 VARCHAR(64)",
        "pending_release_status": "ALTER TABLE store_app ADD COLUMN pending_release_status VARCHAR(20)",
        "pending_release_note": "ALTER TABLE store_app ADD COLUMN pending_release_note TEXT",
        "pending_release_submitted_at": f"ALTER TABLE store_app ADD COLUMN pending_release_submitted_at {datetime_type}",
        "security_scan_status": "ALTER TABLE store_app ADD COLUMN security_scan_status VARCHAR(20) NOT NULL DEFAULT 'unscanned'",
        "security_scan_summary": "ALTER TABLE store_app ADD COLUMN security_scan_summary TEXT",
        "security_scanned_at": f"ALTER TABLE store_app ADD COLUMN security_scanned_at {datetime_type}",
        "pending_security_scan_status": "ALTER TABLE store_app ADD COLUMN pending_security_scan_status VARCHAR(20)",
        "pending_security_scan_summary": "ALTER TABLE store_app ADD COLUMN pending_security_scan_summary TEXT",
        "pending_security_scanned_at": f"ALTER TABLE store_app ADD COLUMN pending_security_scanned_at {datetime_type}",
        "malware_scan_status": "ALTER TABLE store_app ADD COLUMN malware_scan_status VARCHAR(20) NOT NULL DEFAULT 'unscanned'",
        "malware_scan_summary": "ALTER TABLE store_app ADD COLUMN malware_scan_summary TEXT",
        "malware_scanned_at": f"ALTER TABLE store_app ADD COLUMN malware_scanned_at {datetime_type}",
        "pending_malware_scan_status": "ALTER TABLE store_app ADD COLUMN pending_malware_scan_status VARCHAR(20)",
        "pending_malware_scan_summary": "ALTER TABLE store_app ADD COLUMN pending_malware_scan_summary TEXT",
        "pending_malware_scanned_at": f"ALTER TABLE store_app ADD COLUMN pending_malware_scanned_at {datetime_type}",
    }
    for name, statement in additions.items():
        if name not in columns:
            db.session.execute(text(statement))

    db.session.execute(
        text(
            "CREATE INDEX IF NOT EXISTS idx_store_app_pending_release "
            "ON store_app (pending_release_status, pending_release_submitted_at) "
            "WHERE pending_release_status IS NOT NULL"
        )
    )
    if db.engine.dialect.name == "sqlite":
        db.session.execute(text("PRAGMA optimize"))


def create_app():
    app = Flask(__name__)
    app.config["APP_ENV"] = os.getenv("APP_ENV", "development").lower()
    app.debug = os.getenv("FLASK_DEBUG", "false").lower() in {"1", "true", "yes"}
    app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv(
        "DATABASE_URL", "sqlite:///database.db"
    )
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    app.config["SECRET_KEY"] = os.getenv("SECRET_KEY") or secrets.token_hex(32)
    app.config["SESSION_COOKIE_HTTPONLY"] = True
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
    app.config["SESSION_COOKIE_SECURE"] = os.getenv(
        "SESSION_COOKIE_SECURE", "false"
    ).lower() in {"1", "true", "yes"}
    app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(days=30)
    app.config["SESSION_REFRESH_EACH_REQUEST"] = False
    app.config["PUBLIC_BASE_URL"] = os.getenv("PUBLIC_BASE_URL", "http://127.0.0.1:5001").rstrip("/")
    app.config["SMTP_HOST"] = os.getenv("SMTP_HOST")
    app.config["SMTP_PORT"] = int(os.getenv("SMTP_PORT", "587"))
    app.config["SMTP_USERNAME"] = os.getenv("SMTP_USERNAME")
    app.config["SMTP_PASSWORD"] = os.getenv("SMTP_PASSWORD")
    app.config["SMTP_FROM_EMAIL"] = os.getenv("SMTP_FROM_EMAIL", "no-reply@appora.local")
    app.config["SMTP_USE_TLS"] = os.getenv("SMTP_USE_TLS", "true").lower() in {"1", "true", "yes"}
    app.config["ADMIN_USERNAME"] = os.getenv("ADMIN_USERNAME", "admin")
    app.config["ADMIN_EMAIL"] = os.getenv("ADMIN_EMAIL", "admin@appora.local")
    app.config["ADMIN_PASSWORD"] = os.getenv("ADMIN_PASSWORD")
    app.config["MAX_CONTENT_LENGTH"] = 220 * 1024 * 1024
    app.config["PRIVATE_UPLOAD_ROOT"] = os.getenv(
        "PRIVATE_UPLOAD_ROOT",
        str(Path(app.instance_path) / "uploads"),
    )
    app.config["DEVELOPER_ID_MAX_BYTES"] = 8 * 1024 * 1024
    app.config["APP_ICON_MAX_BYTES"] = 5 * 1024 * 1024
    app.config["APP_SCREENSHOT_MAX_BYTES"] = 8 * 1024 * 1024
    app.config["APK_MAX_BYTES"] = 200 * 1024 * 1024
    app.config["CLAMAV_COMMAND"] = os.getenv("CLAMAV_COMMAND", "clamscan")
    app.config["CLAMAV_TIMEOUT_SECONDS"] = int(os.getenv("CLAMAV_TIMEOUT_SECONDS", "180"))
    if app.config["APP_ENV"] == "production":
        configuration_errors = []
        configured_secret = os.getenv("SECRET_KEY", "")
        if len(configured_secret) < 32 or configured_secret.startswith("replace-"):
            configuration_errors.append("SECRET_KEY must be a unique value of at least 32 characters")
        if app.debug:
            configuration_errors.append("FLASK_DEBUG must be false")
        if not app.config["SESSION_COOKIE_SECURE"]:
            configuration_errors.append("SESSION_COOKIE_SECURE must be true")
        if not app.config["PUBLIC_BASE_URL"].startswith("https://"):
            configuration_errors.append("PUBLIC_BASE_URL must use HTTPS")
        admin_password = app.config["ADMIN_PASSWORD"] or ""
        if len(admin_password) < 12 or admin_password.startswith("replace-"):
            configuration_errors.append("ADMIN_PASSWORD must contain at least 12 characters")
        if configuration_errors:
            raise RuntimeError("Unsafe production configuration: " + "; ".join(configuration_errors))
    if os.getenv("TRUST_PROXY", "false").lower() in {"1", "true", "yes"}:
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)
    for folder in ("developer_ids", "app_icons", "app_screenshots", "apks"):
        (Path(app.config["PRIVATE_UPLOAD_ROOT"]) / folder).mkdir(
            parents=True,
            exist_ok=True,
        )
    db.init_app(app)

    @app.after_request
    def apply_security_headers(response):
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
        response.headers.setdefault("Cross-Origin-Opener-Policy", "same-origin")
        response.headers.setdefault("Cross-Origin-Resource-Policy", "same-origin")
        response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; img-src 'self' data:; "
            "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://fonts.googleapis.com; "
            "font-src 'self' https://cdn.jsdelivr.net https://fonts.gstatic.com; "
            "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; connect-src 'self'",
        )
        if app.config["SESSION_COOKIE_SECURE"]:
            response.headers.setdefault(
                "Strict-Transport-Security", "max-age=31536000; includeSubDomains"
            )
        return response

    @app.before_request
    def limit_sensitive_request_sizes():
        sensitive_endpoints = {
            "main.admin_login", "main.account_login", "main.create_account",
            "main.forgot_password", "main.reset_password", "main.account_settings",
        }
        if request.endpoint in sensitive_endpoints and (request.content_length or 0) > 64 * 1024:
            abort(413)

    @app.get("/health")
    def health_check():
        """Lightweight liveness check for the process."""
        return jsonify({"status": "ok"})

    @app.get("/ready")
    def readiness_check():
        """Verify required dependencies before accepting marketplace traffic."""
        checks = {"database": False, "schema": False, "private_storage": False}
        try:
            db.session.execute(text("SELECT 1"))
            checks["database"] = True
            from application.models import SchemaVersion

            schema_version = db.session.get(SchemaVersion, 1)
            checks["schema"] = bool(schema_version and schema_version.version >= 5)
        except Exception:
            db.session.rollback()
            app.logger.exception("Readiness database check failed.")

        try:
            upload_root = Path(app.config["PRIVATE_UPLOAD_ROOT"]).resolve()
            checks["private_storage"] = upload_root.is_dir() and os.access(upload_root, os.R_OK | os.W_OK)
        except OSError:
            app.logger.exception("Readiness private storage check failed.")

        ready = all(checks.values())
        response = jsonify({"status": "ready" if ready else "not_ready", "checks": checks})
        response.status_code = 200 if ready else 503
        response.headers["Cache-Control"] = "no-store"
        return response

    def render_safe_error(status_code, title, message, icon):
        return render_template("error.html", status_code=status_code, title=title, message=message, icon=icon), status_code

    @app.errorhandler(400)
    def bad_request_error(error):
        return render_safe_error(400, "That request could not be completed", "The form may have expired or contained invalid information. Please return and try again.", "bi-exclamation-circle")

    @app.errorhandler(403)
    def forbidden_error(error):
        return render_safe_error(403, "Access is not allowed", "You do not have permission to open this page or perform this action.", "bi-shield-lock")

    @app.errorhandler(404)
    def not_found_error(error):
        return render_safe_error(404, "Page not found", "The page may have moved, been removed, or never existed.", "bi-compass")

    @app.errorhandler(413)
    def request_too_large_error(error):
        return render_safe_error(413, "Upload is too large", "The submitted request exceeds the allowed size. Choose a smaller file and try again.", "bi-file-earmark-x")

    @app.errorhandler(429)
    def rate_limit_error(error):
        response, status = render_safe_error(429, "Too many requests", "Please wait a few minutes before trying again.", "bi-hourglass-split")
        response.headers["Retry-After"] = "900"
        return response, status

    @app.errorhandler(500)
    def internal_error(error):
        db.session.rollback()
        app.logger.error("Unhandled application error", exc_info=error.original_exception or error)
        return render_safe_error(500, "Something went wrong", "The request could not be completed. Your saved data was not partially changed.", "bi-tools")

    with app.app_context():
        from application.models import AccountStatus, SchemaVersion, User, UserRole
        from application.username_linked_list import username_index

        db.create_all()
        try:
            upgrade_existing_user_table()
            upgrade_existing_store_app_table()
            schema_version = db.session.get(SchemaVersion, 1)
            if schema_version is None:
                schema_version = SchemaVersion(id=1, version=5)
                db.session.add(schema_version)
            else:
                schema_version.version = 5
            db.session.commit()
        except Exception:
            db.session.rollback()
            app.logger.exception("Database schema upgrade failed; startup was stopped safely.")
            raise
        admin_password = app.config["ADMIN_PASSWORD"]
        admin = User.query.filter_by(username=app.config["ADMIN_USERNAME"]).first()
        if admin is None and admin_password:
            admin = User(
                username=app.config["ADMIN_USERNAME"],
                email=app.config["ADMIN_EMAIL"],
                role=UserRole.ADMIN,
                status=AccountStatus.APPROVED,
            )
            admin.set_password(admin_password)
            admin.approve()
            db.session.add(admin)
            db.session.commit()
        elif admin is not None:
            admin.role = UserRole.ADMIN
            admin.status = AccountStatus.APPROVED
            if not admin.email:
                admin.email = app.config["ADMIN_EMAIL"]
            if admin_password and not admin.check_password(admin_password):
                admin.set_password(admin_password)
            db.session.commit()

        username_index.rebuild(User.query.order_by(User.id).all())

    from application.controllers import main

    app.register_blueprint(main)
    return app


app = create_app()

if __name__ == "__main__":
    app.run()

import os
import secrets
import shutil
from datetime import timedelta
from pathlib import Path

import click
from dotenv import load_dotenv
from flask import Flask, abort, jsonify, render_template, request
from alembic.migration import MigrationContext
from alembic.script import ScriptDirectory
from flask_migrate import upgrade
from sqlalchemy import inspect, text
from werkzeug.middleware.proxy_fix import ProxyFix

from application.database import db, migrate

load_dotenv()


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
    app.config["AUTO_MIGRATE"] = os.getenv("AUTO_MIGRATE", "false").lower() in {"1", "true", "yes"}
    app.config["TRUST_PROXY"] = os.getenv("TRUST_PROXY", "false").lower() in {"1", "true", "yes"}
    app.config["POLICY_VERSION"] = os.getenv("POLICY_VERSION", "2026-09-03")
    app.config["LEGAL_OPERATOR_NAME"] = os.getenv("LEGAL_OPERATOR_NAME", "Appora")
    app.config["LEGAL_ADDRESS"] = os.getenv("LEGAL_ADDRESS", "India")
    app.config["SUPPORT_EMAIL"] = os.getenv("SUPPORT_EMAIL", "support@appora.local")
    app.config["PRIVACY_EMAIL"] = os.getenv("PRIVACY_EMAIL", "privacy@appora.local")
    app.config["GRIEVANCE_OFFICER_NAME"] = os.getenv("GRIEVANCE_OFFICER_NAME", "Appora Grievance Officer")
    app.config["GRIEVANCE_EMAIL"] = os.getenv("GRIEVANCE_EMAIL", "grievance@appora.local")
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
        if not app.config["SQLALCHEMY_DATABASE_URI"].startswith(
            ("postgresql://", "postgresql+psycopg://")
        ):
            configuration_errors.append("DATABASE_URL must use PostgreSQL in production")
        if not app.config["TRUST_PROXY"]:
            configuration_errors.append("TRUST_PROXY must be true behind the production HTTPS proxy")
        if app.config["AUTO_MIGRATE"]:
            configuration_errors.append("AUTO_MIGRATE must be false in production")
        if not os.getenv("PRIVATE_UPLOAD_ROOT"):
            configuration_errors.append("PRIVATE_UPLOAD_ROOT must point to durable mounted storage")
        elif not Path(app.config["PRIVATE_UPLOAD_ROOT"]).is_absolute():
            configuration_errors.append("PRIVATE_UPLOAD_ROOT must be an absolute production path")
        if not app.config["SMTP_HOST"]:
            configuration_errors.append("SMTP_HOST is required for password-reset email")
        if not app.config["SMTP_FROM_EMAIL"] or app.config["SMTP_FROM_EMAIL"].endswith(".local"):
            configuration_errors.append("SMTP_FROM_EMAIL must be a real sender address")
        for key in ("SUPPORT_EMAIL", "PRIVACY_EMAIL", "GRIEVANCE_EMAIL"):
            if not app.config[key] or app.config[key].endswith(".local"):
                configuration_errors.append(f"{key} must be a real monitored address")
        if not os.getenv("LEGAL_OPERATOR_NAME") or not os.getenv("LEGAL_ADDRESS"):
            configuration_errors.append("LEGAL_OPERATOR_NAME and LEGAL_ADDRESS are required")
        if not os.getenv("GRIEVANCE_OFFICER_NAME"):
            configuration_errors.append("GRIEVANCE_OFFICER_NAME is required")
        if bool(app.config["SMTP_USERNAME"]) != bool(app.config["SMTP_PASSWORD"]):
            configuration_errors.append("SMTP_USERNAME and SMTP_PASSWORD must be configured together")
        clamav_command = app.config["CLAMAV_COMMAND"]
        if not (shutil.which(clamav_command) or Path(clamav_command).is_file()):
            configuration_errors.append("CLAMAV_COMMAND must resolve to an installed ClamAV scanner")
        admin_password = app.config["ADMIN_PASSWORD"] or ""
        if len(admin_password) < 12 or admin_password.startswith("replace-"):
            configuration_errors.append("ADMIN_PASSWORD must contain at least 12 characters")
        if configuration_errors:
            raise RuntimeError("Unsafe production configuration: " + "; ".join(configuration_errors))
    if app.config["TRUST_PROXY"]:
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)
    for folder in ("developer_ids", "app_icons", "app_screenshots", "apks"):
        (Path(app.config["PRIVATE_UPLOAD_ROOT"]) / folder).mkdir(
            parents=True,
            exist_ok=True,
        )
    db.init_app(app)
    migrate.init_app(app, db)

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
        if app.config["APP_ENV"] == "production":
            checks.update({"smtp_config": False, "clamav": False})
        try:
            db.session.execute(text("SELECT 1"))
            checks["database"] = True
            with db.engine.connect() as connection:
                migration_context = MigrationContext.configure(connection)
                current_revision = migration_context.get_current_revision()
            migration_config = app.extensions["migrate"].migrate.get_config()
            head_revision = ScriptDirectory.from_config(migration_config).get_current_head()
            checks["schema"] = bool(current_revision and current_revision == head_revision)
        except Exception:
            db.session.rollback()
            app.logger.exception("Readiness database check failed.")

        try:
            upload_root = Path(app.config["PRIVATE_UPLOAD_ROOT"]).resolve()
            checks["private_storage"] = upload_root.is_dir() and os.access(upload_root, os.R_OK | os.W_OK)
        except OSError:
            app.logger.exception("Readiness private storage check failed.")

        if app.config["APP_ENV"] == "production":
            checks["smtp_config"] = bool(
                app.config["SMTP_HOST"] and app.config["SMTP_FROM_EMAIL"]
            )
            clamav_command = app.config["CLAMAV_COMMAND"]
            checks["clamav"] = bool(
                shutil.which(clamav_command) or Path(clamav_command).is_file()
            )

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

    from application.controllers import main

    app.register_blueprint(main)

    @app.cli.command("production-check")
    def production_check():
        """Fail unless the deployed application and its services are ready."""
        if app.config["APP_ENV"] != "production":
            raise click.ClickException("APP_ENV must be production for this check")
        response = app.test_client().get("/ready")
        result = response.get_json()
        for name, passed in result.get("checks", {}).items():
            click.echo(f"{'PASS' if passed else 'FAIL'}  {name}")
        if response.status_code != 200:
            raise click.ClickException("Production services are not ready")
        click.echo("Production preflight passed.")

    with app.app_context():
        from application.models import AccountStatus, User, UserRole
        from application.username_linked_list import username_index

        if app.config["AUTO_MIGRATE"]:
            upgrade()
        database_tables = set(inspect(db.engine).get_table_names())
        if "user" not in database_tables:
            return app
        database_user_columns = {
            column["name"] for column in inspect(db.engine).get_columns("user")
        }
        if not set(User.__table__.columns.keys()).issubset(database_user_columns):
            return app
        with db.engine.connect() as connection:
            current_revision = MigrationContext.configure(connection).get_current_revision()
        migration_config = app.extensions["migrate"].migrate.get_config()
        head_revision = ScriptDirectory.from_config(migration_config).get_current_head()
        if current_revision != head_revision:
            return app
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

    return app


app = create_app()

if __name__ == "__main__":
    app.run()

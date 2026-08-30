import os
import secrets
from pathlib import Path

from dotenv import load_dotenv
from flask import Flask
from sqlalchemy import inspect, text

from application.database import db

load_dotenv()


def upgrade_existing_user_table():
    """Add new account fields without deleting existing local data."""
    inspector = inspect(db.engine)
    if "user" not in inspector.get_table_names():
        return

    columns = {column["name"] for column in inspector.get_columns("user")}
    additions = {
        "status": "ALTER TABLE user ADD COLUMN status VARCHAR(20) NOT NULL DEFAULT 'approved'",
        "company_name": "ALTER TABLE user ADD COLUMN company_name VARCHAR(120)",
        "created_at": "ALTER TABLE user ADD COLUMN created_at DATETIME",
        "approved_at": "ALTER TABLE user ADD COLUMN approved_at DATETIME",
        "last_login_at": "ALTER TABLE user ADD COLUMN last_login_at DATETIME",
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
    db.session.execute(text("PRAGMA optimize"))
    db.session.commit()


def upgrade_existing_store_app_table():
    """Add release-review fields without replacing existing app records."""
    inspector = inspect(db.engine)
    if "store_app" not in inspector.get_table_names():
        return

    columns = {column["name"] for column in inspector.get_columns("store_app")}
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
        "pending_release_submitted_at": "ALTER TABLE store_app ADD COLUMN pending_release_submitted_at DATETIME",
        "security_scan_status": "ALTER TABLE store_app ADD COLUMN security_scan_status VARCHAR(20) NOT NULL DEFAULT 'unscanned'",
        "security_scan_summary": "ALTER TABLE store_app ADD COLUMN security_scan_summary TEXT",
        "security_scanned_at": "ALTER TABLE store_app ADD COLUMN security_scanned_at DATETIME",
        "pending_security_scan_status": "ALTER TABLE store_app ADD COLUMN pending_security_scan_status VARCHAR(20)",
        "pending_security_scan_summary": "ALTER TABLE store_app ADD COLUMN pending_security_scan_summary TEXT",
        "pending_security_scanned_at": "ALTER TABLE store_app ADD COLUMN pending_security_scanned_at DATETIME",
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
    db.session.execute(text("PRAGMA optimize"))
    db.session.commit()


def create_app():
    app = Flask(__name__)
    app.debug = True
    app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv(
        "DATABASE_URL", "sqlite:///database.db"
    )
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    app.config["SECRET_KEY"] = os.getenv("SECRET_KEY") or secrets.token_hex(32)
    app.config["SESSION_COOKIE_HTTPONLY"] = True
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
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
    for folder in ("developer_ids", "app_icons", "app_screenshots", "apks"):
        (Path(app.config["PRIVATE_UPLOAD_ROOT"]) / folder).mkdir(
            parents=True,
            exist_ok=True,
        )
    db.init_app(app)

    with app.app_context():
        from application.models import AccountStatus, User, UserRole
        from application.username_linked_list import username_index

        db.create_all()
        upgrade_existing_user_table()
        upgrade_existing_store_app_table()
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
from application.controllers import main

app.register_blueprint(main)

if __name__ == "__main__":
    app.run()

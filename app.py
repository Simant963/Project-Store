import os
import secrets

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
    db.init_app(app)

    with app.app_context():
        from application.models import AccountStatus, User, UserRole
        from application.username_linked_list import username_index

        db.create_all()
        upgrade_existing_user_table()
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

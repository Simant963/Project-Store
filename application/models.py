from datetime import datetime, timezone
from enum import Enum

from werkzeug.security import check_password_hash, generate_password_hash

from .database import db


class UserRole(str, Enum):
    ADMIN = "admin"
    USER = "user"
    DEVELOPER = "developer"


class AccountStatus(str, Enum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    BLOCKED = "blocked"


def enum_values(enum_class):
    return [member.value for member in enum_class]


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(
        db.Enum(
            UserRole,
            values_callable=enum_values,
            native_enum=False,
            validate_strings=True,
            length=20,
        ),
        nullable=False,
        default=UserRole.USER,
        index=True,
    )
    status = db.Column(
        db.Enum(
            AccountStatus,
            values_callable=enum_values,
            native_enum=False,
            validate_strings=True,
            length=20,
        ),
        nullable=False,
        default=AccountStatus.APPROVED,
        index=True,
    )
    company_name = db.Column(db.String(120), nullable=True)
    created_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
    approved_at = db.Column(db.DateTime(timezone=True), nullable=True)
    last_login_at = db.Column(db.DateTime(timezone=True), nullable=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    @property
    def role_label(self):
        return self.role.value.title()

    @property
    def status_label(self):
        return self.status.value.title()

    @property
    def initials(self):
        return self.username[:2].upper()

    def approve(self):
        self.status = AccountStatus.APPROVED
        self.approved_at = datetime.now(timezone.utc)

    def reject(self):
        self.status = AccountStatus.REJECTED
        self.approved_at = None

    def block(self):
        self.status = AccountStatus.BLOCKED

    def unblock(self):
        self.status = AccountStatus.APPROVED
        if self.approved_at is None:
            self.approved_at = datetime.now(timezone.utc)

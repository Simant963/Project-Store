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


class GovernmentIdType(str, Enum):
    NATIONAL_ID = "national_id"
    PASSPORT = "passport"
    DRIVING_LICENSE = "driving_license"
    VOTER_ID = "voter_id"


class AppCategory(str, Enum):
    BUSINESS = "business"
    EDUCATION = "education"
    ENTERTAINMENT = "entertainment"
    FINANCE = "finance"
    GAMES = "games"
    HEALTH = "health"
    LIFESTYLE = "lifestyle"
    PRODUCTIVITY = "productivity"
    SOCIAL = "social"
    TOOLS = "tools"
    OTHER = "other"


class AppStatus(str, Enum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    BLOCKED = "blocked"


class ReleaseStatus(str, Enum):
    PENDING = "pending"
    REJECTED = "rejected"


class SecurityScanStatus(str, Enum):
    UNSCANNED = "unscanned"
    PASSED = "passed"
    FAILED = "failed"


class AgeRating(str, Enum):
    EVERYONE = "everyone"
    TEEN = "teen"
    MATURE = "mature"


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
    developer_profile = db.relationship(
        "DeveloperProfile",
        back_populates="user",
        uselist=False,
        cascade="all, delete-orphan",
    )
    apps = db.relationship(
        "StoreApp",
        back_populates="developer",
        cascade="all, delete-orphan",
        order_by="StoreApp.created_at.desc()",
    )

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


class DeveloperProfile(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(
        db.Integer,
        db.ForeignKey("user.id"),
        unique=True,
        nullable=False,
        index=True,
    )
    legal_name = db.Column(db.String(120), nullable=True)
    phone = db.Column(db.String(30), nullable=True)
    country = db.Column(db.String(80), nullable=True)
    website = db.Column(db.String(255), nullable=True)
    government_id_type = db.Column(
        db.Enum(
            GovernmentIdType,
            values_callable=enum_values,
            native_enum=False,
            validate_strings=True,
            length=30,
        ),
        nullable=True,
    )
    government_id_number = db.Column(db.String(80), nullable=True)
    government_id_file = db.Column(db.String(255), nullable=True)
    government_id_original_name = db.Column(db.String(255), nullable=True)
    submitted_at = db.Column(db.DateTime(timezone=True), nullable=True)
    reviewed_at = db.Column(db.DateTime(timezone=True), nullable=True)
    review_note = db.Column(db.Text, nullable=True)

    user = db.relationship("User", back_populates="developer_profile")

    @property
    def is_submitted(self):
        return bool(
            self.legal_name
            and self.phone
            and self.country
            and self.government_id_type
            and self.government_id_number
            and self.government_id_file
            and self.submitted_at
        )


class StoreApp(db.Model):
    __tablename__ = "store_app"

    id = db.Column(db.Integer, primary_key=True)
    developer_id = db.Column(
        db.Integer,
        db.ForeignKey("user.id"),
        nullable=False,
        index=True,
    )
    name = db.Column(db.String(120), nullable=False, index=True)
    slug = db.Column(db.String(160), unique=True, nullable=False, index=True)
    package_name = db.Column(db.String(180), unique=True, nullable=False, index=True)
    short_description = db.Column(db.String(180), nullable=False)
    description = db.Column(db.Text, nullable=False)
    version = db.Column(db.String(40), nullable=False)
    min_android_version = db.Column(db.String(40), nullable=False)
    category = db.Column(
        db.Enum(
            AppCategory,
            values_callable=enum_values,
            native_enum=False,
            validate_strings=True,
            length=30,
        ),
        nullable=False,
        index=True,
    )
    age_rating = db.Column(
        db.Enum(
            AgeRating,
            values_callable=enum_values,
            native_enum=False,
            validate_strings=True,
            length=20,
        ),
        nullable=False,
        default=AgeRating.EVERYONE,
    )
    website = db.Column(db.String(255), nullable=True)
    support_email = db.Column(db.String(120), nullable=False)
    privacy_policy_url = db.Column(db.String(255), nullable=False)
    changelog = db.Column(db.Text, nullable=True)
    icon_file = db.Column(db.String(255), nullable=False)
    apk_file = db.Column(db.String(255), nullable=False)
    apk_original_name = db.Column(db.String(255), nullable=False)
    apk_size = db.Column(db.Integer, nullable=False)
    apk_sha256 = db.Column(db.String(64), nullable=False)
    security_scan_status = db.Column(
        db.Enum(
            SecurityScanStatus,
            values_callable=enum_values,
            native_enum=False,
            validate_strings=True,
            length=20,
        ),
        nullable=False,
        default=SecurityScanStatus.UNSCANNED,
    )
    security_scan_summary = db.Column(db.Text, nullable=True)
    security_scanned_at = db.Column(db.DateTime(timezone=True), nullable=True)
    pending_version = db.Column(db.String(40), nullable=True)
    pending_min_android_version = db.Column(db.String(40), nullable=True)
    pending_changelog = db.Column(db.Text, nullable=True)
    pending_apk_file = db.Column(db.String(255), nullable=True)
    pending_apk_original_name = db.Column(db.String(255), nullable=True)
    pending_apk_size = db.Column(db.Integer, nullable=True)
    pending_apk_sha256 = db.Column(db.String(64), nullable=True)
    pending_security_scan_status = db.Column(
        db.Enum(
            SecurityScanStatus,
            values_callable=enum_values,
            native_enum=False,
            validate_strings=True,
            length=20,
        ),
        nullable=True,
    )
    pending_security_scan_summary = db.Column(db.Text, nullable=True)
    pending_security_scanned_at = db.Column(db.DateTime(timezone=True), nullable=True)
    pending_release_status = db.Column(
        db.Enum(
            ReleaseStatus,
            values_callable=enum_values,
            native_enum=False,
            validate_strings=True,
            length=20,
        ),
        nullable=True,
        index=True,
    )
    pending_release_note = db.Column(db.Text, nullable=True)
    pending_release_submitted_at = db.Column(db.DateTime(timezone=True), nullable=True)
    status = db.Column(
        db.Enum(
            AppStatus,
            values_callable=enum_values,
            native_enum=False,
            validate_strings=True,
            length=20,
        ),
        nullable=False,
        default=AppStatus.PENDING,
        index=True,
    )
    review_note = db.Column(db.Text, nullable=True)
    download_count = db.Column(db.Integer, nullable=False, default=0)
    created_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
    submitted_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
    approved_at = db.Column(db.DateTime(timezone=True), nullable=True)
    updated_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )

    developer = db.relationship("User", back_populates="apps")
    version_history = db.relationship(
        "AppVersionHistory",
        back_populates="app",
        cascade="all, delete-orphan",
        order_by="AppVersionHistory.published_at.desc()",
    )
    screenshots = db.relationship(
        "AppScreenshot",
        back_populates="app",
        cascade="all, delete-orphan",
        order_by="AppScreenshot.position.asc()",
    )

    @property
    def category_label(self):
        return self.category.value.replace("_", " ").title()

    @property
    def status_label(self):
        return self.status.value.title()

    @property
    def formatted_size(self):
        size = float(self.apk_size)
        for unit in ("B", "KB", "MB", "GB"):
            if size < 1024 or unit == "GB":
                return f"{size:.1f} {unit}" if unit != "B" else f"{int(size)} B"
            size /= 1024

    @property
    def pending_formatted_size(self):
        if self.pending_apk_size is None:
            return "—"
        size = float(self.pending_apk_size)
        for unit in ("B", "KB", "MB", "GB"):
            if size < 1024 or unit == "GB":
                return f"{size:.1f} {unit}" if unit != "B" else f"{int(size)} B"
            size /= 1024

    @property
    def has_pending_release(self):
        return self.pending_release_status == ReleaseStatus.PENDING

    def approve(self):
        self.status = AppStatus.APPROVED
        self.approved_at = datetime.now(timezone.utc)
        self.review_note = None

    def reject(self, note=None):
        self.status = AppStatus.REJECTED
        self.approved_at = None
        self.review_note = note or None

    def block(self, note=None):
        self.status = AppStatus.BLOCKED
        self.review_note = note or self.review_note

    def clear_pending_release(self):
        self.pending_version = None
        self.pending_min_android_version = None
        self.pending_changelog = None
        self.pending_apk_file = None
        self.pending_apk_original_name = None
        self.pending_apk_size = None
        self.pending_apk_sha256 = None
        self.pending_security_scan_status = None
        self.pending_security_scan_summary = None
        self.pending_security_scanned_at = None
        self.pending_release_status = None
        self.pending_release_note = None
        self.pending_release_submitted_at = None


class AppVersionHistory(db.Model):
    __tablename__ = "app_version_history"

    id = db.Column(db.Integer, primary_key=True)
    app_id = db.Column(
        db.Integer,
        db.ForeignKey("store_app.id"),
        nullable=False,
        index=True,
    )
    version = db.Column(db.String(40), nullable=False)
    min_android_version = db.Column(db.String(40), nullable=False)
    changelog = db.Column(db.Text, nullable=True)
    apk_file = db.Column(db.String(255), nullable=False)
    apk_original_name = db.Column(db.String(255), nullable=False)
    apk_size = db.Column(db.Integer, nullable=False)
    apk_sha256 = db.Column(db.String(64), nullable=False)
    published_at = db.Column(db.DateTime(timezone=True), nullable=False)
    retired_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )

    app = db.relationship("StoreApp", back_populates="version_history")

    @property
    def formatted_size(self):
        size = float(self.apk_size)
        for unit in ("B", "KB", "MB", "GB"):
            if size < 1024 or unit == "GB":
                return f"{size:.1f} {unit}" if unit != "B" else f"{int(size)} B"
            size /= 1024


class AppScreenshot(db.Model):
    __tablename__ = "app_screenshot"

    id = db.Column(db.Integer, primary_key=True)
    app_id = db.Column(
        db.Integer,
        db.ForeignKey("store_app.id"),
        nullable=False,
        index=True,
    )
    file_name = db.Column(db.String(255), nullable=False)
    original_name = db.Column(db.String(255), nullable=False)
    position = db.Column(db.Integer, nullable=False, default=0)
    created_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )

    app = db.relationship("StoreApp", back_populates="screenshots")

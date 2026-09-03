from datetime import datetime, timezone
from enum import Enum

from werkzeug.security import check_password_hash, generate_password_hash

from .database import db


class UserRole(str, Enum):
    ADMIN = "admin"
    CO_ADMIN = "co_admin"
    USER = "user"
    DEVELOPER = "developer"


class AccountStatus(str, Enum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    BLOCKED = "blocked"
    DELETED = "deleted"


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
    DELETED = "deleted"


class ReleaseStatus(str, Enum):
    PENDING = "pending"
    REJECTED = "rejected"


class SecurityScanStatus(str, Enum):
    UNSCANNED = "unscanned"
    PASSED = "passed"
    FAILED = "failed"


class ReviewStatus(str, Enum):
    PUBLISHED = "published"
    HIDDEN = "hidden"


class ReportReason(str, Enum):
    MALWARE = "malware"
    PRIVACY = "privacy"
    INAPPROPRIATE = "inappropriate"
    COPYRIGHT = "copyright"
    MISLEADING = "misleading"
    OTHER = "other"


class ReportStatus(str, Enum):
    OPEN = "open"
    RESOLVED = "resolved"
    DISMISSED = "dismissed"


class AuditAction(str, Enum):
    CO_ADMIN_MANAGEMENT = "co_admin_management"
    ACCOUNT_MODERATION = "account_moderation"
    APP_MODERATION = "app_moderation"
    RELEASE_MODERATION = "release_moderation"
    REPORT_MODERATION = "report_moderation"
    REVIEW_MODERATION = "review_moderation"


class NotificationType(str, Enum):
    ACCOUNT = "account"
    APP = "app"
    RELEASE = "release"


class AgeRating(str, Enum):
    EVERYONE = "everyone"
    TEEN = "teen"
    MATURE = "mature"


def enum_values(enum_class):
    return [member.value for member in enum_class]


def format_file_size(byte_count):
    if byte_count is None:
        return "—"
    size = float(byte_count)
    for unit in ("B", "KB", "MB", "GB"):
        if size < 1024 or unit == "GB":
            return f"{size:.1f} {unit}" if unit != "B" else f"{int(size)} B"
        size /= 1024


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
    deleted_at = db.Column(db.DateTime(timezone=True), nullable=True)
    status_before_delete = db.Column(db.String(20), nullable=True)
    terms_accepted_at = db.Column(db.DateTime(timezone=True), nullable=True)
    terms_version = db.Column(db.String(20), nullable=True)
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
    saved_apps = db.relationship("SavedApp", back_populates="user", cascade="all, delete-orphan")
    downloads = db.relationship("DownloadRecord", back_populates="user", cascade="all, delete-orphan")
    reviews = db.relationship("AppReview", back_populates="user", cascade="all, delete-orphan")
    reports = db.relationship("AppReport", back_populates="user", cascade="all, delete-orphan")
    notifications = db.relationship("Notification", back_populates="recipient", cascade="all, delete-orphan")

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

    def soft_delete(self):
        if self.status != AccountStatus.DELETED:
            self.status_before_delete = self.status.value
        self.status = AccountStatus.DELETED
        self.deleted_at = datetime.now(timezone.utc)

    def restore(self):
        allowed = {status.value: status for status in AccountStatus if status != AccountStatus.DELETED}
        fallback = AccountStatus.PENDING if self.role == UserRole.DEVELOPER else AccountStatus.APPROVED
        self.status = allowed.get(self.status_before_delete, fallback)
        self.status_before_delete = None
        self.deleted_at = None


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
    malware_scan_status = db.Column(db.Enum(SecurityScanStatus, values_callable=enum_values, native_enum=False, validate_strings=True, length=20), nullable=False, default=SecurityScanStatus.UNSCANNED)
    malware_scan_summary = db.Column(db.Text, nullable=True)
    malware_scanned_at = db.Column(db.DateTime(timezone=True), nullable=True)
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
    pending_malware_scan_status = db.Column(db.Enum(SecurityScanStatus, values_callable=enum_values, native_enum=False, validate_strings=True, length=20), nullable=True)
    pending_malware_scan_summary = db.Column(db.Text, nullable=True)
    pending_malware_scanned_at = db.Column(db.DateTime(timezone=True), nullable=True)
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
    deleted_at = db.Column(db.DateTime(timezone=True), nullable=True)
    status_before_delete = db.Column(db.String(20), nullable=True)
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
    saved_by = db.relationship("SavedApp", back_populates="app", cascade="all, delete-orphan")
    download_records = db.relationship("DownloadRecord", back_populates="app", cascade="all, delete-orphan")
    reviews = db.relationship("AppReview", back_populates="app", cascade="all, delete-orphan")
    reports = db.relationship("AppReport", back_populates="app", cascade="all, delete-orphan")

    @property
    def category_label(self):
        return self.category.value.replace("_", " ").title()

    @property
    def status_label(self):
        return self.status.value.title()

    @property
    def formatted_size(self):
        return format_file_size(self.apk_size)

    @property
    def pending_formatted_size(self):
        return format_file_size(self.pending_apk_size)

    @property
    def has_pending_release(self):
        return self.pending_release_status == ReleaseStatus.PENDING

    @property
    def published_reviews(self):
        return [review for review in self.reviews if review.status == ReviewStatus.PUBLISHED]

    @property
    def review_count(self):
        return len(self.published_reviews)

    @property
    def average_rating(self):
        reviews = self.published_reviews
        if not reviews:
            return None
        return round(sum(review.rating for review in reviews) / len(reviews), 1)

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

    def soft_delete(self, note=None):
        if self.status != AppStatus.DELETED:
            self.status_before_delete = self.status.value
        self.status = AppStatus.DELETED
        self.deleted_at = datetime.now(timezone.utc)
        self.review_note = note or self.review_note

    def restore(self):
        allowed = {status.value: status for status in AppStatus if status != AppStatus.DELETED}
        self.status = allowed.get(self.status_before_delete, AppStatus.PENDING)
        self.status_before_delete = None
        self.deleted_at = None

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
        self.pending_malware_scan_status = None
        self.pending_malware_scan_summary = None
        self.pending_malware_scanned_at = None
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
        return format_file_size(self.apk_size)


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


class PasswordResetToken(db.Model):
    __tablename__ = "password_reset_token"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(
        db.Integer,
        db.ForeignKey("user.id"),
        nullable=False,
        index=True,
    )
    token_hash = db.Column(db.String(64), unique=True, nullable=False, index=True)
    expires_at = db.Column(db.DateTime(timezone=True), nullable=False, index=True)
    used_at = db.Column(db.DateTime(timezone=True), nullable=True)
    created_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )

    user = db.relationship("User")

    @property
    def is_valid(self):
        expires = self.expires_at
        if expires.tzinfo is None:
            expires = expires.replace(tzinfo=timezone.utc)
        return self.used_at is None and expires > datetime.now(timezone.utc)


class LoginThrottle(db.Model):
    __tablename__ = "login_throttle"

    id = db.Column(db.Integer, primary_key=True)
    key_hash = db.Column(db.String(64), unique=True, nullable=False, index=True)
    attempts = db.Column(db.Integer, nullable=False, default=0)
    window_started_at = db.Column(db.DateTime(timezone=True), nullable=False)
    locked_until = db.Column(db.DateTime(timezone=True), nullable=True)
    updated_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )


class SavedApp(db.Model):
    __tablename__ = "saved_app"
    __table_args__ = (db.UniqueConstraint("user_id", "app_id", name="uq_saved_app_user_app"),)

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
    app_id = db.Column(db.Integer, db.ForeignKey("store_app.id"), nullable=False, index=True)
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))
    user = db.relationship("User", back_populates="saved_apps")
    app = db.relationship("StoreApp", back_populates="saved_by")


class DownloadRecord(db.Model):
    __tablename__ = "download_record"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
    app_id = db.Column(db.Integer, db.ForeignKey("store_app.id"), nullable=False, index=True)
    version = db.Column(db.String(40), nullable=False)
    downloaded_at = db.Column(db.DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc), index=True)
    user = db.relationship("User", back_populates="downloads")
    app = db.relationship("StoreApp", back_populates="download_records")


class AppReview(db.Model):
    __tablename__ = "app_review"
    __table_args__ = (
        db.UniqueConstraint("user_id", "app_id", name="uq_app_review_user_app"),
        db.CheckConstraint("rating >= 1 AND rating <= 5", name="ck_app_review_rating"),
    )

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
    app_id = db.Column(db.Integer, db.ForeignKey("store_app.id"), nullable=False, index=True)
    rating = db.Column(db.Integer, nullable=False)
    comment = db.Column(db.Text, nullable=True)
    status = db.Column(db.Enum(ReviewStatus, values_callable=enum_values, native_enum=False, validate_strings=True, length=20), nullable=False, default=ReviewStatus.PUBLISHED, index=True)
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))
    updated_at = db.Column(db.DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
    user = db.relationship("User", back_populates="reviews")
    app = db.relationship("StoreApp", back_populates="reviews")


class AppReport(db.Model):
    __tablename__ = "app_report"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
    app_id = db.Column(db.Integer, db.ForeignKey("store_app.id"), nullable=False, index=True)
    reason = db.Column(db.Enum(ReportReason, values_callable=enum_values, native_enum=False, validate_strings=True, length=30), nullable=False)
    details = db.Column(db.Text, nullable=False)
    status = db.Column(db.Enum(ReportStatus, values_callable=enum_values, native_enum=False, validate_strings=True, length=20), nullable=False, default=ReportStatus.OPEN, index=True)
    admin_note = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc), index=True)
    resolved_at = db.Column(db.DateTime(timezone=True), nullable=True)
    user = db.relationship("User", back_populates="reports")
    app = db.relationship("StoreApp", back_populates="reports")


class AuditLog(db.Model):
    __tablename__ = "audit_log"

    id = db.Column(db.Integer, primary_key=True)
    admin_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
    action = db.Column(db.Enum(AuditAction, values_callable=enum_values, native_enum=False, validate_strings=True, length=40), nullable=False, index=True)
    operation = db.Column(db.String(30), nullable=False)
    target_type = db.Column(db.String(30), nullable=False, index=True)
    target_id = db.Column(db.Integer, nullable=True)
    target_label = db.Column(db.String(180), nullable=False)
    note = db.Column(db.Text, nullable=True)
    ip_address = db.Column(db.String(64), nullable=True)
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc), index=True)

    admin = db.relationship("User", foreign_keys=[admin_id])


class Notification(db.Model):
    __tablename__ = "notification"

    id = db.Column(db.Integer, primary_key=True)
    recipient_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
    type = db.Column(db.Enum(NotificationType, values_callable=enum_values, native_enum=False, validate_strings=True, length=20), nullable=False, index=True)
    title = db.Column(db.String(160), nullable=False)
    message = db.Column(db.Text, nullable=False)
    link = db.Column(db.String(255), nullable=True)
    is_read = db.Column(db.Boolean, nullable=False, default=False, index=True)
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc), index=True)

    recipient = db.relationship("User", back_populates="notifications")

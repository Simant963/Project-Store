import json
import hashlib
import re
import secrets
import smtplib
import subprocess
import zipfile
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from functools import wraps
from pathlib import Path, PurePosixPath
from queue import Empty
from urllib.parse import urlparse

from PIL import Image, ImageOps, UnidentifiedImageError
from flask import (
    Blueprint,
    Response,
    abort,
    current_app,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    send_file,
    stream_with_context,
    url_for,
)
from sqlalchemy import case, func, or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import joinedload, selectinload
from werkzeug.utils import secure_filename

from .database import db
from .models import (
    AccountStatus,
    AuditAction,
    AuditLog,
    AgeRating,
    AppCategory,
    AppStatus,
    AppScreenshot,
    AppReport,
    AppReview,
    AppVersionHistory,
    DeveloperProfile,
    DownloadRecord,
    GovernmentIdType,
    LoginThrottle,
    Notification,
    NotificationType,
    PasswordResetToken,
    ReportReason,
    ReportStatus,
    ReleaseStatus,
    SecurityScanStatus,
    SavedApp,
    ReviewStatus,
    StoreApp,
    User,
    UserRole,
)
from .realtime import account_events
from .username_linked_list import username_index

main = Blueprint("main", __name__)


def get_csrf_token():
    token = session.get("_csrf_token")
    if token is None:
        token = secrets.token_urlsafe(32)
        session["_csrf_token"] = token
    return token


def valid_csrf_token():
    submitted = request.form.get("csrf_token", "")
    saved = session.get("_csrf_token", "")
    return bool(saved) and secrets.compare_digest(saved, submitted)


def current_user():
    user_id = session.get("user_id")
    return db.session.get(User, user_id) if user_id else None


def client_ip_address():
    """Use ProxyFix-normalized remote_addr; never trust forwarding headers directly."""
    return request.remote_addr or "unknown"


def record_admin_audit(
    admin, action, operation, target_type, target_id, target_label, note=None
):
    remote = client_ip_address()
    db.session.add(
        AuditLog(
            admin_id=admin.id,
            action=action,
            operation=operation,
            target_type=target_type,
            target_id=target_id,
            target_label=target_label,
            note=note or None,
            ip_address=remote,
        )
    )


def create_notification(recipient_id, notification_type, title, message, link=None):
    db.session.add(
        Notification(
            recipient_id=recipient_id,
            type=notification_type,
            title=title,
            message=message,
            link=link,
        )
    )


def dashboard_url_for(user):
    destinations = {
        UserRole.ADMIN: "main.admin_dashboard",
        UserRole.CO_ADMIN: "main.admin_apps",
        UserRole.DEVELOPER: "main.developer_dashboard",
        UserRole.USER: "main.user_dashboard",
    }
    return url_for(destinations[user.role])


def sign_in_user(user, remember=False):
    session.clear()
    session["user_id"] = user.id
    session["username"] = user.username
    session["role"] = user.role.value
    session["_csrf_token"] = secrets.token_urlsafe(32)
    session.permanent = remember
    user.last_login_at = datetime.now(timezone.utc)
    db.session.commit()


def aware_datetime(value):
    if value is None or value.tzinfo is not None:
        return value
    return value.replace(tzinfo=timezone.utc)


def login_throttle_key(scope, identifier):
    remote = client_ip_address()
    value = f"{scope}|{remote}|{identifier.casefold().strip()}"
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def login_is_throttled(scope, identifier):
    record = LoginThrottle.query.filter_by(
        key_hash=login_throttle_key(scope, identifier)
    ).first()
    if record is None or record.locked_until is None:
        return False
    return aware_datetime(record.locked_until) > datetime.now(timezone.utc)


def record_login_failure(scope, identifier):
    now = datetime.now(timezone.utc)
    key_hash = login_throttle_key(scope, identifier)
    record = LoginThrottle.query.filter_by(key_hash=key_hash).first()
    if record is None:
        record = LoginThrottle(
            key_hash=key_hash,
            attempts=0,
            window_started_at=now,
        )
        db.session.add(record)
    window_start = aware_datetime(record.window_started_at)
    if now - window_start > timedelta(minutes=15):
        record.attempts = 0
        record.window_started_at = now
        record.locked_until = None
    record.attempts += 1
    if record.attempts >= 5:
        record.locked_until = now + timedelta(minutes=15)
    db.session.commit()


def clear_login_failures(scope, identifier):
    record = LoginThrottle.query.filter_by(
        key_hash=login_throttle_key(scope, identifier)
    ).first()
    if record:
        db.session.delete(record)
        db.session.commit()


def deliver_password_reset(user, reset_url):
    smtp_host = current_app.config.get("SMTP_HOST")
    if not smtp_host:
        return False
    message = EmailMessage()
    message["Subject"] = "Reset your Appora password"
    message["From"] = current_app.config["SMTP_FROM_EMAIL"]
    message["To"] = user.email
    message.set_content(
        "A password reset was requested for your Appora account.\n\n"
        f"Reset your password: {reset_url}\n\n"
        "This link expires in 30 minutes. If you did not request it, ignore this email."
    )
    with smtplib.SMTP(
        smtp_host,
        current_app.config["SMTP_PORT"],
        timeout=15,
    ) as smtp:
        if current_app.config["SMTP_USE_TLS"]:
            smtp.starttls()
        if current_app.config.get("SMTP_USERNAME"):
            smtp.login(
                current_app.config["SMTP_USERNAME"],
                current_app.config.get("SMTP_PASSWORD", ""),
            )
        smtp.send_message(message)
    return True


def role_required(required_role):
    def decorator(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            user = current_user()
            if user is None or user.status != AccountStatus.APPROVED:
                session.clear()
                flash("Please sign in with an approved account to continue.", "error")
                if required_role == UserRole.ADMIN:
                    return redirect(url_for("main.admin_login"))
                return redirect(
                    url_for("main.account_login", role_name=required_role.value)
                )
            if user.role != required_role:
                abort(403)
            return view(user, *args, **kwargs)

        return wrapped

    return decorator


def staff_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        user = current_user()
        if (
            user is None
            or user.role not in {UserRole.ADMIN, UserRole.CO_ADMIN}
            or user.status != AccountStatus.APPROVED
        ):
            session.clear()
            flash("Sign in with an authorized review account to continue.", "error")
            return redirect(url_for("main.admin_login"))
        return view(user, *args, **kwargs)

    return wrapped


def developer_access_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        user = current_user()
        if (
            user is None
            or user.role != UserRole.DEVELOPER
            or user.status in {AccountStatus.BLOCKED, AccountStatus.DELETED}
        ):
            session.clear()
            flash("Please sign in with your developer account to continue.", "error")
            return redirect(url_for("main.account_login", role_name="developer"))
        return view(user, *args, **kwargs)

    return wrapped


def require_permanent_delete_confirmation(admin, target_type, target_label, cancel_url):
    """Return a confirmation response until the admin re-authenticates correctly."""
    confirmed = request.form.get("permanent_confirm") == "yes"
    typed_label = request.form.get("confirm_label", "").strip()
    password = request.form.get("admin_password", "")
    if (
        confirmed
        and secrets.compare_digest(typed_label, target_label)
        and admin.check_password(password)
    ):
        return None

    error = None
    if confirmed:
        error = "The password or confirmation name was incorrect. Nothing was deleted."
    return render_template(
        "hard_delete_confirm.html",
        admin=admin,
        target_type=target_type,
        target_label=target_label,
        cancel_url=cancel_url,
        csrf_token=get_csrf_token(),
        error=error,
    ), 400 if error else 200


def private_upload_folder(folder):
    root = Path(current_app.config["PRIVATE_UPLOAD_ROOT"]).resolve()
    target = (root / folder).resolve()
    if target.parent != root:
        raise ValueError("Invalid upload folder")
    target.mkdir(parents=True, exist_ok=True)
    return target


def safe_delete_upload(folder, filename):
    if not filename or Path(filename).name != filename:
        return
    directory = private_upload_folder(folder)
    target = (directory / filename).resolve()
    if target.parent == directory and target.is_file():
        target.unlink()


def upload_size(file_storage):
    file_storage.stream.seek(0, 2)
    size = file_storage.stream.tell()
    file_storage.stream.seek(0)
    return size


def detect_image_extension(file_storage):
    header = file_storage.stream.read(16)
    file_storage.stream.seek(0)
    if header.startswith(b"\xff\xd8\xff"):
        return ".jpg"
    if header.startswith(b"\x89PNG\r\n\x1a\n"):
        return ".png"
    if header.startswith(b"RIFF") and header[8:12] == b"WEBP":
        return ".webp"
    return None


def save_image_upload(file_storage, folder, maximum_bytes):
    if not file_storage or not file_storage.filename:
        raise ValueError("Choose an image to upload.")
    size = upload_size(file_storage)
    if size <= 0 or size > maximum_bytes:
        raise ValueError(
            f"Image must be smaller than {maximum_bytes // (1024 * 1024)} MB."
        )
    extension = detect_image_extension(file_storage)
    if extension is None:
        raise ValueError("Upload a JPG, PNG, or WebP image.")

    formats = {".jpg": "JPEG", ".png": "PNG", ".webp": "WEBP"}
    try:
        file_storage.stream.seek(0)
        with Image.open(file_storage.stream) as image:
            image.verify()
        file_storage.stream.seek(0)
        with Image.open(file_storage.stream) as image:
            width, height = image.size
            if (
                width < 1
                or height < 1
                or width > 12000
                or height > 12000
                or width * height > 40_000_000
            ):
                raise ValueError("Image dimensions are outside the safe limit.")
            image = ImageOps.exif_transpose(image)
            if extension == ".jpg":
                clean_image = image.convert("RGB")
            else:
                clean_image = image.convert(
                    "RGBA" if "A" in image.getbands() else "RGB"
                )
            clean_image.load()
    except (
        UnidentifiedImageError,
        OSError,
        SyntaxError,
        Image.DecompressionBombError,
    ) as error:
        raise ValueError("The image is damaged or has an unsafe structure.") from error

    stored_name = f"{secrets.token_hex(20)}{extension}"
    target = private_upload_folder(folder) / stored_name
    try:
        save_options = (
            {"quality": 90} if extension in {".jpg", ".webp"} else {"optimize": True}
        )
        clean_image.save(target, format=formats[extension], **save_options)
    except OSError as error:
        if target.is_file():
            target.unlink()
        raise ValueError("The image could not be stored safely.") from error
    original_name = secure_filename(file_storage.filename) or f"upload{extension}"
    return stored_name, original_name, target.stat().st_size


def save_apk_upload(file_storage):
    if not file_storage or not file_storage.filename:
        raise ValueError("Choose an APK file to upload.")
    original_name = secure_filename(file_storage.filename)
    if not original_name.lower().endswith(".apk"):
        raise ValueError("The application file must use the .apk extension.")
    size = upload_size(file_storage)
    maximum_bytes = current_app.config["APK_MAX_BYTES"]
    if size <= 0 or size > maximum_bytes:
        raise ValueError(
            f"APK must be smaller than {maximum_bytes // (1024 * 1024)} MB."
        )
    signature = file_storage.stream.read(4)
    file_storage.stream.seek(0)
    if signature not in {b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08"}:
        raise ValueError("The uploaded file is not a valid APK archive.")

    stored_name = f"{secrets.token_hex(24)}.apk"
    target = private_upload_folder("apks") / stored_name
    try:
        file_storage.save(target)
        scan_summary = inspect_apk_archive(target)
        malware_summary = scan_apk_for_malware(target)
        digest = hashlib.sha256()
        with target.open("rb") as apk_file:
            for chunk in iter(lambda: apk_file.read(1024 * 1024), b""):
                digest.update(chunk)
    except Exception:
        if target.is_file():
            target.unlink()
        raise
    return (
        stored_name,
        original_name,
        size,
        digest.hexdigest(),
        scan_summary,
        malware_summary,
    )


def scan_apk_for_malware(path):
    """Fail closed unless ClamAV explicitly reports a clean APK."""
    command = current_app.config["CLAMAV_COMMAND"]
    timeout = current_app.config["CLAMAV_TIMEOUT_SECONDS"]
    try:
        result = subprocess.run(
            [command, "--no-summary", "--infected", str(path)],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            creationflags=subprocess.CREATE_NO_WINDOW
            if hasattr(subprocess, "CREATE_NO_WINDOW")
            else 0,
        )
    except FileNotFoundError as error:
        raise ValueError(
            "Virus scanner is unavailable. The app was not submitted."
        ) from error
    except subprocess.TimeoutExpired as error:
        raise ValueError(
            "Virus scanning timed out. The app was not submitted."
        ) from error
    except OSError as error:
        raise ValueError(
            "Virus scanning could not start. The app was not submitted."
        ) from error

    if result.returncode == 0:
        return "ClamAV malware scan passed · no threats detected"
    if result.returncode == 1:
        current_app.logger.warning(
            "ClamAV rejected an APK: %s", (result.stdout or "threat detected")[-1000:]
        )
        raise ValueError("The APK was rejected because malware was detected.")
    current_app.logger.error(
        "ClamAV scan error %s: %s",
        result.returncode,
        (result.stderr or result.stdout)[-1000:],
    )
    raise ValueError("Virus scanning failed. The app was not submitted.")


def inspect_apk_archive(path):
    """Perform bounded structural checks without claiming malware detection."""
    try:
        with zipfile.ZipFile(path) as archive:
            entries = archive.infolist()
            if not entries:
                raise ValueError("The APK archive is empty.")
            if len(entries) > 20000:
                raise ValueError("The APK contains too many files to review safely.")

            total_compressed = 0
            total_uncompressed = 0
            names = set()
            dex_files = 0
            native_libraries = 0
            for entry in entries:
                name = entry.filename
                normalized = PurePosixPath(name)
                if (
                    not name
                    or "\\" in name
                    or name.startswith("/")
                    or ".." in normalized.parts
                    or (normalized.parts and ":" in normalized.parts[0])
                ):
                    raise ValueError("The APK contains an unsafe file path.")
                if entry.flag_bits & 0x1:
                    raise ValueError("Encrypted APK entries cannot be reviewed safely.")
                if entry.file_size > 512 * 1024 * 1024:
                    raise ValueError(
                        "The APK contains an unexpectedly large internal file."
                    )
                names.add(name.rstrip("/"))
                total_compressed += entry.compress_size
                total_uncompressed += entry.file_size
                lowered = name.casefold()
                if re.fullmatch(r"classes\d*\.dex", lowered):
                    dex_files += 1
                if lowered.startswith("lib/") and lowered.endswith(".so"):
                    native_libraries += 1

            if "AndroidManifest.xml" not in names:
                raise ValueError("The APK is missing AndroidManifest.xml.")
            if total_uncompressed > 1536 * 1024 * 1024:
                raise ValueError("The APK expands beyond the safe review limit.")
            compression_ratio = total_uncompressed / max(total_compressed, 1)
            if total_uncompressed > 100 * 1024 * 1024 and compression_ratio > 200:
                raise ValueError("The APK has an unsafe compression ratio.")

            manifest = archive.getinfo("AndroidManifest.xml")
            if manifest.file_size <= 0 or manifest.file_size > 20 * 1024 * 1024:
                raise ValueError("The Android manifest has an invalid size.")
            with archive.open(manifest) as manifest_file:
                manifest_file.read(min(manifest.file_size, 64))
    except zipfile.BadZipFile as error:
        raise ValueError("The uploaded file is not a readable APK archive.") from error

    components = []
    if dex_files:
        components.append(f"{dex_files} DEX file{'s' if dex_files != 1 else ''}")
    if native_libraries:
        components.append(
            f"{native_libraries} native librar{'ies' if native_libraries != 1 else 'y'}"
        )
    component_text = " · ".join(components) if components else "resource-only package"
    return (
        f"Archive structure passed · Android manifest found · {len(entries)} files checked "
        f"· {component_text}"
    )


def duplicate_apk_exists(digest, exclude_app_id=None, allow_pending_app_id=None):
    current_query = StoreApp.query.filter(StoreApp.apk_sha256 == digest)
    if exclude_app_id is not None:
        current_query = current_query.filter(StoreApp.id != exclude_app_id)
    if current_query.first():
        return True

    pending_query = StoreApp.query.filter(StoreApp.pending_apk_sha256 == digest)
    excluded_pending_ids = {
        value for value in (exclude_app_id, allow_pending_app_id) if value is not None
    }
    if excluded_pending_ids:
        pending_query = pending_query.filter(~StoreApp.id.in_(excluded_pending_ids))
    if pending_query.first():
        return True

    history_query = AppVersionHistory.query.filter(
        AppVersionHistory.apk_sha256 == digest
    )
    if exclude_app_id is not None:
        history_query = history_query.filter(AppVersionHistory.app_id != exclude_app_id)
    return history_query.first() is not None


def is_valid_web_url(value, required=False):
    if not value:
        return not required
    parsed = urlparse(value)
    return parsed.scheme in {"http", "https"} and bool(parsed.netloc)


def unique_app_slug(name):
    base = re.sub(r"[^a-z0-9]+", "-", name.casefold()).strip("-") or "app"
    slug = base
    while StoreApp.query.filter_by(slug=slug).first():
        slug = f"{base}-{secrets.token_hex(3)}"
    return slug


def send_private_upload(
    folder, filename, download_name=None, as_attachment=False, public_cache=False
):
    if not filename or Path(filename).name != filename:
        abort(404)
    directory = private_upload_folder(folder)
    path = (directory / filename).resolve()
    if path.parent != directory or not path.is_file():
        abort(404)
    response = send_file(
        path,
        as_attachment=as_attachment,
        download_name=download_name,
        conditional=True,
    )
    response.headers["X-Content-Type-Options"] = "nosniff"
    if public_cache:
        response.headers["Cache-Control"] = "public, max-age=86400, immutable"
    else:
        response.headers["Cache-Control"] = "private, no-store"
        response.headers["Pragma"] = "no-cache"
    return response


def validate_registration(form, role):
    username = form.get("username", "").strip()
    email = form.get("email", "").strip().lower()
    password = form.get("password", "")
    confirm_password = form.get("confirm_password", "")
    company_name = form.get("company_name", "").strip()
    errors = []

    if not re.fullmatch(r"[A-Za-z0-9_]{3,30}", username):
        errors.append(
            "Username must be 3–30 characters using letters, numbers, or underscores."
        )
    if not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email):
        errors.append("Enter a valid email address.")
    if (
        len(password) < 8
        or not re.search(r"[A-Za-z]", password)
        or not re.search(r"\d", password)
    ):
        errors.append(
            "Password must be at least 8 characters and include a letter and a number."
        )
    if password != confirm_password:
        errors.append("Passwords do not match.")
    if role == UserRole.DEVELOPER and len(company_name) < 2:
        errors.append("Enter your developer or studio name.")

    username_exists = username_index.contains(username)
    email_exists = User.query.filter(func.lower(User.email) == email).first()
    if username_exists:
        errors.append("That username is already in use.")
    if email_exists:
        errors.append("An account already exists with that email.")

    return errors, {
        "username": username,
        "email": email,
        "password": password,
        "company_name": company_name or None,
    }


@main.route("/")
def home():
    approved_apps = (
        StoreApp.query.filter_by(status=AppStatus.APPROVED)
        .order_by(StoreApp.approved_at.desc(), StoreApp.id.desc())
        .limit(6)
        .all()
    )
    return render_template("home.html", approved_apps=approved_apps)


@main.get("/policies")
def policy_center():
    return render_template("policy_center.html")


@main.get("/privacy")
def privacy_policy():
    return render_template("privacy_policy.html")


@main.get("/terms")
def terms_of_service():
    return render_template("terms_of_service.html")


@main.get("/developer-agreement")
def developer_agreement():
    return render_template("developer_agreement.html")


@main.get("/acceptable-use")
def acceptable_use_policy():
    return render_template("acceptable_use_policy.html")


@main.get("/copyright")
def copyright_policy():
    return render_template("copyright_policy.html")


@main.get("/data-retention")
def data_retention_policy():
    return render_template("data_retention_policy.html")


@main.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    requested_role = request.form.get("role") or request.args.get(
        "role", UserRole.USER.value
    )
    if requested_role not in {UserRole.USER.value, UserRole.DEVELOPER.value}:
        requested_role = UserRole.USER.value
    development_reset_url = None
    request_sent = False
    if request.method == "POST":
        if not valid_csrf_token():
            flash("Your session expired. Please try again.", "error")
            return redirect(url_for("main.forgot_password"))
        email = request.form.get("email", "").strip().lower()
        if not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email):
            flash("Enter a valid email address.", "error")
        else:
            throttled = login_is_throttled("password-reset", email)
            if not throttled:
                record_login_failure("password-reset", email)
                user = User.query.filter(
                    func.lower(User.email) == email,
                    User.status != AccountStatus.BLOCKED,
                ).first()
                if user:
                    now = datetime.now(timezone.utc)
                    PasswordResetToken.query.filter_by(
                        user_id=user.id,
                        used_at=None,
                    ).update({"used_at": now})
                    raw_token = secrets.token_urlsafe(40)
                    reset_record = PasswordResetToken(
                        user_id=user.id,
                        token_hash=hashlib.sha256(
                            raw_token.encode("utf-8")
                        ).hexdigest(),
                        expires_at=now + timedelta(minutes=30),
                    )
                    db.session.add(reset_record)
                    db.session.commit()
                    reset_url = current_app.config["PUBLIC_BASE_URL"] + url_for(
                        "main.reset_password", token=raw_token
                    )
                    try:
                        delivered = deliver_password_reset(user, reset_url)
                    except (OSError, smtplib.SMTPException):
                        delivered = False
                    if (
                        current_app.debug
                        and not delivered
                        and current_app.config["PUBLIC_BASE_URL"].startswith(
                            ("http://127.0.0.1", "http://localhost")
                        )
                    ):
                        development_reset_url = reset_url
            request_sent = True

    return render_template(
        "password_recovery.html",
        mode="request",
        request_sent=request_sent,
        development_reset_url=development_reset_url,
        recovery_role=requested_role,
        csrf_token=get_csrf_token(),
    )


@main.route("/reset-password/<token>", methods=["GET", "POST"])
def reset_password(token):
    token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
    reset_record = PasswordResetToken.query.filter_by(token_hash=token_hash).first()
    if reset_record is None or not reset_record.is_valid:
        return render_template(
            "password_recovery.html",
            mode="invalid",
            csrf_token=get_csrf_token(),
        ), 400

    if request.method == "POST":
        if not valid_csrf_token():
            flash("Your session expired. Please try again.", "error")
            return redirect(url_for("main.reset_password", token=token))
        password = request.form.get("password", "")
        confirmation = request.form.get("confirm_password", "")
        if (
            len(password) < 8
            or not re.search(r"[A-Za-z]", password)
            or not re.search(r"\d", password)
        ):
            flash(
                "Password must be at least 8 characters and include a letter and a number.",
                "error",
            )
        elif password != confirmation:
            flash("Passwords do not match.", "error")
        else:
            now = datetime.now(timezone.utc)
            reset_record.user.set_password(password)
            PasswordResetToken.query.filter_by(
                user_id=reset_record.user_id,
                used_at=None,
            ).update({"used_at": now})
            db.session.commit()
            session.clear()
            flash(
                "Your password was updated. Sign in with the new password.", "success"
            )
            return redirect(
                url_for("main.account_login", role_name=reset_record.user.role.value)
                if reset_record.user.role not in {UserRole.ADMIN, UserRole.CO_ADMIN}
                else url_for("main.admin_login")
            )

    return render_template(
        "password_recovery.html",
        mode="reset",
        token=token,
        csrf_token=get_csrf_token(),
    )


@main.get("/api/usernames/availability")
def username_availability():
    username = request.args.get("username", "").strip()
    valid = bool(re.fullmatch(r"[A-Za-z0-9_]{3,30}", username))
    return jsonify(
        {
            "username": username,
            "valid": valid,
            "available": valid and not username_index.contains(username),
        }
    )


@main.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    signed_in = current_user()
    if signed_in and signed_in.role in {UserRole.ADMIN, UserRole.CO_ADMIN}:
        return redirect(dashboard_url_for(signed_in))

    if request.method == "POST":
        if not valid_csrf_token():
            flash("Your session expired. Please try again.", "error")
            return redirect(url_for("main.admin_login"))

        identifier = request.form.get("identifier", "").strip()
        password = request.form.get("password", "")
        if login_is_throttled("admin-login", identifier):
            flash("Too many sign-in attempts. Try again in 15 minutes.", "error")
            return redirect(url_for("main.admin_login"))
        admin = User.query.filter(
            User.role.in_([UserRole.ADMIN, UserRole.CO_ADMIN]),
            or_(
                func.lower(User.username) == identifier.lower(),
                func.lower(User.email) == identifier.lower(),
            ),
        ).first()

        if (
            admin
            and admin.status == AccountStatus.APPROVED
            and admin.check_password(password)
        ):
            clear_login_failures("admin-login", identifier)
            sign_in_user(admin, request.form.get("remember") == "on")
            flash("Welcome back. You are signed in.", "success")
            return redirect(dashboard_url_for(admin))

        record_login_failure("admin-login", identifier)
        flash("Incorrect administrator username or password.", "error")

    return render_template(
        "auth_login.html",
        account_role=UserRole.ADMIN,
        csrf_token=get_csrf_token(),
    )


@main.route("/login/<role_name>", methods=["GET", "POST"])
def account_login(role_name):
    try:
        role = UserRole(role_name)
    except ValueError:
        abort(404)
    if role in {UserRole.ADMIN, UserRole.CO_ADMIN}:
        return redirect(url_for("main.admin_login"))

    signed_in = current_user()
    if signed_in and signed_in.role == role:
        if signed_in.status == AccountStatus.APPROVED:
            return redirect(dashboard_url_for(signed_in))
        if role == UserRole.DEVELOPER and signed_in.status in {
            AccountStatus.PENDING,
            AccountStatus.REJECTED,
        }:
            return redirect(url_for("main.developer_verification"))

    if request.method == "POST":
        if not valid_csrf_token():
            flash("Your session expired. Please try again.", "error")
            return redirect(url_for("main.account_login", role_name=role.value))

        identifier = request.form.get("identifier", "").strip()
        password = request.form.get("password", "")
        if login_is_throttled(f"{role.value}-login", identifier):
            flash("Too many sign-in attempts. Try again in 15 minutes.", "error")
            return redirect(url_for("main.account_login", role_name=role.value))
        user = User.query.filter(
            User.role == role,
            or_(
                func.lower(User.username) == identifier.lower(),
                func.lower(User.email) == identifier.lower(),
            ),
        ).first()

        if not user or not user.check_password(password):
            record_login_failure(f"{role.value}-login", identifier)
            flash("Incorrect email, username, or password.", "error")
        elif user.status == AccountStatus.BLOCKED:
            flash(
                "This account has been blocked. Contact the marketplace administrator.",
                "error",
            )
        elif role == UserRole.DEVELOPER and user.status in {
            AccountStatus.PENDING,
            AccountStatus.REJECTED,
        }:
            clear_login_failures(f"{role.value}-login", identifier)
            sign_in_user(user, request.form.get("remember") == "on")
            return redirect(url_for("main.developer_verification"))
        elif user.status == AccountStatus.PENDING:
            flash("This account is waiting for administrator approval.", "warning")
        elif user.status == AccountStatus.REJECTED:
            flash(
                "This account request was not approved. Contact the marketplace administrator.",
                "error",
            )
        else:
            clear_login_failures(f"{role.value}-login", identifier)
            sign_in_user(user, request.form.get("remember") == "on")
            return redirect(dashboard_url_for(user))

    return render_template(
        "auth_login.html",
        account_role=role,
        csrf_token=get_csrf_token(),
    )


@main.route("/register")
def register():
    return redirect(url_for("main.create_account", role_name=UserRole.USER.value))


@main.route("/register/<role_name>", methods=["GET", "POST"])
def create_account(role_name):
    try:
        role = UserRole(role_name)
    except ValueError:
        abort(404)
    if role in {UserRole.ADMIN, UserRole.CO_ADMIN}:
        abort(404)

    form_values = {
        "username": request.form.get("username", ""),
        "email": request.form.get("email", ""),
        "company_name": request.form.get("company_name", ""),
    }

    if request.method == "POST":
        if not valid_csrf_token():
            flash("Your session expired. Please try again.", "error")
            return redirect(url_for("main.create_account", role_name=role.value))

        errors, values = validate_registration(request.form, role)
        if request.form.get("accept_terms") != "yes":
            errors.append(
                "You must accept the Terms, Privacy Policy, and Acceptable Use Policy."
            )
        if errors:
            for error in errors:
                flash(error, "error")
        else:
            status = (
                AccountStatus.PENDING
                if role == UserRole.DEVELOPER
                else AccountStatus.APPROVED
            )
            account = User(
                username=values["username"],
                email=values["email"],
                company_name=values["company_name"],
                role=role,
                status=status,
                terms_accepted_at=datetime.now(timezone.utc),
                terms_version=current_app.config["POLICY_VERSION"],
            )
            account.set_password(values["password"])
            if status == AccountStatus.APPROVED:
                account.approve()
            db.session.add(account)
            try:
                db.session.commit()
            except IntegrityError:
                db.session.rollback()
                flash(
                    "That username or email was just registered. Try another one.",
                    "error",
                )
                return render_template(
                    "register.html",
                    account_role=role,
                    form_values=form_values,
                    csrf_token=get_csrf_token(),
                )

            username_index.add(account.username, account.id)
            account_events.publish(
                {
                    "type": "account_created",
                    "user_id": account.id,
                    "username": account.username,
                    "role": account.role.value,
                    "status": account.status.value,
                }
            )
            return render_template(
                "account_created.html",
                account=account,
                csrf_token=get_csrf_token(),
            )

    return render_template(
        "register.html",
        account_role=role,
        form_values=form_values,
        csrf_token=get_csrf_token(),
    )


@main.route("/developer/verification", methods=["GET", "POST"])
@developer_access_required
def developer_verification(user):
    profile = user.developer_profile
    if profile is None:
        profile = DeveloperProfile(user=user)
        db.session.add(profile)

    if request.method == "POST":
        if not valid_csrf_token():
            flash("Your session expired. Please try again.", "error")
            return redirect(url_for("main.developer_verification"))

        legal_name = request.form.get("legal_name", "").strip()
        phone = request.form.get("phone", "").strip()
        country = request.form.get("country", "").strip()
        website = request.form.get("website", "").strip()
        id_number = request.form.get("government_id_number", "").strip()
        try:
            id_type = GovernmentIdType(request.form.get("government_id_type", ""))
        except ValueError:
            id_type = None

        errors = []
        if len(legal_name) < 3:
            errors.append("Enter your full legal name.")
        if not re.fullmatch(r"[+0-9][0-9()\-\s]{6,24}", phone):
            errors.append("Enter a valid phone number.")
        if len(country) < 2:
            errors.append("Enter your country.")
        if id_type is None:
            errors.append("Choose a government ID type.")
        if len(id_number) < 4:
            errors.append("Enter the government ID number.")
        if website and not is_valid_web_url(website):
            errors.append("Website must start with http:// or https://.")

        id_upload = request.files.get("government_id_photo")
        new_id_file = None
        new_id_original = None
        if not errors and id_upload and id_upload.filename:
            try:
                new_id_file, new_id_original, _ = save_image_upload(
                    id_upload,
                    "developer_ids",
                    current_app.config["DEVELOPER_ID_MAX_BYTES"],
                )
            except ValueError as error:
                errors.append(str(error))
        elif not profile.government_id_file:
            errors.append("Upload a clear photo of your government ID.")

        if errors:
            for error in errors:
                flash(error, "error")
        else:
            old_id_file = profile.government_id_file
            profile.legal_name = legal_name
            profile.phone = phone
            profile.country = country
            profile.website = website or None
            profile.government_id_type = id_type
            profile.government_id_number = id_number
            if new_id_file:
                profile.government_id_file = new_id_file
                profile.government_id_original_name = new_id_original
            profile.submitted_at = datetime.now(timezone.utc)
            profile.reviewed_at = None
            profile.review_note = None
            user.status = AccountStatus.PENDING
            user.approved_at = None
            db.session.commit()
            if new_id_file and old_id_file and old_id_file != new_id_file:
                safe_delete_upload("developer_ids", old_id_file)
            account_events.publish(
                {
                    "type": "account_updated",
                    "action": "verification_submitted",
                    "user_id": user.id,
                    "username": user.username,
                    "role": user.role.value,
                    "status": user.status.value,
                }
            )
            flash(
                "Your verification details were sent for administrator review.",
                "success",
            )
            return redirect(url_for("main.developer_verification"))

    return render_template(
        "developer_verification.html",
        user=user,
        profile=profile,
        id_types=GovernmentIdType,
        csrf_token=get_csrf_token(),
    )


@main.route("/developer/apps/new", methods=["GET", "POST"])
@main.route("/developer/apps/<int:app_id>/edit", methods=["GET", "POST"])
@developer_access_required
def submit_app(user, app_id=None):
    if user.status != AccountStatus.APPROVED:
        flash(
            "Administrator approval is required before you can upload an app.",
            "warning",
        )
        return redirect(url_for("main.developer_verification"))
    if not user.developer_profile or not user.developer_profile.is_submitted:
        flash("Complete developer verification before uploading an app.", "error")
        return redirect(url_for("main.developer_verification"))

    app_record = None
    if app_id is not None:
        app_record = db.session.get(StoreApp, app_id)
        if app_record is None or app_record.developer_id != user.id:
            abort(404)
        if app_record.status != AppStatus.REJECTED:
            flash("Only rejected submissions can be edited and resubmitted.", "warning")
            return redirect(url_for("main.developer_dashboard"))

    field_names = (
        "name",
        "package_name",
        "short_description",
        "description",
        "version",
        "min_android_version",
        "category",
        "age_rating",
        "website",
        "support_email",
        "privacy_policy_url",
        "changelog",
    )
    if request.method == "POST":
        form_values = {key: request.form.get(key, "") for key in field_names}
    elif app_record:
        form_values = {
            "name": app_record.name,
            "package_name": app_record.package_name,
            "short_description": app_record.short_description,
            "description": app_record.description,
            "version": app_record.version,
            "min_android_version": app_record.min_android_version,
            "category": app_record.category.value,
            "age_rating": app_record.age_rating.value,
            "website": app_record.website or "",
            "support_email": app_record.support_email,
            "privacy_policy_url": app_record.privacy_policy_url,
            "changelog": app_record.changelog or "",
        }
    else:
        form_values = {key: "" for key in field_names}

    if request.method == "POST":
        if not valid_csrf_token():
            flash("Your session expired. Please try again.", "error")
            return redirect(url_for("main.submit_app"))

        name = form_values["name"].strip()
        package_name = form_values["package_name"].strip()
        short_description = form_values["short_description"].strip()
        description = form_values["description"].strip()
        version = form_values["version"].strip()
        min_android_version = form_values["min_android_version"].strip()
        support_email = form_values["support_email"].strip().lower()
        privacy_policy_url = form_values["privacy_policy_url"].strip()
        website = form_values["website"].strip()
        try:
            category = AppCategory(form_values["category"])
        except ValueError:
            category = None
        try:
            age_rating = AgeRating(form_values["age_rating"])
        except ValueError:
            age_rating = None

        errors = []
        if not 2 <= len(name) <= 120:
            errors.append("App name must be between 2 and 120 characters.")
        package_conflict = None
        if not re.fullmatch(
            r"[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z][A-Za-z0-9_]*)+", package_name
        ):
            errors.append("Enter a valid package name such as com.example.myapp.")
        else:
            package_query = StoreApp.query.filter(
                func.lower(StoreApp.package_name) == package_name.lower()
            )
            if app_record:
                package_query = package_query.filter(StoreApp.id != app_record.id)
            package_conflict = package_query.first()
        if package_conflict:
            errors.append("That package name is already registered.")
        if not 20 <= len(short_description) <= 180:
            errors.append("Short description must be between 20 and 180 characters.")
        if len(description) < 80:
            errors.append("Full description must contain at least 80 characters.")
        if not version or len(version) > 40:
            errors.append("Enter a valid version.")
        if not min_android_version or len(min_android_version) > 40:
            errors.append("Enter the minimum Android version.")
        if category is None:
            errors.append("Choose an app category.")
        if age_rating is None:
            errors.append("Choose an age rating.")
        if not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", support_email):
            errors.append("Enter a valid support email.")
        if not is_valid_web_url(privacy_policy_url, required=True):
            errors.append(
                "Enter a valid privacy-policy URL beginning with http:// or https://."
            )
        if website and not is_valid_web_url(website):
            errors.append("App website must begin with http:// or https://.")

        icon_file = None
        apk_file = None
        apk_original = None
        apk_size = None
        apk_sha256 = None
        apk_scan_summary = None
        apk_scan_status = None
        apk_scanned_at = None
        malware_scan_summary = None
        malware_scan_status = None
        malware_scanned_at = None
        new_screenshots = []
        screenshot_uploads = [
            upload
            for upload in request.files.getlist("screenshots")
            if upload and upload.filename
        ]
        if len(screenshot_uploads) > 8:
            errors.append("Upload no more than 8 screenshots.")
        if not errors:
            try:
                icon_upload = request.files.get("app_icon")
                apk_upload = request.files.get("apk_file")
                if icon_upload and icon_upload.filename:
                    icon_file, _, _ = save_image_upload(
                        icon_upload,
                        "app_icons",
                        current_app.config["APP_ICON_MAX_BYTES"],
                    )
                elif app_record:
                    icon_file = app_record.icon_file
                else:
                    raise ValueError("Choose an app icon to upload.")
                if apk_upload and apk_upload.filename:
                    (
                        apk_file,
                        apk_original,
                        apk_size,
                        apk_sha256,
                        apk_scan_summary,
                        malware_scan_summary,
                    ) = save_apk_upload(apk_upload)
                    if duplicate_apk_exists(
                        apk_sha256,
                        exclude_app_id=app_record.id if app_record else None,
                    ):
                        raise ValueError(
                            "This exact APK build is already registered in the marketplace."
                        )
                    apk_scan_status = SecurityScanStatus.PASSED
                    apk_scanned_at = datetime.now(timezone.utc)
                    malware_scan_status = SecurityScanStatus.PASSED
                    malware_scanned_at = datetime.now(timezone.utc)
                elif app_record:
                    apk_file = app_record.apk_file
                    apk_original = app_record.apk_original_name
                    apk_size = app_record.apk_size
                    apk_sha256 = app_record.apk_sha256
                    apk_scan_summary = app_record.security_scan_summary
                    apk_scan_status = app_record.security_scan_status
                    apk_scanned_at = app_record.security_scanned_at
                    malware_scan_summary = app_record.malware_scan_summary
                    malware_scan_status = app_record.malware_scan_status
                    malware_scanned_at = app_record.malware_scanned_at
                else:
                    raise ValueError("Choose an APK file to upload.")
                for position, screenshot_upload in enumerate(screenshot_uploads):
                    stored_name, original_name, _ = save_image_upload(
                        screenshot_upload,
                        "app_screenshots",
                        current_app.config["APP_SCREENSHOT_MAX_BYTES"],
                    )
                    new_screenshots.append(
                        {
                            "file_name": stored_name,
                            "original_name": original_name,
                            "position": position,
                        }
                    )
            except ValueError as error:
                errors.append(str(error))
                if icon_file and (not app_record or icon_file != app_record.icon_file):
                    safe_delete_upload("app_icons", icon_file)
                if apk_file and (not app_record or apk_file != app_record.apk_file):
                    safe_delete_upload("apks", apk_file)
                for screenshot in new_screenshots:
                    safe_delete_upload("app_screenshots", screenshot["file_name"])
                new_screenshots = []

        if errors:
            for error in errors:
                flash(error, "error")
        else:
            old_icon_file = app_record.icon_file if app_record else None
            old_apk_file = app_record.apk_file if app_record else None
            old_screenshot_files = (
                [screenshot.file_name for screenshot in app_record.screenshots]
                if app_record and new_screenshots
                else []
            )
            if app_record is None:
                app_record = StoreApp(developer=user, slug=unique_app_slug(name))
                db.session.add(app_record)
            app_record.name = name
            app_record.package_name = package_name
            app_record.short_description = short_description
            app_record.description = description
            app_record.version = version
            app_record.min_android_version = min_android_version
            app_record.category = category
            app_record.age_rating = age_rating
            app_record.website = website or None
            app_record.support_email = support_email
            app_record.privacy_policy_url = privacy_policy_url
            app_record.changelog = form_values["changelog"].strip() or None
            app_record.icon_file = icon_file
            app_record.apk_file = apk_file
            app_record.apk_original_name = apk_original
            app_record.apk_size = apk_size
            app_record.apk_sha256 = apk_sha256
            app_record.security_scan_status = apk_scan_status
            app_record.security_scan_summary = apk_scan_summary
            app_record.security_scanned_at = apk_scanned_at
            app_record.malware_scan_status = malware_scan_status
            app_record.malware_scan_summary = malware_scan_summary
            app_record.malware_scanned_at = malware_scanned_at
            app_record.status = AppStatus.PENDING
            app_record.review_note = None
            app_record.submitted_at = datetime.now(timezone.utc)
            app_record.approved_at = None
            if new_screenshots:
                app_record.screenshots.clear()
                app_record.screenshots.extend(
                    AppScreenshot(**screenshot) for screenshot in new_screenshots
                )
            try:
                db.session.commit()
            except IntegrityError:
                db.session.rollback()
                if icon_file and icon_file != old_icon_file:
                    safe_delete_upload("app_icons", icon_file)
                if apk_file and apk_file != old_apk_file:
                    safe_delete_upload("apks", apk_file)
                for screenshot in new_screenshots:
                    safe_delete_upload("app_screenshots", screenshot["file_name"])
                flash(
                    "The app or package name was just submitted. Please review your details.",
                    "error",
                )
            else:
                if old_icon_file and old_icon_file != icon_file:
                    safe_delete_upload("app_icons", old_icon_file)
                if old_apk_file and old_apk_file != apk_file:
                    safe_delete_upload("apks", old_apk_file)
                for screenshot_file in old_screenshot_files:
                    safe_delete_upload("app_screenshots", screenshot_file)
                account_events.publish(
                    {
                        "type": "app_resubmitted" if app_id else "app_created",
                        "app_id": app_record.id,
                        "user_id": user.id,
                        "name": app_record.name,
                        "status": app_record.status.value,
                    }
                )
                flash(
                    "Your changes were resubmitted for administrator approval."
                    if app_id
                    else "Your app was uploaded and is waiting for administrator approval.",
                    "success",
                )
                return redirect(url_for("main.developer_dashboard"))

    return render_template(
        "app_submit.html",
        user=user,
        categories=AppCategory,
        age_ratings=AgeRating,
        form_values=form_values,
        app_record=app_record,
        csrf_token=get_csrf_token(),
    )


@main.route("/developer/apps/<int:app_id>/new-version", methods=["GET", "POST"])
@role_required(UserRole.DEVELOPER)
def submit_app_version(user, app_id):
    app_record = db.session.get(StoreApp, app_id)
    if app_record is None or app_record.developer_id != user.id:
        abort(404)
    if app_record.status != AppStatus.APPROVED:
        flash(
            "The first release must be approved before adding another version.",
            "warning",
        )
        return redirect(url_for("main.developer_dashboard"))
    if app_record.pending_release_status == ReleaseStatus.PENDING:
        flash(
            "This app already has a version waiting for administrator review.",
            "warning",
        )
        return redirect(url_for("main.developer_dashboard"))

    if request.method == "POST":
        form_values = {
            "version": request.form.get("version", "").strip(),
            "min_android_version": request.form.get("min_android_version", "").strip(),
            "changelog": request.form.get("changelog", "").strip(),
        }
    else:
        form_values = {
            "version": app_record.pending_version or "",
            "min_android_version": (
                app_record.pending_min_android_version or app_record.min_android_version
            ),
            "changelog": app_record.pending_changelog or "",
        }

    if request.method == "POST":
        if not valid_csrf_token():
            flash("Your session expired. Please try again.", "error")
            return redirect(url_for("main.submit_app_version", app_id=app_id))

        errors = []
        version = form_values["version"]
        min_android_version = form_values["min_android_version"]
        changelog = form_values["changelog"]
        if not version or len(version) > 40:
            errors.append("Enter a valid version number.")
        elif version.casefold() == app_record.version.casefold():
            errors.append(
                "The new version must be different from the published version."
            )
        elif any(
            history.version.casefold() == version.casefold()
            for history in app_record.version_history
        ):
            errors.append("That version number was already published.")
        if not min_android_version or len(min_android_version) > 40:
            errors.append("Enter the minimum Android version.")
        if len(changelog) < 10:
            errors.append("Describe what changed in at least 10 characters.")

        old_pending_apk = app_record.pending_apk_file
        apk_file = None
        apk_original = None
        apk_size = None
        apk_sha256 = None
        apk_scan_summary = None
        apk_scan_status = None
        apk_scanned_at = None
        malware_scan_summary = None
        malware_scan_status = None
        malware_scanned_at = None
        apk_upload = request.files.get("apk_file")
        if not errors:
            try:
                if apk_upload and apk_upload.filename:
                    (
                        apk_file,
                        apk_original,
                        apk_size,
                        apk_sha256,
                        apk_scan_summary,
                        malware_scan_summary,
                    ) = save_apk_upload(apk_upload)
                    if duplicate_apk_exists(
                        apk_sha256,
                        allow_pending_app_id=app_record.id,
                    ):
                        raise ValueError(
                            "This exact APK build is already registered in the marketplace."
                        )
                    apk_scan_status = SecurityScanStatus.PASSED
                    apk_scanned_at = datetime.now(timezone.utc)
                    malware_scan_status = SecurityScanStatus.PASSED
                    malware_scanned_at = datetime.now(timezone.utc)
                elif app_record.pending_apk_file:
                    apk_file = app_record.pending_apk_file
                    apk_original = app_record.pending_apk_original_name
                    apk_size = app_record.pending_apk_size
                    apk_sha256 = app_record.pending_apk_sha256
                    apk_scan_summary = app_record.pending_security_scan_summary
                    apk_scan_status = app_record.pending_security_scan_status
                    apk_scanned_at = app_record.pending_security_scanned_at
                    malware_scan_summary = app_record.pending_malware_scan_summary
                    malware_scan_status = app_record.pending_malware_scan_status
                    malware_scanned_at = app_record.pending_malware_scanned_at
                else:
                    raise ValueError("Choose the APK for this version.")
            except ValueError as error:
                errors.append(str(error))
                if apk_file and apk_file != old_pending_apk:
                    safe_delete_upload("apks", apk_file)

        if errors:
            for error in errors:
                flash(error, "error")
        else:
            app_record.pending_version = version
            app_record.pending_min_android_version = min_android_version
            app_record.pending_changelog = changelog
            app_record.pending_apk_file = apk_file
            app_record.pending_apk_original_name = apk_original
            app_record.pending_apk_size = apk_size
            app_record.pending_apk_sha256 = apk_sha256
            app_record.pending_security_scan_status = apk_scan_status
            app_record.pending_security_scan_summary = apk_scan_summary
            app_record.pending_security_scanned_at = apk_scanned_at
            app_record.pending_malware_scan_status = malware_scan_status
            app_record.pending_malware_scan_summary = malware_scan_summary
            app_record.pending_malware_scanned_at = malware_scanned_at
            app_record.pending_release_status = ReleaseStatus.PENDING
            app_record.pending_release_note = None
            app_record.pending_release_submitted_at = datetime.now(timezone.utc)
            db.session.commit()
            if old_pending_apk and old_pending_apk != apk_file:
                safe_delete_upload("apks", old_pending_apk)
            account_events.publish(
                {
                    "type": "release_submitted",
                    "app_id": app_record.id,
                    "user_id": user.id,
                    "name": app_record.name,
                    "status": ReleaseStatus.PENDING.value,
                    "version": version,
                }
            )
            flash(
                f"Version {version} is waiting for administrator approval. "
                f"Version {app_record.version} remains live.",
                "success",
            )
            return redirect(url_for("main.developer_dashboard"))

    return render_template(
        "app_version_submit.html",
        user=user,
        app_record=app_record,
        form_values=form_values,
        csrf_token=get_csrf_token(),
    )


@main.get("/apps")
def app_marketplace():
    page = request.args.get("page", 1, type=int)
    category_value = request.args.get("category", "all")
    query_text = request.args.get("q", "").strip()
    apps_query = StoreApp.query.options(joinedload(StoreApp.developer)).filter_by(
        status=AppStatus.APPROVED
    )
    if category_value in {category.value for category in AppCategory}:
        apps_query = apps_query.filter(StoreApp.category == AppCategory(category_value))
    if query_text:
        search = f"%{query_text.lower()}%"
        apps_query = apps_query.filter(
            or_(
                func.lower(StoreApp.name).like(search),
                func.lower(StoreApp.short_description).like(search),
                func.lower(StoreApp.description).like(search),
            )
        )
    pagination = apps_query.order_by(
        StoreApp.approved_at.desc(), StoreApp.id.desc()
    ).paginate(page=page, per_page=12, error_out=False)
    apps = pagination.items
    return render_template(
        "app_marketplace.html",
        apps=apps,
        categories=AppCategory,
        category_value=category_value,
        query_text=query_text,
        pagination=pagination,
        pagination_params={
            key: value for key, value in request.args.items() if key != "page"
        },
    )


@main.get("/apps/<slug>")
def app_detail(slug):
    app_record = (
        StoreApp.query.options(
            joinedload(StoreApp.developer),
            selectinload(
                StoreApp.reviews.and_(AppReview.status == ReviewStatus.PUBLISHED)
            ).joinedload(AppReview.user),
            selectinload(StoreApp.screenshots),
        )
        .filter_by(slug=slug, status=AppStatus.APPROVED)
        .first_or_404()
    )
    viewer = current_user()
    viewer_review = None
    is_saved = False
    has_downloaded = False
    if (
        viewer
        and viewer.role == UserRole.USER
        and viewer.status == AccountStatus.APPROVED
    ):
        viewer_review = AppReview.query.filter_by(
            user_id=viewer.id, app_id=app_record.id
        ).first()
        is_saved, has_downloaded = db.session.query(
            db.session.query(SavedApp.id)
            .filter_by(user_id=viewer.id, app_id=app_record.id)
            .exists(),
            db.session.query(DownloadRecord.id)
            .filter_by(user_id=viewer.id, app_id=app_record.id)
            .exists(),
        ).one()
    reviews = sorted(
        app_record.published_reviews,
        key=lambda review: review.updated_at,
        reverse=True,
    )[:20]
    return render_template(
        "app_detail.html",
        app_record=app_record,
        viewer=viewer,
        viewer_review=viewer_review,
        is_saved=is_saved,
        has_downloaded=has_downloaded,
        reviews=reviews,
        report_reasons=ReportReason,
        csrf_token=get_csrf_token(),
    )


@main.get("/apps/<slug>/download")
def download_app(slug):
    app_record = StoreApp.query.filter_by(
        slug=slug, status=AppStatus.APPROVED
    ).first_or_404()
    apk_path = private_upload_folder("apks") / app_record.apk_file
    if not apk_path.is_file():
        abort(404)
    viewer = current_user()
    count_download = False
    if (
        viewer
        and viewer.role == UserRole.USER
        and viewer.status == AccountStatus.APPROVED
    ):
        existing_download = DownloadRecord.query.filter_by(
            user_id=viewer.id, app_id=app_record.id, version=app_record.version
        ).first()
        if existing_download is None:
            db.session.add(
                DownloadRecord(
                    user_id=viewer.id,
                    app_id=app_record.id,
                    version=app_record.version,
                )
            )
            count_download = True
    else:
        download_key = f"{app_record.id}:{app_record.version}"
        counted_downloads = session.get("_counted_downloads", [])
        if download_key not in counted_downloads:
            counted_downloads.append(download_key)
            session["_counted_downloads"] = counted_downloads[-100:]
            count_download = True
    if count_download:
        app_record.download_count += 1
        db.session.commit()
    return send_private_upload(
        "apks",
        app_record.apk_file,
        download_name=app_record.apk_original_name,
        as_attachment=True,
    )


@main.post("/apps/<slug>/save")
@role_required(UserRole.USER)
def toggle_saved_app(user, slug):
    if not valid_csrf_token():
        abort(400)
    app_record = StoreApp.query.filter_by(
        slug=slug, status=AppStatus.APPROVED
    ).first_or_404()
    saved = SavedApp.query.filter_by(user_id=user.id, app_id=app_record.id).first()
    if saved:
        db.session.delete(saved)
        message = f"{app_record.name} was removed from your saved apps."
    else:
        db.session.add(SavedApp(user_id=user.id, app_id=app_record.id))
        message = f"{app_record.name} was saved to your library."
    db.session.commit()
    flash(message, "success")
    return redirect(url_for("main.app_detail", slug=slug))


@main.post("/apps/<slug>/review")
@role_required(UserRole.USER)
def review_app(user, slug):
    if not valid_csrf_token():
        abort(400)
    app_record = StoreApp.query.filter_by(
        slug=slug, status=AppStatus.APPROVED
    ).first_or_404()
    if not DownloadRecord.query.filter_by(
        user_id=user.id, app_id=app_record.id
    ).first():
        flash("Download the app before posting a review.", "warning")
        return redirect(url_for("main.app_detail", slug=slug))
    try:
        rating = int(request.form.get("rating", "0"))
    except ValueError:
        rating = 0
    comment = request.form.get("comment", "").strip()
    if rating not in range(1, 6):
        flash("Choose a rating from 1 to 5 stars.", "error")
    elif len(comment) > 1500:
        flash("Review text must be 1,500 characters or fewer.", "error")
    else:
        review = AppReview.query.filter_by(
            user_id=user.id, app_id=app_record.id
        ).first()
        if review is None:
            review = AppReview(user_id=user.id, app_id=app_record.id)
            db.session.add(review)
        review.rating = rating
        review.comment = comment or None
        review.status = ReviewStatus.PUBLISHED
        db.session.commit()
        flash("Your review was published.", "success")
    return redirect(url_for("main.app_detail", slug=slug))


@main.post("/apps/<slug>/report")
@role_required(UserRole.USER)
def report_app(user, slug):
    if not valid_csrf_token():
        abort(400)
    app_record = StoreApp.query.filter_by(
        slug=slug, status=AppStatus.APPROVED
    ).first_or_404()
    try:
        reason = ReportReason(request.form.get("reason", ""))
    except ValueError:
        reason = None
    details = request.form.get("details", "").strip()
    if reason is None or not 10 <= len(details) <= 2000:
        flash("Choose a reason and provide 10–2,000 characters of detail.", "error")
    else:
        recent_report = AppReport.query.filter_by(
            user_id=user.id,
            app_id=app_record.id,
            status=ReportStatus.OPEN,
        ).first()
        if recent_report:
            flash("You already have an open report for this app.", "warning")
        else:
            db.session.add(
                AppReport(
                    user_id=user.id,
                    app_id=app_record.id,
                    reason=reason,
                    details=details,
                )
            )
            db.session.commit()
            flash("Your report was sent to the administrator.", "success")
    return redirect(url_for("main.app_detail", slug=slug))


@main.get("/apps/<int:app_id>/icon")
def app_icon(app_id):
    app_record = db.session.get(StoreApp, app_id)
    if app_record is None:
        abort(404)
    viewer = current_user()
    can_view = app_record.status == AppStatus.APPROVED or (
        viewer
        and (
            viewer.role in {UserRole.ADMIN, UserRole.CO_ADMIN}
            or viewer.id == app_record.developer_id
        )
    )
    if not can_view:
        abort(404)
    return send_private_upload(
        "app_icons",
        app_record.icon_file,
        public_cache=app_record.status == AppStatus.APPROVED,
    )


@main.get("/apps/screenshots/<int:screenshot_id>")
def app_screenshot(screenshot_id):
    screenshot = db.session.get(AppScreenshot, screenshot_id)
    if screenshot is None:
        abort(404)
    viewer = current_user()
    can_view = screenshot.app.status == AppStatus.APPROVED or (
        viewer
        and (
            viewer.role in {UserRole.ADMIN, UserRole.CO_ADMIN}
            or viewer.id == screenshot.app.developer_id
        )
    )
    if not can_view:
        abort(404)
    return send_private_upload(
        "app_screenshots",
        screenshot.file_name,
        public_cache=screenshot.app.status == AppStatus.APPROVED,
    )


@main.route("/admin")
@staff_required
def admin_dashboard(admin):
    page = request.args.get("page", 1, type=int)
    query_text = request.args.get("q", "").strip()
    role_filter = request.args.get("role", "all")
    status_filter = request.args.get("status", "all")

    accounts_query = User.query.options(selectinload(User.developer_profile)).filter(
        User.role.notin_([UserRole.ADMIN, UserRole.CO_ADMIN]),
        User.status != AccountStatus.DELETED,
    )
    if admin.role == UserRole.CO_ADMIN:
        accounts_query = accounts_query.filter(User.role == UserRole.DEVELOPER)
    if query_text:
        search = f"%{query_text.lower()}%"
        accounts_query = accounts_query.filter(
            or_(
                func.lower(User.username).like(search),
                func.lower(User.email).like(search),
                func.lower(func.coalesce(User.company_name, "")).like(search),
            )
        )
    if role_filter in {UserRole.USER.value, UserRole.DEVELOPER.value}:
        accounts_query = accounts_query.filter(User.role == UserRole(role_filter))
    if status_filter in {status.value for status in AccountStatus}:
        accounts_query = accounts_query.filter(
            User.status == AccountStatus(status_filter)
        )

    pagination = accounts_query.order_by(
        User.created_at.desc(), User.id.desc()
    ).paginate(page=page, per_page=20, error_out=False)
    accounts = pagination.items
    count_row = db.session.query(
        func.count(
            case(
                (User.role.notin_([UserRole.ADMIN, UserRole.CO_ADMIN]))
                & (User.status != AccountStatus.DELETED),
                1,
            )
        ),
        func.count(case((User.status == AccountStatus.PENDING, 1))),
        func.count(case((User.role == UserRole.DEVELOPER, 1))),
        func.count(case((User.status == AccountStatus.BLOCKED, 1))),
    ).one()
    counts = dict(zip(("total", "pending", "developers", "blocked"), count_row))
    return render_template(
        "admin_dashboard.html",
        admin=admin,
        accounts=accounts,
        counts=counts,
        role_filter=role_filter,
        status_filter=status_filter,
        query_text=query_text,
        statuses=[
            status for status in AccountStatus if status != AccountStatus.DELETED
        ],
        pagination=pagination,
        pagination_params={
            key: value for key, value in request.args.items() if key != "page"
        },
        csrf_token=get_csrf_token(),
    )


@main.get("/admin/developers/<int:user_id>")
@staff_required
def admin_developer_review(admin, user_id):
    developer = db.session.get(User, user_id)
    if developer is None or developer.role != UserRole.DEVELOPER:
        abort(404)
    return render_template(
        "admin_developer_review.html",
        admin=admin,
        developer=developer,
        profile=developer.developer_profile,
        csrf_token=get_csrf_token(),
    )


@main.get("/admin/developers/<int:user_id>/government-id")
@staff_required
def admin_developer_government_id(admin, user_id):
    developer = db.session.get(User, user_id)
    if (
        developer is None
        or developer.role != UserRole.DEVELOPER
        or developer.developer_profile is None
        or not developer.developer_profile.government_id_file
    ):
        abort(404)
    return send_private_upload(
        "developer_ids",
        developer.developer_profile.government_id_file,
        download_name=developer.developer_profile.government_id_original_name,
    )


@main.get("/admin/moderation")
@role_required(UserRole.ADMIN)
def admin_moderation(admin):
    report_status = request.args.get("report_status", ReportStatus.OPEN.value)
    reports_query = AppReport.query.options(
        joinedload(AppReport.app), joinedload(AppReport.user)
    )
    if report_status in {status.value for status in ReportStatus}:
        reports_query = reports_query.filter(
            AppReport.status == ReportStatus(report_status)
        )
    reports = reports_query.order_by(AppReport.created_at.desc()).limit(100).all()
    reviews = (
        AppReview.query.options(joinedload(AppReview.app), joinedload(AppReview.user))
        .order_by(AppReview.updated_at.desc())
        .limit(100)
        .all()
    )
    count_row = db.session.query(
        db.session.query(func.count(AppReport.id))
        .filter(AppReport.status == ReportStatus.OPEN)
        .scalar_subquery(),
        db.session.query(func.count(AppReview.id))
        .filter(AppReview.status == ReviewStatus.PUBLISHED)
        .scalar_subquery(),
        db.session.query(func.count(AppReview.id))
        .filter(AppReview.status == ReviewStatus.HIDDEN)
        .scalar_subquery(),
    ).one()
    counts = dict(
        zip(("open_reports", "published_reviews", "hidden_reviews"), count_row)
    )
    return render_template(
        "admin_moderation.html",
        admin=admin,
        reports=reports,
        reviews=reviews,
        counts=counts,
        report_status=report_status,
        report_statuses=ReportStatus,
        csrf_token=get_csrf_token(),
    )


@main.get("/admin/audit-log")
@role_required(UserRole.ADMIN)
def admin_audit_log(admin):
    page = request.args.get("page", 1, type=int)
    action_value = request.args.get("action", "all")
    logs_query = AuditLog.query.options(joinedload(AuditLog.admin))
    if action_value in {action.value for action in AuditAction}:
        logs_query = logs_query.filter(AuditLog.action == AuditAction(action_value))
    pagination = logs_query.order_by(
        AuditLog.created_at.desc(), AuditLog.id.desc()
    ).paginate(page=page, per_page=30, error_out=False)
    return render_template(
        "admin_audit_log.html",
        admin=admin,
        logs=pagination.items,
        pagination=pagination,
        pagination_params={"action": action_value},
        actions=AuditAction,
        action_value=action_value,
        csrf_token=get_csrf_token(),
    )


@main.route("/admin/co-admins", methods=["GET", "POST"])
@role_required(UserRole.ADMIN)
def admin_co_admins(admin):
    if request.method == "POST":
        if not valid_csrf_token():
            abort(400)
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        errors = []
        if not re.fullmatch(r"[A-Za-z0-9_]{3,30}", username):
            errors.append(
                "Username must be 3–30 characters using letters, numbers, or underscores."
            )
        if not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email):
            errors.append("Enter a valid email address.")
        if (
            len(password) < 12
            or not re.search(r"[A-Za-z]", password)
            or not re.search(r"\d", password)
        ):
            errors.append(
                "Temporary password must be at least 12 characters with a letter and number."
            )
        if username_index.contains(username):
            errors.append("That username is already in use.")
        if User.query.filter(func.lower(User.email) == email).first():
            errors.append("That email address is already in use.")
        if errors:
            for error in errors:
                flash(error, "error")
        else:
            co_admin = User(
                username=username,
                email=email,
                role=UserRole.CO_ADMIN,
                status=AccountStatus.APPROVED,
            )
            co_admin.set_password(password)
            co_admin.approve()
            db.session.add(co_admin)
            db.session.flush()
            record_admin_audit(
                admin,
                AuditAction.CO_ADMIN_MANAGEMENT,
                "create",
                "co_admin",
                co_admin.id,
                username,
            )
            db.session.commit()
            username_index.add(co_admin.username, co_admin.id)
            flash(f"Co-admin {username} was created.", "success")
            return redirect(url_for("main.admin_co_admins"))
    co_admins = (
        User.query.filter_by(role=UserRole.CO_ADMIN)
        .order_by(User.created_at.desc())
        .all()
    )
    return render_template(
        "admin_co_admins.html",
        admin=admin,
        co_admins=co_admins,
        csrf_token=get_csrf_token(),
    )


@main.get("/admin/trash")
@role_required(UserRole.ADMIN)
def admin_trash(admin):
    deleted_accounts = (
        User.query.options(selectinload(User.developer_profile))
        .filter(
            User.role.notin_([UserRole.ADMIN, UserRole.CO_ADMIN]),
            User.status == AccountStatus.DELETED,
        )
        .order_by(User.deleted_at.desc(), User.id.desc())
        .all()
    )
    deleted_apps = (
        StoreApp.query.options(joinedload(StoreApp.developer))
        .filter(
            StoreApp.status == AppStatus.DELETED,
        )
        .order_by(StoreApp.deleted_at.desc(), StoreApp.id.desc())
        .all()
    )
    return render_template(
        "admin_trash.html",
        admin=admin,
        accounts=deleted_accounts,
        apps=deleted_apps,
        csrf_token=get_csrf_token(),
    )


@main.route("/admin/settings", methods=["GET", "POST"])
@staff_required
def admin_settings(admin):
    if request.method == "POST":
        if not valid_csrf_token():
            abort(400)
        email = request.form.get("email", "").strip().lower()
        current_password = request.form.get("current_password", "")
        new_password = request.form.get("new_password", "")
        confirm_password = request.form.get("confirm_password", "")
        errors = []
        if not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email):
            errors.append("Enter a valid email address.")
        elif User.query.filter(
            func.lower(User.email) == email, User.id != admin.id
        ).first():
            errors.append("That email address is already in use.")
        if not admin.check_password(current_password):
            errors.append("Enter your current administrator password to save changes.")
        if new_password or confirm_password:
            if (
                len(new_password) < 12
                or not re.search(r"[A-Za-z]", new_password)
                or not re.search(r"\d", new_password)
            ):
                errors.append(
                    "The new password must be at least 12 characters with a letter and number."
                )
            elif new_password != confirm_password:
                errors.append("The new passwords do not match.")
        if errors:
            for error in errors:
                flash(error, "error")
        else:
            email_changed = admin.email != email
            admin.email = email
            if new_password:
                admin.set_password(new_password)
            note_parts = []
            if email_changed:
                note_parts.append("email updated")
            if new_password:
                note_parts.append("password updated")
            record_admin_audit(
                admin,
                AuditAction.ACCOUNT_MODERATION,
                "update_settings",
                "administrator",
                admin.id,
                admin.username,
                ", ".join(note_parts) or "settings confirmed",
            )
            try:
                db.session.commit()
                flash("Administrator settings were updated securely.", "success")
                return redirect(url_for("main.admin_settings"))
            except IntegrityError:
                db.session.rollback()
                flash("That email address is already in use.", "error")
    return render_template(
        "admin_settings.html", admin=admin, csrf_token=get_csrf_token()
    )


@main.post("/admin/co-admins/<int:user_id>/toggle")
@role_required(UserRole.ADMIN)
def toggle_co_admin(admin, user_id):
    if not valid_csrf_token():
        abort(400)
    co_admin = db.session.get(User, user_id)
    if co_admin is None or co_admin.role != UserRole.CO_ADMIN:
        abort(404)
    enabling = co_admin.status == AccountStatus.BLOCKED
    if enabling:
        co_admin.unblock()
    else:
        co_admin.block()
    operation = "enable" if enabling else "disable"
    record_admin_audit(
        admin,
        AuditAction.CO_ADMIN_MANAGEMENT,
        operation,
        "co_admin",
        co_admin.id,
        co_admin.username,
    )
    db.session.commit()
    flash(f"Co-admin {co_admin.username} was {operation}d.", "success")
    return redirect(url_for("main.admin_co_admins"))


@main.post("/admin/reports/<int:report_id>/<action>")
@role_required(UserRole.ADMIN)
def manage_report(admin, report_id, action):
    if not valid_csrf_token():
        abort(400)
    report = db.session.get(AppReport, report_id)
    if report is None or action not in {"resolve", "dismiss"}:
        abort(404)
    report.status = (
        ReportStatus.RESOLVED if action == "resolve" else ReportStatus.DISMISSED
    )
    report.admin_note = request.form.get("admin_note", "").strip() or None
    report.resolved_at = datetime.now(timezone.utc)
    record_admin_audit(
        admin,
        AuditAction.REPORT_MODERATION,
        action,
        "report",
        report.id,
        report.app.name,
        report.admin_note,
    )
    db.session.commit()
    flash(f"Report #{report.id} was {report.status.value}.", "success")
    return redirect(url_for("main.admin_moderation"))


@main.post("/admin/reviews/<int:review_id>/<action>")
@role_required(UserRole.ADMIN)
def manage_review(admin, review_id, action):
    if not valid_csrf_token():
        abort(400)
    review = db.session.get(AppReview, review_id)
    if review is None or action not in {"hide", "publish", "delete"}:
        abort(404)
    target_label = f"{review.app.name} review by {review.user.username}"
    if action == "delete":
        db.session.delete(review)
    else:
        review.status = (
            ReviewStatus.HIDDEN if action == "hide" else ReviewStatus.PUBLISHED
        )
    record_admin_audit(
        admin, AuditAction.REVIEW_MODERATION, action, "review", review_id, target_label
    )
    db.session.commit()
    labels = {"hide": "hidden", "publish": "published", "delete": "deleted"}
    flash(f"Review was {labels[action]}.", "success")
    return redirect(url_for("main.admin_moderation"))


@main.get("/admin/apps")
@staff_required
def admin_apps(admin):
    page = request.args.get("page", 1, type=int)
    status_value = request.args.get("status", "all")
    query_text = request.args.get("q", "").strip()
    apps_query = StoreApp.query.options(joinedload(StoreApp.developer)).filter(
        StoreApp.status != AppStatus.DELETED
    )
    if status_value == AppStatus.PENDING.value:
        apps_query = apps_query.filter(
            or_(
                StoreApp.status == AppStatus.PENDING,
                StoreApp.pending_release_status == ReleaseStatus.PENDING,
            )
        )
    elif status_value in {status.value for status in AppStatus}:
        apps_query = apps_query.filter(StoreApp.status == AppStatus(status_value))
    if query_text:
        search = f"%{query_text.lower()}%"
        apps_query = apps_query.join(User).filter(
            or_(
                func.lower(StoreApp.name).like(search),
                func.lower(StoreApp.package_name).like(search),
                func.lower(User.username).like(search),
            )
        )
    pagination = apps_query.order_by(
        StoreApp.submitted_at.desc(), StoreApp.id.desc()
    ).paginate(page=page, per_page=20, error_out=False)
    apps = pagination.items
    pending_condition = or_(
        StoreApp.status == AppStatus.PENDING,
        StoreApp.pending_release_status == ReleaseStatus.PENDING,
    )
    count_row = db.session.query(
        func.count(case((StoreApp.status != AppStatus.DELETED, 1))),
        func.count(case((pending_condition, 1))),
        func.count(case((StoreApp.status == AppStatus.APPROVED, 1))),
        func.count(case((StoreApp.status == AppStatus.BLOCKED, 1))),
    ).one()
    counts = dict(zip(("total", "pending", "approved", "blocked"), count_row))
    return render_template(
        "admin_apps.html",
        admin=admin,
        apps=apps,
        counts=counts,
        statuses=[status for status in AppStatus if status != AppStatus.DELETED],
        pagination=pagination,
        pagination_params={
            key: value for key, value in request.args.items() if key != "page"
        },
        status_value=status_value,
        query_text=query_text,
        csrf_token=get_csrf_token(),
    )


@main.get("/admin/apps/<int:app_id>")
@staff_required
def admin_app_review(admin, app_id):
    app_record = db.session.get(StoreApp, app_id)
    if app_record is None:
        abort(404)
    return render_template(
        "admin_app_review.html",
        admin=admin,
        app_record=app_record,
        csrf_token=get_csrf_token(),
    )


@main.get("/admin/apps/<int:app_id>/apk")
@staff_required
def admin_download_apk(admin, app_id):
    app_record = db.session.get(StoreApp, app_id)
    if app_record is None:
        abort(404)
    return send_private_upload(
        "apks",
        app_record.apk_file,
        download_name=app_record.apk_original_name,
        as_attachment=True,
    )


@main.get("/admin/apps/<int:app_id>/pending-apk")
@staff_required
def admin_download_pending_apk(admin, app_id):
    app_record = db.session.get(StoreApp, app_id)
    if app_record is None or not app_record.pending_apk_file:
        abort(404)
    return send_private_upload(
        "apks",
        app_record.pending_apk_file,
        download_name=app_record.pending_apk_original_name,
        as_attachment=True,
    )


@main.post("/admin/apps/<int:app_id>/release/<action>")
@staff_required
def manage_app_release(admin, app_id, action):
    if not valid_csrf_token():
        flash("Your session expired. Please try again.", "error")
        return redirect(url_for("main.admin_apps"))
    app_record = db.session.get(StoreApp, app_id)
    if app_record is None or app_record.pending_release_status is None:
        abort(404)
    if action not in {"approve", "reject"}:
        abort(404)

    version = app_record.pending_version
    if action == "approve":
        if app_record.pending_release_status != ReleaseStatus.PENDING:
            flash("Only a pending version can be approved.", "error")
            return redirect(url_for("main.admin_app_review", app_id=app_id))
        if app_record.pending_security_scan_status != SecurityScanStatus.PASSED:
            flash(
                "This version must pass structural safety checks before approval.",
                "error",
            )
            return redirect(url_for("main.admin_app_review", app_id=app_id))
        if app_record.pending_malware_scan_status != SecurityScanStatus.PASSED:
            flash("This version must pass malware scanning before approval.", "error")
            return redirect(url_for("main.admin_app_review", app_id=app_id))
        previous = AppVersionHistory(
            app=app_record,
            version=app_record.version,
            min_android_version=app_record.min_android_version,
            changelog=app_record.changelog,
            apk_file=app_record.apk_file,
            apk_original_name=app_record.apk_original_name,
            apk_size=app_record.apk_size,
            apk_sha256=app_record.apk_sha256,
            published_at=app_record.approved_at or app_record.created_at,
        )
        db.session.add(previous)
        app_record.version = app_record.pending_version
        app_record.min_android_version = app_record.pending_min_android_version
        app_record.changelog = app_record.pending_changelog
        app_record.apk_file = app_record.pending_apk_file
        app_record.apk_original_name = app_record.pending_apk_original_name
        app_record.apk_size = app_record.pending_apk_size
        app_record.apk_sha256 = app_record.pending_apk_sha256
        app_record.security_scan_status = app_record.pending_security_scan_status
        app_record.security_scan_summary = app_record.pending_security_scan_summary
        app_record.security_scanned_at = app_record.pending_security_scanned_at
        app_record.malware_scan_status = app_record.pending_malware_scan_status
        app_record.malware_scan_summary = app_record.pending_malware_scan_summary
        app_record.malware_scanned_at = app_record.pending_malware_scanned_at
        app_record.approved_at = datetime.now(timezone.utc)
        app_record.clear_pending_release()
        message = f"Version {version} of {app_record.name} was published."
        status_value = "approved"
    else:
        note = request.form.get("review_note", "").strip()
        app_record.pending_release_status = ReleaseStatus.REJECTED
        app_record.pending_release_note = note or "This version was not approved."
        message = f"Version {version} of {app_record.name} was rejected."
        status_value = "rejected"

    create_notification(
        app_record.developer_id,
        NotificationType.RELEASE,
        f"{app_record.name} version {version} {status_value}",
        message,
        url_for("main.developer_dashboard"),
    )
    if action == "approve":
        saved_user_ids = (
            db.session.query(SavedApp.user_id).filter_by(app_id=app_id).all()
        )
        for (saved_user_id,) in saved_user_ids:
            create_notification(
                saved_user_id,
                NotificationType.RELEASE,
                f"{app_record.name} {version} is available",
                "A new administrator-approved version is ready to download.",
                url_for("main.app_detail", slug=app_record.slug),
            )
    record_admin_audit(
        admin,
        AuditAction.RELEASE_MODERATION,
        action,
        "release",
        app_id,
        f"{app_record.name} v{version}",
        request.form.get("review_note", "").strip(),
    )
    db.session.commit()
    event = account_events.publish(
        {
            "type": "release_updated",
            "action": action,
            "app_id": app_record.id,
            "user_id": app_record.developer_id,
            "name": app_record.name,
            "version": version,
            "status": status_value,
        }
    )
    if request.headers.get("X-Requested-With") == "fetch":
        return jsonify({"ok": True, "message": message, "event": event})
    flash(message, "success")
    return redirect(url_for("main.admin_app_review", app_id=app_id))


@main.post("/admin/apps/<int:app_id>/<action>")
@staff_required
def manage_app(admin, app_id, action):
    if not valid_csrf_token():
        flash("Your session expired. Please try again.", "error")
        return redirect(url_for("main.admin_apps"))
    app_record = db.session.get(StoreApp, app_id)
    if app_record is None:
        abort(404)
    if action not in {"approve", "reject", "block", "delete", "restore", "hard_delete"}:
        abort(404)
    if admin.role == UserRole.CO_ADMIN and action not in {"approve", "reject"}:
        abort(403)
    if app_record.status == AppStatus.DELETED and action not in {
        "restore",
        "hard_delete",
    }:
        abort(409)
    if action == "hard_delete":
        if app_record.status != AppStatus.DELETED:
            abort(409)
        confirmation = require_permanent_delete_confirmation(
            admin, "app", app_record.name, url_for("main.admin_trash")
        )
        if confirmation:
            return confirmation
    if action == "approve" and app_record.developer.status != AccountStatus.APPROVED:
        flash("Approve the developer account before approving this app.", "error")
        return redirect(url_for("main.admin_app_review", app_id=app_id))
    if (
        action == "approve"
        and app_record.security_scan_status != SecurityScanStatus.PASSED
    ):
        flash("This APK must pass structural safety checks before approval.", "error")
        return redirect(url_for("main.admin_app_review", app_id=app_id))
    if (
        action == "approve"
        and app_record.malware_scan_status != SecurityScanStatus.PASSED
    ):
        flash("This APK must pass malware scanning before approval.", "error")
        return redirect(url_for("main.admin_app_review", app_id=app_id))

    action_labels = {
        "approve": "approved",
        "reject": "rejected",
        "block": "blocked",
        "delete": "moved to trash",
        "restore": "restored",
        "hard_delete": "permanently deleted",
    }

    review_note = request.form.get("review_note", "").strip()
    app_name = app_record.name
    developer_id = app_record.developer_id
    cleanup_files = []
    if action == "approve":
        app_record.approve()
    elif action == "reject":
        app_record.reject(review_note)
    elif action == "block":
        app_record.block(review_note)
    elif action == "delete":
        app_record.soft_delete(review_note)
    elif action == "restore":
        app_record.restore()
    elif action == "hard_delete":
        cleanup_files.extend(
            [
                ("apks", app_record.apk_file),
                ("apks", app_record.pending_apk_file),
                ("app_icons", app_record.icon_file),
            ]
        )
        cleanup_files.extend(
            ("apks", history.apk_file) for history in app_record.version_history
        )
        cleanup_files.extend(
            ("app_screenshots", screenshot.file_name)
            for screenshot in app_record.screenshots
        )
        db.session.delete(app_record)

    create_notification(
        developer_id,
        NotificationType.APP,
        f"{app_name} {action_labels[action]}",
        review_note
        or f"The administrator {action_labels[action]} your app submission.",
        url_for("main.developer_dashboard"),
    )
    record_admin_audit(
        admin, AuditAction.APP_MODERATION, action, "app", app_id, app_name, review_note
    )
    db.session.commit()
    if action == "hard_delete":
        for folder, filename in cleanup_files:
            safe_delete_upload(folder, filename)
        status_value = "hard_deleted"
    else:
        status_value = app_record.status.value
    event = account_events.publish(
        {
            "type": "app_updated",
            "action": action,
            "app_id": app_id,
            "user_id": developer_id,
            "name": app_name,
            "status": status_value,
        }
    )
    message = f"{app_name} was {action_labels[action]}."
    if request.headers.get("X-Requested-With") == "fetch":
        return jsonify({"ok": True, "message": message, "event": event})
    flash(message, "success")
    if request.referrer and urlparse(request.referrer).path == url_for(
        "main.admin_trash"
    ):
        return redirect(url_for("main.admin_trash"))
    return redirect(url_for("main.admin_apps"))


def server_event_response(event_filter):
    subscriber = account_events.subscribe()

    @stream_with_context
    def generate():
        yield "retry: 2500\n\n"
        try:
            while True:
                try:
                    event = subscriber.get(timeout=15)
                except Empty:
                    yield ": keep-alive\n\n"
                    continue
                if event_filter(event):
                    yield f"id: {event['event_id']}\n"
                    yield "event: account-change\n"
                    yield f"data: {json.dumps(event)}\n\n"
        finally:
            account_events.unsubscribe(subscriber)

    return Response(
        generate(),
        mimetype="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@main.get("/events/admin-accounts")
@staff_required
def admin_account_events(admin):
    return server_event_response(
        lambda event: event.get("type", "").startswith("account_")
    )


@main.get("/events/admin-apps")
@staff_required
def admin_app_events(admin):
    return server_event_response(
        lambda event: event.get("type", "").startswith(("app_", "release_"))
    )


@main.get("/events/developer-apps")
@developer_access_required
def developer_app_events(user):
    return server_event_response(
        lambda event: event.get("type", "").startswith(("app_", "release_"))
        and event.get("user_id") == user.id
    )


@main.get("/events/my-account")
def my_account_events():
    user = current_user()
    if user is None or user.status in {AccountStatus.BLOCKED, AccountStatus.DELETED}:
        return Response(status=401)
    user_id = user.id
    return server_event_response(lambda event: event.get("user_id") == user_id)


@main.get("/account/access-changed")
def account_access_changed():
    role_value = session.get("role", UserRole.USER.value)
    if role_value not in {UserRole.USER.value, UserRole.DEVELOPER.value}:
        role_value = UserRole.USER.value
    state = request.args.get("state", "blocked")
    session.clear()
    messages = {
        "blocked": "Your account was blocked by an administrator.",
        "rejected": "Your account access was rejected by an administrator.",
        "deleted": "Your account was moved to trash by an administrator and can be restored.",
    }
    flash(
        messages.get(state, "Your account access changed. Please sign in again."),
        "error",
    )
    return redirect(url_for("main.account_login", role_name=role_value))


@main.post("/admin/accounts/<int:user_id>/<action>")
@staff_required
def manage_account(admin, user_id, action):
    if not valid_csrf_token():
        flash("Your session expired. Please try again.", "error")
        return redirect(url_for("main.admin_dashboard"))

    account = db.session.get(User, user_id)
    if account is None:
        abort(404)
    if account.role in {UserRole.ADMIN, UserRole.CO_ADMIN} or account.id == admin.id:
        flash("Administrator accounts cannot be changed here.", "error")
        return redirect(url_for("main.admin_dashboard"))

    labels = {
        "approve": "approved",
        "reject": "rejected",
        "block": "blocked",
        "unblock": "unblocked",
        "delete": "moved to trash",
        "restore": "restored",
        "hard_delete": "permanently deleted",
    }
    if action not in labels:
        abort(404)
    if admin.role == UserRole.CO_ADMIN and (
        account.role != UserRole.DEVELOPER or action not in {"approve", "reject"}
    ):
        abort(403)
    if account.status == AccountStatus.DELETED and action not in {
        "restore",
        "hard_delete",
    }:
        abort(409)
    if action == "hard_delete":
        if account.status != AccountStatus.DELETED:
            abort(409)
        confirmation = require_permanent_delete_confirmation(
            admin, "account", account.username, url_for("main.admin_trash")
        )
        if confirmation:
            return confirmation

    if (
        action == "approve"
        and account.role == UserRole.DEVELOPER
        and (
            account.developer_profile is None
            or not account.developer_profile.is_submitted
        )
    ):
        message = "The developer must sign in and submit all identity details before approval."
        if request.headers.get("X-Requested-With") == "fetch":
            return jsonify({"ok": False, "message": message}), 409
        flash(message, "error")
        return redirect(url_for("main.admin_developer_review", user_id=account.id))

    username = account.username
    role_value = account.role.value
    review_note = request.form.get("review_note", "").strip()
    cleanup_files = []
    if action == "approve":
        account.approve()
        if account.developer_profile:
            account.developer_profile.reviewed_at = datetime.now(timezone.utc)
            account.developer_profile.review_note = None
    elif action == "reject":
        account.reject()
        if account.developer_profile:
            account.developer_profile.reviewed_at = datetime.now(timezone.utc)
            account.developer_profile.review_note = (
                review_note or "Verification was not approved."
            )
    elif action == "block":
        account.block()
    elif action == "unblock":
        if account.role == UserRole.DEVELOPER and (
            account.developer_profile is None
            or not account.developer_profile.is_submitted
        ):
            account.status = AccountStatus.PENDING
            account.approved_at = None
        else:
            account.unblock()
    elif action == "delete":
        account.soft_delete()
    elif action == "restore":
        account.restore()
    elif action == "hard_delete":
        if account.developer_profile and account.developer_profile.government_id_file:
            cleanup_files.append(
                ("developer_ids", account.developer_profile.government_id_file)
            )
        for app_record in account.apps:
            cleanup_files.extend(
                [
                    ("app_icons", app_record.icon_file),
                    ("apks", app_record.apk_file),
                    ("apks", app_record.pending_apk_file),
                ]
            )
            cleanup_files.extend(
                ("apks", history.apk_file) for history in app_record.version_history
            )
            cleanup_files.extend(
                ("app_screenshots", screenshot.file_name)
                for screenshot in app_record.screenshots
            )
        db.session.delete(account)

    if action != "hard_delete":
        create_notification(
            user_id,
            NotificationType.ACCOUNT,
            f"Account {labels[action]}",
            review_note
            or f"Your {role_value} account was {labels[action]} by an administrator.",
            url_for("main.developer_dashboard")
            if role_value == UserRole.DEVELOPER.value
            else url_for("main.user_dashboard"),
        )
    record_admin_audit(
        admin,
        AuditAction.ACCOUNT_MODERATION,
        action,
        "account",
        user_id,
        username,
        review_note,
    )
    db.session.commit()
    if action == "hard_delete":
        username_index.remove(username)
        for folder, filename in cleanup_files:
            safe_delete_upload(folder, filename)
        status_value = "hard_deleted"
    else:
        status_value = account.status.value

    event = account_events.publish(
        {
            "type": "account_updated",
            "action": action,
            "user_id": user_id,
            "username": username,
            "role": role_value,
            "status": status_value,
        }
    )
    message = f"{username} was {labels[action]}."
    if request.headers.get("X-Requested-With") == "fetch":
        return jsonify({"ok": True, "message": message, "event": event})

    flash(message, "success")
    if request.referrer and urlparse(request.referrer).path == url_for(
        "main.admin_trash"
    ):
        return redirect(url_for("main.admin_trash"))
    return redirect(url_for("main.admin_dashboard"))


@main.route("/user/dashboard")
@role_required(UserRole.USER)
def user_dashboard(user):
    download_count = DownloadRecord.query.filter_by(user_id=user.id).count()
    latest_download_ids = (
        db.session.query(func.max(DownloadRecord.id).label("id"))
        .filter(DownloadRecord.user_id == user.id)
        .group_by(DownloadRecord.app_id)
        .subquery()
    )
    recent_downloads = (
        DownloadRecord.query.options(joinedload(DownloadRecord.app))
        .filter(DownloadRecord.id.in_(select(latest_download_ids.c.id)))
        .order_by(DownloadRecord.downloaded_at.desc())
        .all()
    )
    saved_apps = (
        SavedApp.query.options(joinedload(SavedApp.app))
        .filter_by(user_id=user.id)
        .order_by(SavedApp.created_at.desc())
        .all()
    )
    reviews = (
        AppReview.query.options(joinedload(AppReview.app))
        .filter_by(user_id=user.id)
        .order_by(AppReview.updated_at.desc())
        .all()
    )
    return render_template(
        "user_dashboard.html",
        user=user,
        recent_downloads=recent_downloads,
        download_count=download_count,
        saved_apps=saved_apps,
        reviews=reviews,
        csrf_token=get_csrf_token(),
    )


@main.route("/account/settings", methods=["GET", "POST"])
def account_settings():
    user = current_user()
    if (
        user is None
        or user.role == UserRole.ADMIN
        or user.status != AccountStatus.APPROVED
    ):
        session.clear()
        flash("Sign in to manage your account.", "error")
        return redirect(url_for("main.account_login", role_name="user"))

    if request.method == "POST":
        if not valid_csrf_token():
            abort(400)
        email = request.form.get("email", "").strip().lower()
        company_name = request.form.get("company_name", "").strip()
        current_password = request.form.get("current_password", "")
        new_password = request.form.get("new_password", "")
        confirm_password = request.form.get("confirm_password", "")
        errors = []
        if not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email):
            errors.append("Enter a valid email address.")
        elif User.query.filter(
            func.lower(User.email) == email, User.id != user.id
        ).first():
            errors.append("That email address is already in use.")
        if user.role == UserRole.DEVELOPER and not company_name:
            errors.append("Enter your developer or company name.")
        if new_password or confirm_password or current_password:
            if not user.check_password(current_password):
                errors.append("Your current password is incorrect.")
            elif len(new_password) < 8:
                errors.append("The new password must contain at least 8 characters.")
            elif new_password != confirm_password:
                errors.append("The new passwords do not match.")
        if errors:
            for error in errors:
                flash(error, "error")
        else:
            user.email = email
            if user.role == UserRole.DEVELOPER:
                user.company_name = company_name
            if new_password:
                user.set_password(new_password)
            try:
                db.session.commit()
                flash("Your account settings were updated.", "success")
                return redirect(url_for("main.account_settings"))
            except IntegrityError:
                db.session.rollback()
                flash("That email address is already in use.", "error")

    return render_template(
        "account_settings.html",
        user=user,
        csrf_token=get_csrf_token(),
    )


@main.get("/notifications")
def notifications():
    user = current_user()
    if (
        user is None
        or user.role == UserRole.ADMIN
        or user.status != AccountStatus.APPROVED
    ):
        flash("Sign in to view notifications.", "error")
        return redirect(url_for("main.account_login", role_name="user"))
    items = (
        Notification.query.filter_by(recipient_id=user.id)
        .order_by(Notification.created_at.desc(), Notification.id.desc())
        .limit(100)
        .all()
    )
    return render_template(
        "notifications.html",
        user=user,
        notifications=items,
        csrf_token=get_csrf_token(),
    )


@main.post("/notifications/read-all")
def read_all_notifications():
    user = current_user()
    if (
        user is None
        or user.role == UserRole.ADMIN
        or user.status != AccountStatus.APPROVED
    ):
        abort(403)
    if not valid_csrf_token():
        abort(400)
    Notification.query.filter_by(recipient_id=user.id, is_read=False).update(
        {"is_read": True}
    )
    db.session.commit()
    return redirect(url_for("main.notifications"))


@main.post("/notifications/<int:notification_id>/open")
def open_notification(notification_id):
    user = current_user()
    if (
        user is None
        or user.role == UserRole.ADMIN
        or user.status != AccountStatus.APPROVED
    ):
        abort(403)
    if not valid_csrf_token():
        abort(400)
    item = Notification.query.filter_by(
        id=notification_id, recipient_id=user.id
    ).first_or_404()
    item.is_read = True
    db.session.commit()
    safe_link = (
        item.link
        if item.link and item.link.startswith("/") and not item.link.startswith("//")
        else dashboard_url_for(user)
    )
    return redirect(safe_link)


@main.route("/developer/dashboard")
@role_required(UserRole.DEVELOPER)
def developer_dashboard(user):
    if not user.developer_profile or not user.developer_profile.is_submitted:
        flash(
            "Complete identity verification before using the developer studio.",
            "warning",
        )
        return redirect(url_for("main.developer_verification"))
    apps = (
        StoreApp.query.options(
            selectinload(
                StoreApp.reviews.and_(AppReview.status == ReviewStatus.PUBLISHED)
            )
        )
        .filter_by(developer_id=user.id)
        .order_by(
            StoreApp.submitted_at.desc(),
            StoreApp.id.desc(),
        )
        .all()
    )
    app_counts = {
        "published": sum(app.status == AppStatus.APPROVED for app in apps),
        "pending": sum(app.status == AppStatus.PENDING for app in apps),
        "downloads": sum(app.download_count for app in apps),
        "reviews": sum(app.review_count for app in apps),
    }
    approved_app_ids = [app.id for app in apps if app.status == AppStatus.APPROVED]
    recent_downloads = []
    seven_day_downloads = []
    if approved_app_ids:
        recent_downloads = (
            DownloadRecord.query.options(joinedload(DownloadRecord.app))
            .filter(DownloadRecord.app_id.in_(approved_app_ids))
            .order_by(DownloadRecord.downloaded_at.desc())
            .limit(10)
            .all()
        )
        start_day = (datetime.now(timezone.utc) - timedelta(days=6)).date()
        day_expression = func.date(DownloadRecord.downloaded_at)
        tracked = (
            db.session.query(day_expression.label("day"), func.count().label("count"))
            .filter(
                DownloadRecord.app_id.in_(approved_app_ids),
                DownloadRecord.downloaded_at
                >= datetime.combine(
                    start_day, datetime.min.time(), tzinfo=timezone.utc
                ),
            )
            .group_by(day_expression)
            .all()
        )
        downloads_by_day = {
            datetime.strptime(day, "%Y-%m-%d").date(): count for day, count in tracked
        }
        seven_day_downloads = [
            {
                "date": start_day + timedelta(days=offset),
                "count": downloads_by_day.get(start_day + timedelta(days=offset), 0),
            }
            for offset in range(7)
        ]
    max_daily_downloads = max(
        (item["count"] for item in seven_day_downloads), default=0
    )
    return render_template(
        "developer_dashboard.html",
        user=user,
        apps=apps,
        app_counts=app_counts,
        recent_downloads=recent_downloads,
        seven_day_downloads=seven_day_downloads,
        max_daily_downloads=max_daily_downloads,
        csrf_token=get_csrf_token(),
    )


@main.post("/logout")
def logout():
    if not valid_csrf_token():
        abort(400)
    user = current_user()
    if request.form.get("confirm") != "yes":
        return render_template(
            "logout_confirm.html",
            user=user,
            cancel_url=dashboard_url_for(user) if user else url_for("main.home"),
            csrf_token=get_csrf_token(),
        )
    session.clear()
    flash("You have been signed out safely.", "success")
    return redirect(url_for("main.home"))

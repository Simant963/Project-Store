import json
import os
import hashlib
import re
import secrets
import smtplib
import ssl
# ClamAV runs as a fixed argument list; shell execution is never enabled.
import subprocess  # nosec B404
import zipfile
import time
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
from werkzeug.security import check_password_hash, generate_password_hash
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
    ManualPasswordReset,
    ManualResetStatus,
    MarketplaceSettings,
    Notification,
    NotificationType,
    PasswordResetToken,
    ReportReason,
    ReportStatus,
    ReleaseStatus,
    SecurityScanStatus,
    SubmissionStatus,
    SavedApp,
    SecurityQuestion,
    ReviewStatus,
    StoreApp,
    User,
    UserRole,
)
from .realtime import account_events
from .submission_workflow import set_status, start_submission, submission_view
from .username_linked_list import username_index

main = Blueprint("main", __name__)
_DUMMY_PASSWORD_HASH = generate_password_hash(secrets.token_urlsafe(32), method="scrypt:32768:8:3")
CLAMAV_SCAN_OPTIONS = (
    "--no-summary",
    "--infected",
    "--scan-archive=yes",
    "--detect-pua=yes",
    "--detect-structured=yes",
    "--heuristic-alerts=yes",
    "--phishing-sigs=yes",
    "--phishing-scan-urls=yes",
    "--bytecode=yes",
    "--alert-exceeds-max=yes",
    "--alert-encrypted=yes",
    "--max-filesize=512M",
    "--max-scansize=1536M",
    "--max-files=20000",
    "--max-recursion=16",
    "--max-scantime=0",  # Wall-clock subprocess timeout fails closed instead.
)


def get_csrf_token():
    token = session.get("_csrf_token")
    if token is None:
        token = secrets.token_urlsafe(32)
        session["_csrf_token"] = token
    return token


def valid_csrf_token():
    submitted = request.form.get("csrf_token", "")
    saved = session.get("_csrf_token", "")
    return bool(saved) and submitted.isascii() and secrets.compare_digest(saved, submitted)


def current_user():
    user_id = session.get("user_id")
    user = db.session.get(User, user_id) if user_id else None
    privileged_expired = bool(user and user.role in {UserRole.ADMIN, UserRole.CO_ADMIN} and
                              session.get("privileged_until", 0) <= time.time())
    if user is not None and not privileged_expired and user.status not in {AccountStatus.BLOCKED, AccountStatus.DELETED} and session.get("session_version") == user.session_version:
        return user
    if user_id:
        session.clear()
    return None


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
    session["session_version"] = user.session_version
    session["_csrf_token"] = secrets.token_urlsafe(32)
    if user.role in {UserRole.ADMIN, UserRole.CO_ADMIN}:
        session["privileged_until"] = time.time() + 1800
        remember = False
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
    current_app.logger.warning('authentication_failure flow=%s identifier_digest=%s', scope.split('-', 1)[0], key_hash[:16])
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
            smtp.starttls(context=ssl.create_default_context())
        if current_app.config.get("SMTP_USERNAME"):
            smtp.login(
                current_app.config["SMTP_USERNAME"],
                current_app.config.get("SMTP_PASSWORD", ""),
            )
        smtp.send_message(message)
    return True


def issue_password_reset(user):
    now = datetime.now(timezone.utc)
    PasswordResetToken.query.filter_by(user_id=user.id, used_at=None).update(
        {"used_at": now}
    )
    raw_token = secrets.token_urlsafe(40)
    db.session.add(
        PasswordResetToken(
            user_id=user.id,
            token_hash=hashlib.sha256(raw_token.encode("utf-8")).hexdigest(),
            expires_at=now + timedelta(minutes=30),
        )
    )
    db.session.commit()
    return raw_token


def create_manual_reset_request(user):
    """Create one pending request per account and invalidate older requests."""
    now = datetime.now(timezone.utc)
    ManualPasswordReset.query.filter(
        ManualPasswordReset.user_id == user.id,
        ManualPasswordReset.status.in_([
            ManualResetStatus.PENDING,
            ManualResetStatus.APPROVED,
        ]),
    ).update(
        {
            "status": ManualResetStatus.REJECTED,
            "reviewed_at": now,
            "code_hash": None,
            "code_expires_at": None,
        },
        synchronize_session=False,
    )
    reference = secrets.token_hex(6).upper()
    while ManualPasswordReset.query.filter_by(reference=reference).first():
        reference = secrets.token_hex(6).upper()
    reset_request = ManualPasswordReset(user_id=user.id, reference=reference)
    db.session.add(reset_request)
    db.session.commit()
    return reset_request


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
            if request.headers.get("X-Requested-With") == "fetch":
                abort(403, description="Only authorized administrators can review or publish applications.")
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
    maximum_bytes = marketplace_settings().max_apk_size_mb * 1024 * 1024
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
    limiter = current_app.extensions['security_limits']
    lease = limiter.acquire('malware-scans', 'global', 2, timeout + 30)
    if not lease:
        raise ValueError("Virus scanner is busy. Please retry shortly; the app was not submitted.")
    try:
        result = subprocess.run(  # nosec B603
            [command, *CLAMAV_SCAN_OPTIONS,
             *(["--database=" + current_app.config["CLAMAV_DATABASE_DIR"]] if current_app.config.get("CLAMAV_DATABASE_DIR") else []), str(path)],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            env={key: value for key, value in os.environ.items() if key.upper() in {
                'PATH', 'SYSTEMROOT', 'WINDIR', 'TEMP', 'TMP', 'LANG', 'LC_ALL', 'LD_LIBRARY_PATH'}},
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
    finally:
        limiter.release(lease)

    if result.returncode == 0:
        return (
            "ClamAV scan passed · archive, heuristic, ransomware/malware signature, "
            "PUA, phishing, structured-data and bytecode checks found no threat"
        )
    if result.returncode == 1:
        signatures = []
        for line in (result.stdout or "").splitlines():
            if line.rstrip().endswith(" FOUND"):
                signatures.append(
                    line.rsplit(": ", 1)[-1].removesuffix(" FOUND")[:160]
                )
        current_app.logger.warning("ClamAV rejected an APK; threat or scan-limit detected")
        finding = ", ".join(dict.fromkeys(signatures)) or "malware signature"
        raise ValueError(f"The APK was rejected: {finding} detected.")
    current_app.logger.error("ClamAV scan failed; exit code=%s", result.returncode)
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


def deep_scan_apk(path):
    """Run 60 bounded static checks; warnings require human review, failures block."""
    checks = []

    def add(name, status, detail):
        checks.append({"name": name, "status": status, "detail": detail})

    with zipfile.ZipFile(path) as archive:
        entries = archive.infolist()
        names = [entry.filename for entry in entries]
        lowered_names = [name.casefold() for name in names]
        total_compressed = sum(entry.compress_size for entry in entries)
        total_uncompressed = sum(entry.file_size for entry in entries)
        ratio = total_uncompressed / max(total_compressed, 1)
        unsafe_paths = [
            name
            for name in names
            if not name
            or "\\" in name
            or name.startswith("/")
            or ".." in PurePosixPath(name).parts
        ]
        add("Readable APK/ZIP container", "pass", f"{len(entries)} entries indexed")
        add("Archive entry-count limit", "pass" if len(entries) <= 20000 else "fail", f"{len(entries):,} of 20,000 maximum")
        add("Safe internal paths", "pass" if not unsafe_paths else "fail", "No traversal paths" if not unsafe_paths else f"{len(unsafe_paths)} unsafe paths")
        encrypted = sum(bool(entry.flag_bits & 1) for entry in entries)
        add("No encrypted archive entries", "pass" if not encrypted else "fail", f"{encrypted} encrypted entries")
        add("Expanded-size limit", "pass" if total_uncompressed <= 1536 * 1024 * 1024 else "fail", f"{total_uncompressed / 1048576:.1f} MB expanded")
        add("Compression-ratio limit", "pass" if ratio <= 200 or total_uncompressed <= 100 * 1024 * 1024 else "fail", f"{ratio:.1f}:1 ratio")
        manifest_entries = [entry for entry in entries if entry.filename == "AndroidManifest.xml"]
        add("Android manifest present", "pass" if manifest_entries else "fail", "AndroidManifest.xml found" if manifest_entries else "Missing manifest")
        manifest_size = manifest_entries[0].file_size if manifest_entries else 0
        add("Android manifest size", "pass" if 0 < manifest_size <= 20 * 1024 * 1024 else "fail", f"{manifest_size:,} bytes")
        dex_count = sum(bool(re.fullmatch(r"classes\d*\.dex", name)) for name in lowered_names)
        add("DEX application code present", "pass" if dex_count else "warning", f"{dex_count} DEX files")
        signed = any(name.startswith("meta-inf/") and name.endswith((".rsa", ".dsa", ".ec")) for name in lowered_names)
        add("Signing metadata present", "pass" if signed else "warning", "Certificate metadata found" if signed else "No v1 certificate metadata; verify modern APK signature externally")
        duplicate_count = len(names) - len(set(names))
        add("No duplicate archive names", "pass" if not duplicate_count else "fail", f"{duplicate_count} duplicate names")
        symlinks = sum(((entry.external_attr >> 16) & 0o170000) == 0o120000 for entry in entries)
        add("No symbolic links", "pass" if not symlinks else "fail", f"{symlinks} symbolic links")
        desktop_exec = sum(name.endswith((".exe", ".dll", ".msi", ".bat", ".cmd", ".ps1")) for name in lowered_names)
        add("No desktop executables/scripts", "pass" if not desktop_exec else "warning", f"{desktop_exec} matching files")
        nested = sum(name.endswith((".zip", ".rar", ".7z", ".jar", ".apk")) for name in lowered_names)
        add("No nested archives", "pass" if not nested else "warning", f"{nested} nested archives")
        oversized = sum(entry.file_size > 512 * 1024 * 1024 for entry in entries)
        add("No oversized internal file", "pass" if not oversized else "fail", f"{oversized} oversized entries")

        sampled = bytearray()
        for entry in entries:
            if entry.is_dir() or len(sampled) >= 32 * 1024 * 1024:
                continue
            name = entry.filename.casefold()
            if name == "androidmanifest.xml" or name.endswith((".dex", ".xml", ".json", ".js", ".txt", ".properties")):
                with archive.open(entry) as source:
                    sampled.extend(source.read(min(entry.file_size, 1024 * 1024)))
        evidence = bytes(sampled).lower()

    permission_checks = [
        ("SMS sending permission", b"android.permission.send_sms"),
        ("SMS reading permission", b"android.permission.read_sms"),
        ("Call-log reading permission", b"android.permission.read_call_log"),
        ("Call-log writing permission", b"android.permission.write_call_log"),
        ("Direct phone-call permission", b"android.permission.call_phone"),
        ("Contact reading permission", b"android.permission.read_contacts"),
        ("Contact writing permission", b"android.permission.write_contacts"),
        ("Precise-location permission", b"android.permission.access_fine_location"),
        ("Background-location permission", b"android.permission.access_background_location"),
        ("Microphone permission", b"android.permission.record_audio"),
        ("Camera permission", b"android.permission.camera"),
        ("Calendar reading permission", b"android.permission.read_calendar"),
        ("Calendar writing permission", b"android.permission.write_calendar"),
        ("Body-sensors permission", b"android.permission.body_sensors"),
        ("Activity-recognition permission", b"android.permission.activity_recognition"),
        ("External-storage read permission", b"android.permission.read_external_storage"),
        ("External-storage write permission", b"android.permission.write_external_storage"),
        ("All-files access permission", b"android.permission.manage_external_storage"),
        ("Package installation permission", b"android.permission.request_install_packages"),
        ("Package deletion permission", b"android.permission.delete_packages"),
        ("Installed-app query permission", b"android.permission.query_all_packages"),
        ("Accessibility-service binding", b"android.permission.bind_accessibility_service"),
        ("Device-admin binding", b"android.permission.bind_device_admin"),
        ("VPN-service binding", b"android.permission.bind_vpn_service"),
        ("Notification-listener binding", b"android.permission.bind_notification_listener_service"),
        ("Overlay-window permission", b"android.permission.system_alert_window"),
        ("Usage-stats permission", b"android.permission.package_usage_stats"),
        ("Boot-completed receiver", b"android.permission.receive_boot_completed"),
        ("Wake-lock permission", b"android.permission.wake_lock"),
        ("Biometric permission", b"android.permission.use_biometric"),
    ]
    for name, marker in permission_checks:
        found = marker in evidence
        add(name, "warning" if found else "pass", "Declared; verify it is essential" if found else "Not detected")

    behavior_checks = [
        ("Cleartext HTTP endpoints", b"http://"),
        ("Localhost endpoints", b"localhost"),
        ("Loopback IP endpoints", b"127.0.0.1"),
        ("Embedded private key", b"begin private key"),
        ("AWS access-key pattern", b"akia"),
        ("Firebase database endpoint", b"firebaseio.com"),
        ("Root-shell path", b"/system/bin/su"),
        ("Dynamic DEX loading", b"dexclassloader"),
        ("Native library loading", b"loadlibrary"),
        ("WebView JavaScript bridge", b"addjavascriptinterface"),
        ("WebView JavaScript enabling", b"setjavascriptenabled"),
        ("Runtime command execution", b"runtime;->exec"),
        ("ProcessBuilder execution", b"processbuilder"),
        ("Cryptomining indicators", b"stratum+tcp"),
        ("Debug/test-only build flags", b"android:testonly"),
    ]
    for name, marker in behavior_checks:
        found = marker in evidence
        add(name, "warning" if found else "pass", "Indicator detected; inspect before approval" if found else "Not detected")

    counts = {status: sum(check["status"] == status for check in checks) for status in ("pass", "warning", "fail")}
    return {
        "version": 1,
        "total": len(checks),
        "passed": counts["pass"],
        "warnings": counts["warning"],
        "failed": counts["fail"],
        "sampled_bytes": len(evidence),
        "checks": checks,
        "disclaimer": "Static indicators are not proof of safety or correctness; review warnings and test the app in an isolated environment.",
    }


def parse_deep_scan_report(summary):
    try:
        report = json.loads(summary or "")
    except (TypeError, ValueError):
        return None
    return report if isinstance(report, dict) and report.get("version") == 1 else None


def deep_scan_passed(summary):
    report = parse_deep_scan_report(summary)
    return bool(report and report.get("total") == 60 and report.get("failed") == 0)


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


def escaped_search_term(value, maximum_length=100):
    """Bound LIKE searches and treat SQL wildcard characters as plain text."""
    value = value.strip()[:maximum_length].casefold()
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def unique_app_slug(name):
    base = re.sub(r"[^a-z0-9]+", "-", name.casefold()).strip("-") or "app"
    slug = base
    while StoreApp.query.filter_by(slug=slug).first():
        slug = f"{base}-{secrets.token_hex(3)}"
    return slug


def marketplace_settings():
    return db.session.get(MarketplaceSettings, 1)


def developer_app_limit(user):
    return (
        user.app_upload_limit
        if user.app_upload_limit is not None
        else marketplace_settings().default_app_limit
    )


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
    security_answer = form.get("security_answer", "").strip()
    try:
        security_question = SecurityQuestion(form.get("security_question", ""))
    except ValueError:
        security_question = None
    errors = []

    if not re.fullmatch(r"[A-Za-z0-9_]{3,30}", username):
        errors.append(
            "Username must be 3–30 characters using letters, numbers, or underscores."
        )
    if username.casefold() == current_app.config["ADMIN_USERNAME"].casefold():
        errors.append("That username is reserved. Choose another username.")
    if len(email) > 120 or not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email):
        errors.append("Enter a valid email address.")
    if (
        len(password) < 12
        or not re.search(r"[A-Za-z]", password)
        or not re.search(r"\d", password)
    ):
        errors.append(
            "Password must be at least 12 characters and include a letter and a number."
        )
    if password != confirm_password:
        errors.append("Passwords do not match.")
    if role == UserRole.DEVELOPER and len(company_name) < 2:
        errors.append("Enter your developer or studio name.")
    if len(company_name) > 120:
        errors.append("Developer or studio name must contain at most 120 characters.")
    if security_question is None:
        errors.append("Choose a security question.")
    if not 4 <= len(security_answer) <= 200:
        errors.append("Security answer must contain 4–200 characters.")

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
        "security_question": security_question,
        "security_answer": security_answer,
    }


@main.route("/")
def home():
    approved_apps = (
        StoreApp.query.options(joinedload(StoreApp.developer)).filter_by(status=AppStatus.APPROVED)
        .order_by(StoreApp.approved_at.desc(), StoreApp.id.desc())
        .limit(12)
        .all()
    )
    return render_template("universe.html", approved_apps=approved_apps,
        categories=AppCategory, viewer=current_user())


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


@main.route("/grievance")
def grievance_policy():
    return render_template("grievance_policy.html")


@main.route("/security-and-legal")
def security_legal_policy():
    return render_template("security_legal_policy.html")


@main.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    requested_role = request.form.get("role") or request.args.get(
        "role", UserRole.USER.value
    )
    if requested_role not in {UserRole.USER.value, UserRole.DEVELOPER.value}:
        requested_role = UserRole.USER.value
    if current_app.config.get("PASSWORD_RESET_MODE", "manual") == "manual":
        return redirect(
            url_for("main.security_question_recovery", role=requested_role)
        )
    request_sent = False
    if request.method == "POST":
        if not valid_csrf_token():
            flash("Your session expired. Please try again.", "error")
            return redirect(url_for("main.forgot_password"))
        email = request.form.get("email", "").strip().lower()
        if len(email) > 120 or not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email):
            flash("Enter a valid email address.", "error")
        else:
            throttled = login_is_throttled("password-reset", email)
            if not throttled:
                record_login_failure("password-reset", email)
                user = User.query.filter(
                    func.lower(User.email) == email,
                    User.role == UserRole(requested_role),
                    User.status.notin_([AccountStatus.BLOCKED, AccountStatus.DELETED]),
                ).first()
                if user:
                    raw_token = issue_password_reset(user)
                    reset_url = current_app.config["PUBLIC_BASE_URL"] + url_for(
                        "main.reset_password", token=raw_token
                    )
                    try:
                        delivered = deliver_password_reset(user, reset_url)
                    except (OSError, smtplib.SMTPException):
                        delivered = False
            request_sent = True

    return render_template(
        "password_recovery.html",
        mode="request",
        request_sent=request_sent,
        recovery_role=requested_role,
        csrf_token=get_csrf_token(),
    )


@main.route("/forgot-password/security-question", methods=["GET", "POST"])
def security_question_recovery():
    role_value = request.form.get("role") or request.args.get(
        "role", UserRole.USER.value
    )
    if role_value not in {UserRole.USER.value, UserRole.DEVELOPER.value}:
        role_value = UserRole.USER.value
    if request.method == "POST":
        if not valid_csrf_token():
            abort(400)
        identifier = request.form.get("identifier", "").strip().casefold()
        answer = request.form.get("security_answer", "")
        try:
            question = SecurityQuestion(request.form.get("security_question", ""))
        except ValueError:
            question = None
        scope = f"security-recovery-{role_value}"
        if identifier and not login_is_throttled(scope, identifier):
            user = User.query.filter(
                User.role == UserRole(role_value),
                User.status.notin_([AccountStatus.BLOCKED, AccountStatus.DELETED]),
                or_(
                    func.lower(User.username) == identifier,
                    func.lower(User.email) == identifier,
                ),
            ).first()
            answer_matches = (
                user.check_security_answer(answer)
                if user
                else check_password_hash(
                    _DUMMY_PASSWORD_HASH, " ".join(answer.casefold().split())
                )
            )
            if (
                user
                and question is not None
                and user.security_question == question
                and answer_matches
            ):
                clear_login_failures(scope, identifier)
                reset_request = create_manual_reset_request(user)
                return render_template(
                    "password_recovery.html",
                    mode="manual_requested",
                    reset_reference=reset_request.reference,
                    recovery_role=role_value,
                    csrf_token=get_csrf_token(),
                )
            record_login_failure(scope, identifier)
        flash("Those recovery details could not be verified.", "error")
    return render_template(
        "password_recovery.html",
        mode="security_question",
        recovery_role=role_value,
        security_questions=SecurityQuestion,
        email_recovery_enabled=current_app.config.get("PASSWORD_RESET_MODE")
        == "email",
        csrf_token=get_csrf_token(),
    )


@main.route("/manual-password-reset", methods=["GET", "POST"])
def manual_password_reset():
    if request.method == "POST":
        if not valid_csrf_token():
            abort(400)
        reference = re.sub(r"[^A-Fa-f0-9]", "", request.form.get("reference", ""))[
            :24
        ].upper()
        code = re.sub(r"\D", "", request.form.get("code", ""))[:8]
        scope = f"manual-reset-{reference}"
        reset_request = ManualPasswordReset.query.filter_by(reference=reference).first()
        supplied_hash = hashlib.sha256(code.encode("utf-8")).hexdigest()
        stored_hash = reset_request.code_hash if reset_request else "0" * 64
        valid_code = secrets.compare_digest(stored_hash or "0" * 64, supplied_hash)
        if (
            reset_request
            and reset_request.code_is_valid
            and not login_is_throttled(scope, reference)
            and valid_code
            and reset_request.user.status
            not in {AccountStatus.BLOCKED, AccountStatus.DELETED}
        ):
            now = datetime.now(timezone.utc)
            redeemed = ManualPasswordReset.query.filter(
                ManualPasswordReset.id == reset_request.id,
                ManualPasswordReset.status == ManualResetStatus.APPROVED,
                ManualPasswordReset.code_hash == supplied_hash,
                ManualPasswordReset.code_expires_at > now,
            ).update({"status": ManualResetStatus.USED, "used_at": now, "code_hash": None}, synchronize_session=False)
            if redeemed != 1:
                db.session.rollback()
                abort(400)
            db.session.refresh(reset_request)
            if reset_request.reviewed_by:
                record_admin_audit(
                    reset_request.reviewed_by,
                    AuditAction.PASSWORD_RECOVERY,
                    "redeem",
                    "manual_password_reset",
                    reset_request.id,
                    reset_request.reference,
                    f"One-time reset code redeemed for user ID {reset_request.user_id}.",
                )
            token = issue_password_reset(reset_request.user)
            clear_login_failures(scope, reference)
            return redirect(url_for("main.reset_password", token=token))
        if reset_request and reset_request.status == ManualResetStatus.APPROVED:
            reset_request.failed_attempts += 1
            if reset_request.failed_attempts >= 5:
                reset_request.status = ManualResetStatus.REJECTED
                reset_request.code_hash = None
            db.session.commit()
        record_login_failure(scope, reference)
        flash("The reference or code is invalid, expired, or not approved.", "error")
    return render_template(
        "password_recovery.html",
        mode="manual_code",
        reference=request.args.get("reference", "")[:24],
        csrf_token=get_csrf_token(),
    )


@main.route("/reset-password/<token>", methods=["GET", "POST"])
def reset_password(token):
    token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
    reset_record = PasswordResetToken.query.filter_by(token_hash=token_hash).first()
    if reset_record is None or not reset_record.is_valid or reset_record.user.status in {AccountStatus.BLOCKED, AccountStatus.DELETED}:
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
            len(password) < 12
            or not re.search(r"[A-Za-z]", password)
            or not re.search(r"\d", password)
        ):
            flash(
                "Password must be at least 12 characters and include a letter and a number.",
                "error",
            )
        elif password != confirmation:
            flash("Passwords do not match.", "error")
        else:
            now = datetime.now(timezone.utc)
            consumed = PasswordResetToken.query.filter(
                PasswordResetToken.id == reset_record.id,
                PasswordResetToken.used_at.is_(None),
                PasswordResetToken.expires_at > now,
            ).update({"used_at": now}, synchronize_session=False)
            if consumed != 1:
                db.session.rollback()
                abort(400)
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

        password_matches = (
            admin.check_password(password)
            if admin
            else check_password_hash(_DUMMY_PASSWORD_HASH, password)
        )

        if (
            admin
            and admin.status == AccountStatus.APPROVED
            and password_matches
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

        password_matches = (
            user.check_password(password)
            if user
            else check_password_hash(_DUMMY_PASSWORD_HASH, password)
        )

        if not user or not password_matches:
            record_login_failure(f"{role.value}-login", identifier)
            flash("Incorrect email, username, or password.", "error")
        elif user.status in {AccountStatus.BLOCKED, AccountStatus.DELETED}:
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
        "security_question": request.form.get("security_question", ""),
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
        if request.form.get("confirm_adult") != "yes":
            errors.append("You must confirm that you are at least 18 years old.")
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
                security_question=values["security_question"],
            )
            account.set_password(values["password"])
            account.set_security_answer(values["security_answer"])
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
                    security_questions=SecurityQuestion,
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
        security_questions=SecurityQuestion,
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
    if app_id is None:
        app_count = StoreApp.query.filter_by(developer_id=user.id).count()
        app_limit = developer_app_limit(user)
        if app_count >= app_limit:
            flash(
                f"Your current plan allows {app_limit} app"
                f"{'s' if app_limit != 1 else ''}. Contact an administrator for more slots.",
                "warning",
            )
            return redirect(url_for("main.developer_dashboard"))

    app_record = None
    if app_id is not None:
        app_record = db.session.get(StoreApp, app_id)
        if app_record is None or app_record.developer_id != user.id:
            abort(404)
        if app_record.status not in {AppStatus.REJECTED, AppStatus.PENDING} or app_record.submission_status not in {SubmissionStatus.ADMIN_REJECTED, SubmissionStatus.SECURITY_CHECK_FAILED}:
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
                # Serialize final slot allocation, not the expensive file scan.
                owner = User.query.filter_by(id=user.id).with_for_update().populate_existing().one()
                allowed = owner.status == AccountStatus.APPROVED and StoreApp.query.filter_by(developer_id=owner.id).count() < developer_app_limit(owner)
                if not allowed:
                    db.session.rollback()
                    safe_delete_upload("app_icons", icon_file)
                    safe_delete_upload("apks", apk_file)
                    for screenshot in new_screenshots:
                        safe_delete_upload("app_screenshots", screenshot["file_name"])
                    abort(409, description="Developer approval or upload allowance changed. Review your dashboard before submitting again.")
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
            start_submission(app_record, user)
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
    if app_record.pending_release_status == ReleaseStatus.PENDING and app_record.submission_status != SubmissionStatus.SECURITY_CHECK_FAILED:
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
            start_submission(app_record, user)
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
    query_text = request.args.get("q", "").strip()[:100]
    apps_query = StoreApp.query.options(joinedload(StoreApp.developer)).filter_by(
        status=AppStatus.APPROVED
    )
    if category_value in {category.value for category in AppCategory}:
        apps_query = apps_query.filter(StoreApp.category == AppCategory(category_value))
    if query_text:
        search = f"%{escaped_search_term(query_text)}%"
        apps_query = apps_query.filter(
            or_(
                func.lower(StoreApp.name).like(search, escape="\\"),
                func.lower(StoreApp.short_description).like(search, escape="\\"),
                func.lower(StoreApp.description).like(search, escape="\\"),
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
    # Serialize tracking for this app so concurrent first downloads cannot
    # duplicate user/version records or lose increments on PostgreSQL.
    app_record = (
        StoreApp.query.filter_by(slug=slug, status=AppStatus.APPROVED)
        .with_for_update()
        .first_or_404()
    )
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
        viewer and viewer.status == AccountStatus.APPROVED
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
        viewer and viewer.status == AccountStatus.APPROVED
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
    query_text = request.args.get("q", "").strip()[:100]
    role_filter = request.args.get("role", "all")
    status_filter = request.args.get("status", "all")

    accounts_query = User.query.options(selectinload(User.developer_profile)).filter(
        User.role.notin_([UserRole.ADMIN, UserRole.CO_ADMIN]),
        User.status != AccountStatus.DELETED,
    )
    if admin.role == UserRole.CO_ADMIN:
        accounts_query = accounts_query.filter(User.role == UserRole.DEVELOPER)
    if query_text:
        search = f"%{escaped_search_term(query_text)}%"
        accounts_query = accounts_query.filter(
            or_(
                func.lower(User.username).like(search, escape="\\"),
                func.lower(User.email).like(search, escape="\\"),
                func.lower(func.coalesce(User.company_name, "")).like(
                    search, escape="\\"
                ),
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
                (
                    (User.role.notin_([UserRole.ADMIN, UserRole.CO_ADMIN]))
                    & (User.status != AccountStatus.DELETED),
                    1,
                )
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
        submissions=StoreApp.query.options(joinedload(StoreApp.developer)).filter(
            StoreApp.status != AppStatus.DELETED
        ).order_by(StoreApp.updated_at.desc()).limit(5).all(),
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
        marketplace_settings=marketplace_settings(),
        csrf_token=get_csrf_token(),
    )


@main.route("/admin/password-resets", methods=["GET", "POST"])
@role_required(UserRole.ADMIN)
def admin_password_resets(admin):
    issued_code = None
    issued_reference = None
    if request.method == "POST":
        if not valid_csrf_token():
            abort(400)
        reset_request = db.session.get(
            ManualPasswordReset, request.form.get("request_id", type=int)
        )
        action = request.form.get("action", "")
        admin_password = request.form.get("admin_password", "")
        if reset_request is None:
            abort(404)
        if reset_request.status != ManualResetStatus.PENDING:
            flash("That request has already been reviewed.", "error")
        elif not admin.check_password(admin_password):
            flash("Your administrator password was incorrect.", "error")
        elif action == "approve":
            raw_code = f"{secrets.randbelow(100_000_000):08d}"
            reset_request.status = ManualResetStatus.APPROVED
            reset_request.code_hash = hashlib.sha256(
                raw_code.encode("utf-8")
            ).hexdigest()
            reset_request.code_expires_at = datetime.now(timezone.utc) + timedelta(
                minutes=15
            )
            reset_request.failed_attempts = 0
            reset_request.reviewed_by_id = admin.id
            reset_request.reviewed_at = datetime.now(timezone.utc)
            record_admin_audit(
                admin,
                AuditAction.PASSWORD_RECOVERY,
                "approve",
                "manual_password_reset",
                reset_request.id,
                reset_request.reference,
                f"Approved password reset for user ID {reset_request.user_id}.",
            )
            db.session.commit()
            issued_code = raw_code
            issued_reference = reset_request.reference
        elif action == "reject":
            reset_request.status = ManualResetStatus.REJECTED
            reset_request.reviewed_by_id = admin.id
            reset_request.reviewed_at = datetime.now(timezone.utc)
            reset_request.code_hash = None
            reset_request.code_expires_at = None
            record_admin_audit(
                admin,
                AuditAction.PASSWORD_RECOVERY,
                "reject",
                "manual_password_reset",
                reset_request.id,
                reset_request.reference,
                f"Rejected password reset for user ID {reset_request.user_id}.",
            )
            db.session.commit()
            flash("The password-reset request was rejected.", "success")
        else:
            abort(400)

    requests = (
        ManualPasswordReset.query.options(joinedload(ManualPasswordReset.user))
        .order_by(ManualPasswordReset.created_at.desc())
        .limit(100)
        .all()
    )
    return render_template(
        "admin_password_resets.html",
        admin=admin,
        reset_requests=requests,
        issued_code=issued_code,
        issued_reference=issued_reference,
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
    settings = marketplace_settings()
    if request.method == "POST":
        if not valid_csrf_token():
            abort(400)
        if request.form.get("settings_section") == "marketplace":
            if admin.role != UserRole.ADMIN:
                abort(403)
            try:
                default_app_limit = int(request.form.get("default_app_limit", ""))
                max_apk_size_mb = int(request.form.get("max_apk_size_mb", ""))
            except ValueError:
                default_app_limit = max_apk_size_mb = -1
            if not 0 <= default_app_limit <= 1000:
                flash("Default app limit must be between 0 and 1,000.", "error")
            elif not 10 <= max_apk_size_mb <= 200:
                flash("Maximum APK size must be between 10 and 200 MB.", "error")
            else:
                settings.default_app_limit = default_app_limit
                settings.max_apk_size_mb = max_apk_size_mb
                record_admin_audit(
                    admin,
                    AuditAction.ACCOUNT_MODERATION,
                    "update_marketplace_limits",
                    "marketplace",
                    settings.id,
                    "Upload defaults",
                    f"{default_app_limit} apps, {max_apk_size_mb} MB",
                )
                db.session.commit()
                flash("Marketplace upload defaults were updated.", "success")
            return redirect(url_for("main.admin_settings"))
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
                if new_password:
                    session["session_version"] = admin.session_version
                flash("Administrator settings were updated securely.", "success")
                return redirect(url_for("main.admin_settings"))
            except IntegrityError:
                db.session.rollback()
                flash("That email address is already in use.", "error")
    return render_template(
        "admin_settings.html",
        admin=admin,
        marketplace_settings=settings,
        csrf_token=get_csrf_token(),
    )


@main.post("/admin/developers/<int:user_id>/upload-limit")
@role_required(UserRole.ADMIN)
def set_developer_upload_limit(admin, user_id):
    if not valid_csrf_token():
        abort(400)
    developer = db.session.get(User, user_id)
    if developer is None or developer.role != UserRole.DEVELOPER:
        abort(404)
    raw_limit = request.form.get("app_upload_limit", "").strip()
    try:
        limit = None if raw_limit == "" else int(raw_limit)
    except ValueError:
        limit = -1
    if limit is not None and not 0 <= limit <= 1000:
        flash("Developer app limit must be between 0 and 1,000.", "error")
    else:
        developer.app_upload_limit = limit
        label = "default" if limit is None else str(limit)
        record_admin_audit(
            admin,
            AuditAction.ACCOUNT_MODERATION,
            "update_upload_limit",
            "developer",
            developer.id,
            developer.username,
            f"App limit: {label}",
        )
        db.session.commit()
        flash(f"Upload limit for {developer.username} was updated.", "success")
    return redirect(url_for("main.admin_developer_review", user_id=user_id))


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
    query_text = request.args.get("q", "").strip()[:100]
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
    elif status_value in {status.value for status in AppStatus} and status_value != "rejected":
        apps_query = apps_query.filter(StoreApp.status == AppStatus(status_value))
    elif status_value in {
        "security_failed", "waiting_review", "verified", "published", "rejected"
    }:
        workflow_filters = {
            "security_failed": SubmissionStatus.SECURITY_CHECK_FAILED,
            "waiting_review": SubmissionStatus.ADMIN_REVIEW_PENDING,
            "verified": SubmissionStatus.PUBLISH_PENDING,
            "published": SubmissionStatus.PUBLISHED,
            "rejected": SubmissionStatus.ADMIN_REJECTED,
        }
        apps_query = apps_query.filter(StoreApp.submission_status == workflow_filters[status_value])
        if status_value == "published":
            apps_query = apps_query.filter(StoreApp.status == AppStatus.APPROVED)
    if query_text:
        search = f"%{escaped_search_term(query_text)}%"
        apps_query = apps_query.join(User, StoreApp.developer_id == User.id).filter(
            or_(
                func.lower(StoreApp.name).like(search, escape="\\"),
                func.lower(StoreApp.package_name).like(search, escape="\\"),
                func.lower(User.username).like(search, escape="\\"),
                func.lower(User.company_name).like(search, escape="\\"),
                StoreApp.id == (int(query_text) if query_text.isdecimal() else -1),
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
        deep_scan_report=parse_deep_scan_report(app_record.security_scan_summary),
        pending_deep_scan_report=parse_deep_scan_report(
            app_record.pending_security_scan_summary
        ),
        csrf_token=get_csrf_token(),
    )


@main.get("/developer/apps/<int:app_id>")
@developer_access_required
def developer_app_submission(user, app_id):
    app_record = StoreApp.query.filter_by(id=app_id, developer_id=user.id).first_or_404()
    return render_template("developer_app_submission.html", user=user,
        app_record=app_record, csrf_token=get_csrf_token())


def submission_reader():
    user = current_user()
    if not user or user.status in {AccountStatus.BLOCKED, AccountStatus.DELETED}:
        abort(401)
    if user.role in {UserRole.ADMIN, UserRole.CO_ADMIN} and user.status == AccountStatus.APPROVED:
        return user, StoreApp.query
    if user.role == UserRole.DEVELOPER:
        return user, StoreApp.query.filter_by(developer_id=user.id)
    abort(403)


@main.get("/submission-status")
def submission_status_snapshot():
    user, query = submission_reader()
    ids = [int(value) for value in request.args.get("ids", "").split(",") if value.isdecimal()][:50]
    apps = query.filter(StoreApp.id.in_(ids)).all()
    items = []
    for app_record in apps:
        view = submission_view(app_record)
        items.append({"id": app_record.id, "revision": app_record.submission_revision,
            "label": view["label"], "security": view["security"], "admin": view["admin"],
            "publishing": view["publishing"], "scan_running": view["scan_running"],
            "html": render_template("_submission_progress.html", app_record=app_record),
            "actions": render_template("_submission_developer_actions.html", app_record=app_record)
                if user.role == UserRole.DEVELOPER else None,
            "panel": render_template("_submission_panel.html", app_record=app_record,
                admin=user if user.role in {UserRole.ADMIN, UserRole.CO_ADMIN} else None,
                csrf_token=get_csrf_token()) if request.args.get("details") == "1" else None})
    response = jsonify({"items": items})
    response.headers["Cache-Control"] = "private, no-store"
    return response


@main.get("/apps/<int:app_id>/status-history")
def app_submission_history(app_id):
    user, query = submission_reader()
    app_record = query.filter_by(id=app_id).first_or_404()
    response = jsonify({"history": [{"previousStatus": entry.previous_status,
        "newStatus": entry.new_status, "changedBy": entry.changed_by_id,
        "changedByRole": entry.changed_by_role, "reason": entry.reason,
        "version": entry.version, "createdAt": entry.created_at.isoformat()}
        for entry in app_record.submission_history]})
    response.headers["Cache-Control"] = "private, no-store"
    return response


@main.post("/admin/apps/<int:app_id>/scan")
@staff_required
def scan_app(admin, app_id):
    if not valid_csrf_token():
        abort(400)
    app_record = StoreApp.query.filter_by(id=app_id).with_for_update().populate_existing().first()
    if app_record is None:
        abort(404)
    target_name = request.form.get("target", "pending" if app_record.pending_version else "current")
    pending = bool(app_record.pending_version)
    if target_name != ("pending" if pending else "current") or app_record.status in {AppStatus.DELETED, AppStatus.BLOCKED}:
        abort(409, description="Scan the current submission, not a previous live build.")
    if app_record.submission_status not in {SubmissionStatus.SECURITY_CHECK_PENDING, SubmissionStatus.SECURITY_CHECK_FAILED}:
        abort(409, description="This build has already left the security stage.")
    started = app_record.scan_started_at
    now = datetime.now(timezone.utc)
    if started and now - started.replace(tzinfo=timezone.utc) < timedelta(minutes=10):
        abort(409, description="A security scan is already running. Please wait.")
    if app_record.submission_status == SubmissionStatus.SECURITY_CHECK_FAILED:
        set_status(app_record, SubmissionStatus.SECURITY_CHECK_PENDING, admin, "Security scan retried")
    app_record.scan_started_at = now
    filename = app_record.pending_apk_file if pending else app_record.apk_file
    expected_digest = app_record.pending_apk_sha256 if pending else app_record.apk_sha256
    directory = private_upload_folder("apks")
    path = (directory / filename).resolve() if filename else directory
    db.session.commit()
    account_events.publish({"type": "app_scan_started", "app_id": app_id,
        "user_id": app_record.developer_id})
    structural_summary = malware_summary = "The application file is missing or invalid."
    structural_status = malware_status = SecurityScanStatus.FAILED
    try:
        if not filename or Path(filename).name != filename or path.parent != directory or not path.is_file():
            raise ValueError(structural_summary)
        with path.open("rb") as uploaded:
            digest = hashlib.file_digest(uploaded, "sha256").hexdigest()
        if digest != expected_digest:
            raise ValueError("The application file changed after submission.")
        report = deep_scan_apk(path)
        structural_status = SecurityScanStatus.PASSED if report["failed"] == 0 else SecurityScanStatus.FAILED
        structural_summary = json.dumps(report, separators=(",", ":"))
        try:
            malware_summary = scan_apk_for_malware(path)
            malware_status = SecurityScanStatus.PASSED
        except ValueError as error:
            malware_summary = str(error)
    except OSError:
        structural_summary = "The APK could not be read securely. Ask an administrator to check private storage."
    except (ValueError, zipfile.BadZipFile) as error:
        structural_summary = str(error) or "Invalid application package."
    # Reload under lock so edits/download counters during the scan are not overwritten.
    app_record = StoreApp.query.filter_by(id=app_id).with_for_update().populate_existing().first()
    if app_record is None or app_record.scan_started_at is None or app_record.scan_started_at.replace(tzinfo=timezone.utc) != now:
        abort(409, description="The submission changed while the scan was running.")
    if app_record.status in {AppStatus.DELETED, AppStatus.BLOCKED}:
        app_record.scan_started_at = None
        db.session.commit()
        abort(409)
    prefix = "pending_" if pending else ""
    finished = datetime.now(timezone.utc)
    for field, value in {"security_scan_status": structural_status,
        "security_scan_summary": structural_summary, "security_scanned_at": finished,
        "malware_scan_status": malware_status, "malware_scan_summary": malware_summary,
        "malware_scanned_at": finished}.items():
        setattr(app_record, prefix + field, value)
    app_record.scan_started_at = None
    passed = structural_status == malware_status == SecurityScanStatus.PASSED
    if passed:
        set_status(app_record, SubmissionStatus.SECURITY_CHECK_PASSED, reason="Static APK checks and ClamAV malware scan passed")
        set_status(app_record, SubmissionStatus.ADMIN_REVIEW_PENDING, reason="Waiting for an administrator to verify this build")
        app_record.submission_feedback = None
    else:
        reasons = []
        if structural_status == SecurityScanStatus.FAILED:
            parsed = parse_deep_scan_report(structural_summary)
            reasons.append("; ".join(check["name"] + ": " + check["detail"] for check in parsed["checks"] if check["status"] == "fail") if parsed else structural_summary)
        if malware_status == SecurityScanStatus.FAILED:
            reasons.append(malware_summary)
        app_record.submission_feedback = "\n".join(reasons)[:4000]
        set_status(app_record, SubmissionStatus.SECURITY_CHECK_FAILED, reason=app_record.submission_feedback)
    record_admin_audit(admin, AuditAction.APP_MODERATION, "security_scan", "release" if pending else "app",
        app_id, app_record.name, f"{target_name}: static={structural_status.value}, malware={malware_status.value}")
    db.session.commit()
    account_events.publish({"type": "app_scan_completed", "app_id": app_id,
        "user_id": app_record.developer_id, "submission_status": app_record.submission_status.value})
    flash("Security checks passed; awaiting admin verification." if passed else "Security check failed. Review the failure reason.", "success" if passed else "error")
    return redirect(url_for("main.admin_app_review", app_id=app_id))


@main.get("/admin/apps/<int:app_id>/scan-report")
@staff_required
def download_scan_report(admin, app_id):
    app_record = db.session.get(StoreApp, app_id)
    if app_record is None:
        abort(404)
    target_name = request.args.get("target", "current")
    if target_name not in {"current", "pending"}:
        abort(400)
    pending = target_name == "pending"
    prefix = "pending_" if pending else ""
    static_summary = getattr(app_record, f"{prefix}security_scan_summary")
    static_report = parse_deep_scan_report(static_summary)
    if static_report is None:
        abort(404)
    static_status = getattr(app_record, f"{prefix}security_scan_status")
    malware_status = getattr(app_record, f"{prefix}malware_scan_status")
    scanned_at = getattr(app_record, f"{prefix}security_scanned_at")
    malware_scanned_at = getattr(app_record, f"{prefix}malware_scanned_at")
    report = {
        "report_format": "appora-apk-security-report-v1",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "app": {
            "id": app_record.id,
            "name": app_record.name,
            "package_name": app_record.package_name,
            "developer": app_record.developer.username,
            "target": target_name,
            "version": app_record.pending_version if pending else app_record.version,
            "file_name": app_record.pending_apk_original_name if pending else app_record.apk_original_name,
            "size_bytes": app_record.pending_apk_size if pending else app_record.apk_size,
            "sha256": app_record.pending_apk_sha256 if pending else app_record.apk_sha256,
        },
        "verdict": (
            "blocked"
            if static_status != SecurityScanStatus.PASSED
            or malware_status != SecurityScanStatus.PASSED
            else "review_warnings"
            if static_report["warnings"]
            else "eligible_for_approval"
        ),
        "static_analysis": {
            "status": static_status.value if static_status else "unscanned",
            "scanned_at": scanned_at.isoformat() if scanned_at else None,
            **static_report,
        },
        "malware_analysis": {
            "engine": "ClamAV",
            "status": malware_status.value if malware_status else "unscanned",
            "scanned_at": malware_scanned_at.isoformat() if malware_scanned_at else None,
            "result": getattr(app_record, f"{prefix}malware_scan_summary"),
            "coverage": [
                "known malware and ransomware signatures",
                "potentially unwanted applications",
                "archive-contained payloads",
                "heuristic indicators",
                "phishing URLs",
                "structured sensitive data",
                "ClamAV bytecode rules",
            ],
        },
        "limitations": [
            "A clean result is not a guarantee that the APK is safe or bug-free.",
            "Unknown zero-day threats and behavior visible only at runtime may not be detected.",
            "Warnings require administrator review and isolated runtime testing.",
        ],
    }
    response = Response(
        json.dumps(report, indent=2),
        mimetype="application/json",
    )
    response.headers["Content-Disposition"] = (
        f'attachment; filename="appora-scan-{app_record.id}-{target_name}.json"'
    )
    response.headers["Cache-Control"] = "private, no-store"
    return response


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


def publish_submission_build(app_record):
    if app_record.pending_version:
        db.session.add(AppVersionHistory(app=app_record, version=app_record.version,
            min_android_version=app_record.min_android_version, changelog=app_record.changelog,
            apk_file=app_record.apk_file, apk_original_name=app_record.apk_original_name,
            apk_size=app_record.apk_size, apk_sha256=app_record.apk_sha256,
            published_at=app_record.approved_at or app_record.created_at))
        for field in ("version", "min_android_version", "changelog", "apk_file",
                      "apk_original_name", "apk_size", "apk_sha256", "security_scan_status",
                      "security_scan_summary", "security_scanned_at", "malware_scan_status",
                      "malware_scan_summary", "malware_scanned_at"):
            setattr(app_record, field, getattr(app_record, "pending_" + field))
        app_record.clear_pending_release()
    app_record.approve()
    app_record.published_at = datetime.now(timezone.utc)


def perform_submission_action(admin, app_id, action):
    if not valid_csrf_token():
        abort(400, description="Your session expired. Refresh and try again.")
    app_record = StoreApp.query.filter_by(id=app_id).with_for_update().populate_existing().first()
    if app_record is None:
        abort(404)
    if app_record.status in {AppStatus.DELETED, AppStatus.BLOCKED}:
        abort(409, description="Restore or unblock this app through moderation first.")
    state = app_record.submission_status
    if (action == "publish" and state == SubmissionStatus.PUBLISHED) or (
        action == "approve" and state in {SubmissionStatus.ADMIN_VERIFIED, SubmissionStatus.PUBLISH_PENDING, SubmissionStatus.PUBLISHED}
    ):
        return jsonify({"ok": True, "unchanged": True, "status": submission_view(app_record)}) if request.headers.get("X-Requested-With") == "fetch" else redirect(url_for("main.admin_app_review", app_id=app_id))
    revision = request.form.get("revision", type=int)
    if revision is not None and revision != app_record.submission_revision:
        abort(409, description="Another reviewer changed this submission. Refresh before continuing.")
    note = request.form.get("review_note", "").strip()
    if len(note) > 4000:
        abort(400, description="Feedback must be at most 4,000 characters.")
    try:
        if action in {"approve", "publish"}:
            if app_record.developer.status != AccountStatus.APPROVED:
                raise ValueError("The developer must be approved before verification or publication.")
            prefix = "pending_" if app_record.pending_version else ""
            if not deep_scan_passed(getattr(app_record, prefix + "security_scan_summary")) or getattr(app_record, prefix + "malware_scan_status") != SecurityScanStatus.PASSED:
                raise ValueError("Run the administrator security scan; both static and malware checks must pass.")
            filename = getattr(app_record, prefix + "apk_file")
            if not filename or not getattr(app_record, prefix + "apk_sha256"):
                raise ValueError("The build is missing its file or checksum. Resubmit and scan it again.")
            path = private_upload_folder("apks") / filename
            digest = None
            if path.is_file() and Path(filename).name == filename:
                with path.open("rb") as uploaded:
                    digest = hashlib.file_digest(uploaded, "sha256").hexdigest()
            if digest != getattr(app_record, prefix + "apk_sha256"):
                raise ValueError("The scanned APK is missing or has changed. Resubmit and scan the build again.")
            if action == "approve":
                set_status(app_record, SubmissionStatus.ADMIN_VERIFIED, admin, note or "Administrator verified this build")
                app_record.verified_at = datetime.now(timezone.utc)
                app_record.verified_by_id = admin.id
                app_record.submission_feedback = note or None
                set_status(app_record, SubmissionStatus.PUBLISH_PENDING, reason="Awaiting explicit publication")
            else:
                set_status(app_record, SubmissionStatus.PUBLISHED, admin, "Application is now live")
                publish_submission_build(app_record)
                for (saved_user_id,) in db.session.query(SavedApp.user_id).filter_by(app_id=app_id).all():
                    create_notification(saved_user_id, NotificationType.RELEASE,
                        f"{app_record.name} {app_record.version} is available",
                        "An administrator-approved release is ready to download.",
                        url_for("main.app_detail", slug=app_record.slug))
        elif action in {"reject", "request-changes"}:
            if not note:
                raise ValueError("A reason is required for rejection or requested changes.")
            set_status(app_record, SubmissionStatus.ADMIN_REJECTED, admin, note)
            app_record.submission_feedback = note
            app_record.changes_requested = action == "request-changes"
            if app_record.pending_version:
                app_record.pending_release_status = ReleaseStatus.REJECTED
                app_record.pending_release_note = note
            else:
                app_record.reject(note)
        else:
            abort(404)
    except ValueError as error:
        db.session.rollback()
        if request.headers.get("X-Requested-With") == "fetch":
            return jsonify({"ok": False, "message": str(error)}), 409
        flash(str(error), "error")
        return redirect(url_for("main.admin_app_review", app_id=app_id))
    record_admin_audit(admin, AuditAction.APP_MODERATION, action, "app", app_id, app_record.name, note)
    db.session.commit()
    account_events.publish({"type": "app_updated", "app_id": app_id,
        "user_id": app_record.developer_id, "status": app_record.status.value,
        "submission_status": app_record.submission_status.value})
    if request.headers.get("X-Requested-With") == "fetch":
        return jsonify({"ok": True, "status": submission_view(app_record)})
    flash("Submission updated: " + submission_view(app_record)["label"], "success")
    return redirect(url_for("main.admin_app_review", app_id=app_id))


@main.post("/admin/apps/<int:app_id>/release/<action>")
@staff_required
def manage_app_release(admin, app_id, action):
    return perform_submission_action(admin, app_id, action)


@main.post("/admin/apps/<int:app_id>/<action>")
@staff_required
def manage_app(admin, app_id, action):
    if action in {"approve", "reject", "request-changes", "publish"}:
        return perform_submission_action(admin, app_id, action)
    if not valid_csrf_token():
        flash("Your session expired. Please try again.", "error")
        return redirect(url_for("main.admin_apps"))
    app_record = StoreApp.query.filter_by(id=app_id).with_for_update().populate_existing().first()
    if app_record is None:
        abort(404)
    if action not in {"block", "delete", "restore", "hard_delete"}:
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

    action_labels = {
        "block": "blocked",
        "delete": "moved to trash",
        "restore": "restored",
        "hard_delete": "permanently deleted",
    }

    review_note = request.form.get("review_note", "").strip()
    app_name = app_record.name
    developer_id = app_record.developer_id
    cleanup_files = []
    if action == "block":
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
    stream_user = current_user()
    initial_role = stream_user.role if stream_user else None
    limiter = current_app.extensions['security_limits']
    lease = limiter.acquire('event-streams', str(stream_user.id) if stream_user else 'anonymous', 5, 630)
    if not lease:
        abort(429)
    try:
        subscriber = account_events.subscribe()
    except Exception:
        limiter.release(lease)
        raise

    @stream_with_context
    def generate():
        deadline = time.monotonic() + 600
        try:
            yield "retry: 2500\n\n"
            while time.monotonic() < deadline:
                db.session.expire_all()
                live_user = current_user()
                allowed = bool(live_user and live_user.role == initial_role)
                db.session.remove()  # No database connection held during idle streaming.
                if not allowed:
                    return
                try:
                    event = subscriber.get(timeout=15)
                except Empty:
                    yield ": keep-alive\n\n"
                    continue
                db.session.expire_all()
                live_user = current_user()
                allowed = bool(live_user and live_user.role == initial_role)
                db.session.remove()
                if not allowed:
                    return
                if event_filter(event):
                    yield f"id: {event['event_id']}\n"
                    yield "event: account-change\n"
                    yield f"data: {json.dumps(event)}\n\n"
        finally:
            account_events.unsubscribe(subscriber)
            limiter.release(lease)

    return Response(
        generate(),
        mimetype="text/event-stream",
        headers={"Cache-Control": "private, no-store", "X-Accel-Buffering": "no"},
    )


@main.get("/events/admin-accounts")
@staff_required
def admin_account_events(admin):
    return server_event_response(
        lambda event: event.get("type", "").startswith("account_") and (
            admin.role == UserRole.ADMIN or event.get("role") == UserRole.DEVELOPER.value)
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
        security_answer = request.form.get("security_answer", "").strip()
        question_value = request.form.get("security_question")
        try:
            security_question = (
                SecurityQuestion(question_value)
                if question_value is not None
                else user.security_question
            )
        except ValueError:
            security_question = None
        errors = []
        if email != user.email and not user.check_password(current_password):
            errors.append("Enter your current password to change your email address.")
        if not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email):
            errors.append("Enter a valid email address.")
        elif User.query.filter(
            func.lower(User.email) == email, User.id != user.id
        ).first():
            errors.append("That email address is already in use.")
        if user.role == UserRole.DEVELOPER and not company_name:
            errors.append("Enter your developer or company name.")
        if len(company_name) > 120:
            errors.append("Developer or company name must contain at most 120 characters.")
        if new_password or confirm_password:
            if not user.check_password(current_password):
                errors.append("Your current password is incorrect.")
            elif (
                len(new_password) < 12
                or not re.search(r"[A-Za-z]", new_password)
                or not re.search(r"\d", new_password)
            ):
                errors.append(
                    "The new password must be at least 12 characters with a letter and number."
                )
            elif new_password != confirm_password:
                errors.append("The new passwords do not match.")
        security_change = security_answer or security_question != user.security_question
        if security_change:
            if not user.check_password(current_password):
                errors.append(
                    "Enter your current password to change the security question."
                )
            elif security_question is None:
                errors.append("Choose a security question.")
            elif not 4 <= len(security_answer) <= 200:
                errors.append("Security answer must contain 4–200 characters.")
        if errors:
            for error in errors:
                flash(error, "error")
        else:
            user.email = email
            if user.role == UserRole.DEVELOPER:
                user.company_name = company_name
            if new_password:
                user.set_password(new_password)
            if security_change:
                user.security_question = security_question
                user.set_security_answer(security_answer)
            try:
                db.session.commit()
                if new_password:
                    session["session_version"] = user.session_version
                flash("Your account settings were updated.", "success")
                return redirect(url_for("main.account_settings"))
            except IntegrityError:
                db.session.rollback()
                flash("That email address is already in use.", "error")

    return render_template(
        "account_settings.html",
        user=user,
        security_questions=SecurityQuestion,
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
            datetime.strptime(str(day), "%Y-%m-%d").date(): count
            for day, count in tracked
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
        app_limit=developer_app_limit(user),
        max_apk_size_mb=marketplace_settings().max_apk_size_mb,
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
    if user:
        User.query.filter_by(id=user.id).update({"session_version": User.session_version + 1})
        db.session.commit()
    session.clear()
    flash("You have been signed out safely.", "success")
    return redirect(url_for("main.home"))

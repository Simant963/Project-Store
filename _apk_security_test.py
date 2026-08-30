import io
import os
import re
import shutil
import tempfile
import zipfile
from datetime import datetime, timezone
from pathlib import Path

test_root = Path(tempfile.mkdtemp(prefix="appora-apk-security-"))
os.environ["DATABASE_URL"] = f"sqlite:///{(test_root / 'test.db').as_posix()}"
os.environ["PRIVATE_UPLOAD_ROOT"] = str(test_root / "uploads")
os.environ["SECRET_KEY"] = "apk-security-test"
os.environ["ADMIN_USERNAME"] = "security_admin"
os.environ["ADMIN_EMAIL"] = "security-admin@example.com"
os.environ["ADMIN_PASSWORD"] = "AdminPass123!"

from app import app
from application.database import db
from application.models import (
    AccountStatus, DeveloperProfile, GovernmentIdType, SecurityScanStatus,
    StoreApp, User, UserRole,
)

app.config["TESTING"] = True
PNG = b"\x89PNG\r\n\x1a\n" + b"icon-data"


def apk_bytes(entries):
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, content in entries.items():
            archive.writestr(name, content)
    return output.getvalue()


VALID_APK = apk_bytes({
    "AndroidManifest.xml": b"binary-manifest",
    "classes.dex": b"dex-content",
    "resources.arsc": b"resources",
    "META-INF/CERT.SF": b"signature-metadata",
})
MISSING_MANIFEST_APK = apk_bytes({"classes.dex": b"dex-content"})
UNSAFE_PATH_APK = apk_bytes({"AndroidManifest.xml": b"manifest", "../outside": b"bad"})


def csrf(client, url):
    response = client.get(url)
    assert response.status_code == 200, (url, response.status_code)
    return re.search(rb'name="csrf_token" value="([^"]+)"', response.data).group(1).decode()


def app_form(token, name, package, apk):
    return {
        "csrf_token": token, "name": name, "package_name": package,
        "short_description": "A secure application submitted for structural APK validation.",
        "description": "This complete application description is longer than eighty characters and explains the secure marketplace submission clearly.",
        "version": "1.0.0", "min_android_version": "Android 8.0",
        "category": "tools", "age_rating": "everyone",
        "support_email": "support@example.com", "website": "https://example.com/app",
        "privacy_policy_url": "https://example.com/privacy", "changelog": "First release.",
        "app_icon": (io.BytesIO(PNG), f"{name}.png"),
        "apk_file": (io.BytesIO(apk), f"{name}.apk"),
    }


try:
    uploads = test_root / "uploads"
    (uploads / "developer_ids").mkdir(parents=True, exist_ok=True)
    (uploads / "developer_ids" / "id.png").write_bytes(PNG)
    with app.app_context():
        developer = User(username="security_dev", email="security@example.com", role=UserRole.DEVELOPER, status=AccountStatus.APPROVED)
        developer.set_password("Developer123")
        developer.approve()
        developer.developer_profile = DeveloperProfile(
            legal_name="Security Developer", phone="+91 9876543210", country="India",
            government_id_type=GovernmentIdType.PASSPORT, government_id_number="P123456",
            government_id_file="id.png", government_id_original_name="id.png",
            submitted_at=datetime.now(timezone.utc),
        )
        db.session.add(developer)
        db.session.commit()

    developer_client = app.test_client()
    token = csrf(developer_client, "/login/developer")
    developer_client.post("/login/developer", data={"csrf_token": token, "identifier": "security_dev", "password": "Developer123"})

    token = csrf(developer_client, "/developer/apps/new")
    valid = developer_client.post("/developer/apps/new", data=app_form(token, "Secure Notes", "com.example.securenotes", VALID_APK), content_type="multipart/form-data", follow_redirects=True)
    assert valid.status_code == 200
    with app.app_context():
        secure_app = StoreApp.query.filter_by(package_name="com.example.securenotes").one()
        app_id = secure_app.id
        assert secure_app.security_scan_status == SecurityScanStatus.PASSED
        assert "Android manifest found" in secure_app.security_scan_summary

    token = csrf(developer_client, "/developer/apps/new")
    missing = developer_client.post("/developer/apps/new", data=app_form(token, "Missing Manifest", "com.example.missingmanifest", MISSING_MANIFEST_APK), content_type="multipart/form-data", follow_redirects=True)
    assert b"missing AndroidManifest.xml" in missing.data

    token = csrf(developer_client, "/developer/apps/new")
    unsafe = developer_client.post("/developer/apps/new", data=app_form(token, "Unsafe Paths", "com.example.unsafepaths", UNSAFE_PATH_APK), content_type="multipart/form-data", follow_redirects=True)
    assert b"unsafe file path" in unsafe.data

    token = csrf(developer_client, "/developer/apps/new")
    duplicate = developer_client.post("/developer/apps/new", data=app_form(token, "Duplicate Build", "com.example.duplicatebuild", VALID_APK), content_type="multipart/form-data", follow_redirects=True)
    assert b"exact APK build is already registered" in duplicate.data
    with app.app_context():
        assert StoreApp.query.count() == 1

    admin = app.test_client()
    token = csrf(admin, "/admin/login")
    admin.post("/admin/login", data={"csrf_token": token, "identifier": "security_admin", "password": "AdminPass123!"})
    review = admin.get(f"/admin/apps/{app_id}")
    assert review.status_code == 200 and b"Structural safety: Passed" in review.data
    with admin.session_transaction() as session:
        admin_token = session["_csrf_token"]
    approved = admin.post(f"/admin/apps/{app_id}/approve", data={"csrf_token": admin_token}, follow_redirects=True)
    assert approved.status_code == 200
    print("apk-security-tests-passed")
finally:
    shutil.rmtree(test_root, ignore_errors=True)

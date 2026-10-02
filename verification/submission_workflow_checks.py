"""Isolated workflow regression checks. Never connects to the project's database.

Run: env/Scripts/python.exe verification/submission_workflow_checks.py
Add --serve for a disposable browser preview at localhost:5013.
ClamAV is mocked ONLY in this isolated test process; static APK checks are real.
"""
import io
import atexit
import os
import sys
import tempfile
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
scratch = tempfile.TemporaryDirectory(prefix="appora-submission-")
os.environ.update(APP_ENV="development", DATABASE_URL="sqlite:///" + str(Path(scratch.name) / "workflow.db"),
    PRIVATE_UPLOAD_ROOT=str(Path(scratch.name) / "uploads"), AUTO_MIGRATE="false", REDIS_URL="",
    SECRET_KEY="isolated-submission-check-not-a-production-secret", SESSION_COOKIE_SECURE="false",
    ADMIN_PASSWORD="", TRUST_PROXY="false", FLASK_DEBUG="false")
from app import app
from application.database import db
from application.models import (User, UserRole, AccountStatus, DeveloperProfile, GovernmentIdType,
    StoreApp, SubmissionStatus as S, ApplicationStatusHistory, Notification, MarketplaceSettings)
from flask_migrate import upgrade
from sqlalchemy.orm import Session
from sqlalchemy.orm.exc import StaleDataError

def close_fixture_database():
    with app.app_context():
        db.session.remove()
        db.engine.dispose()
    scratch.cleanup()

atexit.register(close_fixture_database)

with app.app_context():
    upgrade()
    for username, role in [("preview_dev", UserRole.DEVELOPER), ("other_dev", UserRole.DEVELOPER),
                           ("preview_admin", UserRole.ADMIN), ("preview_reviewer", UserRole.CO_ADMIN), ("preview_user", UserRole.USER)]:
        user = User(username=username, email=username + "@example.test", role=role, status=AccountStatus.APPROVED)
        user.set_password("Preview-only-123!")
        db.session.add(user)
        if role == UserRole.DEVELOPER:
            user.developer_profile = DeveloperProfile(legal_name="Preview Publisher", phone="1234567890", country="India",
                government_id_type=GovernmentIdType.PASSPORT, government_id_number="TEST", government_id_file="fixture.png",
                submitted_at=datetime.now(timezone.utc))
    settings = db.session.get(MarketplaceSettings, 1)
    settings.default_app_limit = 20
    db.session.commit()

checks = 0


def expect(condition, message):
    global checks
    if not condition:
        raise AssertionError(message)
    checks += 1


def token(client):
    with client.session_transaction() as session:
        return session.get("_csrf_token", "")


def login(username, route):
    client = app.test_client()
    client.get(route)
    result = client.post(route, data={"identifier": username, "password": "Preview-only-123!", "csrf_token": token(client)})
    expect(result.status_code == 302, "Login failed: " + username)
    return client


def apk_bytes(marker="fixture"):
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w") as archive:
        archive.writestr("AndroidManifest.xml", '<manifest package="com.example.preview"><application/></manifest>')
        archive.writestr("classes.dex", b"dex\n035\x00" + marker.encode())
        archive.writestr("resources.arsc", b"resource data")
    return output.getvalue()


def fields(number, version="1.0"):
    return dict(name=f"Preview App {number}", package_name=f"com.example.preview{number}",
        short_description="An isolated submission workflow fixture.", description="Fixture application used to verify the complete review and publication journey. " * 2,
        version=version, min_android_version="8.0", category="tools", age_rating="everyone",
        website="", support_email="support@example.test", privacy_policy_url="https://example.test/privacy", changelog="Fixture release")


def upload(client, number):
    from PIL import Image
    image = io.BytesIO(); Image.new("RGB", (64,64), "purple").save(image, format="PNG"); image.seek(0)
    data = fields(number)
    data.update(csrf_token=token(client), app_icon=(image, "icon.png"), apk_file=(io.BytesIO(apk_bytes(str(number))), "fixture.apk"))
    result = client.post("/developer/apps/new", data=data, content_type="multipart/form-data")
    expect(result.status_code == 302, "Upload did not redirect: " + result.get_data(as_text=True)[:120])
    with app.app_context():
        record = StoreApp.query.filter_by(package_name=f"com.example.preview{number}").one()
        expect(record.submission_status == S.SECURITY_CHECK_PENDING, "Upload must queue security checks")
        return record.id


def status(app_id):
    with app.app_context():
        return db.session.get(StoreApp, app_id).submission_status


def action(client, app_id, name, note=None, revision=None):
    data = {"csrf_token": token(client)}
    if note is not None: data["review_note"] = note
    if revision is not None: data["revision"] = revision
    return client.post(f"/admin/apps/{app_id}/{name}", data=data, headers={"X-Requested-With":"fetch"})


def scan(client, app_id):
    return client.post(f"/admin/apps/{app_id}/scan", data={"csrf_token":token(client)})


with patch("application.controllers.scan_apk_for_malware", return_value="Isolated ClamAV fixture: clean"):
    developer = login("preview_dev", "/login/developer")
    other = login("other_dev", "/login/developer")
    admin = login("preview_admin", "/admin/login")
    reviewer = login("preview_reviewer", "/admin/login")
    normal = login("preview_user", "/login/user")
    first = upload(developer, 1)
    expect(action(admin,first,"publish").status_code == 409, "Cannot skip verification")
    expect(action(admin,first,"approve").status_code == 409, "Cannot skip security")
    expect(scan(admin,first).status_code == 302, "Security scan failed to run")
    expect(status(first) == S.ADMIN_REVIEW_PENDING, "Successful scan must enter review")
    expect(action(admin,first,"reject", "").status_code == 409, "Rejection must require a reason")
    for client in [developer, other, normal]:
        for name in ["approve", "publish", "scan"]:
            expect(action(client, first, name).status_code in [302,403], "Non-admin status mutation was allowed")
    developer = login("preview_dev", "/login/developer")
    other = login("other_dev", "/login/developer")
    expect(other.get(f"/developer/apps/{first}").status_code == 404, "Private submission leaked")
    expect(other.get(f"/apps/{first}/status-history").status_code == 404, "Private audit leaked")
    expect(other.get(f"/submission-status?ids={first}").json["items"] == [], "Status snapshot leaked")
    expect(action(admin,first,"approve").status_code == 200, "Verification failed")
    expect(status(first) == S.PUBLISH_PENDING, "Approval must not publish")
    with app.app_context():
        record = db.session.get(StoreApp,first)
        expect(record.status.value == "pending", "Verified app must not be public")
        history_count = ApplicationStatusHistory.query.count()
    expect(action(admin,first,"approve").json.get("unchanged"), "Duplicate approval must be idempotent")
    with app.app_context(): expect(ApplicationStatusHistory.query.count() == history_count, "Duplicate audit entry")
    expect(action(reviewer,first,"publish",revision=0).status_code == 409, "Stale reviewer mutation accepted")
    expect(action(admin,first,"publish").status_code == 200, "Publication failed")
    expect(status(first) == S.PUBLISHED, "Publication must persist")
    with app.app_context():
        record = db.session.get(StoreApp,first); slug = record.slug
        expect(record.verified_by_id is not None and record.published_at is not None, "Missing verifier/publication timestamps")
        history_count = ApplicationStatusHistory.query.count()
    expect(action(admin,first,"publish").json.get("unchanged"), "Duplicate publication must be idempotent")
    with app.app_context(): expect(ApplicationStatusHistory.query.count() == history_count, "Duplicate publication history")
    expect(scan(admin,first).status_code == 409, "Published build cannot return to security checks")
    expect(developer.get(f"/apps/{slug}/download").status_code in [200,302,404], "Download raised an error")

    rejected = upload(developer, 2)
    scan(admin,rejected)
    expect(action(admin,rejected,"reject","Privacy policy needs correction.").status_code == 200, "Rejection failed")
    expect(b"Privacy policy needs correction." in developer.get(f"/developer/apps/{rejected}").data, "Feedback missing")
    edit = fields(2); edit["csrf_token"] = token(developer)
    expect(developer.post(f"/developer/apps/{rejected}/edit",data=edit).status_code == 302, "Resubmission failed")
    expect(status(rejected) == S.SECURITY_CHECK_PENDING, "Resubmit must restart checks")
    scan(admin,rejected)
    expect(action(admin,rejected,"request-changes","Add a clear support link.").status_code == 200, "Request changes failed")
    expect(b"Changes requested" in developer.get(f"/developer/apps/{rejected}").data, "Changes request missing")

    failed = upload(developer, 3)
    with patch("application.controllers.scan_apk_for_malware", side_effect=ValueError("Malware fixture detected")):
        scan(admin,failed)
    expect(status(failed) == S.SECURITY_CHECK_FAILED, "Malware result must fail stage")
    expect(b"Malware fixture detected" in developer.get(f"/developer/apps/{failed}").data, "Failure reason missing")
    expect(action(admin,failed,"approve").status_code == 409, "Failed security build approved")
    scan(admin,failed)
    expect(status(failed) == S.ADMIN_REVIEW_PENDING, "Retry successful scan did not return to review")
    missing = upload(developer, 4)
    with app.app_context():
        record = db.session.get(StoreApp,missing)
        (Path(app.config["PRIVATE_UPLOAD_ROOT"]) / "apks" / record.apk_file).unlink()
    scan(admin,missing)
    expect(status(missing) == S.SECURITY_CHECK_FAILED, "Missing file must persist a failed stage")

    # A new version stays private; the previous published binary stays downloadable.
    update = {"csrf_token":token(developer), "version":"2.0", "min_android_version":"8.0", "changelog":"Updated fixture release",
              "apk_file":(io.BytesIO(apk_bytes("v2")),"version2.apk")}
    expect(developer.post(f"/developer/apps/{first}/new-version",data=update).status_code == 302, "Version upload failed")
    expect(status(first) == S.SECURITY_CHECK_PENDING, "Version update must restart workflow")
    expect(scan(admin, first).status_code == 302, "Pending version scan failed")
    expect(action(admin,first,"approve").status_code == 200, "Pending version verification failed")
    with app.app_context(): expect(db.session.get(StoreApp,first).version == "1.0", "Verification replaced live APK")
    expect(action(admin,first,"publish").status_code == 200, "Version publication failed")
    with app.app_context():
        record = db.session.get(StoreApp,first)
        expect(record.version == "2.0" and len(record.version_history) == 1, "Version archive/publication incorrect")
        expect(Notification.query.count() > 10, "Workflow notifications missing")
        # Two independent ORM sessions must reject stale writes.
        a, b = Session(db.engine), Session(db.engine)
        one, two = a.get(StoreApp,rejected), b.get(StoreApp,rejected)
        one.submission_feedback = "Concurrent review A"; a.commit()
        two.submission_feedback = "Concurrent review B"
        try:
            b.commit(); expect(False,"Stale update was accepted")
        except StaleDataError: checks += 1; b.rollback()
        finally: a.close(); b.close()
    for client,path in [(developer,"/developer/dashboard"),(developer,f"/developer/apps/{first}"),
                        (admin,"/admin"),(admin,"/admin/apps"),(admin,f"/admin/apps/{first}")]:
        response = client.get(path)
        expect(response.status_code == 200, "Page failed: " + path)
        expect(b"submission-progress" in response.data, "Tracker missing: " + path)
    for filter_name in ["all","pending","security_failed","waiting_review","verified","rejected","published"]:
        expect(admin.get("/admin/apps?status="+filter_name).status_code == 200, "Filter failed: " + filter_name)
    expect(admin.get("/admin/apps?q="+str(first)).status_code == 200, "ID search failed")
    expect(admin.get("/admin/apps?q=preview_dev").status_code == 200, "Developer search failed")
    expect(developer.get(f"/submission-status?ids={first}&details=1").status_code == 200, "Live snapshot failed")
    expect(action(admin,first,"publish").status_code == 200, "Persisted published state failed on refresh")
    print(f"PASS: {checks} isolated workflow checks; migrated SQLite schema, real static checks, mocked ClamAV.")
    if "--serve" in sys.argv:
        print("Disposable UI preview at http://127.0.0.1:5013 — preview_dev / preview_admin, password Preview-only-123!")
        app.run(host="127.0.0.1",port=5013,debug=False,use_reloader=False,threaded=True)
close_fixture_database()

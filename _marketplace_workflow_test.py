# ruff: noqa: E402
import os
import re
import shutil
import tempfile
from datetime import datetime, timezone
from pathlib import Path

test_root = Path(tempfile.mkdtemp(prefix="appora-workflow-"))
os.environ["DATABASE_URL"] = f"sqlite:///{(test_root / 'test.db').as_posix()}"
os.environ["PRIVATE_UPLOAD_ROOT"] = str(test_root / "uploads")
os.environ["SECRET_KEY"] = "workflow-test"
os.environ["ADMIN_USERNAME"] = "workflow_admin"
os.environ["ADMIN_EMAIL"] = "admin@example.com"
os.environ["ADMIN_PASSWORD"] = "AdminPass123!"
os.environ["AUTO_MIGRATE"] = "true"

from app import app
from application.database import db
from application.models import (
    AccountStatus,
    AgeRating,
    AppCategory,
    AppReport,
    AppReview,
    AppStatus,
    AuditLog,
    DeveloperProfile,
    GovernmentIdType,
    DownloadRecord,
    PasswordResetToken,
    ReportStatus,
    SavedApp,
    SecurityScanStatus,
    StoreApp,
    User,
    UserRole,
)

app.config["TESTING"] = True


def csrf(client, url):
    response = client.get(url)
    assert response.status_code == 200, (url, response.status_code)
    match = re.search(rb'name="csrf_token" value="([^"]+)"', response.data)
    assert match, url
    return match.group(1).decode()


try:
    uploads = test_root / "uploads"
    for policy_path in (
        "/policies",
        "/privacy",
        "/terms",
        "/developer-agreement",
        "/acceptable-use",
        "/copyright",
        "/data-retention",
    ):
        assert app.test_client().get(policy_path).status_code == 200
    registration_client = app.test_client()
    registration_token = csrf(registration_client, "/register/user")
    registration_data = {
        "csrf_token": registration_token,
        "username": "policy_user",
        "email": "policy-user@example.com",
        "password": "PolicyPass123!",
        "confirm_password": "PolicyPass123!",
    }
    rejected_terms = registration_client.post(
        "/register/user", data=registration_data, follow_redirects=True
    )
    assert b"must accept the Terms" in rejected_terms.data
    registration_data["accept_terms"] = "yes"
    accepted_terms = registration_client.post("/register/user", data=registration_data)
    assert (
        accepted_terms.status_code == 200 and b"Account created" in accepted_terms.data
    )
    with app.app_context():
        policy_user = User.query.filter_by(username="policy_user").one()
        assert policy_user.terms_accepted_at is not None
        assert policy_user.terms_version == app.config["POLICY_VERSION"]
    assert app.test_client().get("/health").get_json() == {"status": "ok"}
    assert b"Reset user password" in app.test_client().get("/login/user").data
    assert b"Reset developer password" in app.test_client().get("/login/developer").data
    developer_recovery = app.test_client().get("/forgot-password?role=developer")
    assert b"Developer account recovery" in developer_recovery.data
    assert b'name="role" value="developer"' in developer_recovery.data
    oversized = app.test_client().post("/login/user", data={"identifier": "x" * 70000})
    assert oversized.status_code == 413 and b"Upload is too large" in oversized.data
    missing_page = app.test_client().get("/this-page-does-not-exist")
    assert missing_page.status_code == 404 and b"Page not found" in missing_page.data
    ready = app.test_client().get("/ready")
    assert ready.status_code == 200 and ready.get_json()["status"] == "ready"
    admin_client = app.test_client()
    admin_token = csrf(admin_client, "/admin/login")
    admin_dashboard = admin_client.post(
        "/admin/login",
        data={
            "csrf_token": admin_token,
            "identifier": "workflow_admin",
            "password": "AdminPass123!",
        },
        follow_redirects=True,
    )
    assert admin_dashboard.status_code == 200
    assert admin_dashboard.request.path == "/admin"
    (uploads / "app_icons").mkdir(parents=True, exist_ok=True)
    (uploads / "apks").mkdir(parents=True, exist_ok=True)
    (uploads / "app_icons" / "icon.png").write_bytes(b"icon")
    (uploads / "apks" / "app.apk").write_bytes(b"apk")
    with app.app_context():
        user = User(
            username="market_user",
            email="user@example.com",
            role=UserRole.USER,
            status=AccountStatus.APPROVED,
        )
        user.set_password("UserPass123!")
        user.approve()
        developer = User(
            username="market_dev",
            email="dev@example.com",
            role=UserRole.DEVELOPER,
            status=AccountStatus.APPROVED,
            company_name="Market Dev",
        )
        developer.set_password("DevPass123!")
        developer.approve()
        db.session.add_all([user, developer])
        pending_developer = User(
            username="pending_dev",
            email="pending@example.com",
            role=UserRole.DEVELOPER,
            status=AccountStatus.PENDING,
            company_name="Pending Studio",
        )
        pending_developer.set_password("PendingPass123!")
        pending_developer.developer_profile = DeveloperProfile(
            legal_name="Pending Developer",
            phone="+91 9999999999",
            country="India",
            government_id_type=GovernmentIdType.PASSPORT,
            government_id_number="PENDING123",
            government_id_file="id.png",
            government_id_original_name="id.png",
            submitted_at=datetime.now(timezone.utc),
        )
        db.session.add(pending_developer)
        db.session.flush()
        store_app = StoreApp(
            developer_id=developer.id,
            name="Workflow App",
            slug="workflow-app",
            package_name="com.example.workflow",
            short_description="A workflow test app",
            description="A complete application description used to verify marketplace workflows.",
            version="1.0",
            min_android_version="Android 8",
            category=AppCategory.TOOLS,
            age_rating=AgeRating.EVERYONE,
            support_email="support@example.com",
            privacy_policy_url="https://example.com/privacy",
            icon_file="icon.png",
            apk_file="app.apk",
            apk_original_name="workflow.apk",
            apk_size=3,
            apk_sha256="a" * 64,
            security_scan_status=SecurityScanStatus.PASSED,
            malware_scan_status=SecurityScanStatus.PASSED,
            status=AppStatus.APPROVED,
            approved_at=datetime.now(timezone.utc),
        )
        db.session.add(store_app)
        db.session.commit()
        app_id = store_app.id
        pending_developer_id = pending_developer.id

    client = app.test_client()
    public_icon = client.get(f"/apps/{app_id}/icon")
    assert public_icon.status_code == 200
    assert public_icon.headers["Cache-Control"] == "public, max-age=86400, immutable"
    token = csrf(client, "/login/user")
    response = client.post(
        "/login/user",
        data={
            "csrf_token": token,
            "identifier": "market_user",
            "password": "UserPass123!",
        },
    )
    assert response.status_code == 302 and response.location.endswith("/user/dashboard")
    token = csrf(client, "/apps/workflow-app")
    assert (
        client.post("/apps/workflow-app/save", data={"csrf_token": token}).status_code
        == 302
    )
    download = client.get("/apps/workflow-app/download")
    assert download.status_code == 200
    assert client.get("/apps/workflow-app/download").status_code == 200
    token = csrf(client, "/apps/workflow-app")
    review = client.post(
        "/apps/workflow-app/review",
        data={"csrf_token": token, "rating": "5", "comment": "Useful and easy to use."},
        follow_redirects=True,
    )
    assert review.status_code == 200 and b"Useful and easy to use" in review.data
    token = csrf(client, "/apps/workflow-app")
    report = client.post(
        "/apps/workflow-app/report",
        data={
            "csrf_token": token,
            "reason": "privacy",
            "details": "Please verify the privacy disclosure.",
        },
        follow_redirects=True,
    )
    assert b"sent to the administrator" in report.data
    dashboard = client.get("/user/dashboard")
    assert dashboard.status_code == 200 and b"Workflow App" in dashboard.data
    token = csrf(client, "/account/settings")
    settings = client.post(
        "/account/settings",
        data={
            "csrf_token": token,
            "email": "updated@example.com",
            "current_password": "UserPass123!",
            "new_password": "NewPass123!",
            "confirm_password": "NewPass123!",
        },
        follow_redirects=True,
    )
    assert b"settings were updated" in settings.data

    client = app.test_client()
    token = csrf(client, "/forgot-password")
    recovery = client.post(
        "/forgot-password", data={"csrf_token": token, "email": "updated@example.com"}
    )
    assert b"/reset-password/" not in recovery.data
    app.debug = True
    token = csrf(client, "/forgot-password")
    recovery = client.post(
        "/forgot-password", data={"csrf_token": token, "email": "updated@example.com"}
    )
    reset_path = (
        re.search(
            rb'href="http://127\.0\.0\.1:5001(/reset-password/[^"]+)"', recovery.data
        )
        .group(1)
        .decode()
    )
    token = csrf(client, reset_path)
    reset = client.post(
        reset_path,
        data={
            "csrf_token": token,
            "password": "ResetPass123",
            "confirm_password": "ResetPass123",
        },
    )
    assert reset.status_code == 302
    assert client.get(reset_path).status_code == 400

    admin = app.test_client()
    token = csrf(admin, "/admin/login")
    assert (
        admin.post(
            "/admin/login",
            data={
                "csrf_token": token,
                "identifier": "workflow_admin",
                "password": "AdminPass123!",
            },
        ).status_code
        == 302
    )
    with admin.session_transaction() as session:
        admin_token = session["_csrf_token"]
    assert admin.get("/admin/settings").status_code == 200
    refused_settings = admin.post(
        "/admin/settings",
        data={
            "csrf_token": admin_token,
            "email": "new-admin@example.com",
            "current_password": "incorrect",
        },
        follow_redirects=True,
    )
    assert b"current administrator password" in refused_settings.data
    updated_settings = admin.post(
        "/admin/settings",
        data={
            "csrf_token": admin_token,
            "email": "new-admin@example.com",
            "current_password": "AdminPass123!",
        },
        follow_redirects=True,
    )
    assert b"settings were updated securely" in updated_settings.data
    for action in ("approve", "block", "unblock", "reject"):
        response = admin.post(
            f"/admin/accounts/{pending_developer_id}/{action}",
            data={"csrf_token": admin_token, "review_note": "Workflow decision"},
            headers={"X-Requested-With": "fetch"},
        )
        assert response.status_code == 200, (
            action,
            response.status_code,
            response.data,
        )
    moderation = admin.get("/admin/moderation")
    assert (
        moderation.status_code == 200
        and b"Please verify the privacy disclosure" in moderation.data
    )
    with app.app_context():
        report_id = AppReport.query.one().id
        review_id = AppReview.query.one().id
        assert SavedApp.query.count() == 1 and DownloadRecord.query.count() == 1
        assert db.session.get(StoreApp, app_id).download_count == 1
    with admin.session_transaction() as session:
        token = session["_csrf_token"]
    assert (
        admin.post(
            f"/admin/reports/{report_id}/resolve",
            data={"csrf_token": token, "admin_note": "Checked"},
        ).status_code
        == 302
    )
    assert (
        admin.post(
            f"/admin/reviews/{review_id}/hide", data={"csrf_token": token}
        ).status_code
        == 302
    )
    created = admin.post(
        "/admin/co-admins",
        data={
            "csrf_token": token,
            "username": "review_helper",
            "email": "reviewer@example.com",
            "password": "ReviewerPass123!",
        },
    )
    assert created.status_code == 302
    co_admin = app.test_client()
    co_token = csrf(co_admin, "/admin/login")
    signed_in = co_admin.post(
        "/admin/login",
        data={
            "csrf_token": co_token,
            "identifier": "review_helper",
            "password": "ReviewerPass123!",
        },
    )
    assert signed_in.status_code == 302 and signed_in.location.endswith("/admin/apps")
    with co_admin.session_transaction() as session:
        co_token = session["_csrf_token"]
    assert co_admin.get("/admin/apps").status_code == 200
    assert co_admin.get("/admin/settings").status_code == 200
    assert co_admin.get("/admin/moderation").status_code == 403
    assert co_admin.get("/admin/audit-log").status_code == 403
    approved_developer = co_admin.post(
        f"/admin/accounts/{pending_developer_id}/approve",
        data={"csrf_token": co_token},
        headers={"X-Requested-With": "fetch"},
    )
    assert approved_developer.status_code == 200
    forbidden_block = co_admin.post(
        f"/admin/accounts/{pending_developer_id}/block", data={"csrf_token": co_token}
    )
    assert forbidden_block.status_code == 403
    rejected_app = co_admin.post(
        f"/admin/apps/{app_id}/reject",
        data={"csrf_token": co_token, "review_note": "Needs another review"},
    )
    assert rejected_app.status_code == 302
    approved_app = co_admin.post(
        f"/admin/apps/{app_id}/approve", data={"csrf_token": co_token}
    )
    assert approved_app.status_code == 302
    assert (
        co_admin.post(
            f"/admin/apps/{app_id}/delete", data={"csrf_token": co_token}
        ).status_code
        == 403
    )
    assert co_admin.get("/admin/co-admins").status_code == 403
    assert co_admin.get("/admin/trash").status_code == 403
    with app.app_context():
        assert AppReport.query.one().status == ReportStatus.RESOLVED
        assert all(
            token.used_at is not None for token in PasswordResetToken.query.all()
        )
        assert AuditLog.query.count() >= 10
    assert admin.get("/admin/audit-log").status_code == 200
    assert admin.get("/admin/trash").status_code == 200
    soft_deleted_app = admin.post(
        f"/admin/apps/{app_id}/delete", data={"csrf_token": token}
    )
    assert soft_deleted_app.status_code == 302
    with app.app_context():
        deleted_app = db.session.get(StoreApp, app_id)
        assert deleted_app.status == AppStatus.DELETED
        assert (uploads / "apks" / deleted_app.apk_file).exists()
    assert admin.get("/admin/trash").status_code == 200
    restored_app = admin.post(
        f"/admin/apps/{app_id}/restore", data={"csrf_token": token}
    )
    assert restored_app.status_code == 302
    with app.app_context():
        assert db.session.get(StoreApp, app_id).status == AppStatus.APPROVED
    with app.app_context():
        disposable = User(
            username="delete_safety_test",
            email="delete-safety@example.com",
            role=UserRole.USER,
            status=AccountStatus.APPROVED,
        )
        disposable.set_password("DisposablePass123!")
        disposable.approve()
        db.session.add(disposable)
        db.session.commit()
        disposable_id = disposable.id
    soft_deleted = admin.post(
        f"/admin/accounts/{disposable_id}/delete", data={"csrf_token": token}
    )
    assert soft_deleted.status_code == 302
    with app.app_context():
        assert db.session.get(User, disposable_id).status == AccountStatus.DELETED
    confirmation = admin.post(
        f"/admin/accounts/{disposable_id}/hard_delete", data={"csrf_token": token}
    )
    assert (
        confirmation.status_code == 200 and b"Irreversible action" in confirmation.data
    )
    refused = admin.post(
        f"/admin/accounts/{disposable_id}/hard_delete",
        data={
            "csrf_token": token,
            "permanent_confirm": "yes",
            "confirm_label": "delete_safety_test",
            "admin_password": "wrong",
        },
    )
    assert refused.status_code == 400
    permanently_deleted = admin.post(
        f"/admin/accounts/{disposable_id}/hard_delete",
        data={
            "csrf_token": token,
            "permanent_confirm": "yes",
            "confirm_label": "delete_safety_test",
            "admin_password": "AdminPass123!",
        },
    )
    assert permanently_deleted.status_code == 302
    with app.app_context():
        assert db.session.get(User, disposable_id) is None
    logout_warning = co_admin.post("/logout", data={"csrf_token": co_token})
    assert (
        logout_warning.status_code == 200
        and b"Sign out of Appora" in logout_warning.data
    )
    assert co_admin.get("/admin/apps").status_code == 200
    signed_out = co_admin.post(
        "/logout", data={"csrf_token": co_token, "confirm": "yes"}
    )
    assert signed_out.status_code == 302
    assert co_admin.get("/admin/apps").status_code == 302
    print("marketplace-workflow-tests-passed")
finally:
    shutil.rmtree(test_root, ignore_errors=True)

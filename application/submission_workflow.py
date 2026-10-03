"""Latest-build state machine; marketplace visibility remains separate."""
from datetime import datetime, timedelta, timezone
from .database import db
from .models import ApplicationStatusHistory, Notification, NotificationType, SubmissionStatus as S, UserRole

ALLOWED = {
    S.UPLOADED: {S.SECURITY_CHECK_PENDING},
    S.SECURITY_CHECK_PENDING: {S.SECURITY_CHECK_PASSED, S.SECURITY_CHECK_FAILED},
    S.SECURITY_CHECK_FAILED: {S.SECURITY_CHECK_PENDING},
    S.SECURITY_CHECK_PASSED: {S.ADMIN_REVIEW_PENDING},
    S.ADMIN_REVIEW_PENDING: {S.ADMIN_VERIFIED, S.ADMIN_REJECTED},
    S.ADMIN_VERIFIED: {S.PUBLISH_PENDING}, S.PUBLISH_PENDING: {S.PUBLISHED},
    S.ADMIN_REJECTED: set(), S.PUBLISHED: set(),
}
LABELS = {
    S.UPLOADED: "App uploaded",
    S.SECURITY_CHECK_PENDING: "Security checks pending",
    S.SECURITY_CHECK_PASSED: "Security checks passed",
    S.SECURITY_CHECK_FAILED: "Security checks failed",
    S.ADMIN_REVIEW_PENDING: "Waiting for admin verification",
    S.ADMIN_VERIFIED: "Verified by admin",
    S.ADMIN_REJECTED: "Application rejected",
    S.PUBLISH_PENDING: "Verified — waiting to publish",
    S.PUBLISHED: "App published / live",
}


def set_status(app, target, actor=None, reason=None, initial=False):
    previous = app.submission_status
    if previous == target and not initial:
        return False
    if not initial and target not in ALLOWED.get(previous, set()):
        raise ValueError("This submission changed or is not eligible for that action. Refresh and review its current stage.")
    if actor and actor.role not in {UserRole.ADMIN, UserRole.CO_ADMIN} and not initial:
        raise PermissionError("Only authorized reviewers can change review states.")
    app.submission_status = target
    db.session.add(ApplicationStatusHistory(app=app, version=app.pending_version or app.version,
        previous_status=previous.value if previous else None,
        new_status=target.value, changed_by_id=actor.id if actor else None,
        changed_by_role=actor.role.value if actor else "system", reason=reason))
    db.session.add(Notification(recipient_id=app.developer_id or app.developer.id,
        type=NotificationType.APP, title=f"{app.name}: {LABELS[target]}",
        message=reason or LABELS[target],
        link=f"/developer/apps/{app.id}" if app.id else "/developer/dashboard"))
    return True


def start_submission(app, developer):
    # Called only by ownership-checked upload controllers, never by a public status API.
    if app.submission_status not in {None, S.UPLOADED, S.ADMIN_REJECTED,
                                     S.SECURITY_CHECK_FAILED, S.PUBLISHED}:
        raise ValueError("An active submission cannot be replaced.")
    app.verified_at = app.verified_by_id = app.published_at = None
    app.submission_feedback = None
    app.changes_requested = False
    app.scan_started_at = None
    set_status(app, S.UPLOADED, developer, "Application submitted", initial=True)
    set_status(app, S.SECURITY_CHECK_PENDING, reason="Administrator security scan queued")


def submission_view(app):
    status = app.submission_status or S.UPLOADED
    pending = bool(app.pending_version)
    scan_running = bool(app.scan_started_at and datetime.now(timezone.utc) -
                        app.scan_started_at.replace(tzinfo=timezone.utc) < timedelta(minutes=10))
    scanned = getattr(app, ("pending_" if pending else "") + "security_scanned_at")
    submitted = app.pending_release_submitted_at if pending else app.submitted_at
    stage = (1 if status in {S.UPLOADED, S.SECURITY_CHECK_PENDING, S.SECURITY_CHECK_FAILED}
             else 2 if status in {S.SECURITY_CHECK_PASSED, S.ADMIN_REVIEW_PENDING, S.ADMIN_REJECTED} else 3)
    steps = []
    dates = [submitted, scanned, app.verified_at, app.published_at]
    for index, title in enumerate(["App Uploaded", "Security Checks", "Admin Verification", "App Published / Live"]):
        state = "completed" if index < stage or status == S.PUBLISHED else "active" if index == stage else "upcoming"
        if index == 1 and status == S.SECURITY_CHECK_FAILED:
            state = "failed"
        if index == 2 and status == S.ADMIN_REJECTED:
            state = "rejected"
        label = {"completed": "Completed", "active": "Pending", "upcoming": "Waiting",
                 "failed": "Failed", "rejected": "Changes requested" if app.changes_requested else "Rejected"}[state]
        steps.append({"title": title, "state": state, "label": label,
                      "date": dates[index] if state in {"completed", "failed"} else None})
    return {"status": status.value, "label": LABELS[status], "stage": stage + 1,
            "steps": steps, "revision": app.submission_revision,
            "version": app.pending_version or app.version, "feedback": app.submission_feedback,
            "updated_at": app.updated_at, "security": steps[1]["label"],
            "admin": steps[2]["label"], "publishing": steps[3]["label"],
            "changes_requested": app.changes_requested, "scan_running": scan_running}

import json
import re
import secrets
from datetime import datetime, timezone
from functools import wraps
from queue import Empty

from flask import (
    Blueprint,
    Response,
    abort,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    stream_with_context,
    url_for,
)
from sqlalchemy import func, or_
from sqlalchemy.exc import IntegrityError

from .database import db
from .models import AccountStatus, User, UserRole
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


def dashboard_url_for(user):
    destinations = {
        UserRole.ADMIN: "main.admin_dashboard",
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


def role_required(required_role):
    def decorator(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            user = current_user()
            if (
                user is None
                or user.role != required_role
                or user.status != AccountStatus.APPROVED
            ):
                session.clear()
                flash("Please sign in with an approved account to continue.", "error")
                if required_role == UserRole.ADMIN:
                    return redirect(url_for("main.admin_login"))
                return redirect(url_for("main.account_login", role_name=required_role.value))
            return view(user, *args, **kwargs)

        return wrapped

    return decorator


def validate_registration(form, role):
    username = form.get("username", "").strip()
    email = form.get("email", "").strip().lower()
    password = form.get("password", "")
    confirm_password = form.get("confirm_password", "")
    company_name = form.get("company_name", "").strip()
    errors = []

    if not re.fullmatch(r"[A-Za-z0-9_]{3,30}", username):
        errors.append("Username must be 3–30 characters using letters, numbers, or underscores.")
    if not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email):
        errors.append("Enter a valid email address.")
    if len(password) < 8 or not re.search(r"[A-Za-z]", password) or not re.search(r"\d", password):
        errors.append("Password must be at least 8 characters and include a letter and a number.")
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
    return render_template("home.html")


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
    if signed_in and signed_in.role == UserRole.ADMIN:
        return redirect(dashboard_url_for(signed_in))

    if request.method == "POST":
        if not valid_csrf_token():
            flash("Your session expired. Please try again.", "error")
            return redirect(url_for("main.admin_login"))

        identifier = request.form.get("identifier", "").strip()
        password = request.form.get("password", "")
        admin = User.query.filter(
            User.role == UserRole.ADMIN,
            or_(
                func.lower(User.username) == identifier.lower(),
                func.lower(User.email) == identifier.lower(),
            ),
        ).first()

        if admin and admin.status == AccountStatus.APPROVED and admin.check_password(password):
            sign_in_user(admin, request.form.get("remember") == "on")
            flash("Welcome back. You are signed in.", "success")
            return redirect(url_for("main.admin_dashboard"))

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
    if role == UserRole.ADMIN:
        return redirect(url_for("main.admin_login"))

    signed_in = current_user()
    if signed_in and signed_in.role == role and signed_in.status == AccountStatus.APPROVED:
        return redirect(dashboard_url_for(signed_in))

    if request.method == "POST":
        if not valid_csrf_token():
            flash("Your session expired. Please try again.", "error")
            return redirect(url_for("main.account_login", role_name=role.value))

        identifier = request.form.get("identifier", "").strip()
        password = request.form.get("password", "")
        user = User.query.filter(
            User.role == role,
            or_(
                func.lower(User.username) == identifier.lower(),
                func.lower(User.email) == identifier.lower(),
            ),
        ).first()

        if not user or not user.check_password(password):
            flash("Incorrect email, username, or password.", "error")
        elif user.status == AccountStatus.PENDING:
            flash("Your developer account is waiting for administrator approval.", "warning")
        elif user.status == AccountStatus.REJECTED:
            flash("This account request was not approved. Contact the marketplace administrator.", "error")
        elif user.status == AccountStatus.BLOCKED:
            flash("This account has been blocked. Contact the marketplace administrator.", "error")
        else:
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
    if role == UserRole.ADMIN:
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
            )
            account.set_password(values["password"])
            if status == AccountStatus.APPROVED:
                account.approve()
            db.session.add(account)
            try:
                db.session.commit()
            except IntegrityError:
                db.session.rollback()
                flash("That username or email was just registered. Try another one.", "error")
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


@main.route("/admin")
@role_required(UserRole.ADMIN)
def admin_dashboard(admin):
    query_text = request.args.get("q", "").strip()
    role_filter = request.args.get("role", "all")
    status_filter = request.args.get("status", "all")

    accounts_query = User.query.filter(User.role != UserRole.ADMIN)
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
        accounts_query = accounts_query.filter(User.status == AccountStatus(status_filter))

    accounts = accounts_query.order_by(User.created_at.desc(), User.id.desc()).all()
    counts = {
        "total": User.query.filter(User.role != UserRole.ADMIN).count(),
        "pending": User.query.filter(User.status == AccountStatus.PENDING).count(),
        "developers": User.query.filter(User.role == UserRole.DEVELOPER).count(),
        "blocked": User.query.filter(User.status == AccountStatus.BLOCKED).count(),
    }
    return render_template(
        "admin_dashboard.html",
        admin=admin,
        accounts=accounts,
        counts=counts,
        role_filter=role_filter,
        status_filter=status_filter,
        query_text=query_text,
        roles=UserRole,
        statuses=AccountStatus,
        csrf_token=get_csrf_token(),
    )


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
@role_required(UserRole.ADMIN)
def admin_account_events(admin):
    return server_event_response(lambda event: True)


@main.get("/events/my-account")
def my_account_events():
    user = current_user()
    if user is None or user.status != AccountStatus.APPROVED:
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
        "deleted": "Your account was deleted by an administrator.",
    }
    flash(messages.get(state, "Your account access changed. Please sign in again."), "error")
    return redirect(url_for("main.account_login", role_name=role_value))


@main.post("/admin/accounts/<int:user_id>/<action>")
@role_required(UserRole.ADMIN)
def manage_account(admin, user_id, action):
    if not valid_csrf_token():
        flash("Your session expired. Please try again.", "error")
        return redirect(url_for("main.admin_dashboard"))

    account = db.session.get(User, user_id)
    if account is None:
        abort(404)
    if account.role == UserRole.ADMIN or account.id == admin.id:
        flash("Administrator accounts cannot be changed here.", "error")
        return redirect(url_for("main.admin_dashboard"))

    labels = {
        "approve": "approved",
        "reject": "rejected",
        "block": "blocked",
        "unblock": "unblocked",
        "delete": "deleted",
    }
    if action not in labels:
        abort(404)

    username = account.username
    role_value = account.role.value
    if action == "approve":
        account.approve()
    elif action == "reject":
        account.reject()
    elif action == "block":
        account.block()
    elif action == "unblock":
        account.unblock()
    elif action == "delete":
        db.session.delete(account)

    db.session.commit()
    if action == "delete":
        username_index.remove(username)
        status_value = "deleted"
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
    return redirect(url_for("main.admin_dashboard"))


@main.route("/user/dashboard")
@role_required(UserRole.USER)
def user_dashboard(user):
    return render_template(
        "user_dashboard.html",
        user=user,
        csrf_token=get_csrf_token(),
    )


@main.route("/developer/dashboard")
@role_required(UserRole.DEVELOPER)
def developer_dashboard(user):
    return render_template(
        "developer_dashboard.html",
        user=user,
        csrf_token=get_csrf_token(),
    )


@main.post("/logout")
def logout():
    if valid_csrf_token():
        session.clear()
    return redirect(url_for("main.home"))


@main.post("/admin/logout")
def legacy_admin_logout():
    return logout()

"""Application-boundary controls; Redis is the shared production authority."""
import hashlib
import re
import subprocess
import secrets
import time
from threading import Lock
from urllib.parse import urlsplit

from flask import abort, current_app, request, session
from redis import Redis
from redis.exceptions import RedisError


def supported_scanner(command):
    try:
        result = subprocess.run([command, '--version'], capture_output=True, text=True, timeout=10, check=False)
        match = re.search(r'ClamAV (\d+)\.(\d+)\.(\d+)', result.stdout)
        if result.returncode or not match:
            return False
        version = tuple(int(part) for part in match.groups())
        return (1, 4, 6) <= version < (1, 5, 0) or version >= (1, 5, 4)
    except (OSError, subprocess.TimeoutExpired):
        return False


class RequestLimits:
    def __init__(self, redis_url=None):
        self.redis = Redis.from_url(redis_url, socket_timeout=2, socket_connect_timeout=2) if redis_url else None
        self.windows = {}
        self.leases = {}
        self.lock = Lock()

    def consume(self, scope, identity, maximum, seconds):
        # Neither identifiers nor client addresses are stored in clear text.
        key = 'appora:limits:' + hashlib.sha256(f'{scope}|{identity}'.encode()).hexdigest()
        now = time.time()
        if self.redis:
            try:
                count = self.redis.eval("local n=redis.call('INCR',KEYS[1]); if n==1 then redis.call('EXPIRE',KEYS[1],ARGV[1]) end; return n", 1, key, seconds)
                return count <= maximum
            except RedisError:
                current_app.logger.error('Security limiter unavailable')
                abort(503)  # No fail-open bypass in production.
        with self.lock:
            if len(self.windows) >= 10000:
                self.windows = {k:v for k,v in self.windows.items() if v[1] > now}
                if key not in self.windows and len(self.windows) >= 10000:
                    return False
            count, expires = self.windows.get(key, (0, now + seconds))
            if expires <= now:
                count, expires = 0, now + seconds
            self.windows[key] = (count + 1, expires)
            return count < maximum

    def acquire(self, scope, identity, maximum, seconds):
        """Bound simultaneous work across workers; crashed workers expire safely."""
        key = 'appora:leases:' + hashlib.sha256(f'{scope}|{identity}'.encode()).hexdigest()
        token = secrets.token_urlsafe(24)
        now = time.time()
        if self.redis:
            try:
                accepted = self.redis.eval("redis.call('ZREMRANGEBYSCORE',KEYS[1],'-inf',ARGV[1]); if redis.call('ZCARD',KEYS[1])>=tonumber(ARGV[3]) then return 0 end; redis.call('ZADD',KEYS[1],ARGV[2],ARGV[4]); redis.call('EXPIRE',KEYS[1],ARGV[5]); return 1", 1, key, now, now + seconds, maximum, token, seconds)
            except RedisError:
                current_app.logger.error('Security lease authority unavailable')
                abort(503)
        else:
            with self.lock:
                self.leases = {k: {t: end for t, end in slots.items() if end > now} for k, slots in self.leases.items()}
                self.leases = {k: v for k, v in self.leases.items() if v}
                slots = self.leases.setdefault(key, {})
                accepted = len(slots) < maximum and len(self.leases) <= 10000
                if accepted:
                    slots[token] = now + seconds
        return (key, token) if accepted else None

    def release(self, lease):
        if not lease:
            return
        key, token = lease
        if self.redis:
            try:
                self.redis.zrem(key, token)
            except RedisError:
                current_app.logger.error('Security lease cleanup delayed until expiry')
        else:
            with self.lock:
                self.leases.get(key, {}).pop(token, None)


def origin_tuple(value):
    try:
        parsed = urlsplit(value)
        if parsed.scheme not in {'http', 'https'} or not parsed.hostname or parsed.username or parsed.password:
            return None
        return parsed.scheme, parsed.hostname.casefold(), parsed.port or (443 if parsed.scheme == 'https' else 80)
    except ValueError:
        return None


def install_request_controls(app):
    limiter = RequestLimits(app.config.get('REDIS_URL'))
    app.extensions['security_limits'] = limiter

    @app.after_request
    def log_security_denial(response):
        if response.status_code in {401, 403, 429}:
            # Endpoint names are code-owned. Never log URLs, forms or reset tokens.
            app.logger.warning('security_denial endpoint=%s status=%s actor_id=%s', request.endpoint or 'unmatched', response.status_code, session.get('user_id', 'anonymous'))
        return response

    @app.before_request
    def protect_boundary():
        endpoint = request.endpoint or ''
        if endpoint == 'static' or endpoint in {'health_check', 'readiness_check'}:
            return
        ip = request.remote_addr or 'unknown'  # Only ProxyFix's normalized address.
        actor = str(session.get('user_id') or ip)
        if request.method in {'POST', 'PUT', 'PATCH', 'DELETE'}:
            expected_origin = origin_tuple(app.config['PUBLIC_BASE_URL']) if app.config['APP_ENV'] == 'production' else origin_tuple(request.host_url)
            origin = request.headers.get('Origin')
            if origin and origin_tuple(origin) != expected_origin:
                abort(403)
            if request.headers.get('Sec-Fetch-Site') == 'cross-site':
                abort(403)
            # Reject ambiguous scalar inputs rather than silently choosing a value.
            if any(len(values) != 1 for _, values in request.form.lists()):
                abort(400)
            from .controllers import valid_csrf_token
            if endpoint.startswith('main.') and not valid_csrf_token():
                abort(400)
            policy = ('mutation', 120, 60)
            if endpoint in {'main.admin_login', 'main.account_login'}:
                policy = ('authentication', 30, 900)
            elif endpoint == 'main.create_account':
                policy = ('registration', 10, 3600)
            elif endpoint in {'main.forgot_password', 'main.security_question_recovery', 'main.manual_password_reset', 'main.reset_password'}:
                policy = ('recovery', 20, 900)
            elif endpoint in {'main.submit_app', 'main.submit_app_version', 'main.developer_verification', 'main.scan_app'}:
                policy = ('uploads-scans', 30, 3600)
            scope, maximum, seconds = policy
            if not limiter.consume(scope + ':ip', ip, maximum, seconds):
                abort(429)
            if session.get('user_id') and not limiter.consume(scope + ':actor', actor, maximum, seconds):
                abort(429)
            if scope in {'authentication', 'recovery'}:
                identifier = (request.form.get('identifier') or request.form.get('email') or request.form.get('reference') or '').strip().casefold()[:120]
                if identifier and not limiter.consume(scope + ':identifier', identifier, 15, 900):
                    abort(429)
            # Bound password/answer hashing input before invoking costly KDFs.
            for name in ('password', 'confirm_password', 'new_password', 'current_password', 'admin_password', 'security_answer'):
                if len(request.form.get(name, '')) > 512:
                    abort(400)
        else:
            if any(len(values) != 1 for _, values in request.args.lists()):
                abort(400)
            policy = None
            if endpoint in {'main.username_availability', 'main.app_marketplace'}:
                policy = ('public-search', 120, 60)
            elif endpoint == 'main.submission_status_snapshot':
                policy = ('submission-status', 240, 60)
            elif endpoint.startswith('main.') and request.path.startswith('/events/'):
                policy = ('event-connections', 30, 60)
            elif endpoint == 'main.download_app':
                policy = ('downloads', 60, 60)
            if policy and not limiter.consume(policy[0], actor, policy[1], policy[2]):
                abort(429)


def bootstrap_administrator(username, email, password):
    from .database import db
    from .models import User, UserRole, AccountStatus
    from sqlalchemy import func
    from sqlalchemy.exc import IntegrityError
    existing = User.query.filter(func.lower(User.username) == username.casefold()).first()
    if existing:
        if existing.role != UserRole.ADMIN:
            raise RuntimeError('Administrator bootstrap identifier belongs to a non-administrator; resolve ownership manually.')
        # Never promote, unblock or restore an existing account at process startup.
        return existing
    if not password:
        return None
    administrator = User(username=username, email=email, role=UserRole.ADMIN, status=AccountStatus.APPROVED)
    administrator.set_password(password)
    administrator.approve()
    db.session.add(administrator)
    try:
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        existing = User.query.filter(func.lower(User.username) == username.casefold()).first()
        if not existing or existing.role != UserRole.ADMIN:
            raise RuntimeError('Administrator bootstrap collision; resolve account ownership manually.') from None
        return existing
    return administrator

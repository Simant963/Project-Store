"""Extra checks invoked only by the disposable submission fixture (--security).

Never import the live app or load project credentials from this module.
"""
import hashlib
import io
import subprocess
import time
import zipfile
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from werkzeug.datastructures import MultiDict
from werkzeug.datastructures import FileStorage
from werkzeug.exceptions import HTTPException
from werkzeug.security import generate_password_hash


def run(app, login, token, fields, apk_bytes):
    from application.database import db
    from application import controllers as c
    from application.models import User, UserRole, AccountStatus, PasswordResetToken, ManualPasswordReset, ManualResetStatus, StoreApp
    from application.security_controls import RequestLimits, bootstrap_administrator, origin_tuple, supported_scanner
    checks = 0

    def expect(ok, message):
        nonlocal checks
        if not ok:
            raise AssertionError(message)
        checks += 1

    def clear_limits():
        app.extensions['security_limits'].windows.clear()

    def user_record(name):
        return User.query.filter_by(username=name).one()

    def session_client(name):
        client = app.test_client()
        with app.test_request_context('/'):
            c.sign_in_user(user_record(name))
            from flask import session
            values = dict(session)
        with client.session_transaction() as session:
            session.update(values)
        return client

    with app.app_context():
        try:
            bootstrap_administrator('PREVIEW_USER', 'unused@example.test', 'Unused-123456!')
            expect(False, 'Bootstrap promoted a normal user')
        except RuntimeError:
            expect(user_record('preview_user').role == UserRole.USER, 'Collision changed role')
        administrator = user_record('preview_admin')
        administrator.block(); db.session.commit()
        bootstrap_administrator('preview_admin', administrator.email, 'Unused-123456!')
        expect(administrator.status == AccountStatus.BLOCKED, 'Startup restored a blocked admin')
        administrator.unblock(); db.session.commit()
        with app.test_request_context('/'):
            errors, _ = c.validate_registration({'username': app.config['ADMIN_USERNAME'].upper()}, UserRole.USER)
        expect(any('reserved' in error for error in errors), 'Bootstrap name not reserved')

        person = user_record('preview_user')
        expect(person.password_hash.startswith('scrypt:32768:8:3$'), 'Weak new password KDF')
        previous_version = person.session_version
        person.password_hash = generate_password_hash('Preview-only-123!', method='scrypt:32768:8:1')
        expect(person.check_password('Preview-only-123!'), 'Legacy password no longer works')
        expect(person.password_hash.startswith('scrypt:32768:8:3$'), 'Legacy hash not upgraded')
        expect(person.session_version == previous_version, 'Hash upgrade invalidated unrelated sessions')
        db.session.commit()

        client = session_client('preview_user')
        stolen_cookie = client.get_cookie(app.config['SESSION_COOKIE_NAME']).value
        logout = client.post('/logout', data={'csrf_token': token(client), 'confirm': 'yes'})
        expect(logout.status_code == 302, 'Logout failed')
        replay = app.test_client(); replay.set_cookie(app.config['SESSION_COOKIE_NAME'], stolen_cookie)
        expect(replay.get('/account/settings').status_code == 302, 'Logged-out cookie replay accepted')
        client = session_client('preview_user')
        old_cookie = client.get_cookie(app.config['SESSION_COOKIE_NAME']).value
        person = user_record('preview_user'); person.block(); db.session.commit()
        expect(client.get('/account/settings').status_code == 302, 'Blocked user kept access')
        person.unblock(); db.session.commit()
        replay.set_cookie(app.config['SESSION_COOKIE_NAME'], old_cookie)
        expect(replay.get('/account/settings').status_code == 302, 'Unblock revived stolen session')
        person.soft_delete(); db.session.commit()
        guest = app.test_client(); guest.get('/login/user')
        response = guest.post('/login/user', data={'identifier': 'preview_user', 'password': 'Preview-only-123!', 'csrf_token': token(guest)})
        with guest.session_transaction() as state:
            expect('user_id' not in state, 'Deleted account can log in')
        person.restore(); db.session.commit()

        staff = session_client('preview_admin')
        with staff.session_transaction() as state:
            expect(not state.permanent, 'Staff remember-me remains enabled')
            state['privileged_until'] = time.time() - 1
        expect(staff.get('/admin').status_code == 302, 'Expired privileged session remains valid')
        staff = session_client('preview_admin')
        with staff.session_transaction() as state:
            del state['privileged_until']
        expect(staff.get('/admin').status_code == 302, 'Legacy unlimited staff cookie accepted')

        clear_limits()
        client = session_client('preview_user')
        csrf = token(client)
        for data in ({}, {'csrf_token': 'wrong'}, {'csrf_token': '非ASCII'}):
            expect(client.post('/logout', data=data).status_code == 400, 'Missing/invalid CSRF accepted')
        expect(client.post('/logout', data={'csrf_token': csrf}, headers={'Origin': 'https://attacker.invalid'}).status_code == 403, 'Cross-origin mutation accepted')
        expect(client.post('/logout', data={'csrf_token': csrf}, headers={'Sec-Fetch-Site': 'cross-site'}).status_code == 403, 'Cross-site request accepted')
        expect(client.post('/logout', data=MultiDict([('csrf_token', csrf), ('confirm', 'yes'), ('confirm', 'no')])).status_code == 400, 'Ambiguous form accepted')
        expect(client.get('/apps?q=one&q=two').status_code == 400, 'Ambiguous query accepted')
        expect(client.post('/account/settings', data={'csrf_token': csrf, 'password': 'x' * 513}).status_code == 400, 'Unbounded KDF input accepted')
        for url in ('javascript:alert(1)', 'https://user:pass@example.test', 'http://example.test:invalid'):
            expect(origin_tuple(url) is None, 'Malformed origin accepted')
        expect(origin_tuple('https://EXAMPLE.test') == origin_tuple('https://example.test:443'), 'Equivalent origins differ')

        original_email = user_record('preview_user').email
        response = client.post('/account/settings', data={'csrf_token': csrf, 'email': 'changed@example.test'})
        expect(response.status_code == 200 and user_record('preview_user').email == original_email, 'Email changed without password')
        response = client.post('/account/settings', data={'csrf_token': csrf, 'email': 'changed@example.test', 'current_password': 'Preview-only-123!'})
        expect(response.status_code == 302 and user_record('preview_user').email == 'changed@example.test', 'Authorized email change broken')
        person = user_record('preview_user'); person.email = original_email; db.session.commit()

        for target in ('/admin', '/admin/apps', '/admin/audit-log'):
            expect(client.get(target).status_code in (302, 403), 'Normal user accessed staff route')
        for action in ('approve', 'publish', 'scan', 'reject'):
            client = session_client('preview_user')
            expect(client.post('/admin/apps/1/' + action, data={'csrf_token': token(client), 'review_note': 'fixture'}, headers={'X-Requested-With': 'fetch'}).status_code == 403, 'Normal user modified protected workflow')
        expect(client.get('/static/.env').status_code == 404, 'Environment exposed as static asset')
        expect(client.get('/.git/config').status_code == 404, 'Repository exposed')
        expect(client.get('/.env').status_code == 404, 'Environment exposed')
        for folder, filename in [('apks', '../.env'), ('app_icons', '..\\secret'), ('apks', '/absolute/file')]:
            with app.test_request_context('/'):
                try:
                    c.send_private_upload(folder, filename)
                    expect(False, 'Traversal accepted')
                except HTTPException as error:
                    expect(error.code == 404, 'Traversal produced unsafe server error')

        count = User.query.count()
        expect(client.get('/apps?q=%27%20OR%201%3D1--').status_code == 200, 'SQL-shaped search caused error')
        expect(User.query.count() == count, 'SQL-shaped input changed users')
        response = client.get('/apps?q=%3Cscript%3Ealert(1)%3C/script%3E')
        expect(b'<script>alert(1)</script>' not in response.data, 'Search reflected executable HTML')
        response = client.get('/account/settings')
        for header in ('Content-Security-Policy', 'X-Content-Type-Options', 'Referrer-Policy'):
            expect(header in response.headers, 'Missing security header: ' + header)
        expect('no-store' in response.headers.get('Cache-Control', ''), 'Private page may be cached')
        trusted = app.config.get('TRUSTED_HOSTS')
        app.config['TRUSTED_HOSTS'] = ['localhost']
        try:
            expect(client.get('/', base_url='http://evil.invalid').status_code == 400, 'Host injection accepted')
        finally:
            app.config['TRUSTED_HOSTS'] = trusted

        client = session_client('preview_user')
        cookie = client.get_cookie(app.config['SESSION_COOKIE_NAME']).value
        raw = c.issue_password_reset(user_record('preview_user'))
        client.get('/reset-password/' + raw)
        data = {'csrf_token': token(client), 'password': 'Changed-fixture-123!', 'confirm_password': 'Changed-fixture-123!'}
        response = client.post('/reset-password/' + raw, data=data)
        expect(response.status_code == 302, 'Valid reset failed')
        record = PasswordResetToken.query.filter_by(token_hash=hashlib.sha256(raw.encode()).hexdigest()).one()
        expect(record.used_at is not None, 'Reset was not consumed')
        expect(client.get('/reset-password/' + raw).status_code == 400, 'Reset token replay accepted')
        replay.set_cookie(app.config['SESSION_COOKIE_NAME'], cookie)
        expect(replay.get('/account/settings').status_code == 302, 'Password reset left stolen session valid')
        person = user_record('preview_user'); person.set_password('Preview-only-123!'); db.session.commit()
        raw = c.issue_password_reset(person)
        PasswordResetToken.query.filter_by(token_hash=hashlib.sha256(raw.encode()).hexdigest()).update({'expires_at': datetime.now(timezone.utc) - timedelta(seconds=1)})
        db.session.commit()
        expect(client.get('/reset-password/' + raw).status_code == 400, 'Expired reset accepted')

        manual = ManualPasswordReset(reference='ABCDEF1234567890', user_id=person.id, status=ManualResetStatus.APPROVED,
            code_hash=hashlib.sha256(b'12345678').hexdigest(), code_expires_at=datetime.now(timezone.utc) + timedelta(minutes=5))
        db.session.add(manual); db.session.commit()
        guest = app.test_client(); guest.get('/manual-password-reset')
        data = {'csrf_token': token(guest), 'reference': manual.reference, 'code': '12345678'}
        expect(guest.post('/manual-password-reset', data=data).status_code == 302, 'Valid manual code failed')
        db.session.refresh(manual)
        expect(manual.status == ManualResetStatus.USED and manual.code_hash is None, 'Manual code not consumed')
        expect(guest.post('/manual-password-reset', data=data).status_code == 200, 'Replayed manual code issued a reset token')
        # Independent DB transactions must not consume the same reset twice.
        from sqlalchemy import update
        raw = c.issue_password_reset(person)
        reset_id = PasswordResetToken.query.filter_by(token_hash=hashlib.sha256(raw.encode()).hexdigest()).one().id
        engine = db.engine
        def consume_reset(_):
            with engine.begin() as connection:
                return connection.execute(update(PasswordResetToken).where(PasswordResetToken.id == reset_id,
                    PasswordResetToken.used_at.is_(None), PasswordResetToken.expires_at > datetime.now(timezone.utc)).values(used_at=datetime.now(timezone.utc))).rowcount
        with ThreadPoolExecutor(max_workers=8) as pool:
            expect(sum(pool.map(consume_reset, range(8))) == 1, 'Concurrent reset redemption accepted twice')
        manual.status = ManualResetStatus.APPROVED; manual.used_at = None; manual.code_hash = hashlib.sha256(b'12345678').hexdigest()
        db.session.commit()
        manual_id = manual.id
        def consume_code(_):
            with engine.begin() as connection:
                return connection.execute(update(ManualPasswordReset).where(ManualPasswordReset.id == manual_id,
                    ManualPasswordReset.status == ManualResetStatus.APPROVED, ManualPasswordReset.code_hash == hashlib.sha256(b'12345678').hexdigest(),
                    ManualPasswordReset.code_expires_at > datetime.now(timezone.utc)).values(status=ManualResetStatus.USED, code_hash=None, used_at=datetime.now(timezone.utc))).rowcount
        with ThreadPoolExecutor(max_workers=8) as pool:
            expect(sum(pool.map(consume_code, range(8))) == 1, 'Concurrent manual code redemption accepted twice')
        # Independent DB transactions must not consume the same reset twice.
        from sqlalchemy import update
        raw = c.issue_password_reset(person)
        reset_id = PasswordResetToken.query.filter_by(token_hash=hashlib.sha256(raw.encode()).hexdigest()).one().id
        engine = db.engine
        def consume_reset(_):
            with engine.begin() as connection:
                return connection.execute(update(PasswordResetToken).where(PasswordResetToken.id == reset_id,
                    PasswordResetToken.used_at.is_(None), PasswordResetToken.expires_at > datetime.now(timezone.utc)).values(used_at=datetime.now(timezone.utc))).rowcount
        with ThreadPoolExecutor(max_workers=8) as pool:
            expect(sum(pool.map(consume_reset, range(8))) == 1, 'Concurrent reset redemption accepted twice')
        manual.status = ManualResetStatus.APPROVED; manual.used_at = None; manual.code_hash = hashlib.sha256(b'12345678').hexdigest()
        db.session.commit()
        manual_id = manual.id
        def consume_code(_):
            with engine.begin() as connection:
                return connection.execute(update(ManualPasswordReset).where(ManualPasswordReset.id == manual_id,
                    ManualPasswordReset.status == ManualResetStatus.APPROVED, ManualPasswordReset.code_hash == hashlib.sha256(b'12345678').hexdigest(),
                    ManualPasswordReset.code_expires_at > datetime.now(timezone.utc)).values(status=ManualResetStatus.USED, code_hash=None, used_at=datetime.now(timezone.utc))).rowcount
        with ThreadPoolExecutor(max_workers=8) as pool:
            expect(sum(pool.map(consume_code, range(8))) == 1, 'Concurrent manual code redemption accepted twice')

        with app.test_request_context('/'):
            try:
                c.save_image_upload(FileStorage(stream=io.BytesIO(b'<svg onload="alert(1)"/>'), filename='icon.svg'), 'app_icons', 1024)
                expect(False, 'Executable SVG accepted')
            except ValueError:
                expect(True, 'SVG rejected')
        archive_path = Path(app.config['PRIVATE_UPLOAD_ROOT']) / 'unsafe-fixture.apk'
        with zipfile.ZipFile(archive_path, 'w') as archive:
            archive.writestr('AndroidManifest.xml', '<manifest/>')
            archive.writestr('../escape', 'harmless fixture')
        try:
            c.inspect_apk_archive(archive_path)
            expect(False, 'Unsafe archive path accepted')
        except ValueError:
            expect(True, 'Unsafe archive rejected')
        finally:
            archive_path.unlink()

        # Revoke access while the SSE reader is waiting: no queued private event leaks.
        staff = user_record('preview_admin')
        def revoke_while_waiting(**_):
            target = user_record('preview_admin'); target.block(); db.session.commit()
            return {'event_id': 'fixture', 'type': 'private', 'user_id': staff.id}
        with app.test_request_context('/'):
            c.sign_in_user(staff)
            with patch.object(c.account_events, 'subscribe') as subscribe, patch.object(c.account_events, 'unsubscribe') as unsubscribe:
                subscribe.return_value.get.side_effect = revoke_while_waiting
                response = c.server_event_response(lambda event: True)
                stream = iter(response.response)
                expect(next(stream).startswith('retry:'), 'SSE handshake failed')
                try:
                    next(stream); expect(False, 'Revoked SSE leaked a queued event')
                except StopIteration:
                    expect(True, 'Revoked SSE closed')
                response.close()
                expect(unsubscribe.called, 'SSE subscription not released')
        staff = user_record('preview_admin'); staff.unblock(); db.session.commit()

        # Simulate a quota change during scanning, before final slot allocation.
        from PIL import Image
        developer = session_client('preview_dev')
        root = Path(app.config['PRIVATE_UPLOAD_ROOT'])
        before_files = {str(path) for path in root.rglob('*') if path.is_file()}
        before_apps = StoreApp.query.count()
        image = io.BytesIO(); Image.new('RGB', (64, 64), 'purple').save(image, format='PNG'); image.seek(0)
        form = fields(999)
        form.update(csrf_token=token(developer), app_icon=(image, '../../icon.png'), apk_file=(io.BytesIO(apk_bytes('quota-test')), 'fixture.apk'))
        def revoke_quota(_):
            owner = user_record('preview_dev'); owner.app_upload_limit = 0; db.session.commit()
            return 'Isolated scanner fixture clean'
        with patch.object(c, 'scan_apk_for_malware', side_effect=revoke_quota):
            expect(developer.post('/developer/apps/new', data=form).status_code == 409, 'Quota change during scan was ignored')
        expect(StoreApp.query.count() == before_apps, 'Denied upload created an application')
        expect({str(path) for path in root.rglob('*') if path.is_file()} == before_files, 'Denied upload left files or removed existing files')
        owner = user_record('preview_dev'); owner.app_upload_limit = None; db.session.commit()

        with patch.object(c.subprocess, 'run', return_value=SimpleNamespace(returncode=0, stdout='', stderr='')) as execute:
            c.scan_apk_for_malware(Path('fixture.apk'))
            args, kwargs = execute.call_args
            for flag in ('--alert-exceeds-max=yes', '--alert-encrypted=yes', '--max-filesize=512M', '--max-scantime=0'):
                expect(flag in args[0], 'Scanner can silently skip inputs: ' + flag)
            expect(not kwargs.get('shell') and isinstance(args[0], list), 'Scanner uses shell interpolation')
            expect(kwargs['timeout'] > 0, 'Scanner lacks wall-clock deadline')
            expect('DATABASE_URL' not in kwargs['env'] and 'SECRET_KEY' not in kwargs['env'], 'Scanner inherited application credentials')
        for version, expected in [('1.4.3', False), ('1.4.6', True), ('1.5.2', False), ('1.5.4', True)]:
            with patch('application.security_controls.subprocess.run', return_value=SimpleNamespace(returncode=0, stdout='ClamAV ' + version)):
                expect(supported_scanner('fixture') == expected, 'Scanner security release gate incorrect')
        for outcome in (SimpleNamespace(returncode=1, stdout='Heuristics.Limits.Exceeded FOUND', stderr=''), SimpleNamespace(returncode=2, stdout='', stderr='private/path'), subprocess.TimeoutExpired('clamscan', 1), FileNotFoundError()):
            options = {'side_effect': outcome} if isinstance(outcome, Exception) else {'return_value': outcome}
            with patch.object(c.subprocess, 'run', **options):
                try:
                    c.scan_apk_for_malware(Path('fixture.apk'))
                    expect(False, 'Scanner did not fail closed')
                except ValueError as error:
                    expect('private/path' not in str(error), 'Scanner error leaked private path')
        old_config = {name: app.config[name] for name in ('SMTP_HOST', 'SMTP_USE_TLS', 'SMTP_USERNAME')}
        app.config.update(SMTP_HOST='smtp.example.test', SMTP_USE_TLS=True, SMTP_USERNAME='')
        try:
            with patch.object(c.smtplib, 'SMTP') as smtp:
                c.deliver_password_reset(user_record('preview_user'), 'https://example.test/reset/fixture')
                context = smtp.return_value.__enter__.return_value.starttls.call_args.kwargs['context']
                expect(context.check_hostname and context.verify_mode == 2, 'SMTP does not verify TLS certificate')
        finally:
            app.config.update(old_config)

        limiter = RequestLimits()
        with ThreadPoolExecutor(max_workers=12) as pool:
            results = list(pool.map(lambda _: limiter.consume('fixture', 'same', 10, 60), range(40)))
        expect(sum(results) == 10, 'Concurrent limiter exceeded budget')
        expect(all('same' not in key for key in limiter.windows), 'Limiter stores clear-text identifiers')
        with ThreadPoolExecutor(max_workers=12) as pool:
            leases = list(pool.map(lambda _: limiter.acquire('streams', 'one', 3, 60), range(20)))
        expect(sum(bool(lease) for lease in leases) == 3, 'Concurrent lease limit exceeded')
        for lease in leases:
            limiter.release(lease)
        expect(bool(limiter.acquire('streams', 'one', 3, 60)), 'Released lease not reusable')
        clear_limits()
        guest = app.test_client(); guest.get('/login/user')
        with patch.object(c, 'check_password_hash', return_value=False):
            outcomes = [guest.post('/login/user', data={'identifier': 'rotating' + str(n), 'password': 'invalid-fixture', 'csrf_token': token(guest)}).status_code for n in range(31)]
        expect(outcomes[-1] == 429, 'Rotating identifiers bypassed IP limit')
        clear_limits()
    print(f'PASS: {checks} additional isolated security regression checks.')
    return checks

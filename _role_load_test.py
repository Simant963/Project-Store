"""Run one concurrent request wave for each authenticated role."""
from gevent import monkey

monkey.patch_all()

import argparse
import os
import re
import time
from http.cookiejar import CookieJar
from urllib.parse import urlencode, urlparse
from urllib.request import HTTPCookieProcessor, Request, build_opener

from gevent.pool import Pool


CSRF_RE = re.compile(r'name="csrf_token"[^>]*value="([^"]+)"')
ROLES = {
    "admin": ("/admin/login", "/admin"),
    "coadmin": ("/admin/login", "/admin"),
    "developer": ("/login/developer", "/developer/dashboard"),
    "user": ("/login/user", "/user/dashboard"),
}


def login(base_url, role):
    username = os.environ[f"LOAD_{role.upper()}_USERNAME"]
    password = os.environ[f"LOAD_{role.upper()}_PASSWORD"]
    login_path, _ = ROLES[role]
    opener = build_opener(HTTPCookieProcessor(CookieJar()))
    page = opener.open(base_url + login_path, timeout=30).read().decode()
    csrf = CSRF_RE.search(page)
    if csrf is None:
        raise RuntimeError(f"Could not find CSRF token for {role}")
    body = urlencode(
        {"csrf_token": csrf.group(1), "identifier": username, "password": password}
    ).encode()
    response = opener.open(Request(base_url + login_path, data=body), timeout=30)
    if response.geturl().endswith(login_path):
        raise RuntimeError(f"Login failed for {role}")
    return opener


def run_wave(base_url, role, concurrency):
    opener = login(base_url, role)
    path = ROLES[role][1]

    def request(_):
        started = time.perf_counter()
        try:
            response = opener.open(base_url + path, timeout=60)
            status = response.status
            response.read()
            if urlparse(response.geturl()).path != path:
                status = f"redirected:{response.geturl()}"
            return time.perf_counter() - started, status
        except Exception as exc:
            return time.perf_counter() - started, type(exc).__name__

    started = time.perf_counter()
    results = Pool(concurrency).map(request, range(concurrency))
    elapsed = time.perf_counter() - started
    timings = sorted(duration for duration, _ in results)
    failures = [status for _, status in results if status != 200]
    p95 = timings[int(len(timings) * 0.95) - 1]
    print(
        f"{role}: requests={concurrency} errors={len(failures)} "
        f"rps={concurrency / elapsed:.1f} p95={p95 * 1000:.0f}ms"
    )
    return not failures


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", required=True)
    parser.add_argument("--concurrency", type=int, default=1000)
    args = parser.parse_args()
    base_url = args.url.rstrip("/")
    passed = all([run_wave(base_url, role, args.concurrency) for role in ROLES])
    raise SystemExit(0 if passed else 1)


if __name__ == "__main__":
    main()

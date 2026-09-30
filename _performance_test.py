"""Disposable in-process baseline: env/Scripts/python.exe _performance_test.py."""
import json
import math
import os
import runpy
import statistics
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path


def benchmark(app):
    from application.database import db
    from application.models import StoreApp, User

    with app.app_context():
        original = StoreApp.query.filter_by(slug="workflow-app").one()
        values = {column.name: getattr(original, column.name)
                  for column in StoreApp.__table__.columns
                  if column.name not in {"id", "slug", "package_name", "name"}}
        db.session.add_all([StoreApp(**values, name=f"Benchmark App {i}",
            slug=f"benchmark-{i}", package_name=f"com.benchmark.app{i}") for i in range(500)])
        db.session.commit()
        admin = User.query.filter_by(username="workflow_admin").one()
        user = User.query.filter_by(username="market_user").one()
        admin_identity = (admin.id, admin.session_version)
        user_identity = (user.id, user.session_version)

    cases = [("home", "/", None), ("browse", "/apps", None),
             ("search", "/apps?q=Benchmark", None),
             ("details", "/apps/workflow-app", None),
             ("admin", "/admin/apps", admin_identity),
             ("library", "/user/dashboard", user_identity)]
    results = []
    for name, path, identity in cases:
        for workers in (1, 8, 24):
            def request(_):
                client = app.test_client()
                if identity:
                    with client.session_transaction() as session:
                        session["user_id"], session["session_version"] = identity
                started = time.perf_counter()
                try:
                    response = client.get(path)
                    size = len(response.data)
                    status = response.status_code
                    response.close()
                    error = None if status == 200 else f"HTTP {status}"
                except Exception as exc:
                    status, size, error = 0, 0, type(exc).__name__
                return (time.perf_counter() - started) * 1000, status, size, error

            request(0)  # Warm template and connection caches; excluded from timings.
            started = time.perf_counter()
            with ThreadPoolExecutor(max_workers=workers) as executor:
                observations = list(executor.map(request, range(48)))
            elapsed = time.perf_counter() - started
            times = sorted(row[0] for row in observations)
            result = dict(page=name, workers=workers, requests=len(times),
                median_ms=round(statistics.median(times), 1),
                p95_ms=round(times[math.ceil(len(times) * .95) - 1], 1),
                max_ms=round(max(times), 1), requests_per_second=round(len(times)/elapsed, 1),
                errors=sum(row[3] is not None for row in observations),
                error_types=sorted({row[3] for row in observations if row[3]}))
            results.append(result)
            print(json.dumps(result), flush=True)
    print("PERFORMANCE_RESULTS=" + json.dumps(results), flush=True)
    assert not any(row["errors"] for row in results), "Request errors occurred"


if __name__ == "__main__":
    os.environ["RUN_PERFORMANCE_TEST"] = "1"
    os.environ["APP_ENV"] = "development"
    runpy.run_path(str(Path(__file__).with_name("_marketplace_workflow_test.py")), run_name="__main__")

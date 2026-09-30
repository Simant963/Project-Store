# Performance baseline

Disposable SQLite database with 501 approved apps; Flask in-process test clients on this Windows machine. Six routes, 48 requests per route at each concurrency level (1, 8, 24): **864 measured requests, zero errors**. Warm-up requests excluded. Single short run, not a capacity guarantee.

| Page | 1 worker p95 | 8 workers p95 | 24 workers p95 |
|---|---:|---:|---:|
| home | 2.8 ms | 33.3 ms | 139.7 ms |
| browse | 4.8 ms | 90.1 ms | 277.1 ms |
| search | 5.9 ms | 89 ms | 299.1 ms |
| details | 5.6 ms | 63.9 ms | 151.2 ms |
| admin | 10.1 ms | 139 ms | 517.5 ms |
| library | 6.8 ms | 74.1 ms | 241.4 ms |

The admin app list was the slowest measured route. No performance changes were made to application behavior.

## Reproduce

Run `env/Scripts/python.exe _performance_test.py` from the project root. It uses the existing workflow fixture, adds 500 synthetic apps, prints results, and cleans its temporary database/uploads on normal exit. It does not target the real database.

## Scope and remaining tests

- Times cover route execution and response consumption, not browser rendering, TLS, real network, or reverse proxy latency. Sessions are pre-authenticated; login hashing is not measured.
- This is a thread-pool burst, not a sustained arrival-rate or many-distinct-users simulation. SQLite and the local Python interpreter differ from production PostgreSQL/Gunicorn.
- Still needed: real HTTP tests on the production-like server, sustained real-time connections alongside normal traffic, APK upload/download throughput and scanner contention, larger data sets, memory/CPU monitoring, repeated runs, and agreed latency/error budgets.
- The Procfile configures three threaded workers with two threads each. Long-lived event streams occupy request threads; test this configuration with concurrent dashboard users before claiming capacity. This is a code/configuration risk, not a measured production failure.


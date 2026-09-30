# Appora production-like test report

Date: 24 September 2026

## Result

Application regression tests passed. Deployment preflight is blocked and the project is not ready for public production traffic yet.

On 25 September 2026, Docker Desktop and Compose were verified, the current images built successfully, Redis became healthy, staging migrations reached the current head, and the rebuilt Gunicorn web container passed its internal production readiness check.

The backup scripts were corrected to use binary-safe Docker volume transfers and to fail closed. A PostgreSQL custom-format dump and private-upload archive were created and successfully parsed on 25 September 2026; four invalid archives produced by the former PowerShell redirection method were removed because they were not recoverable.

## Passed

- APK upload validation, fail-closed malware scanner behavior, duplicate-build detection, 60-point administrator scan, report export, and approval gating.
- Complete marketplace workflow across administrator, co-administrator, developer, and user functions.
- Confidentiality controls: debug traceback suppression, generic errors, no browser reset-token disclosure, dotfile denial, security headers, and non-cacheable protected responses.
- All nine legal pages and their internal/email links.
- Python compilation and UI motion regression checks.
- In-process concurrency benchmark completed with zero request errors.

## Performance sample

The isolated SQLite benchmark used 500 app records and 48 requests per page/concurrency level. This is a regression baseline, not production capacity certification.

| Page | Workers | Throughput | p95 |
| --- | ---: | ---: | ---: |
| Home | 24 | 365.6 req/s | 108.0 ms |
| Browse | 24 | 180.6 req/s | 239.6 ms |
| Search | 24 | 170.4 req/s | 252.1 ms |
| App details | 24 | 242.6 req/s | 157.0 ms |
| Admin apps | 24 | 107.5 req/s | 405.9 ms |
| User library | 24 | 165.8 req/s | 244.6 ms |

## Blocking production gates

1. Configure real Redis, administrator email, public HTTPS URL, SMTP sender/host, registered operator/address, privacy/support contacts, and appointed grievance officer in `.env.production`.
2. Install the real TLS certificate and key in `deployment/certs`; Nginx cannot start without them.
3. Docker Desktop/Engine and the production images are now validated. The remaining Compose mismatch is database configuration: `.env.production` still targets the preserved local Docker PostgreSQL container, while the current deployment is designed for Supabase. Update the secret setting before removing the orphan database container.
4. Verify Supabase connection pooling, readiness, backup, and restore in staging. The configured database accepted an SSL connection and Alembic reported no pending model migrations on 25 September 2026.
5. Run ClamAV with current signatures inside the built production image.
6. Run `_role_load_test.py` against an isolated staging deployment with 1,000 concurrent authenticated requests for every role. Do not run this against the live database first.
7. Run external TLS, DNS, SMTP-delivery, firewall, monitoring, and vulnerability checks after a staging domain is available.

## Release decision

**NO-GO** until every blocking gate above passes. Re-run `deployment/preflight.ps1`, then the staging role load test, before changing this decision.

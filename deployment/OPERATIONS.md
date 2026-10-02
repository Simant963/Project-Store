# Monitoring and recovery

The `monitor` Compose service checks application readiness every 30 seconds.
Three consecutive failures produce an outage alert; the next successful check
produces a recovery alert. Alerts are printed to container logs and persisted
in the `monitor_data` volume. The alert log rotates at 5 MB with three retained
copies. Outage state survives monitor restarts.

To enable external delivery, copy `deployment/.env.monitor.example` to
`deployment/.env.monitor`, set `ALERT_WEBHOOK_URL` to your private HTTPS
notification endpoint, and recreate the monitor service. The endpoint receives
JSON fields `service`, `event`, and `timestamp`. Failed delivery retries on
subsequent checks. Local monitoring works without an external service; external
delivery requires a real endpoint. The endpoint must support this JSON format.

```text
docker compose -f docker-compose.production.yml up -d --build monitor
docker compose -f docker-compose.production.yml logs --tail 100 monitor
docker compose -f docker-compose.production.yml exec monitor cat /data/monitor/state.json
```

The monitor shares the server's failure domain. After choosing a domain and
host, run a second monitor on a separate machine against the public HTTPS
`/ready` endpoint to detect host, proxy, certificate, and network failures.

## Backup operations

Quiesce account changes and uploads while taking a paired database/file backup.
Run `deployment/backup.ps1`, copy both resulting files to encrypted off-server
storage, and record their checksums and date. Retain 30 daily pairs in accordance
with the published policy. Do not restore into production as a test.

Run restore drills in a disposable PostgreSQL database and separate upload
volume. Verify migration revision, every file's SHA-256 checksum, and actual
downloads after recovery. A valid tar archive alone is insufficient.


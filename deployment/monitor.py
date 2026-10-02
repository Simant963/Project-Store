"""Readiness monitoring with durable local alerts and optional webhook delivery."""
import json
import logging
from logging.handlers import RotatingFileHandler
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.request import Request, urlopen
from urllib.parse import urlparse


def check(url):
    try:
        # Internal Docker DNS must use a host accepted by Flask's allowlist.
        headers = {"Host": "localhost"} if urlparse(url).hostname == "web" else {}
        with urlopen(Request(url, headers=headers), timeout=10) as response:
            result = json.load(response)
            return response.status == 200 and result.get("status") == "ready"
    except Exception:
        return False


class Monitor:
    def __init__(self, threshold=3):
        self.threshold = threshold
        self.failures = 0
        self.unhealthy = False

    def observe(self, healthy):
        self.failures = 0 if healthy else self.failures + 1
        if not healthy and self.failures >= self.threshold and not self.unhealthy:
            self.unhealthy = True
            return "unavailable"
        if healthy and self.unhealthy:
            self.unhealthy = False
            return "recovered"
        return None


def main():
    url = os.getenv("MONITOR_URL", "http://web:8000/ready")
    interval = max(5, int(os.getenv("MONITOR_INTERVAL", "30")))
    threshold = max(1, int(os.getenv("MONITOR_FAILURE_THRESHOLD", "3")))
    webhook = os.getenv("ALERT_WEBHOOK_URL", "")
    if webhook and not webhook.startswith("https://"):
        raise ValueError("ALERT_WEBHOOK_URL must use HTTPS")
    root = Path(os.getenv("MONITOR_STATE_DIR", "/data/monitor"))
    root.mkdir(parents=True, exist_ok=True)
    monitor = Monitor(threshold)
    logger = logging.getLogger("alerts")
    logger.setLevel(logging.INFO)
    logger.addHandler(RotatingFileHandler(root / "alerts.jsonl", maxBytes=5_000_000, backupCount=3))
    pending = None
    max_checks = int(os.getenv("MONITOR_MAX_CHECKS", "0"))
    completed_checks = 0
    # Preserve outage state across monitor restarts to avoid duplicate alerts.
    state_file = root / "state.json"
    if state_file.exists():
        saved = json.loads(state_file.read_text())
        monitor.unhealthy = saved.get("unhealthy", False)
        pending = saved.get("pending")
    while True:
        event = monitor.observe(check(url))
        if event:
            pending = {
                "service": "project-store",
                "event": event,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
            logger.info(json.dumps(pending))
            print(json.dumps(pending), flush=True)
        if pending and webhook:
            try:
                req = Request(
                    webhook,
                    data=json.dumps(pending).encode(),
                    headers={"Content-Type": "application/json"},
                    method="POST",
                )
                with urlopen(req, timeout=10) as response:
                    if 200 <= response.status < 300:
                        pending = None
            except Exception:
                # Do not log the webhook URL or exception: URLs can contain secrets.
                print("Alert delivery failed; retrying next check.", flush=True)
        if not webhook:
            pending = None
        temporary = root / "state.tmp"
        temporary.write_text(json.dumps({"unhealthy": monitor.unhealthy, "pending": pending, "checked_at": datetime.now(timezone.utc).isoformat()}))
        temporary.replace(state_file)
        completed_checks += 1
        if max_checks and completed_checks >= max_checks:
            return
        time.sleep(interval)


if __name__ == "__main__":
    main()

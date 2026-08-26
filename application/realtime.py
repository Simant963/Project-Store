from datetime import datetime, timezone
from queue import Empty, Full, Queue
from threading import Lock
from uuid import uuid4


class AccountEventBus:
    """In-process event fan-out for live dashboard updates."""

    def __init__(self):
        self._subscribers = set()
        self._lock = Lock()

    def subscribe(self):
        subscriber = Queue(maxsize=50)
        with self._lock:
            self._subscribers.add(subscriber)
        return subscriber

    def unsubscribe(self, subscriber):
        with self._lock:
            self._subscribers.discard(subscriber)

    def publish(self, event):
        payload = {
            "event_id": uuid4().hex,
            "sent_at": datetime.now(timezone.utc).isoformat(),
            **event,
        }
        with self._lock:
            subscribers = tuple(self._subscribers)
        for subscriber in subscribers:
            try:
                subscriber.put_nowait(payload)
            except Full:
                try:
                    subscriber.get_nowait()
                    subscriber.put_nowait(payload)
                except (Empty, Full):
                    pass
        return payload


account_events = AccountEventBus()

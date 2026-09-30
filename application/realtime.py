import json
import os
from datetime import datetime, timezone
from queue import Empty, Full, Queue
from threading import Lock
from uuid import uuid4

from redis import Redis


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


class RedisSubscriber:
    def __init__(self, client, channel):
        self._pubsub = client.pubsub(ignore_subscribe_messages=True)
        self._pubsub.subscribe(channel)

    def get(self, timeout):
        message = self._pubsub.get_message(timeout=timeout)
        if message is None:
            raise Empty
        return json.loads(message["data"])

    def close(self):
        self._pubsub.close()


class RedisEventBus:
    """Cross-worker event fan-out for production SSE connections."""

    def __init__(self, url, channel="appora-events"):
        self._client = Redis.from_url(url, decode_responses=True)
        self._channel = channel

    def subscribe(self):
        return RedisSubscriber(self._client, self._channel)

    def unsubscribe(self, subscriber):
        subscriber.close()

    def publish(self, event):
        payload = {
            "event_id": uuid4().hex,
            "sent_at": datetime.now(timezone.utc).isoformat(),
            **event,
        }
        self._client.publish(self._channel, json.dumps(payload))
        return payload


account_events = (
    RedisEventBus(os.environ["REDIS_URL"])
    if os.getenv("REDIS_URL")
    else AccountEventBus()
)

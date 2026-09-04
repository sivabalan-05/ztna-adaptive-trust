"""Event bus for live push.

The continuous-verification worker produces score changes; WebSocket clients
consume them. Those two may or may not be in the same process, so there are two
backends behind one interface:

* **Redis pub/sub** when ``REDIS_URL`` is set — the worker runs as its own
  Compose service and the API relays what it publishes.
* **In-process fan-out** otherwise — a plain asyncio queue per subscriber.

The in-process bus only carries events between coroutines in *one* process.
That is why, with no Redis configured, the verification loop runs inside the
API process rather than in the separate worker: a loop that published into a
bus nobody could subscribe to would look like it was working and do nothing.
``app.main`` makes that choice explicitly at startup and logs which mode it is
in.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from app.core.config import settings
from app.models.base import utcnow

logger = logging.getLogger(__name__)

CHANNEL = "ztna:events"

#: Dropped rather than queued forever if a client cannot keep up. A slow
#: dashboard must not be able to grow the server's memory without bound.
SUBSCRIBER_QUEUE_SIZE = 256


@dataclass(frozen=True)
class Event:
    """One thing that happened, addressed to whoever is allowed to see it."""

    type: str
    payload: dict[str, Any]
    #: Users who may receive this event. Empty means "operators only"
    #: (administrators and security analysts).
    audience_user_ids: tuple[str, ...] = ()
    at: datetime = field(default_factory=utcnow)

    def to_json(self) -> str:
        return json.dumps(
            {
                "type": self.type,
                "at": self.at.isoformat(),
                "audience": list(self.audience_user_ids),
                "payload": self.payload,
            },
            default=str,
        )

    @staticmethod
    def from_json(raw: str) -> "Event":
        data = json.loads(raw)
        return Event(
            type=data["type"],
            payload=data.get("payload", {}),
            audience_user_ids=tuple(data.get("audience", [])),
            at=datetime.fromisoformat(data["at"]),
        )

    def visible_to(self, user_id: str, is_operator: bool) -> bool:
        if is_operator:
            return True
        return user_id in self.audience_user_ids


class InProcessBus:
    """Fan-out to every subscriber in this process."""

    name = "in-process"

    def __init__(self) -> None:
        self._subscribers: set[asyncio.Queue[Event]] = set()
        self._lock = asyncio.Lock()

    async def publish(self, event: Event) -> None:
        for queue in list(self._subscribers):
            try:
                queue.put_nowait(event)
            except asyncio.QueueFull:
                # The client is not draining. Drop this event for them rather
                # than blocking every other subscriber behind one slow reader.
                logger.debug("Dropped %s for a saturated subscriber", event.type)

    @contextlib.asynccontextmanager
    async def subscribe(self) -> AsyncIterator[asyncio.Queue[Event]]:
        queue: asyncio.Queue[Event] = asyncio.Queue(maxsize=SUBSCRIBER_QUEUE_SIZE)
        async with self._lock:
            self._subscribers.add(queue)
        try:
            yield queue
        finally:
            async with self._lock:
                self._subscribers.discard(queue)

    @property
    def subscriber_count(self) -> int:
        return len(self._subscribers)


class RedisBus:
    """Pub/sub across processes, with a local fan-out for this process's clients."""

    name = "redis"

    def __init__(self, url: str) -> None:
        self._url = url
        self._local = InProcessBus()
        self._relay: asyncio.Task[None] | None = None

    async def _client(self):
        import redis.asyncio as aioredis

        return aioredis.from_url(self._url, decode_responses=True)

    async def start(self) -> None:
        """Relay everything on the channel into this process's subscribers."""
        if self._relay is not None:
            return
        self._relay = asyncio.create_task(self._relay_loop())

    async def _relay_loop(self) -> None:
        while True:
            try:
                client = await self._client()
                pubsub = client.pubsub()
                await pubsub.subscribe(CHANNEL)
                logger.info("Subscribed to Redis channel %s", CHANNEL)
                async for message in pubsub.listen():
                    if message.get("type") != "message":
                        continue
                    try:
                        await self._local.publish(Event.from_json(message["data"]))
                    except (ValueError, KeyError):
                        logger.warning("Discarded a malformed event from Redis.")
            except asyncio.CancelledError:
                raise
            except Exception:
                # A dropped Redis connection must not end live push for good.
                logger.exception("Redis relay failed; retrying in 5s.")
                await asyncio.sleep(5)

    async def publish(self, event: Event) -> None:
        try:
            client = await self._client()
            await client.publish(CHANNEL, event.to_json())
        except Exception:
            logger.exception("Could not publish to Redis; delivering locally only.")
            await self._local.publish(event)

    @contextlib.asynccontextmanager
    async def subscribe(self) -> AsyncIterator[asyncio.Queue[Event]]:
        async with self._local.subscribe() as queue:
            yield queue

    @property
    def subscriber_count(self) -> int:
        return self._local.subscriber_count

    async def stop(self) -> None:
        if self._relay is not None:
            self._relay.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._relay
            self._relay = None


def _build_bus() -> InProcessBus | RedisBus:
    if settings.redis_url:
        logger.info("Event bus: Redis pub/sub at %s", settings.redis_url)
        return RedisBus(settings.redis_url)
    logger.info("Event bus: in-process fan-out (no REDIS_URL configured)")
    return InProcessBus()


bus: InProcessBus | RedisBus = _build_bus()


def publish_sync(event: Event) -> None:
    """Publish from synchronous code (the worker, a request handler).

    Schedules onto the running loop when there is one; when called from a
    thread with no loop — the worker's own thread — it runs a short loop of its
    own rather than silently discarding the event.
    """
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        try:
            asyncio.run(bus.publish(event))
        except Exception:
            logger.exception("Could not publish %s", event.type)
        return
    loop.create_task(bus.publish(event))

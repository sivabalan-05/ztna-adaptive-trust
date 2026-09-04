"""Session-state, revocation-list and rate-limit store.

Redis when ``REDIS_URL`` is configured, an in-process dictionary otherwise, so
the whole platform still runs on a laptop with no network and no containers.
The two backends implement the same small interface; nothing above this module
knows which one is live.
"""

from __future__ import annotations

import logging
import threading
import time
from typing import Protocol

from app.core.config import settings

logger = logging.getLogger(__name__)


class CacheBackend(Protocol):
    """The only cache operations the application uses."""

    def get(self, key: str) -> str | None: ...
    def set(self, key: str, value: str, ttl_seconds: int) -> None: ...
    def delete(self, key: str) -> None: ...
    def exists(self, key: str) -> bool: ...
    def increment(self, key: str, ttl_seconds: int) -> int: ...
    def ttl(self, key: str) -> int: ...


class InMemoryCache:
    """Thread-safe dict with per-key expiry.

    Single-process only: it is the offline fallback, not a production store.
    Expired keys are removed lazily on read plus on a cheap sweep during writes.
    """

    def __init__(self) -> None:
        self._data: dict[str, tuple[str, float]] = {}
        self._lock = threading.Lock()

    def _purge_locked(self) -> None:
        now = time.monotonic()
        expired = [k for k, (_, exp) in self._data.items() if exp <= now]
        for key in expired:
            del self._data[key]

    def get(self, key: str) -> str | None:
        with self._lock:
            entry = self._data.get(key)
            if entry is None:
                return None
            value, expires_at = entry
            if expires_at <= time.monotonic():
                del self._data[key]
                return None
            return value

    def set(self, key: str, value: str, ttl_seconds: int) -> None:
        with self._lock:
            self._purge_locked()
            self._data[key] = (value, time.monotonic() + max(1, ttl_seconds))

    def delete(self, key: str) -> None:
        with self._lock:
            self._data.pop(key, None)

    def exists(self, key: str) -> bool:
        return self.get(key) is not None

    def increment(self, key: str, ttl_seconds: int) -> int:
        with self._lock:
            now = time.monotonic()
            entry = self._data.get(key)
            if entry is None or entry[1] <= now:
                self._data[key] = ("1", now + max(1, ttl_seconds))
                return 1
            value, expires_at = entry
            new_value = int(value) + 1
            self._data[key] = (str(new_value), expires_at)   # window does not slide
            return new_value

    def ttl(self, key: str) -> int:
        with self._lock:
            entry = self._data.get(key)
            if entry is None:
                return -2
            remaining = entry[1] - time.monotonic()
            return int(remaining) if remaining > 0 else -2


class RedisCache:
    """Thin wrapper over redis-py with the same interface."""

    def __init__(self, url: str) -> None:
        import redis

        self._client = redis.Redis.from_url(url, decode_responses=True)
        self._client.ping()

    def get(self, key: str) -> str | None:
        return self._client.get(key)

    def set(self, key: str, value: str, ttl_seconds: int) -> None:
        self._client.setex(key, max(1, ttl_seconds), value)

    def delete(self, key: str) -> None:
        self._client.delete(key)

    def exists(self, key: str) -> bool:
        return bool(self._client.exists(key))

    def increment(self, key: str, ttl_seconds: int) -> int:
        pipe = self._client.pipeline()
        pipe.incr(key)
        pipe.expire(key, max(1, ttl_seconds), nx=True)
        count, _ = pipe.execute()
        return int(count)

    def ttl(self, key: str) -> int:
        return int(self._client.ttl(key))


def _build_cache() -> CacheBackend:
    if not settings.redis_url:
        logger.info("No REDIS_URL configured; using the in-process cache.")
        return InMemoryCache()
    try:
        cache = RedisCache(settings.redis_url)
        logger.info("Connected to Redis at %s", settings.redis_url)
        return cache
    except Exception:
        # A missing Redis must not take the platform down: the demo has to run
        # offline. The degraded state is logged loudly and surfaced on /health.
        logger.exception(
            "REDIS_URL is set but unreachable; falling back to the in-process "
            "cache. Revocation and rate limits will not be shared across workers."
        )
        return InMemoryCache()


cache: CacheBackend = _build_cache()


def cache_kind() -> str:
    return "redis" if isinstance(cache, RedisCache) else "in-memory"

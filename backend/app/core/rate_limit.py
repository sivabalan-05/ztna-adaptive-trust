"""Fixed-window rate limiting backed by the shared cache.

Applied to the authentication endpoints in Phase 2; Phase 3 promotes it to a
gateway middleware covering every route.
"""

from __future__ import annotations

from dataclasses import dataclass

from app.core.cache import cache


@dataclass(frozen=True)
class RateLimit:
    limit: int
    window_seconds: int


#: Deliberately tight: these are the endpoints a credential-stuffing run hits.
LOGIN_LIMIT = RateLimit(limit=10, window_seconds=60)
MFA_LIMIT = RateLimit(limit=8, window_seconds=60)
REFRESH_LIMIT = RateLimit(limit=30, window_seconds=60)


class RateLimitExceeded(Exception):
    def __init__(self, retry_after: int) -> None:
        super().__init__("Too many requests.")
        self.retry_after = retry_after


def check(bucket: str, identity: str, rule: RateLimit) -> int:
    """Count one hit; raise ``RateLimitExceeded`` past the limit.

    Returns the number of requests remaining in the current window.
    """
    key = f"ratelimit:{bucket}:{identity}"
    count = cache.increment(key, rule.window_seconds)
    if count > rule.limit:
        retry_after = cache.ttl(key)
        raise RateLimitExceeded(retry_after if retry_after > 0 else rule.window_seconds)
    return rule.limit - count

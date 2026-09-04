"""API gateway middleware: a global per-address request ceiling.

This is a coarse backstop against a client hammering the platform. The tight,
security-relevant limits stay on the authentication endpoints, where they can
key on the username as well as the address.
"""

from __future__ import annotations

import logging
from collections.abc import Awaitable, Callable

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from app.core import rate_limit
from app.middleware.context import client_ip

logger = logging.getLogger(__name__)

GLOBAL_LIMIT = rate_limit.RateLimit(limit=300, window_seconds=60)

#: Health checks and docs must stay reachable even while a client is being
#: throttled, or Compose would mark a busy API unhealthy and restart it.
EXEMPT_PATHS = frozenset({"/health", "/docs", "/redoc", "/openapi.json"})


class RateLimitMiddleware(BaseHTTPMiddleware):
    async def dispatch(
        self, request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        if request.url.path in EXEMPT_PATHS or request.method == "OPTIONS":
            return await call_next(request)

        try:
            rate_limit.check("gateway", client_ip(request), GLOBAL_LIMIT)
        except rate_limit.RateLimitExceeded as exc:
            logger.warning(
                "Gateway rate limit hit by %s on %s", client_ip(request), request.url.path
            )
            return JSONResponse(
                status_code=429,
                content={
                    "detail": "Too many requests. Please slow down.",
                    "code": "rate_limited",
                    "request_id": getattr(request.state, "request_id", None),
                },
                headers={"Retry-After": str(exc.retry_after)},
            )
        return await call_next(request)

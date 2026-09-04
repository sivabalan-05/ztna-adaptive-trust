"""Integrity and context collector middleware.

Runs on every request, before authentication, and attaches a ``ContextBundle``
to ``request.state``. Everything downstream — the policy engine, the scoring
engine, the audit logger — reads that one object rather than re-parsing headers
or repeating GeoIP lookups.

Lookups are cached per address, so a burst of requests from one client costs a
single resolution.
"""

from __future__ import annotations

import logging
import uuid
from collections.abc import Awaitable, Callable

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

from app.core.context import ContextBundle, NetworkContext, TemporalContext
from app.external import geoip, ip_reputation, network_intel
from app.models.base import utcnow
from app.services.device_service import DeviceContext

logger = logging.getLogger(__name__)

DEVICE_FINGERPRINT_HEADER = "X-Device-Fingerprint"


def client_ip(request: Request) -> str:
    """Client address, honouring exactly one proxy hop.

    ``X-Forwarded-For`` is attacker-controlled unless a trusted proxy sets it.
    Behind the Compose gateway there is one hop, so the first entry is used and
    nothing further is inferred from the chain.
    """
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else ""


def collect_network_context(ip: str) -> NetworkContext:
    """Resolve one address through all three network providers."""
    geo = geoip.lookup(ip)
    intel = network_intel.analyse(ip, geo.asn, geo.isp)
    reputation = ip_reputation.score(ip, intel)
    return NetworkContext(
        ip_address=ip, geo=geo, intel=intel, reputation=reputation
    )


def collect_device_context(request: Request) -> DeviceContext | None:
    fingerprint = request.headers.get(DEVICE_FINGERPRINT_HEADER, "").strip()
    if not fingerprint:
        return None
    headers = request.headers
    return DeviceContext(
        fingerprint=fingerprint,
        user_agent=headers.get("User-Agent", ""),
        platform=headers.get("X-Device-Platform", ""),
        screen_resolution=headers.get("X-Device-Screen", ""),
        timezone=headers.get("X-Device-Timezone", ""),
        language=headers.get("Accept-Language", "").split(",")[0],
    )


def build_bundle(request: Request, request_id: str) -> ContextBundle:
    return ContextBundle(
        request_id=request_id,
        method=request.method,
        path=request.url.path,
        user_agent=request.headers.get("User-Agent", ""),
        network=collect_network_context(client_ip(request)),
        temporal=TemporalContext.from_utc(utcnow()),
        device=collect_device_context(request),
    )


class ContextCollectorMiddleware(BaseHTTPMiddleware):
    """Attaches ``request.state.context`` and ``request.state.request_id``."""

    async def dispatch(
        self, request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        request_id = request.headers.get("X-Request-ID") or uuid.uuid4().hex
        request.state.request_id = request_id

        try:
            request.state.context = build_bundle(request, request_id)
        except Exception:
            # Context enrichment must never take the API down. A failed lookup
            # degrades the signal; it does not deny the request, and the scoring
            # engine sees an unresolved location rather than a fabricated one.
            logger.exception(
                "Context collection failed for %s %s", request.method, request.url.path
            )
            from app.core.context import anonymous_bundle

            request.state.context = anonymous_bundle(request_id)

        response = await call_next(request)
        response.headers["X-Request-ID"] = request_id
        return response

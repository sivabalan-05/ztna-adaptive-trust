"""The ContextBundle: everything known about a request before any decision.

Zero Trust evaluates *context*, not just credentials. This module defines the
shape the collector middleware assembles on every request and the scoring engine
consumes in Phase 4. It holds data only — no I/O, no policy, no verdicts.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any
from zoneinfo import ZoneInfo

from app.external.geoip import GeoLocation
from app.external.ip_reputation import IPReputation
from app.external.network_intel import ASNType, NetworkIntel
from app.services.device_service import DeviceContext

BUSINESS_TIMEZONE = ZoneInfo("Asia/Kolkata")


@dataclass(frozen=True)
class NetworkContext:
    """Where the request came from and what kind of network that is."""

    ip_address: str
    geo: GeoLocation
    intel: NetworkIntel
    reputation: IPReputation

    @property
    def country(self) -> str:
        return self.geo.country

    @property
    def city(self) -> str:
        return self.geo.city

    @property
    def is_anonymised(self) -> bool:
        return self.intel.is_anonymised

    def summary(self) -> dict[str, Any]:
        """Flat, JSON-safe view for audit payloads and the API."""
        return {
            "ip": self.ip_address,
            "country": self.geo.country,
            "city": self.geo.city,
            "latitude": self.geo.latitude,
            "longitude": self.geo.longitude,
            "asn": self.intel.asn or self.geo.asn,
            "isp": self.geo.isp,
            "asn_type": self.intel.asn_type.value,
            "is_vpn": self.intel.is_vpn,
            "is_tor": self.intel.is_tor,
            "is_datacenter": self.intel.is_datacenter,
            "is_private": self.geo.is_private,
            "abuse_confidence": self.reputation.abuse_confidence,
            "geoip_provider": self.geo.provider,
            "reputation_provider": self.reputation.provider,
        }


@dataclass(frozen=True)
class TemporalContext:
    """When the request happened, in the business timezone."""

    at: datetime                 # UTC
    local_time: datetime         # Asia/Kolkata
    hour_of_day: int
    day_of_week: int             # Monday = 0
    is_weekend: bool
    is_business_hours: bool

    @classmethod
    def from_utc(cls, at: datetime) -> "TemporalContext":
        local = at.astimezone(BUSINESS_TIMEZONE)
        weekday = local.weekday()
        return cls(
            at=at,
            local_time=local,
            hour_of_day=local.hour,
            day_of_week=weekday,
            is_weekend=weekday >= 5,
            is_business_hours=weekday < 5 and 8 <= local.hour < 20,
        )

    def summary(self) -> dict[str, Any]:
        return {
            "at": self.at.isoformat(),
            "local_time": self.local_time.isoformat(),
            "hour_of_day": self.hour_of_day,
            "day_of_week": self.day_of_week,
            "is_weekend": self.is_weekend,
            "is_business_hours": self.is_business_hours,
        }


@dataclass(frozen=True)
class ContextBundle:
    """Assembled once per request by the collector middleware.

    Deliberately contains no user: the middleware runs before authentication.
    Identity, session and behaviour history are attached afterwards by the
    ``get_principal`` dependency, which is the first point at which they exist.
    """

    request_id: str
    method: str
    path: str
    user_agent: str
    network: NetworkContext
    temporal: TemporalContext
    device: DeviceContext | None = None
    extra: dict[str, Any] = field(default_factory=dict)

    @property
    def ip_address(self) -> str:
        return self.network.ip_address

    @property
    def device_fingerprint(self) -> str:
        return self.device.fingerprint if self.device else ""

    def summary(self) -> dict[str, Any]:
        return {
            "request_id": self.request_id,
            "method": self.method,
            "path": self.path,
            "network": self.network.summary(),
            "temporal": self.temporal.summary(),
            "device_fingerprint": (
                f"{self.device_fingerprint[:16]}..." if self.device_fingerprint else None
            ),
            "user_agent": self.user_agent,
        }


def anonymous_bundle(request_id: str | None = None) -> ContextBundle:
    """A bundle for code paths with no HTTP request behind them.

    Used by the background worker and the demo scripts, which re-score sessions
    outside any request. The empty network context makes it obvious in an audit
    payload that no client was involved.
    """
    from app.models.base import utcnow

    empty_ip = ""
    return ContextBundle(
        request_id=request_id or uuid.uuid4().hex,
        method="INTERNAL",
        path="",
        user_agent="",
        network=NetworkContext(
            ip_address=empty_ip,
            geo=GeoLocation(ip=empty_ip, provider="none"),
            intel=NetworkIntel(asn_type=ASNType.UNKNOWN),
            reputation=IPReputation(ip=empty_ip, provider="none"),
        ),
        temporal=TemporalContext.from_utc(utcnow()),
    )

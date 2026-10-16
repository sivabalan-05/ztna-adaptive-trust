"""IP geolocation.

Two implementations behind one interface:

* ``MaxMindGeoIP`` reads a local GeoLite2 ``.mmdb`` file — real data, no network
  calls, so it works in an air-gapped review room.
* ``OfflineGeoIP`` resolves a curated prefix table covering the addresses the
  seeder and the attack demos actually use.

``get_provider()`` picks MaxMind when the database file is present and falls
back to the prefix table otherwise. Both report which one answered, so the UI
can say where a location came from instead of implying more precision than it has.
"""

from __future__ import annotations

import ipaddress
import logging
import threading
import time
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Protocol

from app.core.config import settings
from app.external.base import ProviderInfo

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class GeoLocation:
    ip: str
    country: str = ""            # ISO-3166 alpha-2
    country_name: str = ""
    city: str = ""
    latitude: float | None = None
    longitude: float | None = None
    asn: str = ""
    isp: str = ""
    is_private: bool = False     # RFC1918 / loopback / link-local
    provider: str = "unknown"
    resolved: bool = False       # False when the address could not be placed

    @property
    def has_coordinates(self) -> bool:
        return self.latitude is not None and self.longitude is not None

    @property
    def label(self) -> str:
        if self.is_private:
            return "Private network"
        if not self.resolved:
            return "Unknown location"
        return f"{self.city}, {self.country}" if self.city else self.country


#: Prefix -> location. Covers every address family the seeder and the seven
#: attack demos generate, plus a few well-known hosting ranges.
_PREFIX_TABLE: dict[str, dict[str, object]] = {
    # --- India, residential ISPs (the normal-behaviour baseline) -----------
    "117.192": {
        "country": "IN", "country_name": "India", "city": "Coimbatore",
        "latitude": 11.0168, "longitude": 76.9558,
        "asn": "AS9829", "isp": "Bharat Sanchar Nigam Ltd",
    },
    "106.51": {
        "country": "IN", "country_name": "India", "city": "Chennai",
        "latitude": 13.0827, "longitude": 80.2707,
        "asn": "AS24560", "isp": "Airtel Broadband",
    },
    "49.207": {
        "country": "IN", "country_name": "India", "city": "Bangalore",
        "latitude": 12.9716, "longitude": 77.5946,
        "asn": "AS24309", "isp": "ACT Fibernet",
    },
    "223.184": {
        "country": "IN", "country_name": "India", "city": "Mumbai",
        "latitude": 19.0760, "longitude": 72.8777,
        "asn": "AS55836", "isp": "Reliance Jio",
    },
    # --- Residential networks abroad (credential-theft scenario) ----------
    "5.32": {
        "country": "AE", "country_name": "United Arab Emirates", "city": "Dubai",
        "latitude": 25.2048, "longitude": 55.2708,
        "asn": "AS5384", "isp": "Etisalat",
    },
    "175.139": {
        "country": "MY", "country_name": "Malaysia", "city": "Kuala Lumpur",
        "latitude": 3.1390, "longitude": 101.6869,
        "asn": "AS4788", "isp": "TM Net",
    },
    # --- Locations used by the attack scenarios ---------------------------
    "185.234": {
        "country": "UA", "country_name": "Ukraine", "city": "Kyiv",
        "latitude": 50.4501, "longitude": 30.5234,
        "asn": "AS200000", "isp": "Hosting Ukraine LLC",
    },
    "191.96": {
        "country": "BR", "country_name": "Brazil", "city": "Sao Paulo",
        "latitude": -23.5505, "longitude": -46.6333,
        "asn": "AS262287", "isp": "Datacenter Brasil",
    },
    "197.210": {
        "country": "NG", "country_name": "Nigeria", "city": "Lagos",
        "latitude": 6.5244, "longitude": 3.3792,
        "asn": "AS37282", "isp": "Cloud Exit Node",
    },
    "45.83": {
        "country": "NL", "country_name": "Netherlands", "city": "Amsterdam",
        "latitude": 52.3676, "longitude": 4.9041,
        "asn": "AS9009", "isp": "M247 VPN",
    },
    "159.89": {
        "country": "SG", "country_name": "Singapore", "city": "Singapore",
        "latitude": 1.3521, "longitude": 103.8198,
        "asn": "AS14061", "isp": "DigitalOcean",
    },
    # --- Common hosting ranges, so a demo from a cloud box is recognised ---
    "104.16": {
        "country": "US", "country_name": "United States", "city": "San Francisco",
        "latitude": 37.7749, "longitude": -122.4194,
        "asn": "AS13335", "isp": "Cloudflare",
    },
    "34.72": {
        "country": "US", "country_name": "United States", "city": "Council Bluffs",
        "latitude": 41.2619, "longitude": -95.8608,
        "asn": "AS15169", "isp": "Google Cloud",
    },
}

#: Where a request from the developer's own machine is treated as coming from.
#: Stated explicitly rather than left as a silent (0, 0) that would read as a
#: 6,000 km trip to the Gulf of Guinea in the location trust factor.
LOOPBACK_LOCATION = {
    "country": "IN", "country_name": "India", "city": "Coimbatore",
    "latitude": 11.0168, "longitude": 76.9558,
    "asn": "AS0", "isp": "Local network",
}


def _is_private(ip: str) -> bool:
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return (
        address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_reserved
    )


class GeoIPProvider(Protocol):
    info: ProviderInfo

    def lookup(self, ip: str) -> GeoLocation: ...


class OfflineGeoIP:
    """Prefix-table lookup. No files, no network, deterministic."""

    info = ProviderInfo(
        name="offline-prefix-table",
        live=False,
        detail="Curated prefix table covering the seeded and demo address ranges.",
    )

    def lookup(self, ip: str) -> GeoLocation:
        if not ip:
            return GeoLocation(ip=ip, provider=self.info.name)

        if _is_private(ip):
            return GeoLocation(
                ip=ip, is_private=True, resolved=True,
                provider=self.info.name, **LOOPBACK_LOCATION,
            )

        # Match on the longest prefix first (two octets, then one).
        parts = ip.split(".")
        for width in (2, 1):
            key = ".".join(parts[:width])
            entry = _PREFIX_TABLE.get(key)
            if entry:
                return GeoLocation(
                    ip=ip, resolved=True, provider=self.info.name, **entry  # type: ignore[arg-type]
                )

        return GeoLocation(ip=ip, resolved=False, provider=self.info.name)


class MaxMindGeoIP:
    """GeoLite2 City reader.

    The database is a local file; nothing is sent anywhere. ASN and ISP are only
    populated when the matching GeoLite2-ASN database sits beside the City one.
    """

    def __init__(self, db_path: Path) -> None:
        import geoip2.database

        self._city_reader = geoip2.database.Reader(str(db_path))
        self._asn_reader = None
        asn_path = db_path.with_name("GeoLite2-ASN.mmdb")
        if asn_path.exists():
            self._asn_reader = geoip2.database.Reader(str(asn_path))

        self.info = ProviderInfo(
            name="maxmind-geolite2",
            live=False,   # a local database, not a network call
            detail=f"GeoLite2 City at {db_path.name}"
            + (" with ASN database" if self._asn_reader else ""),
        )
        self._fallback = OfflineGeoIP()

    def lookup(self, ip: str) -> GeoLocation:
        if not ip:
            return GeoLocation(ip=ip, provider=self.info.name)
        if _is_private(ip):
            return GeoLocation(
                ip=ip, is_private=True, resolved=True,
                provider=self.info.name, **LOOPBACK_LOCATION,
            )

        import geoip2.errors

        try:
            record = self._city_reader.city(ip)
        except (geoip2.errors.AddressNotFoundError, ValueError):
            # A public address the database does not know: fall through to the
            # prefix table rather than returning a blank location.
            return self._fallback.lookup(ip)
        except Exception:
            logger.exception("GeoLite2 lookup failed for %s", ip)
            return self._fallback.lookup(ip)

        asn, isp = "", ""
        if self._asn_reader is not None:
            try:
                asn_record = self._asn_reader.asn(ip)
                asn = f"AS{asn_record.autonomous_system_number}"
                isp = asn_record.autonomous_system_organization or ""
            except Exception:  # noqa: BLE001 - ASN is optional enrichment
                pass

        return GeoLocation(
            ip=ip,
            country=record.country.iso_code or "",
            country_name=record.country.name or "",
            city=record.city.name or "",
            latitude=record.location.latitude,
            longitude=record.location.longitude,
            asn=asn,
            isp=isp,
            resolved=True,
            provider=self.info.name,
        )


def _is_public(ip: str) -> bool:
    """True only for a real, globally routable address (never a hostname)."""
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


#: Positive answers are kept a day, failures ten minutes, so a service outage
#: neither hammers the provider nor pins an address as "unknown" for long.
_ONLINE_TTL_OK = 24 * 3600.0
_ONLINE_TTL_FAILED = 600.0
_ONLINE_CACHE_MAX = 4096


class OnlineGeoIP:
    """Resolves public addresses the wrapped provider cannot place.

    The wrapped provider answers first (private ranges, the demo prefix table,
    GeoLite2 when present). Only a public address that is still unresolved is
    looked up through ipwho.is, which needs no key. The address is sent to that
    service, so this is opt-in outside production (see ``geoip_online``). Any
    failure leaves the location unresolved, exactly as before.
    """

    URL = "https://ipwho.is/{ip}"

    def __init__(self, base: GeoIPProvider, timeout: float) -> None:
        self._base = base
        self._timeout = timeout
        self._cache: dict[str, tuple[float, GeoLocation | None]] = {}
        self._lock = threading.Lock()
        self.info = ProviderInfo(
            name=f"{base.info.name}+ipwho.is",
            live=True,
            detail=(
                f"{base.info.detail} Public addresses it cannot place are looked "
                "up through ipwho.is and cached."
            ),
        )

    def lookup(self, ip: str) -> GeoLocation:
        known = self._base.lookup(ip)
        if known.resolved or not _is_public(ip):
            return known
        return self._online(ip) or known

    def _online(self, ip: str) -> GeoLocation | None:
        now = time.monotonic()
        with self._lock:
            cached = self._cache.get(ip)
        if cached is not None and cached[0] > now:
            return cached[1]

        result = self._fetch(ip)
        ttl = _ONLINE_TTL_OK if result is not None else _ONLINE_TTL_FAILED
        with self._lock:
            if len(self._cache) >= _ONLINE_CACHE_MAX:
                self._cache.clear()
            self._cache[ip] = (now + ttl, result)
        return result

    def _fetch(self, ip: str) -> GeoLocation | None:
        import httpx

        try:
            response = httpx.get(self.URL.format(ip=ip), timeout=self._timeout)
            response.raise_for_status()
            data = response.json()
        except Exception as exc:  # noqa: BLE001 - any failure means "unresolved"
            logger.warning("Online geolocation failed for %s: %s", ip, exc)
            return None

        latitude, longitude = data.get("latitude"), data.get("longitude")
        if not data.get("success") or latitude is None or longitude is None:
            return None
        connection = data.get("connection") or {}
        asn = connection.get("asn")
        return GeoLocation(
            ip=ip,
            country=str(data.get("country_code") or ""),
            country_name=str(data.get("country") or ""),
            city=str(data.get("city") or ""),
            latitude=float(latitude),
            longitude=float(longitude),
            asn=f"AS{asn}" if asn else "",
            isp=str(connection.get("isp") or connection.get("org") or ""),
            resolved=True,
            provider="ipwho.is",
        )


@lru_cache(maxsize=1)
def get_provider() -> GeoIPProvider:
    path = Path(settings.geoip_db_path)
    provider: GeoIPProvider | None = None
    if path.exists():
        try:
            provider = MaxMindGeoIP(path)
            logger.info("GeoIP: using %s", provider.info.detail)
        except Exception:
            logger.exception(
                "GeoLite2 database at %s could not be opened; using the offline "
                "prefix table instead.", path,
            )
    else:
        logger.info(
            "No GeoLite2 database at %s; using the offline prefix table.", path
        )
    if provider is None:
        provider = OfflineGeoIP()

    if settings.geoip_online_enabled:
        logger.info("GeoIP: unknown public addresses will be resolved via ipwho.is")
        return OnlineGeoIP(provider, settings.geoip_online_timeout_s)
    return provider


def lookup(ip: str) -> GeoLocation:
    return get_provider().lookup(ip)

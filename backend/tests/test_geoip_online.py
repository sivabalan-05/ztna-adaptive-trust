"""The online geolocation fallback: when it is used, and when it must not be."""

from __future__ import annotations

import httpx
import pytest

from app.core.config import settings
from app.external import geoip
from app.external.geoip import OfflineGeoIP, OnlineGeoIP

# An address that is public but absent from the demo prefix table.
UNKNOWN_PUBLIC = "110.224.91.116"
# In the prefix table (Coimbatore, BSNL), so it must never need the network.
KNOWN_PREFIX = "117.192.4.4"

REPLY = {
    "success": True,
    "country_code": "IN",
    "country": "India",
    "city": "Coimbatore",
    "latitude": 11.0168,
    "longitude": 76.9558,
    "connection": {"asn": 9829, "isp": "Bharat Sanchar Nigam Ltd"},
}


class FakeResponse:
    def __init__(self, payload: dict) -> None:
        self._payload = payload

    def raise_for_status(self) -> None:
        return None

    def json(self) -> dict:
        return self._payload


@pytest.fixture
def calls(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Replace the HTTP call and record every URL that would have been fetched."""
    seen: list[str] = []

    def fake_get(url: str, timeout: float) -> FakeResponse:
        seen.append(url)
        return FakeResponse(REPLY)

    monkeypatch.setattr(httpx, "get", fake_get)
    return seen


def test_unknown_public_address_is_resolved_and_then_cached(calls: list[str]) -> None:
    provider = OnlineGeoIP(OfflineGeoIP(), timeout=1.0)

    first = provider.lookup(UNKNOWN_PUBLIC)
    assert first.resolved
    assert (first.country, first.city) == ("IN", "Coimbatore")
    assert first.asn == "AS9829"
    assert first.provider == "ipwho.is"

    provider.lookup(UNKNOWN_PUBLIC)
    assert len(calls) == 1, "the second lookup must come from the cache"


def test_addresses_the_local_table_knows_never_leave_the_machine(
    calls: list[str],
) -> None:
    provider = OnlineGeoIP(OfflineGeoIP(), timeout=1.0)
    located = provider.lookup(KNOWN_PREFIX)
    assert located.resolved and located.provider == "offline-prefix-table"
    assert calls == []


@pytest.mark.parametrize("address", ["10.0.0.5", "192.168.1.20", "127.0.0.1", "testclient", ""])
def test_private_and_invalid_addresses_are_never_sent(
    calls: list[str], address: str
) -> None:
    OnlineGeoIP(OfflineGeoIP(), timeout=1.0).lookup(address)
    assert calls == []


def test_a_failed_lookup_leaves_the_address_unresolved_and_is_not_retried_at_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    attempts = 0

    def failing_get(url: str, timeout: float) -> FakeResponse:
        nonlocal attempts
        attempts += 1
        raise httpx.ConnectError("service unreachable")

    monkeypatch.setattr(httpx, "get", failing_get)
    provider = OnlineGeoIP(OfflineGeoIP(), timeout=1.0)

    assert provider.lookup(UNKNOWN_PUBLIC).resolved is False
    assert provider.lookup(UNKNOWN_PUBLIC).resolved is False
    assert attempts == 3, "each service is tried once, then the failure is cached"


def test_a_rate_limited_service_falls_back_to_the_next(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Render's shared egress address gets 429 from ipwho.is; ip-api.com answers."""
    request = httpx.Request("GET", "https://ipwho.is/")

    def get(url: str, timeout: float) -> FakeResponse:
        if "ipwho.is" in url:
            raise httpx.HTTPStatusError(
                "429", request=request, response=httpx.Response(429, request=request)
            )
        return FakeResponse(
            {
                "status": "success", "countryCode": "IN", "country": "India",
                "city": "Puducherry", "lat": 11.93, "lon": 79.83,
                "as": "AS9829 National Internet Backbone",
                "isp": "Bharat Sanchar Nigam Ltd",
            }
        )

    monkeypatch.setattr(httpx, "get", get)
    located = OnlineGeoIP(OfflineGeoIP(), timeout=1.0).lookup(UNKNOWN_PUBLIC)

    assert located.resolved
    assert (located.country, located.city, located.asn) == ("IN", "Puducherry", "AS9829")
    assert located.provider == "ip-api.com"


def test_an_unsuccessful_reply_is_treated_as_unresolved(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        httpx, "get", lambda url, timeout: FakeResponse({"success": False})
    )
    assert OnlineGeoIP(OfflineGeoIP(), timeout=1.0).lookup(UNKNOWN_PUBLIC).resolved is False


def test_online_lookup_is_off_outside_production_unless_asked_for(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(settings, "geoip_online", None)

    monkeypatch.setattr(settings, "app_env", "development")
    assert settings.geoip_online_enabled is False

    monkeypatch.setattr(settings, "app_env", "production")
    assert settings.geoip_online_enabled is True

    # An explicit setting always wins over the automatic default.
    monkeypatch.setattr(settings, "geoip_online", False)
    assert settings.geoip_online_enabled is False


def test_get_provider_only_wraps_with_the_online_lookup_when_enabled(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    geoip.get_provider.cache_clear()
    try:
        monkeypatch.setattr(settings, "geoip_online", False)
        assert not isinstance(geoip.get_provider(), OnlineGeoIP)

        geoip.get_provider.cache_clear()
        monkeypatch.setattr(settings, "geoip_online", True)
        assert isinstance(geoip.get_provider(), OnlineGeoIP)
    finally:
        geoip.get_provider.cache_clear()

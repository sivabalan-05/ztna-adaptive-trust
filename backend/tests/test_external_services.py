"""GeoIP, network classification, IP reputation and notification providers."""

from __future__ import annotations

import pytest

from app.external import geoip, ip_reputation, network_intel, notification
from app.external.network_intel import ASNType
from app.models.enums import AlertSeverity


# --- GeoIP -----------------------------------------------------------------

@pytest.mark.parametrize(
    ("ip", "country", "city"),
    [
        ("117.192.4.7", "IN", "Coimbatore"),
        ("106.51.30.9", "IN", "Chennai"),
        ("49.207.11.2", "IN", "Bangalore"),
        ("185.234.9.1", "UA", "Kyiv"),
        ("191.96.4.4", "BR", "Sao Paulo"),
        ("159.89.1.1", "SG", "Singapore"),
    ],
)
def test_seeded_ranges_resolve(ip: str, country: str, city: str) -> None:
    location = geoip.lookup(ip)
    assert location.resolved is True
    assert location.country == country
    assert location.city == city
    assert location.has_coordinates


def test_private_addresses_are_flagged_not_geolocated_to_the_ocean() -> None:
    """(0, 0) would read as a 6,000 km trip in the location trust factor."""
    for ip in ("127.0.0.1", "192.168.1.10", "10.0.0.5", "172.16.4.1"):
        location = geoip.lookup(ip)
        assert location.is_private is True
        assert location.label == "Private network"
        assert location.latitude not in (None, 0.0)


def test_unknown_public_address_is_marked_unresolved_not_guessed() -> None:
    location = geoip.lookup("8.8.8.8")
    assert location.resolved is False
    assert location.country == ""
    assert location.has_coordinates is False


def test_empty_and_malformed_input_does_not_raise() -> None:
    assert geoip.lookup("").resolved is False
    assert geoip.lookup("not-an-ip").resolved is False


def test_provider_reports_itself() -> None:
    info = geoip.get_provider().info
    assert info.name in ("offline-prefix-table", "maxmind-geolite2")
    assert info.live is False, "geolocation must never require a network call"


# --- network classification -------------------------------------------------

def test_residential_isp_is_not_flagged() -> None:
    intel = network_intel.analyse("117.192.4.7", "AS9829", "Bharat Sanchar Nigam Ltd")
    assert intel.asn_type is ASNType.RESIDENTIAL
    assert intel.is_vpn is False
    assert intel.is_datacenter is False
    assert intel.is_anonymised is False


def test_hosting_provider_is_flagged_as_datacenter() -> None:
    intel = network_intel.analyse("159.89.1.1", "AS14061", "DigitalOcean")
    assert intel.asn_type is ASNType.HOSTING
    assert intel.is_datacenter is True
    assert intel.is_vpn is False
    assert any("hosting provider" in r for r in intel.reasons)


def test_vpn_asn_is_flagged() -> None:
    intel = network_intel.analyse("45.83.1.1", "AS9009", "M247")
    assert intel.is_vpn is True
    assert intel.is_proxy is True
    assert intel.is_datacenter is True


def test_known_tor_exit_node_is_flagged() -> None:
    intel = network_intel.analyse("197.210.44.9", "AS37282", "Cloud Exit Node")
    assert intel.is_tor is True
    assert intel.asn_type is ASNType.TOR
    assert intel.is_anonymised is True


def test_operator_name_catches_unlisted_vpn_ranges() -> None:
    intel = network_intel.analyse("203.0.113.9", "AS64999", "SomeCo VPN Services")
    assert intel.is_vpn is True
    assert any("VPN or proxy" in r for r in intel.reasons)


def test_unknown_asn_is_unknown_not_assumed_hostile() -> None:
    intel = network_intel.analyse("203.0.113.1", "AS64500", "Example Telecom")
    assert intel.asn_type is ASNType.UNKNOWN
    assert intel.is_vpn is False
    assert intel.is_datacenter is False


# --- IP reputation ----------------------------------------------------------

def test_clean_address_scores_zero() -> None:
    intel = network_intel.analyse("117.192.4.7", "AS9829", "BSNL")
    result = ip_reputation.LocalReputation().score("117.192.4.7", intel)
    assert result.abuse_confidence == 0
    assert result.is_suspicious is False
    assert result.is_malicious is False


def test_blocklisted_range_scores_high() -> None:
    result = ip_reputation.LocalReputation().score("185.234.9.1")
    assert result.abuse_confidence == 95
    assert result.is_malicious is True
    assert "brute-force" in result.categories


def test_tor_raises_the_baseline_even_without_a_blocklist_hit() -> None:
    intel = network_intel.analyse("198.51.100.7", "AS64500", "Example")
    tor_intel = type(intel)(**{**intel.__dict__, "is_tor": True})
    result = ip_reputation.LocalReputation().score("198.51.100.7", tor_intel)
    assert result.abuse_confidence >= 70


def test_hosting_gets_a_modest_baseline() -> None:
    intel = network_intel.analyse("159.89.1.1", "AS14061", "DigitalOcean")
    result = ip_reputation.LocalReputation().score("159.89.1.1", intel)
    assert 20 <= result.abuse_confidence <= 40


def test_reputation_always_explains_itself() -> None:
    result = ip_reputation.LocalReputation().score("117.192.4.7")
    assert result.reasons, "a score with no reason is not defensible to a reviewer"


def test_scores_are_cached_per_address() -> None:
    first = ip_reputation.score("185.234.9.9")
    second = ip_reputation.score("185.234.9.9")
    assert first.abuse_confidence == second.abuse_confidence
    assert "Cached" in second.reasons[0]


# --- notification -----------------------------------------------------------

def test_console_provider_is_the_offline_default() -> None:
    provider = notification.get_provider()
    assert provider.info.name in ("console", "smtp")


def test_notify_writes_a_system_log_and_never_raises(db) -> None:
    from sqlalchemy import select

    from app.models import SystemLog

    delivered = notification.notify(
        db,
        subject="Impossible travel detected",
        body="Coimbatore to Sao Paulo in 20 minutes.",
        severity=AlertSeverity.CRITICAL,
        context={"user": "ramya.iyer"},
    )
    db.commit()
    assert delivered is True

    row = db.scalar(select(SystemLog).where(SystemLog.logger == "notification"))
    assert row is not None
    assert row.level.value == "CRITICAL"
    assert row.context["user"] == "ramya.iyer"

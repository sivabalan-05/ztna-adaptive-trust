"""VPN, proxy, Tor and datacenter detection.

Classifies the *kind* of network a request arrives from. A residential ISP is
ordinary; a hosting provider, commercial VPN or Tor exit node is not, and the
network trust factor weighs each differently.

Everything is decided from local data — an ASN classification table and an
optional Tor exit-node list on disk — so this works offline. Nothing here is a
verdict on its own: a developer legitimately on a VPN loses points, they are
not blocked.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from enum import StrEnum
from functools import lru_cache
from pathlib import Path

from app.core.config import ROOT_DIR

logger = logging.getLogger(__name__)


class ASNType(StrEnum):
    RESIDENTIAL = "residential"
    BUSINESS = "business"
    MOBILE = "mobile"
    HOSTING = "hosting"
    VPN = "vpn"
    TOR = "tor"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class NetworkIntel:
    asn: str = ""
    asn_type: ASNType = ASNType.UNKNOWN
    is_vpn: bool = False
    is_proxy: bool = False
    is_tor: bool = False
    is_datacenter: bool = False
    reasons: tuple[str, ...] = ()

    @property
    def is_anonymised(self) -> bool:
        return self.is_vpn or self.is_proxy or self.is_tor


#: Autonomous systems that host servers rather than homes. A user session from
#: one of these is either a jump box, a scraper or a proxy — all worth points.
_HOSTING_ASNS: dict[str, str] = {
    "AS14061": "DigitalOcean",
    "AS16509": "Amazon AWS",
    "AS14618": "Amazon AWS",
    "AS15169": "Google Cloud",
    "AS396982": "Google Cloud",
    "AS8075": "Microsoft Azure",
    "AS13335": "Cloudflare",
    "AS20473": "Vultr / Choopa",
    "AS24940": "Hetzner",
    "AS16276": "OVH",
    "AS63949": "Akamai / Linode",
    "AS262287": "Datacenter Brasil",
    "AS200000": "Hosting Ukraine LLC",
}

#: Commercial VPN and anonymising proxy operators.
_VPN_ASNS: dict[str, str] = {
    "AS9009": "M247 (VPN transit)",
    "AS60068": "Datacamp / CDN77 (VPN transit)",
    "AS212238": "Datacamp",
    "AS51852": "Private Layer (VPN)",
    "AS62240": "Clouvider (VPN)",
    "AS37282": "Cloud Exit Node",
}

#: Residential and mobile carriers seen in the seeded Indian corpus.
_RESIDENTIAL_ASNS: dict[str, str] = {
    "AS9829": "BSNL",
    "AS24560": "Airtel Broadband",
    "AS24309": "ACT Fibernet",
    "AS55836": "Reliance Jio",
    "AS45609": "Airtel Mobile",
    "AS38266": "Vodafone Idea",
    "AS5384": "Etisalat",
    "AS4788": "TM Net",
}

_MOBILE_ASNS = {"AS45609", "AS38266"}

#: Tor exit nodes change constantly. A refreshed list can be dropped at
#: data/tor-exit-nodes.txt (one address per line); these few are the ones the
#: demo scripts use, so the scenario works with no list file present.
_BUILTIN_TOR_EXITS = frozenset(
    {"197.210.44.9", "185.234.218.84", "45.83.91.7"}
)

TOR_LIST_PATH = ROOT_DIR / "data" / "tor-exit-nodes.txt"


@lru_cache(maxsize=1)
def _tor_exit_nodes() -> frozenset[str]:
    if not TOR_LIST_PATH.exists():
        return _BUILTIN_TOR_EXITS
    try:
        lines = TOR_LIST_PATH.read_text(encoding="utf-8").splitlines()
    except OSError:
        logger.exception("Could not read the Tor exit-node list at %s", TOR_LIST_PATH)
        return _BUILTIN_TOR_EXITS

    addresses = {
        line.strip() for line in lines
        if line.strip() and not line.lstrip().startswith("#")
    }
    logger.info("Loaded %d Tor exit nodes from %s", len(addresses), TOR_LIST_PATH)
    return frozenset(addresses | _BUILTIN_TOR_EXITS)


def classify_asn(asn: str) -> tuple[ASNType, str]:
    """Map an AS number to what kind of network it operates."""
    if not asn:
        return ASNType.UNKNOWN, ""
    if asn in _VPN_ASNS:
        return ASNType.VPN, _VPN_ASNS[asn]
    if asn in _MOBILE_ASNS:
        return ASNType.MOBILE, _RESIDENTIAL_ASNS.get(asn, "")
    if asn in _RESIDENTIAL_ASNS:
        return ASNType.RESIDENTIAL, _RESIDENTIAL_ASNS[asn]
    if asn in _HOSTING_ASNS:
        return ASNType.HOSTING, _HOSTING_ASNS[asn]
    return ASNType.UNKNOWN, ""


def analyse(ip: str, asn: str = "", isp: str = "") -> NetworkIntel:
    """Classify one address, given whatever the GeoIP layer already resolved."""
    reasons: list[str] = []
    asn_type, operator = classify_asn(asn)

    is_tor = ip in _tor_exit_nodes()
    if is_tor:
        asn_type = ASNType.TOR
        reasons.append("Address is a known Tor exit node.")

    is_vpn = asn_type is ASNType.VPN
    if is_vpn:
        reasons.append(f"ASN {asn} belongs to {operator}, a VPN transit provider.")

    is_datacenter = asn_type in (ASNType.HOSTING, ASNType.VPN, ASNType.TOR)
    if asn_type is ASNType.HOSTING:
        reasons.append(
            f"ASN {asn} belongs to {operator}, a hosting provider rather than a "
            f"residential ISP."
        )

    # An ISP name is a weaker signal than an ASN, but it catches ranges the
    # tables do not list yet.
    lowered = (isp or "").lower()
    if not is_vpn and any(word in lowered for word in ("vpn", "proxy", "anonym")):
        is_vpn = True
        is_datacenter = True
        reasons.append(f"Network operator name '{isp}' indicates a VPN or proxy.")

    is_proxy = is_vpn or is_tor

    if not reasons and asn_type is ASNType.RESIDENTIAL:
        reasons.append(f"Residential ISP ({operator}).")

    return NetworkIntel(
        asn=asn,
        asn_type=asn_type,
        is_vpn=is_vpn,
        is_proxy=is_proxy,
        is_tor=is_tor,
        is_datacenter=is_datacenter,
        reasons=tuple(reasons),
    )

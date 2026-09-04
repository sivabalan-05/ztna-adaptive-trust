"""IP reputation.

``AbuseIPDBReputation`` is used when ``ABUSEIPDB_API_KEY`` is set; otherwise a
local blocklist plus network heuristics answers. The live provider degrades to
the local one on any timeout or error rather than failing the request — a
reputation lookup must never be able to lock a user out of the platform.

Scores are an abuse *confidence* from 0 (clean) to 100 (known malicious), the
same scale AbuseIPDB uses, so the network trust factor reads identically either
way.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Protocol

from app.core.cache import cache
from app.core.config import ROOT_DIR, settings
from app.external.base import ProviderInfo
from app.external.network_intel import ASNType, NetworkIntel

logger = logging.getLogger(__name__)

#: Reputation rarely changes minute to minute; caching keeps a burst of requests
#: from one address to a single lookup.
CACHE_TTL_SECONDS = 900
BLOCKLIST_PATH = ROOT_DIR / "data" / "ip-blocklist.txt"


@dataclass(frozen=True)
class IPReputation:
    ip: str
    abuse_confidence: int = 0        # 0-100
    categories: tuple[str, ...] = ()
    total_reports: int = 0
    provider: str = "unknown"
    reasons: list[str] = field(default_factory=list)

    @property
    def is_malicious(self) -> bool:
        return self.abuse_confidence >= 90

    @property
    def is_suspicious(self) -> bool:
        return self.abuse_confidence >= 40


#: Prefixes seen attacking the seeded corpus, plus the ranges the demo scripts
#: use. A real deployment would sync this from a threat feed.
_BUILTIN_BLOCKLIST: dict[str, tuple[int, tuple[str, ...]]] = {
    "185.234": (95, ("brute-force", "credential-stuffing")),
    "197.210": (88, ("tor-exit", "web-app-attack")),
    "191.96": (76, ("port-scan", "brute-force")),
    "45.83": (64, ("vpn-abuse", "scanning")),
}


@lru_cache(maxsize=1)
def _blocklist() -> dict[str, tuple[int, tuple[str, ...]]]:
    """Built-in entries plus anything in data/ip-blocklist.txt.

    File format, one entry per line:  ``<prefix-or-ip> <score> <category,...>``
    """
    entries = dict(_BUILTIN_BLOCKLIST)
    if not BLOCKLIST_PATH.exists():
        return entries
    try:
        for line in BLOCKLIST_PATH.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split()
            prefix = parts[0]
            score = int(parts[1]) if len(parts) > 1 else 100
            categories = tuple(parts[2].split(",")) if len(parts) > 2 else ("blocklist",)
            entries[prefix] = (max(0, min(100, score)), categories)
        logger.info("Loaded %d blocklist entries from %s", len(entries), BLOCKLIST_PATH)
    except (OSError, ValueError):
        logger.exception("Could not parse the blocklist at %s", BLOCKLIST_PATH)
    return entries


class IPReputationProvider(Protocol):
    info: ProviderInfo

    def score(self, ip: str, intel: NetworkIntel | None = None) -> IPReputation: ...


class LocalReputation:
    """Blocklist match, then heuristics from the network classification."""

    info = ProviderInfo(
        name="local-blocklist",
        live=False,
        detail="Built-in blocklist plus ASN-type heuristics; no network calls.",
    )

    def score(self, ip: str, intel: NetworkIntel | None = None) -> IPReputation:
        if not ip:
            return IPReputation(ip=ip, provider=self.info.name)

        reasons: list[str] = []
        confidence = 0
        categories: tuple[str, ...] = ()

        table = _blocklist()
        parts = ip.split(".")
        for width in (4, 3, 2):
            key = ".".join(parts[:width])
            hit = table.get(key)
            if hit:
                confidence, categories = hit
                reasons.append(
                    f"Address range {key}.* is on the local blocklist "
                    f"({', '.join(categories)})."
                )
                break

        if intel is not None:
            if intel.is_tor and confidence < 70:
                confidence = max(confidence, 70)
                reasons.append("Tor exit nodes carry an elevated baseline score.")
            elif intel.is_vpn and confidence < 35:
                confidence = max(confidence, 35)
                reasons.append("Commercial VPN egress carries a modest baseline score.")
            elif intel.asn_type is ASNType.HOSTING and confidence < 25:
                confidence = max(confidence, 25)
                reasons.append(
                    "Hosting-provider address, unusual for an interactive user session."
                )

        if not reasons:
            reasons.append("No abuse reports and no blocklist match.")

        return IPReputation(
            ip=ip, abuse_confidence=confidence, categories=categories,
            provider=self.info.name, reasons=reasons,
        )


class AbuseIPDBReputation:
    """AbuseIPDB v2 check endpoint, with the local provider as a safety net."""

    def __init__(self, api_key: str) -> None:
        self._api_key = api_key
        self._fallback = LocalReputation()
        self.info = ProviderInfo(
            name="abuseipdb",
            live=True,
            detail="AbuseIPDB v2 /check, 3s timeout, falls back to the local list.",
        )

    def score(self, ip: str, intel: NetworkIntel | None = None) -> IPReputation:
        if not ip:
            return IPReputation(ip=ip, provider=self.info.name)

        import httpx

        try:
            response = httpx.get(
                "https://api.abuseipdb.com/api/v2/check",
                params={"ipAddress": ip, "maxAgeInDays": 90},
                headers={"Key": self._api_key, "Accept": "application/json"},
                timeout=3.0,
            )
            response.raise_for_status()
            data = response.json()["data"]
        except Exception:
            # Never let an external outage decide an access request.
            logger.warning(
                "AbuseIPDB lookup for %s failed; using the local blocklist.", ip,
                exc_info=True,
            )
            local = self._fallback.score(ip, intel)
            local.reasons.append("AbuseIPDB was unreachable; local data used instead.")
            return local

        confidence = int(data.get("abuseConfidenceScore", 0))
        reports = int(data.get("totalReports", 0))
        reasons = [
            f"AbuseIPDB reports {reports} submission(s) with {confidence}/100 "
            f"confidence over the last 90 days."
            if reports
            else "AbuseIPDB has no reports for this address."
        ]
        if data.get("isTor"):
            reasons.append("AbuseIPDB flags this address as a Tor node.")

        return IPReputation(
            ip=ip, abuse_confidence=confidence, total_reports=reports,
            categories=("abuseipdb",) if reports else (),
            provider=self.info.name, reasons=reasons,
        )


@lru_cache(maxsize=1)
def get_provider() -> IPReputationProvider:
    if settings.abuseipdb_api_key:
        logger.info("IP reputation: AbuseIPDB (live)")
        return AbuseIPDBReputation(settings.abuseipdb_api_key)
    logger.info("IP reputation: local blocklist (offline)")
    return LocalReputation()


def score(ip: str, intel: NetworkIntel | None = None) -> IPReputation:
    """Cached reputation lookup."""
    key = f"ipreputation:{ip}"
    cached = cache.get(key)
    provider = get_provider()
    if cached is not None:
        try:
            confidence = int(cached)
        except ValueError:
            confidence = 0
        else:
            return IPReputation(
                ip=ip, abuse_confidence=confidence, provider=provider.info.name,
                reasons=[f"Cached reputation for {ip} ({confidence}/100)."],
            )

    result = provider.score(ip, intel)
    cache.set(key, str(result.abuse_confidence), CACHE_TTL_SECONDS)
    return result

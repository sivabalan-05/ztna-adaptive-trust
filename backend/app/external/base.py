"""Common shape for every external-service adapter.

Each provider is defined as a Protocol with at least one implementation that
works with no network access, so ``docker compose up`` on an offline laptop
still gives a complete demo.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ProviderInfo:
    """Which implementation answered, so the UI can say so honestly."""

    name: str
    live: bool          # True when a real external service was consulted
    detail: str = ""

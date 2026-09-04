"""The chain-of-trust hash primitive.

Kept separate from the audit *service* (which owns the database session and the
insert ordering) so it can be unit-tested and reused by the seed script without
importing the whole application.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any

GENESIS_HASH = "0" * 64


def canonical_json(payload: Any) -> str:
    """Deterministic JSON: sorted keys, no insignificant whitespace.

    Two structurally identical payloads must always hash identically, or chain
    verification would fail on a re-serialisation rather than on tampering.
    """
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)


def hash_payload(payload: Any) -> str:
    return hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()


def canonical_timestamp(value: datetime) -> str:
    """Dialect-independent timestamp rendering for the hash material.

    PostgreSQL returns TIMESTAMPTZ as timezone-aware and SQLite returns the
    same instant as naive, so ``isoformat()`` alone would produce two different
    strings for one stored row and every verification would fail on the
    dialect rather than on tampering.  Everything written is UTC, so a naive
    value is tagged UTC and an aware one is converted to UTC, then rendered in
    a single fixed form.
    """
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    else:
        value = value.astimezone(timezone.utc)
    return value.strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"


def compute_record_hash(
    prev_hash: str,
    timestamp: datetime,
    actor: str,
    action: str,
    payload_hash: str,
) -> str:
    """SHA256(prev_hash + timestamp + actor + action + payload_hash).

    The timestamp is normalised by ``canonical_timestamp`` so that the hash
    does not depend on the database dialect's datetime representation.
    """
    ts = canonical_timestamp(timestamp)
    material = f"{prev_hash}{ts}{actor}{action}{payload_hash}"
    return hashlib.sha256(material.encode("utf-8")).hexdigest()

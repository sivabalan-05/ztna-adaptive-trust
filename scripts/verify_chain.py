#!/usr/bin/env python3
"""Walk the audit hash chain and report whether it has been tampered with.

The same logic is exposed over HTTP as ``GET /api/audit/verify`` in Phase 7;
this script exists so the chain can be checked from the command line, including
before the API is running.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR / "backend"))

from sqlalchemy import select  # noqa: E402

from app.core.database import SessionLocal  # noqa: E402
from app.models import AuditLog  # noqa: E402
from app.services.hash_chain import (  # noqa: E402
    GENESIS_HASH, compute_record_hash, hash_payload,
)


def main() -> int:
    with SessionLocal() as db:
        records = db.scalars(select(AuditLog).order_by(AuditLog.seq)).all()

    if not records:
        print("Audit log is empty; nothing to verify.")
        return 0

    prev = GENESIS_HASH
    for record in records:
        if record.prev_hash != prev:
            print(
                f"BROKEN at record #{record.seq}: prev_hash does not match the "
                f"previous record's hash. A record was altered, inserted or removed."
            )
            return 1
        if hash_payload(record.payload) != record.payload_hash:
            print(f"BROKEN at record #{record.seq}: payload was modified.")
            return 1
        expected = compute_record_hash(
            record.prev_hash, record.timestamp, record.actor_label,
            record.action, record.payload_hash,
        )
        if expected != record.record_hash:
            print(
                f"BROKEN at record #{record.seq}: record hash does not match its "
                f"own contents ({record.action} by {record.actor_label})."
            )
            return 1
        prev = record.record_hash

    print(f"Chain verified: {len(records)} records, unbroken from genesis.")
    print(f"  first record : #{records[0].seq}  {records[0].timestamp.isoformat()}")
    print(f"  last record  : #{records[-1].seq}  {records[-1].timestamp.isoformat()}")
    print(f"  head hash    : {prev}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

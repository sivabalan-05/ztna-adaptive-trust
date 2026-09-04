#!/usr/bin/env python3
"""Scenario 3 — insider threat.

The hardest case, and the one that shows why the weighted sum needs help. Valid
credentials, an approved device, a clean residential network — every factor the
system usually leans on says "fine". Only the *behaviour* is wrong: a burst of
confidential-resource access far outside this account's baseline.

Identity, device, network and location together are worth 75 of the 100 points,
and all four are clean. Behaviour is worth 20. The arithmetic alone cannot put
this session below about 77, which is why mass enumeration is a hard override.
"""

from __future__ import annotations

import sys

from _harness import (
    DemoClient, DEMO_PASSWORD, header, detail, pick_user, require_api,
    score_line, step, verdict,
)


def run() -> bool:
    header(3, "Insider threat", "behaviour anomaly, score decays, session revoked")

    username = pick_user("employee", index=2)
    client = DemoClient(
        device_seed=f"known-laptop-{username}", context="office_coimbatore", host=23
    )

    try:
        step(f"{username} signs in normally — everything about this looks fine.")
        client.sign_in(username, DEMO_PASSWORD)
        start = client.sign_in(username, DEMO_PASSWORD)
        score_line(start.trust_score, start.risk_level, start.action)
        detail("approved device · residential ISP · usual location")

        step("They then start enumerating every resource in the catalogue.")
        catalogue = [r["slug"] for r in client.resources()]
        detail(f"{len(catalogue)} resources visible; opening each in turn")

        trail: list[tuple[int, float, str]] = []
        for index, slug in enumerate(catalogue, start=1):
            status, _ = client.access(slug)
            score, band = client.current_score()
            trail.append((index, score, band))
            if index % 3 == 0 or band == "TERMINATED":
                detail(f"after {index:>2} resources → trust {score:5.1f}  {band}")
            if band == "TERMINATED":
                detail("session terminated mid-enumeration")
                break

        step("Where did it end up?")
        final = client.me()
        detail(f"GET /api/auth/me → HTTP {final.status_code}")
        if final.status_code != 200:
            detail(final.json().get("detail", ""))

        first_score = trail[0][1] if trail else start.trust_score
        last_score = trail[-1][1] if trail else start.trust_score
        decayed = last_score < first_score
        stopped = final.status_code == 401 or trail[-1][2] in ("CRITICAL", "TERMINATED")

        return verdict(
            decayed and stopped,
            f"Credentials, device and network all clean; behaviour alone took "
            f"trust {first_score:.0f} → {last_score:.0f} and ended the session.",
        )
    finally:
        client.close()


if __name__ == "__main__":
    sys.exit(0 if (require_api() and run()) else 1)

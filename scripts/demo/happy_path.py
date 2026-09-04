#!/usr/bin/env python3
"""Scenario 7 — legitimate user, happy path.

Included first in spirit even though it is numbered last: a system that flags
everything is not a security control, it is a nuisance. This is the false
positive story.
"""

from __future__ import annotations

import sys

from _harness import (
    DemoClient, DEMO_PASSWORD, approve_devices_for, header, detail, pick_user,
    require_api, score_line, step, verdict,
)


def run() -> bool:
    header(7, "Legitimate user, happy path", "score stays high, no friction")

    username = pick_user("employee", index=4)
    client = DemoClient(device_seed=f"known-laptop-{username}", context="office_coimbatore", host=27)

    try:
        step(f"{username} signs in from the {client.where} on their usual laptop.")
        detail(f"source {client.ip} · residential ISP · business hours")

        # An established user has an approved device. Register it, have an
        # administrator approve it, then sign in as they would every morning —
        # otherwise this measures a first-day employee on a new laptop, which
        # is a different scenario and legitimately scores lower.
        client.sign_in(username, DEMO_PASSWORD)
        approved = approve_devices_for(username)
        detail(f"{approved} device(s) approved by an administrator")
        session = client.sign_in(username, DEMO_PASSWORD)
        score_line(session.trust_score, session.risk_level, session.action, session.reason)

        step("They open the resources they use every day.")
        opened = []
        for slug in ("public-docs", "hr-portal", "ticketing-system"):
            status, body = client.access(slug)
            opened.append(status == 200)
            detail(f"{slug:<20} HTTP {status}  {body.get('reason', body.get('detail', ''))[:60]}")

        step("The engine re-scores the session.")
        result = client.rescore()
        score_line(result["score"], result["risk_level"], result["action"])
        detail(result["narrative"][:150])

        quiet = result["risk_level"] in ("LOW", "MEDIUM") and all(opened)
        return verdict(
            quiet,
            "Normal work proceeds without a single challenge — the engine stays "
            "quiet on legitimate use."
            if quiet
            else "Expected an unimpeded session; the engine intervened.",
        )
    finally:
        client.close()


if __name__ == "__main__":
    sys.exit(0 if (require_api() and run()) else 1)

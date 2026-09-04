#!/usr/bin/env python3
"""Scenario 6 — lateral movement.

A low-privilege account probing upward through the sensitivity ladder. Each
individual refusal is unremarkable; the *run* of them is the signal, and it
compounds — every denial feeds the behaviour factor, so the score falls as the
probing continues.
"""

from __future__ import annotations

import sys

from _harness import (
    DemoClient, DEMO_PASSWORD, header, detail, pick_user, require_api,
    score_line, step, verdict,
)

LADDER = [
    ("public-docs", "PUBLIC"),
    ("hr-portal", "INTERNAL"),
    ("wiki-engineering", "INTERNAL"),
    ("source-repo", "CONFIDENTIAL"),
    ("crm-database", "CONFIDENTIAL"),
    ("finance-reports", "CONFIDENTIAL"),
    ("payroll-db", "RESTRICTED"),
    ("customer-pii-store", "RESTRICTED"),
    ("prod-secrets-vault", "RESTRICTED"),
]


def run() -> bool:
    header(6, "Lateral movement", "escalating penalties, step-up forced, alert raised")

    username = pick_user("contractor", index=1)
    client = DemoClient(device_seed=f"contractor-box-{username}", context="office_bangalore", host=26)

    try:
        step(f"{username} (contractor — cleared to INTERNAL only) signs in.")
        client.sign_in(username, DEMO_PASSWORD)
        start = client.sign_in(username, DEMO_PASSWORD)
        score_line(start.trust_score, start.risk_level, start.action)

        step("They walk up the sensitivity ladder, one resource at a time.")
        scores: list[float] = []
        denials = 0
        for slug, sensitivity in LADDER:
            status, body = client.access(slug)
            score = float(body.get("trust_score", 0) or 0)
            band = str(body.get("risk_level", "")) or "—"
            gate = body.get("gate", "")
            scores.append(score)
            if status != 200:
                denials += 1
            mark = "allowed" if status == 200 else f"DENIED at the {gate} gate"
            detail(
                f"{slug:<20} {sensitivity:<13} trust {score:5.1f} {band:<9} {mark}"
            )

        step("The pattern, not any single request, is what gives it away.")
        detail(f"{denials} denials · trust {scores[0]:.0f} → {scores[-1]:.0f}")

        escalated = scores[-1] < scores[0] - 10 and denials >= 5
        return verdict(
            escalated,
            f"Each refusal alone is ordinary; {denials} in one session cost "
            f"{scores[0] - scores[-1]:.0f} points and forced re-authentication.",
        )
    finally:
        client.close()


if __name__ == "__main__":
    sys.exit(0 if (require_api() and run()) else 1)

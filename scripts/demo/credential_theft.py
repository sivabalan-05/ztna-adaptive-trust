#!/usr/bin/env python3
"""Scenario 1 — credential theft.

The attacker has the correct password. Everything else about them is wrong: a
machine the account has never used, in a country it has never signed in from.
No single one of those is fatal; together they should cost enough to force a
re-authentication rather than hand over an access token.
"""

from __future__ import annotations

import sys

from _harness import (
    DemoClient, DEMO_PASSWORD, WINDOWS_UA, header, detail, pick_user,
    require_api, score_line, step, verdict,
)


def run() -> bool:
    header(
        1, "Credential theft",
        "score falls to HIGH, step-up MFA required before anything opens",
    )

    username = pick_user("employee", index=0)

    legitimate = DemoClient(
        device_seed=f"known-laptop-{username}", context="office_coimbatore", host=21
    )
    attacker = DemoClient(
        device_seed="attacker-workstation",
        context="home_dubai",
        host=31,
        user_agent=WINDOWS_UA,
        platform="Win32",
        screen="1366x768",
        timezone="Asia/Dubai",
    )

    try:
        step(f"First, {username} establishes their normal pattern.")
        legitimate.sign_in(username, DEMO_PASSWORD)
        baseline = legitimate.sign_in(username, DEMO_PASSWORD)
        score_line(baseline.trust_score, baseline.risk_level, baseline.action)
        detail(f"{legitimate.where} · known device")

        step("The password leaks. Someone else uses it, correctly, from Dubai.")
        detail(f"source {attacker.ip} · {attacker.where} · Windows, never seen before")
        stolen = attacker.sign_in(username, DEMO_PASSWORD)
        score_line(stolen.trust_score, stolen.risk_level, stolen.action, stolen.reason)

        step("What can that session actually reach?")
        blocked = 0
        for slug in ("hr-portal", "source-repo"):
            status, body = attacker.access(slug)
            if status != 200:
                blocked += 1
            detail(f"{slug:<14} HTTP {status}  {body.get('detail', body.get('reason', ''))[:60]}")

        dropped = stolen.trust_score < baseline.trust_score - 15
        challenged = stolen.risk_level in ("HIGH", "CRITICAL")
        return verdict(
            dropped and challenged,
            f"Correct password, wrong everything else: trust fell "
            f"{baseline.trust_score:.0f} → {stolen.trust_score:.0f} "
            f"({stolen.risk_level}), {blocked} resource(s) refused."
            if dropped and challenged
            else "Expected the stolen-credential session to be challenged.",
        )
    finally:
        legitimate.close()
        attacker.close()


if __name__ == "__main__":
    sys.exit(0 if (require_api() and run()) else 1)

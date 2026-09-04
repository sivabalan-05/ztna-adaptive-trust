#!/usr/bin/env python3
"""Scenario 2 — impossible travel.

Two sign-ins minutes apart from cities thousands of kilometres apart. The
weighted sum alone cannot express this: location is worth 10 points. It is a
hard override, because it is not graded risk — it is proof that the two
sessions cannot both be the same person.
"""

from __future__ import annotations

import sys

from _harness import (
    DemoClient, DEMO_PASSWORD, WINDOWS_UA, header, detail, pick_user,
    require_api, score_line, step, verdict,
)


def run() -> bool:
    header(2, "Impossible travel", "CRITICAL, session blocked and revoked")

    username = pick_user("employee", index=1)
    home = DemoClient(device_seed=f"known-laptop-{username}", context="office_coimbatore", host=22)
    abroad = DemoClient(
        device_seed="attacker-brazil",
        context="hosting_brazil",
        host=32,
        user_agent=WINDOWS_UA,
        platform="Win32",
    )

    try:
        step(f"{username} signs in from Coimbatore.")
        home.sign_in(username, DEMO_PASSWORD)
        first = home.sign_in(username, DEMO_PASSWORD)
        score_line(first.trust_score, first.risk_level, first.action)

        step("Moments later, the same account signs in from Sao Paulo.")
        detail(f"source {abroad.ip} · {abroad.where} · ~14,000 km away")
        second = abroad.sign_in(username, DEMO_PASSWORD)
        score_line(second.trust_score, second.risk_level, second.action, second.reason)

        step("The Brazilian session tries to use its token.")
        response = abroad.me()
        detail(f"GET /api/auth/me → HTTP {response.status_code}")
        if response.status_code != 200:
            detail(response.json().get("detail", ""))

        stopped = second.risk_level == "CRITICAL" and response.status_code == 401
        return verdict(
            stopped,
            "Impossible travel overrode the arithmetic: the session was revoked "
            "and its very next request refused.",
        )
    finally:
        home.close()
        abroad.close()


if __name__ == "__main__":
    sys.exit(0 if (require_api() and run()) else 1)

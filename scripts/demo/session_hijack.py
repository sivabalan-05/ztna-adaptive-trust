#!/usr/bin/env python3
"""Scenario 5 — session hijack.

A valid access token is stolen and replayed from another machine on another
network. The token itself is cryptographically perfect — this is precisely the
case a stateless JWT check cannot catch, and precisely why the token carries the
fingerprint it was issued to.
"""

from __future__ import annotations

import sys

from _harness import (
    DemoClient, DEMO_PASSWORD, WINDOWS_UA, header, detail, pick_user,
    require_api, score_line, step, verdict,
)


def run() -> bool:
    header(5, "Session hijack", "context mismatch, token refused immediately")

    username = pick_user("employee", index=3)
    victim = DemoClient(device_seed=f"known-laptop-{username}", context="office_chennai", host=25)

    try:
        step(f"{username} signs in and works normally.")
        victim.sign_in(username, DEMO_PASSWORD)
        session = victim.sign_in(username, DEMO_PASSWORD)
        score_line(session.trust_score, session.risk_level, session.action)
        status, _ = victim.access("public-docs")
        detail(f"opens public-docs → HTTP {status}")

        step("The access token is stolen and replayed from Amsterdam.")
        thief = DemoClient(
            device_seed="thief-machine",
            context="vpn_amsterdam",
            host=35,
            user_agent=WINDOWS_UA,
            platform="Win32",
        )
        thief.session = session          # the same, entirely valid, token
        detail(f"identical bearer token · {thief.where} · different fingerprint")

        replay = thief.me()
        detail(f"GET /api/auth/me → HTTP {replay.status_code}")
        if replay.status_code != 200:
            detail(replay.json().get("detail", ""))

        step("Meanwhile the real user is unaffected.")
        original = victim.me()
        detail(f"victim's own request → HTTP {original.status_code}")

        caught = replay.status_code == 401 and original.status_code == 200
        thief.close()
        return verdict(
            caught,
            "The token was valid and still refused: it is bound to the device it "
            "was issued to, and the real user kept working.",
        )
    finally:
        victim.close()


if __name__ == "__main__":
    sys.exit(0 if (require_api() and run()) else 1)

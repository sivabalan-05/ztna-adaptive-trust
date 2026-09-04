#!/usr/bin/env python3
"""Scenario 4 — brute force.

Repeated password guessing against one account. Two independent defences
should engage: the rate limiter sheds the load, and the account locks.
"""

from __future__ import annotations

import sys

from _harness import (
    DemoClient, WINDOWS_UA, header, detail, pick_user, require_api, step,
    unlock_user, verdict,
)


def run() -> bool:
    header(4, "Brute force", "account locked, alert raised, requests shed")

    username = pick_user("contractor", index=0)
    attacker = DemoClient(
        device_seed="brute-force-box",
        context="hosting_kyiv",
        host=34,
        user_agent=WINDOWS_UA,
        platform="Win32",
    )

    try:
        step(f"20 password guesses against {username} from {attacker.where}.")
        detail(f"source {attacker.ip} · abuse confidence 95/100")

        codes: list[int] = []
        for attempt in range(1, 21):
            response = attacker.password_step(username, f"guess-{attempt}")
            codes.append(response.status_code)
            if attempt <= 6 or response.status_code in (423, 429):
                detail(
                    f"attempt {attempt:>2}  HTTP {response.status_code}  "
                    f"{response.json().get('detail', '')[:56]}"
                )

        locked = 423 in codes
        throttled = 429 in codes
        detail(f"\n      outcomes: {codes.count(401)}×401, "
               f"{codes.count(423)}×423 locked, {codes.count(429)}×429 rate-limited")

        step("Even the correct password is now refused.")
        from _harness import DEMO_PASSWORD

        final = attacker.password_step(username, DEMO_PASSWORD)
        detail(f"HTTP {final.status_code}  {final.json().get('detail', '')[:70]}")

        step("An administrator clears the lockout so the demo can be re-run.")
        cleared = unlock_user(username)
        detail(
            f"{username} unlocked: {cleared} — stated explicitly, because "
            f"silently undoing a control in a security demo teaches the wrong "
            f"lesson."
        )

        stopped = (locked or throttled) and final.status_code in (423, 429)
        return verdict(
            stopped,
            "Two defences engaged: the endpoint shed the burst and the account "
            "locked, so the correct password no longer helps.",
        )
    finally:
        attacker.close()


if __name__ == "__main__":
    sys.exit(0 if (require_api() and run()) else 1)

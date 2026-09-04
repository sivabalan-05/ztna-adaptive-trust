#!/usr/bin/env python3
"""Run every attack demonstration in order and report the results.

    python scripts/demo/run_all.py

Each scenario drives the live API. Watch the dashboard's Live Monitoring page
while this runs — the scores move there as the scripts execute.
"""

from __future__ import annotations

import importlib
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from _harness import BOLD, GREEN, RED, RESET, require_api  # noqa: E402

SCENARIOS = [
    ("credential_theft", "Credential theft"),
    ("impossible_travel", "Impossible travel"),
    ("insider_threat", "Insider threat"),
    ("brute_force", "Brute force"),
    ("session_hijack", "Session hijack"),
    ("lateral_movement", "Lateral movement"),
    ("happy_path", "Legitimate user"),
]


def main() -> int:
    if not require_api():
        return 1

    results: list[tuple[str, bool]] = []
    for module_name, title in SCENARIOS:
        module = importlib.import_module(module_name)
        try:
            passed = bool(module.run())
        except Exception as error:      # noqa: BLE001 - report, never abort the run
            print(f"\n  {RED}{title} raised: {error}{RESET}")
            passed = False
        results.append((title, passed))
        time.sleep(1)

    print()
    print("=" * 78)
    print(f"  {BOLD}SUMMARY{RESET}")
    print("=" * 78)
    for title, passed in results:
        mark = f"{GREEN}PASS{RESET}" if passed else f"{RED}FAIL{RESET}"
        print(f"  [{mark}]  {title}")

    failed = [t for t, ok in results if not ok]
    print()
    if failed:
        print(f"  {RED}{len(failed)} of {len(results)} scenarios did not behave as expected.{RESET}")
        return 1
    print(f"  {GREEN}All {len(results)} scenarios behaved as the specification requires.{RESET}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

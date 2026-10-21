"""Naming the operating system a client signs in from."""

from __future__ import annotations

import pytest

from app.services.device_service import parse_os

DESKTOP_LINUX_UA = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/155.0.0.0 Safari/537.36"
)
ANDROID_UA = (
    "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/154.0.0.0 Mobile Safari/537.36"
)


def test_android_user_agent_is_android() -> None:
    assert parse_os(ANDROID_UA, "Linux armv81") == "Android 10"


@pytest.mark.parametrize("platform", ["Linux armv81", "Linux armv8l", "Linux aarch64"])
def test_desktop_site_mode_on_an_android_phone_is_still_android(platform: str) -> None:
    """Chrome's "Desktop site" sends a desktop Linux UA; the ARM platform gives it away."""
    assert parse_os(DESKTOP_LINUX_UA, platform) == "Android"


@pytest.mark.parametrize("platform", ["Linux x86_64", "", "unknown"])
def test_a_real_linux_desktop_stays_linux(platform: str) -> None:
    assert parse_os(DESKTOP_LINUX_UA, platform) == "Linux"

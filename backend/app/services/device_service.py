"""Device registration with trust-on-first-use plus administrator approval.

An unrecognised fingerprint is *registered*, not blocked: Zero Trust treats it
as a risk signal that the scoring engine weighs, rather than a gate that keeps
a legitimate user out of a new laptop. The device lands in ``PENDING`` until an
administrator approves it, and the device trust factor penalises both the
unknown fingerprint and the pending state.
"""

from __future__ import annotations

import re
import uuid
from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.base import utcnow
from app.models.device import Device
from app.models.enums import DeviceStatus
from app.models.user import User

#: A device stops being "brand new" once it has been used this many times from
#: consistent context. Until then the scoring engine keeps a small penalty on it.
TRUSTED_AFTER_SIGHTINGS = 5

_BROWSERS: list[tuple[str, str]] = [
    (r"Edg/([\d.]+)", "Edge"),
    (r"OPR/([\d.]+)", "Opera"),
    (r"Firefox/([\d.]+)", "Firefox"),
    (r"Chrome/([\d.]+)", "Chrome"),
    (r"Version/([\d.]+).*Safari", "Safari"),
]

_PLATFORMS: list[tuple[str, str]] = [
    (r"Windows NT 10\.0", "Windows 10/11"),
    (r"Windows NT", "Windows"),
    (r"Mac OS X", "macOS"),
    (r"CrOS", "ChromeOS"),
    (r"Android ([\d.]+)", "Android"),
    (r"(iPhone|iPad|iPod)", "iOS"),
    (r"Ubuntu", "Ubuntu"),
    (r"Linux", "Linux"),
]


@dataclass(frozen=True)
class DeviceContext:
    """What the client reported about itself on this request."""

    fingerprint: str
    user_agent: str = ""
    platform: str = ""
    screen_resolution: str = ""
    timezone: str = ""
    language: str = ""


def parse_browser(user_agent: str) -> str:
    for pattern, name in _BROWSERS:
        match = re.search(pattern, user_agent)
        if match:
            return f"{name} {match.group(1).split('.')[0]}"
    return "Unknown browser"


def parse_os(user_agent: str) -> str:
    for pattern, name in _PLATFORMS:
        match = re.search(pattern, user_agent)
        if match:
            groups = match.groups()
            if groups and groups[0] and groups[0][0].isdigit():
                return f"{name} {groups[0]}"
            return name
    return "Unknown OS"


@dataclass(frozen=True)
class DeviceResolution:
    device: Device
    is_new: bool
    #: True when the stored OS/browser no longer match what the client reports,
    #: which is a fingerprint-reuse signal for the device trust factor.
    consistent: bool


class DeviceService:
    @staticmethod
    def get_by_fingerprint(
        db: Session, user_id: uuid.UUID, fingerprint: str
    ) -> Device | None:
        return db.scalar(
            select(Device).where(
                Device.user_id == user_id, Device.fingerprint == fingerprint
            )
        )

    @classmethod
    def register_or_touch(
        cls, db: Session, user: User, context: DeviceContext
    ) -> DeviceResolution:
        """Look up the fingerprint, creating it on first sight."""
        now = utcnow()
        device = cls.get_by_fingerprint(db, user.id, context.fingerprint)

        observed_os = parse_os(context.user_agent)
        observed_browser = parse_browser(context.user_agent)

        if device is None:
            device = Device(
                user_id=user.id,
                fingerprint=context.fingerprint,
                label=f"{observed_os} / {observed_browser}",
                status=DeviceStatus.PENDING,
                os=observed_os,
                browser=observed_browser,
                platform=context.platform,
                screen_resolution=context.screen_resolution,
                device_timezone=context.timezone,
                language=context.language,
                user_agent=context.user_agent,
                first_seen_at=now,
                last_seen_at=now,
                seen_count=1,
                is_trusted=False,
            )
            db.add(device)
            db.flush()
            return DeviceResolution(device=device, is_new=True, consistent=True)

        consistent = (
            device.os == observed_os and device.browser == observed_browser
        ) or not context.user_agent

        device.last_seen_at = now
        device.seen_count += 1
        if (
            device.status is DeviceStatus.APPROVED
            and device.seen_count >= TRUSTED_AFTER_SIGHTINGS
            and consistent
        ):
            device.is_trusted = True
        db.flush()
        return DeviceResolution(device=device, is_new=False, consistent=consistent)

    @staticmethod
    def approve(db: Session, device: Device, approver: User) -> Device:
        device.status = DeviceStatus.APPROVED
        device.approved_at = utcnow()
        device.approved_by_id = approver.id
        device.revoked_at = None
        db.flush()
        return device

    @staticmethod
    def revoke(db: Session, device: Device) -> Device:
        device.status = DeviceStatus.REVOKED
        device.is_trusted = False
        device.revoked_at = utcnow()
        db.flush()
        return device

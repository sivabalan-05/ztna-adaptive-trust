"""TOTP multi-factor authentication.

RFC 6238 time-based one-time passwords via ``pyotp``, with a provisioning URI
and an inline SVG QR code for Google Authenticator / Authy enrolment. No network
access is involved at any point, so MFA works in an air-gapped review room.
"""

from __future__ import annotations

import base64
import io

import pyotp
import qrcode
import qrcode.image.svg

from app.core.config import settings

#: How many 30-second steps either side of now are accepted. One step tolerates
#: ordinary clock drift; more than that meaningfully widens the replay window.
TOTP_VALID_WINDOW = 1
TOTP_INTERVAL_SECONDS = 30
TOTP_DIGITS = 6


def generate_secret() -> str:
    """A fresh base32 shared secret for a new enrolment."""
    return pyotp.random_base32()


def _totp(secret: str) -> pyotp.TOTP:
    return pyotp.TOTP(secret, digits=TOTP_DIGITS, interval=TOTP_INTERVAL_SECONDS)


def provisioning_uri(secret: str, username: str) -> str:
    """``otpauth://`` URI that an authenticator app can import."""
    return _totp(secret).provisioning_uri(
        name=username, issuer_name=settings.mfa_issuer
    )


def verify_code(secret: str, code: str) -> bool:
    """Verify a 6-digit code against the shared secret.

    ``pyotp`` compares in constant time. Non-numeric or wrong-length input is
    rejected before that, so a malformed code cannot raise.
    """
    cleaned = (code or "").strip().replace(" ", "")
    if len(cleaned) != TOTP_DIGITS or not cleaned.isdigit():
        return False
    return _totp(secret).verify(cleaned, valid_window=TOTP_VALID_WINDOW)


def current_code(secret: str) -> str:
    """The code an authenticator app would be showing right now.

    Used by the automated tests and the Phase 10 demo scripts so they can drive
    a real MFA challenge without a phone.
    """
    return _totp(secret).now()


def qr_code_svg(secret: str, username: str) -> str:
    """Enrolment QR as an SVG string, safe to inline in the page."""
    factory = qrcode.image.svg.SvgPathImage
    image = qrcode.make(provisioning_uri(secret, username), image_factory=factory)
    buffer = io.BytesIO()
    image.save(buffer)
    return buffer.getvalue().decode("utf-8")


def qr_code_data_uri(secret: str, username: str) -> str:
    """The same QR as a ``data:`` URI, for use in an ``<img src>``."""
    svg = qr_code_svg(secret, username)
    encoded = base64.b64encode(svg.encode("utf-8")).decode("ascii")
    return f"data:image/svg+xml;base64,{encoded}"

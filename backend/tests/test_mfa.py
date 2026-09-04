"""TOTP generation and verification."""

from __future__ import annotations

import pytest

from app.external import mfa


@pytest.fixture
def secret() -> str:
    return mfa.generate_secret()


def test_current_code_verifies(secret: str) -> None:
    assert mfa.verify_code(secret, mfa.current_code(secret)) is True


def test_code_from_a_different_secret_fails(secret: str) -> None:
    other = mfa.generate_secret()
    assert mfa.verify_code(secret, mfa.current_code(other)) is False


@pytest.mark.parametrize("bad", ["", "12345", "1234567", "abcdef", "12 34 56 78"])
def test_malformed_codes_are_rejected_without_raising(secret: str, bad: str) -> None:
    assert mfa.verify_code(secret, bad) is False


def test_whitespace_in_a_valid_code_is_tolerated(secret: str) -> None:
    code = mfa.current_code(secret)
    assert mfa.verify_code(secret, f" {code[:3]} {code[3:]} ") is True


def test_provisioning_uri_carries_issuer_and_account(secret: str) -> None:
    uri = mfa.provisioning_uri(secret, "ramya.iyer")
    assert uri.startswith("otpauth://totp/")
    assert "ramya.iyer" in uri
    assert "issuer=" in uri


def test_qr_code_is_an_svg_data_uri(secret: str) -> None:
    data_uri = mfa.qr_code_data_uri(secret, "ramya.iyer")
    assert data_uri.startswith("data:image/svg+xml;base64,")
    assert len(data_uri) > 500

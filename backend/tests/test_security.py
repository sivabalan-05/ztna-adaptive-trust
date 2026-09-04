"""Password hashing and strength estimation."""

from __future__ import annotations

import pytest

from app.core.security import (
    estimate_password_strength, hash_password, needs_rehash, verify_password,
)


def test_hash_is_argon2id_and_salted() -> None:
    first = hash_password("Correct-Horse-Battery-7!")
    second = hash_password("Correct-Horse-Battery-7!")
    assert first.startswith("$argon2id$")
    assert first != second, "identical passwords must not produce identical hashes"


def test_verify_accepts_correct_and_rejects_wrong() -> None:
    hashed = hash_password("Correct-Horse-Battery-7!")
    assert verify_password("Correct-Horse-Battery-7!", hashed) is True
    assert verify_password("correct-horse-battery-7!", hashed) is False
    assert verify_password("", hashed) is False


def test_verify_never_raises_on_garbage_hash() -> None:
    assert verify_password("anything", "not-a-hash") is False
    assert needs_rehash("not-a-hash") is True


def test_empty_password_is_rejected_at_hash_time() -> None:
    with pytest.raises(ValueError):
        hash_password("")


@pytest.mark.parametrize(
    ("password", "ceiling"),
    [("password", 10), ("admin123", 10), ("abc12345", 45), ("aaaaaaaa", 40)],
)
def test_weak_passwords_score_low(password: str, ceiling: int) -> None:
    assert estimate_password_strength(password) <= ceiling


def test_strong_passphrase_scores_high() -> None:
    assert estimate_password_strength("Tr0ub4dor&3-Coimbatore-Winter") >= 70


def test_strength_is_bounded() -> None:
    assert estimate_password_strength("") == 0
    assert 0 <= estimate_password_strength("x" * 200) <= 100

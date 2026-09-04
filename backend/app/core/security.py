"""Password hashing and strength estimation.

Argon2id is used directly (via ``argon2-cffi``) rather than through a wrapper,
so there is exactly one hashing path and no silent fallback to a weaker scheme.
"""

from __future__ import annotations

import math
import re
import string

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

# OWASP-recommended Argon2id parameters (2 iterations, 64 MiB, 4 lanes).
_hasher = PasswordHasher(
    time_cost=2, memory_cost=65536, parallelism=4, hash_len=32, salt_len=16
)

_COMMON_PASSWORDS = frozenset(
    {
        "password", "password1", "123456", "12345678", "qwerty", "abc123",
        "letmein", "welcome", "admin", "admin123", "iloveyou", "monkey",
        "dragon", "football", "india123", "password123", "changeme",
    }
)


def hash_password(password: str) -> str:
    """Return an Argon2id hash string (algorithm + params + salt + digest)."""
    if not password:
        raise ValueError("Password must not be empty")
    return _hasher.hash(password)


def verify_password(password: str, hashed: str) -> bool:
    """Constant-time verification; never raises on a wrong password."""
    try:
        return _hasher.verify(hashed, password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def needs_rehash(hashed: str) -> bool:
    """True when the stored hash used weaker parameters than the current policy."""
    try:
        return _hasher.check_needs_rehash(hashed)
    except InvalidHashError:
        return True


def estimate_password_strength(password: str) -> int:
    """Score a password 0-100.

    Shannon entropy over the character classes actually used, penalised for
    known-common passwords and for long single-character runs.  The result is
    stored on the user (never the password) and feeds the identity factor.
    """
    if not password:
        return 0
    lowered = password.lower()
    if lowered in _COMMON_PASSWORDS:
        return 5

    # A dictionary word with digits or punctuation bolted on is the word, not a
    # passphrase: "password1234" must not out-score a real 12-character secret
    # simply because it is long enough.
    stem = lowered.rstrip("0123456789!@#$%^&*._-")
    if stem and stem != lowered and stem in _COMMON_PASSWORDS:
        return 10

    pool = 0
    if any(c in string.ascii_lowercase for c in password):
        pool += 26
    if any(c in string.ascii_uppercase for c in password):
        pool += 26
    if any(c in string.digits for c in password):
        pool += 10
    if any(c in string.punctuation for c in password):
        pool += len(string.punctuation)
    if any(c not in string.printable for c in password):
        pool += 100

    entropy_bits = len(password) * math.log2(pool) if pool else 0.0
    score = min(100.0, entropy_bits / 80.0 * 100.0)

    # Penalise obvious repetition and simple sequences.
    if re.search(r"(.)\1{2,}", password):
        score -= 15
    if re.search(r"(012|123|234|345|456|567|678|789|abc|qwe)", password.lower()):
        score -= 15

    return max(0, min(100, int(round(score))))

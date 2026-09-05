"""Enumerations shared by the ORM models, the scoring engine and the API.

Stored as VARCHAR with a CHECK constraint (``native_enum=False``) rather than a
PostgreSQL ENUM type, so migrations behave identically on SQLite.
"""

from __future__ import annotations

from enum import StrEnum


class AccountStatus(StrEnum):
    ACTIVE = "ACTIVE"
    LOCKED = "LOCKED"
    DISABLED = "DISABLED"
    PENDING = "PENDING"


class DeviceStatus(StrEnum):
    PENDING = "PENDING"      # seen, awaiting admin approval
    APPROVED = "APPROVED"
    REVOKED = "REVOKED"


class SessionStatus(StrEnum):
    ACTIVE = "ACTIVE"
    EXPIRED = "EXPIRED"
    REVOKED = "REVOKED"      # killed by an admin or by the scoring engine
    LOGGED_OUT = "LOGGED_OUT"


class RiskLevel(StrEnum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class AccessAction(StrEnum):
    """What the policy engine decided to do."""

    ALLOW = "ALLOW"
    ALLOW_LIMITED = "ALLOW_LIMITED"
    STEP_UP_MFA = "STEP_UP_MFA"
    BLOCK = "BLOCK"
    REVOKE_SESSION = "REVOKE_SESSION"


class Sensitivity(StrEnum):
    PUBLIC = "PUBLIC"
    INTERNAL = "INTERNAL"
    CONFIDENTIAL = "CONFIDENTIAL"
    RESTRICTED = "RESTRICTED"


#: Minimum trust score required to touch a resource of each sensitivity.
SENSITIVITY_MIN_TRUST: dict[Sensitivity, int] = {
    Sensitivity.PUBLIC: 0,
    Sensitivity.INTERNAL: 60,
    Sensitivity.CONFIDENTIAL: 75,
    Sensitivity.RESTRICTED: 90,
}

#: Ordering, so a role's clearance ceiling can be compared to a resource.
SENSITIVITY_ORDINAL: dict[Sensitivity, int] = {
    Sensitivity.PUBLIC: 0,
    Sensitivity.INTERNAL: 1,
    Sensitivity.CONFIDENTIAL: 2,
    Sensitivity.RESTRICTED: 3,
}


def sensitivity_at_or_below(ordinal: int) -> set[Sensitivity]:
    """Every sensitivity a clearance of ``ordinal`` permits."""
    return {s for s, o in SENSITIVITY_ORDINAL.items() if o <= ordinal}


class PolicyEffect(StrEnum):
    ALLOW = "ALLOW"
    DENY = "DENY"


class AlertSeverity(StrEnum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class AlertStatus(StrEnum):
    OPEN = "OPEN"
    ACKNOWLEDGED = "ACKNOWLEDGED"
    RESOLVED = "RESOLVED"


class TrustFactorName(StrEnum):
    IDENTITY = "identity"
    DEVICE = "device"
    NETWORK = "network"
    BEHAVIOR = "behavior"
    LOCATION = "location"
    TEMPORAL = "temporal"


class ScoreTrigger(StrEnum):
    """Why a trust score was (re)calculated."""

    LOGIN = "LOGIN"
    PERIODIC = "PERIODIC"            # the 30s continuous-verification sweep
    CONTEXT_CHANGE = "CONTEXT_CHANGE"
    ACCESS_REQUEST = "ACCESS_REQUEST"
    STEP_UP = "STEP_UP"
    ADMIN = "ADMIN"


class LogLevel(StrEnum):
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"

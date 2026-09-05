"""ORM models.

Importing this package registers every table on ``Base.metadata``, which is
what Alembic's autogenerate and ``scripts/seed.py`` rely on.
"""

from app.core.database import Base
from app.models.access_request import AccessRequest
from app.models.alert import Alert
from app.models.audit_log import GENESIS_HASH, AuditLog
from app.models.behavior_profile import BehaviorProfile
from app.models.device import Device
from app.models.policy import Policy
from app.models.resource import Resource
from app.models.role import Role
from app.models.session import UserSession
from app.models.system_log import SystemLog
from app.models.trust_score import TrustScore
from app.models.user import User

__all__ = [
    "AccessRequest",
    "Alert",
    "AuditLog",
    "Base",
    "BehaviorProfile",
    "Device",
    "GENESIS_HASH",
    "Policy",
    "Resource",
    "Role",
    "SystemLog",
    "TrustScore",
    "User",
    "UserSession",
]

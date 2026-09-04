"""Request and response models for the authentication API."""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator

from app.schemas.common import ORMModel


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=255,
                          description="Username or email address")
    password: str = Field(min_length=1, max_length=256)

    @field_validator("username")
    @classmethod
    def _normalise(cls, value: str) -> str:
        return value.strip().lower()


class LoginChallengeResponse(BaseModel):
    """Password accepted. No access is granted until MFA succeeds."""

    mfa_required: bool = True
    mfa_token: str = Field(description="Short-lived token for /auth/mfa/verify")
    expires_in: int = Field(description="Seconds until the MFA token expires")
    session_id: uuid.UUID
    device_known: bool = Field(description="False when this fingerprint is new")
    device_status: str


class MFAVerifyRequest(BaseModel):
    mfa_token: str = Field(min_length=10)
    code: str = Field(min_length=6, max_length=6,
                      description="6-digit TOTP code")


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int
    session_id: uuid.UUID
    username: str | None = None
    full_name: str | None = None
    role: str | None = None
    is_admin: bool | None = None
    permissions: list[str] | None = None
    device_status: str | None = None
    device_approved: bool | None = None
    trust_score: float | None = None
    risk_level: str | None = None
    action: str | None = None
    trust_reason: str | None = None


class RefreshRequest(BaseModel):
    refresh_token: str = Field(min_length=10)


class RefreshResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int
    session_id: uuid.UUID


class RegisterRequest(BaseModel):
    username: str = Field(min_length=3, max_length=64, pattern=r"^[a-z0-9._-]+$")
    email: EmailStr
    full_name: str = Field(min_length=1, max_length=128)
    password: str = Field(min_length=12, max_length=256)
    role: str = Field(default="employee",
                      description="admin | security_analyst | employee | contractor")
    department: str = Field(default="", max_length=64)
    home_city: str = Field(default="Coimbatore", max_length=64)


class MFAEnrolmentResponse(BaseModel):
    """Returned once, at enrolment. The secret is not retrievable afterwards."""

    secret: str
    provisioning_uri: str
    qr_code_svg_data_uri: str
    issuer: str
    digits: int
    interval_seconds: int


class MFAConfirmRequest(BaseModel):
    code: str = Field(min_length=6, max_length=6)


class DeviceOut(ORMModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    label: str
    fingerprint: str
    status: str
    os: str
    browser: str
    is_trusted: bool
    seen_count: int
    first_seen_at: datetime
    last_seen_at: datetime
    approved_at: datetime | None = None


class SessionOut(ORMModel):
    id: uuid.UUID
    status: str
    ip_address: str
    city: str
    country: str
    started_at: datetime
    last_seen_at: datetime
    expires_at: datetime
    mfa_passed: bool
    step_up_required: bool
    current_trust_score: float
    current_risk_level: str
    current_action: str
    request_count: int
    revoked_reason: str


class UserSummary(BaseModel):
    """A user without any session context — what registration returns."""

    id: uuid.UUID
    username: str
    email: str
    full_name: str
    department: str
    role: str
    is_admin: bool
    permissions: list[str]
    mfa_enabled: bool
    mfa_enrolled: bool = Field(
        description="False until the user completes /auth/mfa/confirm"
    )
    account_status: str
    home_city: str
    home_country: str


class MeResponse(BaseModel):
    id: uuid.UUID
    username: str
    email: str
    full_name: str
    department: str
    role: str
    is_admin: bool
    permissions: list[str]
    mfa_enabled: bool
    account_status: str
    last_login_at: datetime | None
    home_city: str
    home_country: str
    session: SessionOut
    device: DeviceOut | None

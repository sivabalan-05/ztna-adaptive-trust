"""Authentication router: login, MFA, token lifecycle, enrolment, identity."""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core import rate_limit
from app.core.config import settings
from app.core.database import get_db
from app.core.dependencies import (
    Principal, get_principal, get_request_context, require_admin,
)
from app.core.security import estimate_password_strength, hash_password
from app.external import mfa
from app.models.base import utcnow
from app.models.role import Role
from app.models.user import User
from app.schemas.auth import (
    DeviceOut, LoginChallengeResponse, LoginRequest, MeResponse,
    MFAConfirmRequest, MFAEnrolmentResponse, MFAVerifyRequest, RefreshRequest,
    RefreshResponse, RegisterRequest, SessionOut, TokenResponse, UserSummary,
)
from app.services.audit_service import AuditService
from app.services.auth_service import AuthError, AuthService, RequestContext

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/auth", tags=["authentication"])

#: Minimum acceptable strength for a new password, on the 0-100 scale in
#: app.core.security. Rejecting weak passwords at the door is cheaper than
#: penalising them forever through the identity trust factor.
MIN_PASSWORD_STRENGTH = 45


def _guard(bucket: str, identity: str, rule: rate_limit.RateLimit) -> None:
    try:
        rate_limit.check(bucket, identity or "anonymous", rule)
    except rate_limit.RateLimitExceeded as exc:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many attempts. Please wait before trying again.",
            headers={"Retry-After": str(exc.retry_after)},
        ) from exc


def _auth_error(exc: AuthError) -> HTTPException:
    return HTTPException(
        status_code=exc.status_code,
        detail=exc.message,
        headers={"WWW-Authenticate": f'Bearer error="{exc.code}"'}
        if exc.status_code == 401
        else None,
    )


@router.post(
    "/login",
    response_model=LoginChallengeResponse,
    summary="Step 1 — verify the password",
    responses={
        401: {"description": "Invalid credentials"},
        423: {"description": "Account locked"},
        429: {"description": "Rate limited"},
    },
)
def login(
    payload: LoginRequest,
    request: Request,
    db: Session = Depends(get_db),
    context: RequestContext = Depends(get_request_context),
) -> LoginChallengeResponse:
    """Verify username and password, register the device, and issue an MFA challenge.

    A correct password alone grants nothing: the response carries a five-minute
    MFA token, not an access token.
    """
    _guard("login", context.ip_address, rate_limit.LOGIN_LIMIT)
    _guard("login-user", payload.username, rate_limit.LOGIN_LIMIT)

    try:
        challenge = AuthService.login(db, payload.username, payload.password, context)
    except AuthError as exc:
        db.commit()   # persist failure counters, lockouts and audit records
        raise _auth_error(exc) from exc

    return LoginChallengeResponse(
        mfa_required=challenge.mfa_required,
        mfa_token=challenge.mfa_token,
        expires_in=challenge.expires_in,
        session_id=challenge.session_id,
        device_known=challenge.device_known,
        device_status=challenge.device_status,
    )


@router.post(
    "/mfa/verify",
    response_model=TokenResponse,
    summary="Step 2 — verify the TOTP code and issue tokens",
)
def verify_mfa(
    payload: MFAVerifyRequest,
    db: Session = Depends(get_db),
    context: RequestContext = Depends(get_request_context),
) -> TokenResponse:
    _guard("mfa", context.ip_address, rate_limit.MFA_LIMIT)
    try:
        tokens = AuthService.verify_mfa(db, payload.mfa_token, payload.code, context)
    except AuthError as exc:
        db.commit()
        raise _auth_error(exc) from exc

    return TokenResponse(
        access_token=tokens.access_token,
        refresh_token=tokens.refresh_token,
        expires_in=tokens.expires_in,
        session_id=tokens.session_id,
        **tokens.extra,
    )


@router.post("/refresh", response_model=RefreshResponse, summary="Rotate tokens")
def refresh(
    payload: RefreshRequest,
    db: Session = Depends(get_db),
    context: RequestContext = Depends(get_request_context),
) -> RefreshResponse:
    """Exchange a refresh token for a new pair. The old token is revoked.

    Presenting a superseded refresh token is treated as replay: the session is
    revoked and a CRITICAL alert is raised.
    """
    _guard("refresh", context.ip_address, rate_limit.REFRESH_LIMIT)
    try:
        tokens = AuthService.refresh(db, payload.refresh_token, context)
    except AuthError as exc:
        db.commit()
        raise _auth_error(exc) from exc

    return RefreshResponse(
        access_token=tokens.access_token,
        refresh_token=tokens.refresh_token,
        expires_in=tokens.expires_in,
        session_id=tokens.session_id,
    )


@router.post(
    "/logout",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="End the current session",
)
def logout(
    principal: Principal = Depends(get_principal),
    db: Session = Depends(get_db),
    context: RequestContext = Depends(get_request_context),
) -> Response:
    AuthService.logout(
        db, principal.session, principal.user, principal.access_jti, context
    )
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get("/me", response_model=MeResponse, summary="Current identity and session")
def me(principal: Principal = Depends(get_principal)) -> MeResponse:
    user, session, device = principal.user, principal.session, principal.device
    return MeResponse(
        id=user.id,
        username=user.username,
        email=user.email,
        full_name=user.full_name,
        department=user.department,
        role=user.role.name,
        is_admin=user.role.is_admin,
        permissions=user.role.permissions or [],
        mfa_enabled=user.mfa_enabled,
        account_status=user.account_status.value,
        last_login_at=user.last_login_at,
        home_city=user.home_city,
        home_country=user.home_country,
        session=SessionOut.model_validate(session),
        device=DeviceOut.model_validate(device) if device else None,
    )


@router.post(
    "/register",
    response_model=UserSummary,
    status_code=status.HTTP_201_CREATED,
    summary="Create a user (administrators only)",
)
def register(
    payload: RegisterRequest,
    principal: Principal = Depends(require_admin),
    db: Session = Depends(get_db),
    context: RequestContext = Depends(get_request_context),
) -> UserSummary:
    """Create an account. Creating users is an administrative action, so this
    route is not open to anonymous callers."""
    strength = estimate_password_strength(payload.password)
    if strength < MIN_PASSWORD_STRENGTH:
        raise HTTPException(
            status_code=422,
            detail=(
                f"Password is too weak (strength {strength}/100, minimum "
                f"{MIN_PASSWORD_STRENGTH}). Use a longer passphrase with mixed "
                f"character types."
            ),
        )

    role = db.scalar(select(Role).where(Role.name == payload.role))
    if role is None:
        raise HTTPException(
            status_code=422,
            detail=f"Unknown role '{payload.role}'.",
        )

    clash = db.scalar(
        select(User).where(
            (User.username == payload.username) | (User.email == payload.email)
        )
    )
    if clash is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="That username or email address is already registered.",
        )

    user = User(
        username=payload.username,
        email=payload.email,
        full_name=payload.full_name,
        department=payload.department,
        hashed_password=hash_password(payload.password),
        password_changed_at=utcnow(),
        password_strength=strength,
        role_id=role.id,
        mfa_enabled=True,
        mfa_secret=None,           # set at enrolment, by the user themselves
        home_city=payload.home_city,
    )
    db.add(user)
    db.flush()

    AuditService.record(
        db, action="USER_CREATED", actor_id=principal.user.id,
        actor_label=principal.user.username, resource_type="user",
        resource_id=str(user.id), ip_address=context.ip_address,
        payload={
            "username": user.username, "role": role.name,
            "password_strength": strength,
        },
    )

    return UserSummary(
        id=user.id, username=user.username, email=user.email,
        full_name=user.full_name, department=user.department, role=role.name,
        is_admin=role.is_admin, permissions=role.permissions or [],
        mfa_enabled=user.mfa_enabled, mfa_enrolled=user.mfa_secret is not None,
        account_status=user.account_status.value, home_city=user.home_city,
        home_country=user.home_country,
    )


@router.post(
    "/mfa/enrol",
    response_model=MFAEnrolmentResponse,
    summary="Generate a TOTP secret and enrolment QR code",
)
def enrol_mfa(
    principal: Principal = Depends(get_principal),
    db: Session = Depends(get_db),
    context: RequestContext = Depends(get_request_context),
) -> MFAEnrolmentResponse:
    """Issue a fresh TOTP secret for the caller.

    The secret is returned exactly once. It is not active until
    ``/auth/mfa/confirm`` proves the authenticator app has it.
    """
    user = principal.user
    secret = mfa.generate_secret()
    user.mfa_secret = secret
    user.mfa_confirmed_at = None

    AuditService.record(
        db, action="MFA_ENROLMENT_STARTED", actor_id=user.id,
        actor_label=user.username, resource_type="user", resource_id=str(user.id),
        ip_address=context.ip_address, payload={"username": user.username},
    )

    return MFAEnrolmentResponse(
        secret=secret,
        provisioning_uri=mfa.provisioning_uri(secret, user.username),
        qr_code_svg_data_uri=mfa.qr_code_data_uri(secret, user.username),
        issuer=settings.mfa_issuer,
        digits=mfa.TOTP_DIGITS,
        interval_seconds=mfa.TOTP_INTERVAL_SECONDS,
    )


@router.post(
    "/mfa/confirm",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Confirm TOTP enrolment with a code from the app",
)
def confirm_mfa(
    payload: MFAConfirmRequest,
    principal: Principal = Depends(get_principal),
    db: Session = Depends(get_db),
    context: RequestContext = Depends(get_request_context),
) -> Response:
    user = principal.user
    if not user.mfa_secret:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Start enrolment first with POST /api/auth/mfa/enrol.",
        )
    if not mfa.verify_code(user.mfa_secret, payload.code):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="That code does not match. Check the time on your device.",
        )

    user.mfa_enabled = True
    user.mfa_confirmed_at = utcnow()
    AuditService.record(
        db, action="MFA_ENROLLED", actor_id=user.id, actor_label=user.username,
        resource_type="user", resource_id=str(user.id),
        ip_address=context.ip_address, payload={"username": user.username},
    )
    return Response(status_code=status.HTTP_204_NO_CONTENT)

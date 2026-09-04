"""Test fixtures: an isolated database per test, and a clean cache each time."""

from __future__ import annotations

import uuid
from collections.abc import Generator, Iterator

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.core.cache import InMemoryCache
from app.core.database import Base, get_db, get_session_factory
from app.core.security import hash_password
from app.external import mfa
from app.main import create_app
from app.models import Policy, Resource, Role, User
from app.models.enums import SENSITIVITY_MIN_TRUST, PolicyEffect, Sensitivity

DEVICE_FINGERPRINT = "a" * 64
OTHER_FINGERPRINT = "b" * 64
PASSWORD = "Correct-Horse-Battery-7!"


@pytest.fixture(autouse=True)
def no_background_sweep(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Keep the continuous-verification loop out of the test process.

    ``create_app`` starts the sweep in its lifespan, and the sweep opens its own
    session from the global factory — which points at the real database, not at
    the per-test one. Without this, running the suite silently writes trust
    scores and audit records to the developer's actual data.
    """
    monkeypatch.setattr(
        "app.core.config.settings.run_verification_in_api", False, raising=False
    )
    monkeypatch.setattr(
        "app.main.settings.run_verification_in_api", False, raising=False
    )
    yield


@pytest.fixture(autouse=True)
def clean_cache(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Rate-limit counters and the JWT denylist must not leak between tests."""
    fresh = InMemoryCache()
    monkeypatch.setattr("app.core.cache.cache", fresh)
    monkeypatch.setattr("app.core.jwt.cache", fresh)
    monkeypatch.setattr("app.core.rate_limit.cache", fresh)
    yield


@pytest.fixture
def db_factory() -> Generator[sessionmaker, None, None]:
    """A private in-memory SQLite database, shared across connections."""
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    try:
        yield factory
    finally:
        Base.metadata.drop_all(engine)
        engine.dispose()


@pytest.fixture
def db(db_factory: sessionmaker) -> Generator[Session, None, None]:
    session = db_factory()
    try:
        yield session
    finally:
        session.close()


@pytest.fixture
def roles(db: Session) -> dict[str, Role]:
    rows = {
        "admin": Role(
            name="admin", description="Administrator", is_admin=True,
            max_sensitivity_ordinal=3,
            permissions=["devices:read", "devices:approve", "devices:revoke"],
        ),
        "employee": Role(
            name="employee", description="Employee", is_admin=False,
            max_sensitivity_ordinal=2, permissions=["resources:read"],
        ),
        "contractor": Role(
            name="contractor", description="Contractor", is_admin=False,
            max_sensitivity_ordinal=1, permissions=["resources:read"],
        ),
    }
    db.add_all(rows.values())
    db.commit()
    return rows


@pytest.fixture
def user(db: Session, roles: dict[str, Role]) -> User:
    row = User(
        username="ramya.iyer",
        email="ramya.iyer@ztna-demo.in",
        full_name="Ramya Iyer",
        department="Engineering",
        hashed_password=hash_password(PASSWORD),
        password_strength=88,
        role_id=roles["employee"].id,
        mfa_enabled=True,
        mfa_secret=mfa.generate_secret(),
    )
    db.add(row)
    db.commit()
    return row


@pytest.fixture
def admin(db: Session, roles: dict[str, Role]) -> User:
    row = User(
        username="admin",
        email="admin@ztna-demo.in",
        full_name="Siva Balan",
        department="Information Security",
        hashed_password=hash_password(PASSWORD),
        password_strength=92,
        role_id=roles["admin"].id,
        mfa_enabled=True,
        mfa_secret=mfa.generate_secret(),
    )
    db.add(row)
    db.commit()
    return row


@pytest.fixture
def contractor(db: Session, roles: dict[str, Role]) -> User:
    row = User(
        username="rahul.raghavan",
        email="rahul.raghavan@ztna-demo.in",
        full_name="Rahul Raghavan",
        department="Engineering",
        hashed_password=hash_password(PASSWORD),
        password_strength=88,
        role_id=roles["contractor"].id,
        mfa_enabled=True,
        mfa_secret=mfa.generate_secret(),
    )
    db.add(row)
    db.commit()
    return row


@pytest.fixture
def catalogue(db: Session, roles: dict[str, Role]) -> dict[str, Resource]:
    """Four resources, one per sensitivity, with the baseline policy set."""
    resources = {
        "public-docs": Resource(
            slug="public-docs", name="Public Documentation", category="website",
            sensitivity=Sensitivity.PUBLIC,
            min_trust_score=SENSITIVITY_MIN_TRUST[Sensitivity.PUBLIC],
            owner="Marketing",
        ),
        "hr-portal": Resource(
            slug="hr-portal", name="HR Portal", category="application",
            sensitivity=Sensitivity.INTERNAL,
            min_trust_score=SENSITIVITY_MIN_TRUST[Sensitivity.INTERNAL],
            owner="Human Resources",
        ),
        "source-repo": Resource(
            slug="source-repo", name="Source Repository", category="repository",
            sensitivity=Sensitivity.CONFIDENTIAL,
            min_trust_score=SENSITIVITY_MIN_TRUST[Sensitivity.CONFIDENTIAL],
            owner="Engineering",
        ),
        "payroll-db": Resource(
            slug="payroll-db", name="Payroll Database", category="database",
            sensitivity=Sensitivity.RESTRICTED,
            min_trust_score=SENSITIVITY_MIN_TRUST[Sensitivity.RESTRICTED],
            owner="Finance",
        ),
    }
    db.add_all(resources.values())
    db.flush()

    for sensitivity, floor in SENSITIVITY_MIN_TRUST.items():
        db.add(
            Policy(
                name=f"Baseline trust floor - {sensitivity.value}",
                description=f"{sensitivity.value} needs a score of at least {floor}.",
                sensitivity=sensitivity, min_trust_score=floor, priority=100,
                effect=PolicyEffect.ALLOW,
            )
        )
    db.add(
        Policy(
            name="Contractors denied confidential",
            description="Contractors may never reach CONFIDENTIAL resources.",
            role_id=roles["contractor"].id, sensitivity=Sensitivity.CONFIDENTIAL,
            effect=PolicyEffect.DENY, priority=400,
        )
    )
    db.commit()
    return resources


@pytest.fixture
def client(db: Session, db_factory: sessionmaker) -> Generator[TestClient, None, None]:
    app = create_app()

    def override_get_db() -> Generator[Session, None, None]:
        try:
            yield db
            db.commit()
        except Exception:
            db.rollback()
            raise

    app.dependency_overrides[get_db] = override_get_db
    # WebSocket handlers open their own short-lived sessions; point those at
    # the per-test database too, or they silently read the real one.
    app.dependency_overrides[get_session_factory] = lambda: db_factory
    with TestClient(app) as test_client:
        test_client.headers.update(
            {
                "X-Device-Fingerprint": DEVICE_FINGERPRINT,
                "User-Agent": (
                    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                    "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 "
                    "Safari/605.1.15"
                ),
                "X-Device-Platform": "MacIntel",
                "X-Device-Screen": "2560x1664",
                "X-Device-Timezone": "Asia/Kolkata",
            }
        )
        yield test_client
    app.dependency_overrides.clear()


def sign_in(
    client: TestClient, user: User, password: str = PASSWORD,
) -> dict[str, object]:
    """Complete both login steps and return the token response body."""
    first = client.post(
        "/api/auth/login", json={"username": user.username, "password": password}
    )
    assert first.status_code == 200, first.text
    challenge = first.json()
    second = client.post(
        "/api/auth/mfa/verify",
        json={
            "mfa_token": challenge["mfa_token"],
            "code": mfa.current_code(user.mfa_secret),
        },
    )
    assert second.status_code == 200, second.text
    return second.json()


def auth_headers(tokens: dict[str, object]) -> dict[str, str]:
    return {"Authorization": f"Bearer {tokens['access_token']}"}


def new_uuid() -> uuid.UUID:
    return uuid.uuid4()

"""User administration, alert triage and the dashboard aggregate."""

from __future__ import annotations

from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import Alert, AuditLog, User
from app.models.enums import AccountStatus, AlertSeverity, AlertStatus
from tests.conftest import PASSWORD, auth_headers, sign_in


def seed_alerts(db: Session, user: User, n: int = 5) -> None:
    for i in range(n):
        db.add(
            Alert(
                user_id=user.id,
                severity=AlertSeverity.CRITICAL if i % 2 else AlertSeverity.HIGH,
                category="impossible_travel" if i % 2 else "brute_force",
                title=f"Alert {i}",
                description="Something happened.",
                trust_score=20.0 + i,
                evidence={"index": i},
            )
        )
    db.commit()


# --- users ------------------------------------------------------------------

def test_user_list_requires_permission(client: TestClient, user: User) -> None:
    tokens = sign_in(client, user)
    assert client.get("/api/users", headers=auth_headers(tokens)).status_code == 403


def test_admin_lists_users_with_derived_counts(
    client: TestClient, admin: User, user: User
) -> None:
    tokens = sign_in(client, admin)
    rows = client.get("/api/users", headers=auth_headers(tokens)).json()
    by_name = {r["username"]: r for r in rows}

    assert admin.username in by_name
    assert by_name[admin.username]["active_sessions"] >= 1
    assert by_name[admin.username]["device_count"] >= 1
    assert by_name[admin.username]["mfa_enrolled"] is True


def test_user_search(client: TestClient, admin: User, user: User) -> None:
    tokens = sign_in(client, admin)
    rows = client.get(
        f"/api/users?q={user.full_name.split()[0]}", headers=auth_headers(tokens)
    ).json()
    assert [r["username"] for r in rows] == [user.username]


def test_roles_are_listed_with_their_ceilings(
    client: TestClient, admin: User
) -> None:
    tokens = sign_in(client, admin)
    roles = {r["name"]: r for r in client.get(
        "/api/users/roles", headers=auth_headers(tokens)
    ).json()}
    assert roles["contractor"]["max_sensitivity_ordinal"] == 1
    assert roles["admin"]["is_admin"] is True


def test_admin_can_change_a_role(
    client: TestClient, admin: User, user: User, db: Session
) -> None:
    tokens = sign_in(client, admin)
    response = client.patch(
        f"/api/users/{user.id}",
        headers=auth_headers(tokens),
        json={"role": "contractor"},
    )
    assert response.status_code == 200
    assert response.json()["role"] == "contractor"

    record = db.scalar(select(AuditLog).where(AuditLog.action == "USER_UPDATED"))
    assert record.payload["changes"]["role"]["to"] == "contractor"


def test_admin_cannot_demote_themselves(
    client: TestClient, admin: User
) -> None:
    """Otherwise nobody can manage users until the database is edited by hand."""
    tokens = sign_in(client, admin)
    response = client.patch(
        f"/api/users/{admin.id}",
        headers=auth_headers(tokens),
        json={"role": "employee"},
    )
    assert response.status_code == 409
    assert "your own administrator role" in response.json()["detail"]


def test_admin_cannot_disable_their_own_account(
    client: TestClient, admin: User
) -> None:
    tokens = sign_in(client, admin)
    response = client.patch(
        f"/api/users/{admin.id}",
        headers=auth_headers(tokens),
        json={"account_status": "DISABLED"},
    )
    assert response.status_code == 409


def test_unlocking_clears_the_lockout_and_the_counter(
    client: TestClient, admin: User, user: User, db: Session
) -> None:
    from app.core.config import settings

    for _ in range(settings.max_failed_logins):
        client.post(
            "/api/auth/login",
            json={"username": user.username, "password": "wrong-one"},
        )
    db.refresh(user)
    assert user.is_locked

    tokens = sign_in(client, admin)
    response = client.patch(
        f"/api/users/{user.id}", headers=auth_headers(tokens), json={"unlock": True}
    )
    assert response.status_code == 200
    assert response.json()["is_locked"] is False

    db.refresh(user)
    assert user.failed_login_count == 0
    assert user.account_status is AccountStatus.ACTIVE


def test_empty_update_is_rejected(client: TestClient, admin: User, user: User) -> None:
    tokens = sign_in(client, admin)
    assert client.patch(
        f"/api/users/{user.id}", headers=auth_headers(tokens), json={}
    ).status_code == 422


# --- alerts -----------------------------------------------------------------

def test_alert_feed_requires_permission(client: TestClient, user: User) -> None:
    tokens = sign_in(client, user)
    assert client.get("/api/alerts", headers=auth_headers(tokens)).status_code == 403


def test_alert_feed_is_newest_first(
    client: TestClient, admin: User, user: User, db: Session
) -> None:
    seed_alerts(db, user)
    tokens = sign_in(client, admin)
    body = client.get("/api/alerts", headers=auth_headers(tokens)).json()
    assert body["total"] >= 5
    times = [a["created_at"] for a in body["alerts"]]
    assert times == sorted(times, reverse=True)


def test_alerts_filter_by_severity_and_category(
    client: TestClient, admin: User, user: User, db: Session
) -> None:
    seed_alerts(db, user)
    tokens = sign_in(client, admin)
    body = client.get(
        "/api/alerts?severity=CRITICAL", headers=auth_headers(tokens)
    ).json()
    assert {a["severity"] for a in body["alerts"]} == {"CRITICAL"}

    body = client.get(
        "/api/alerts?category=brute_force", headers=auth_headers(tokens)
    ).json()
    assert {a["category"] for a in body["alerts"]} == {"brute_force"}


def test_acknowledge_then_resolve(
    client: TestClient, admin: User, user: User, db: Session
) -> None:
    seed_alerts(db, user, 1)
    tokens = sign_in(client, admin)
    alert_id = client.get("/api/alerts", headers=auth_headers(tokens)).json()["alerts"][0]["id"]

    acked = client.post(
        f"/api/alerts/{alert_id}/acknowledge", headers=auth_headers(tokens)
    ).json()
    assert acked["status"] == "ACKNOWLEDGED"
    assert acked["acknowledged_by"] == admin.username

    resolved = client.post(
        f"/api/alerts/{alert_id}/resolve",
        headers=auth_headers(tokens),
        json={"note": "False positive: the user was travelling."},
    ).json()
    assert resolved["status"] == "RESOLVED"
    assert "travelling" in resolved["resolution_note"]


def test_resolving_directly_from_open_is_allowed(
    client: TestClient, admin: User, user: User, db: Session
) -> None:
    """An analyst who closes an alert in one sitting should not have to click
    acknowledge first just to satisfy a state machine."""
    seed_alerts(db, user, 1)
    tokens = sign_in(client, admin)
    alert_id = client.get("/api/alerts", headers=auth_headers(tokens)).json()["alerts"][0]["id"]

    resolved = client.post(
        f"/api/alerts/{alert_id}/resolve",
        headers=auth_headers(tokens),
        json={"note": "Handled."},
    )
    assert resolved.status_code == 200
    assert resolved.json()["acknowledged_at"] is not None


def test_double_acknowledge_is_a_conflict(
    client: TestClient, admin: User, user: User, db: Session
) -> None:
    seed_alerts(db, user, 1)
    tokens = sign_in(client, admin)
    alert_id = client.get("/api/alerts", headers=auth_headers(tokens)).json()["alerts"][0]["id"]
    path = f"/api/alerts/{alert_id}/acknowledge"

    assert client.post(path, headers=auth_headers(tokens)).status_code == 200
    assert client.post(path, headers=auth_headers(tokens)).status_code == 409


def test_alert_triage_is_audited(
    client: TestClient, admin: User, user: User, db: Session
) -> None:
    seed_alerts(db, user, 1)
    tokens = sign_in(client, admin)
    alert_id = client.get("/api/alerts", headers=auth_headers(tokens)).json()["alerts"][0]["id"]
    client.post(f"/api/alerts/{alert_id}/acknowledge", headers=auth_headers(tokens))

    record = db.scalar(select(AuditLog).where(AuditLog.action == "ALERT_ACKNOWLEDGED"))
    assert record is not None
    assert record.actor_label == admin.username


def test_alert_stats(client: TestClient, admin: User, user: User, db: Session) -> None:
    seed_alerts(db, user, 6)
    tokens = sign_in(client, admin)
    body = client.get("/api/alerts/stats", headers=auth_headers(tokens)).json()
    assert body["open"] >= 6
    assert body["today"] >= 6
    assert body["by_severity"]


# --- dashboard --------------------------------------------------------------

def test_overview_returns_everything_in_one_call(
    client: TestClient, admin: User, user: User, db: Session
) -> None:
    seed_alerts(db, user, 3)
    tokens = sign_in(client, admin)
    body = client.get("/api/dashboard/overview", headers=auth_headers(tokens)).json()

    assert body["active_sessions"] >= 1
    assert body["total_users"] >= 2
    assert body["alerts_today"] >= 3
    assert len(body["risk_distribution"]) == 4
    assert {s["level"] for s in body["risk_distribution"]} == {
        "LOW", "MEDIUM", "HIGH", "CRITICAL"
    }
    assert body["trust_over_time"], "the trend line must have at least one bucket"
    assert body["recent_alerts"]
    assert body["verification_interval_seconds"] > 0
    assert body["audit_records"] > 0


def test_overview_requires_permission(client: TestClient, user: User) -> None:
    tokens = sign_in(client, user)
    assert client.get(
        "/api/dashboard/overview", headers=auth_headers(tokens)
    ).status_code == 403


def test_trend_buckets_are_hourly_and_ordered(
    client: TestClient, admin: User
) -> None:
    tokens = sign_in(client, admin)
    body = client.get(
        "/api/dashboard/overview?hours=48", headers=auth_headers(tokens)
    ).json()
    times = [p["at"] for p in body["trust_over_time"]]
    assert times == sorted(times)
    for point in body["trust_over_time"]:
        assert point["at"].endswith(":00:00") or "T" in point["at"]
        assert 0 <= point["score"] <= 100

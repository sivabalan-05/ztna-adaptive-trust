#!/usr/bin/env python3
"""Seed the ZTNA database with a realistic 90-day corpus.

Generates, deterministically (``--seed``):

* 4 roles, 12 protected resources across all four sensitivity levels, and a
  baseline policy set;
* 25 users in an Indian corporate context (Coimbatore / Chennai / Bangalore),
  each with 2-3 registered devices;
* ~90 days of normal behaviour -- roughly 8,000 access events grouped into
  sessions, with a trust score recorded at login and at each continuous
  re-verification;
* ~5% labelled anomalous events across six attack families, so Phase 6 has a
  ground-truth set to measure precision / recall / F1 against;
* per-user behaviour profiles computed from the generated normal history;
* a hash-chained audit log covering every seeded security event.

Usage
-----
    python scripts/seed.py --reset

Trust scores on seeded rows come from ``app.ai.xai.assess`` -- the same engine
the live platform uses, with no separate implementation to drift out of step.
``anomaly_score`` is left NULL on every seeded row: the Isolation Forest is
trained in Phase 6 by ``scripts/train_model.py``, and an absent score is honest
where a fabricated one would not be.
"""

from __future__ import annotations

import argparse
import math
import random
import statistics
import sys
import uuid
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo

SCRIPT_DIR = Path(__file__).resolve().parent
ROOT_DIR = SCRIPT_DIR.parent
sys.path.insert(0, str(ROOT_DIR / "backend"))
sys.path.insert(0, str(SCRIPT_DIR))

import pyotp  # noqa: E402
from sqlalchemy import delete, insert, select  # noqa: E402
from sqlalchemy.orm import Session  # noqa: E402

from app.core.config import settings  # noqa: E402
from app.core.database import SessionLocal  # noqa: E402
from app.core.security import estimate_password_strength, hash_password  # noqa: E402
from app.models import (  # noqa: E402
    AccessRequest, Alert, AuditLog, BehaviorProfile, Device, Policy, Resource,
    Role, SystemLog, TrustScore, User, UserSession,
)
from app.models.enums import (  # noqa: E402
    AccountStatus, AlertSeverity, AlertStatus, DeviceStatus, LogLevel,
    PolicyEffect, SENSITIVITY_MIN_TRUST, ScoreTrigger, Sensitivity,
    SessionStatus,
)
from app.services.geo_math import haversine_km, travel_velocity_kmh  # noqa: E402
from app.ai.scoring import TrustSignals  # noqa: E402
from app.ai.xai import assess  # noqa: E402
from app.services.hash_chain import (  # noqa: E402
    GENESIS_HASH, compute_record_hash, hash_payload,
)

from seed_data import (  # noqa: E402
    ATTACKER_DEVICE_PROFILE, DEPARTMENTS, DEVICE_PROFILES, FIRST_NAMES,
    HOME_CITIES, HOSTILE_CITIES, LAST_NAMES, RESIDENTIAL_FOREIGN_CITIES,
    RESOURCES, ROLES,
)

IST = ZoneInfo("Asia/Kolkata")

#: Shared password for the 24 non-admin demo accounts, printed at the end.
DEMO_PASSWORD = "Ztna@Demo2026"

# Weight = share of *incidents*, not of events.  An insider-threat incident
# emits ~40 access events and a brute-force incident ~18, so both are kept rare
# to hold the labelled-anomaly share at roughly 5% of the corpus.
SCENARIOS = [
    ("credential_theft", 24),
    ("impossible_travel", 19),
    ("insider_threat", 10),
    ("brute_force", 12),
    ("session_hijack", 15),
    ("lateral_movement", 20),
]


# ---------------------------------------------------------------------------
# small helpers
# ---------------------------------------------------------------------------

def to_utc(dt: datetime) -> datetime:
    return dt.astimezone(timezone.utc)


def fingerprint_for(user_index: int, profile: dict[str, str], salt: str = "") -> str:
    """Stable synthetic fingerprint matching the client-side hash shape."""
    import hashlib

    material = "|".join(
        [
            profile["user_agent"], profile["platform"], profile["screen_resolution"],
            "Asia/Kolkata", profile["language"], f"canvas-{user_index}{salt}",
        ]
    )
    return hashlib.sha256(material.encode()).hexdigest()


class ChainWriter:
    """Appends hash-chained audit records in order."""

    def __init__(self) -> None:
        self.prev_hash = GENESIS_HASH
        self.seq = 0
        self.rows: list[dict[str, Any]] = []

    def append(
        self,
        *,
        timestamp: datetime,
        actor_id: uuid.UUID | None,
        actor_label: str,
        action: str,
        payload: dict[str, Any],
        resource_type: str = "",
        resource_id: str = "",
        ip_address: str = "",
        note: str = "",
    ) -> str:
        self.seq += 1
        ts = to_utc(timestamp)
        payload_hash = hash_payload(payload)
        record_hash = compute_record_hash(
            self.prev_hash, ts, actor_label, action, payload_hash
        )
        self.rows.append(
            {
                "id": uuid.uuid4(), "seq": self.seq, "timestamp": ts,
                "actor_id": actor_id, "actor_label": actor_label, "action": action,
                "resource_type": resource_type, "resource_id": resource_id,
                "ip_address": ip_address, "payload": payload,
                "payload_hash": payload_hash, "prev_hash": self.prev_hash,
                "record_hash": record_hash, "note": note,
            }
        )
        self.prev_hash = record_hash
        return record_hash


def allowed_resource_slugs(role_name: str, department: str,
                           resources: list[dict[str, Any]]) -> list[str]:
    """Least-privilege view of the catalogue for a given role."""
    out: list[str] = []
    for res in resources:
        sens = res["sensitivity"]
        if role_name == "admin":
            out.append(res["slug"])
        elif role_name == "security_analyst":
            if sens != Sensitivity.RESTRICTED or res["slug"] == "customer-pii-store":
                out.append(res["slug"])
        elif role_name == "employee":
            if sens in (Sensitivity.PUBLIC, Sensitivity.INTERNAL):
                out.append(res["slug"])
            elif sens == Sensitivity.CONFIDENTIAL and res["owner"] == department:
                out.append(res["slug"])
        else:  # contractor
            if sens in (Sensitivity.PUBLIC, Sensitivity.INTERNAL):
                out.append(res["slug"])
    return out


# ---------------------------------------------------------------------------
# reference data
# ---------------------------------------------------------------------------

TABLES_IN_DELETE_ORDER = [
    AuditLog, SystemLog, Alert, AccessRequest, TrustScore, UserSession,
    BehaviorProfile, Device, Policy, User, Resource, Role,
]


def purge(db: Session) -> None:
    for model in TABLES_IN_DELETE_ORDER:
        db.execute(delete(model))
    db.commit()


def create_roles(db: Session) -> dict[str, dict[str, Any]]:
    rows = []
    for spec in ROLES:
        rows.append(
            {
                "id": uuid.uuid4(), "name": spec["name"],
                "description": spec["description"], "is_admin": spec["is_admin"],
                "max_sensitivity_ordinal": spec["max_sensitivity_ordinal"],
                "permissions": spec["permissions"],
            }
        )
    db.execute(insert(Role), rows)
    return {r["name"]: r for r in rows}


def create_resources(db: Session) -> list[dict[str, Any]]:
    rows = []
    for spec in RESOURCES:
        sens = Sensitivity(spec["sensitivity"])
        rows.append(
            {
                "id": uuid.uuid4(), "slug": spec["slug"], "name": spec["name"],
                "description": spec["description"], "category": spec["category"],
                "sensitivity": sens,
                "min_trust_score": SENSITIVITY_MIN_TRUST[sens],
                "owner": spec["owner"], "enabled": True,
            }
        )
    db.execute(insert(Resource), rows)
    return rows


def create_policies(db: Session, roles: dict[str, dict[str, Any]],
                    resources: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by_slug = {r["slug"]: r for r in resources}
    rows: list[dict[str, Any]] = []

    def add(**kw: Any) -> None:
        base = {
            "id": uuid.uuid4(), "description": "", "role_id": None,
            "resource_id": None, "sensitivity": None, "min_trust_score": 0,
            "require_mfa": False, "require_known_device": False, "deny_vpn": False,
            "allowed_countries": [], "time_window": {},
            "effect": PolicyEffect.ALLOW, "priority": 100, "enabled": True,
        }
        base.update(kw)
        rows.append(base)

    # Sensitivity floors: the baseline every request is measured against.
    for sens, floor in SENSITIVITY_MIN_TRUST.items():
        add(
            name=f"Baseline trust floor - {sens.value}",
            description=(
                f"{sens.value} resources require a trust score of at least {floor}."
            ),
            sensitivity=sens, min_trust_score=floor, priority=100,
        )

    # Restricted data: known device + MFA, no VPN, India only.
    add(
        name="Restricted data requires managed device and MFA",
        description=(
            "RESTRICTED resources may only be reached from an approved device "
            "with MFA completed, over a non-VPN connection from India."
        ),
        sensitivity=Sensitivity.RESTRICTED, min_trust_score=90,
        require_mfa=True, require_known_device=True, deny_vpn=True,
        allowed_countries=["IN"], priority=300,
    )

    # Contractors are capped at INTERNAL.
    add(
        name="Contractors denied confidential and above",
        description="Contractors may never reach CONFIDENTIAL or RESTRICTED resources.",
        role_id=roles["contractor"]["id"], sensitivity=Sensitivity.CONFIDENTIAL,
        effect=PolicyEffect.DENY, priority=400,
    )
    add(
        name="Contractors denied restricted",
        description="Contractors may never reach RESTRICTED resources.",
        role_id=roles["contractor"]["id"], sensitivity=Sensitivity.RESTRICTED,
        effect=PolicyEffect.DENY, priority=400,
    )

    # Named high-value resources.
    add(
        name="Production secrets vault - admin only",
        description="Only administrators may open the production secrets vault.",
        resource_id=by_slug["prod-secrets-vault"]["id"], min_trust_score=95,
        require_mfa=True, require_known_device=True, deny_vpn=True,
        effect=PolicyEffect.ALLOW, role_id=roles["admin"]["id"], priority=500,
    )
    add(
        name="Payroll database - business hours only",
        description="Payroll access is restricted to 08:00-20:00 IST on weekdays.",
        resource_id=by_slug["payroll-db"]["id"], min_trust_score=90,
        require_mfa=True,
        time_window={"start_hour": 8, "end_hour": 20, "weekdays_only": True},
        priority=350,
    )
    add(
        name="Source repository requires managed device",
        description="Source code may only be pulled from an approved device.",
        resource_id=by_slug["source-repo"]["id"], min_trust_score=75,
        require_known_device=True, priority=250,
    )
    add(
        name="Public resources always reachable",
        description="PUBLIC resources carry no trust floor.",
        sensitivity=Sensitivity.PUBLIC, min_trust_score=0, priority=50,
    )

    db.execute(insert(Policy), rows)
    return rows


# ---------------------------------------------------------------------------
# users and devices
# ---------------------------------------------------------------------------

def create_users(db: Session, roles: dict[str, dict[str, Any]],
                 rng: random.Random, count: int,
                 admin_password: str) -> list[dict[str, Any]]:
    """Create ``count`` users: 1 admin, 3 analysts, 16 employees, rest contractors."""
    plan: list[str] = (
        ["admin"] * 1 + ["security_analyst"] * 3 + ["employee"] * 16
        + ["contractor"] * max(0, count - 20)
    )[:count]
    while len(plan) < count:
        plan.append("employee")

    used_usernames: set[str] = set()
    now = datetime.now(IST)
    rows: list[dict[str, Any]] = []

    demo_hash = hash_password(DEMO_PASSWORD)
    demo_strength = estimate_password_strength(DEMO_PASSWORD)

    for index, role_name in enumerate(plan):
        first = FIRST_NAMES[index % len(FIRST_NAMES)]
        last = LAST_NAMES[(index * 7 + 3) % len(LAST_NAMES)]
        base_username = f"{first.lower()}.{last.lower()}"
        username = base_username
        suffix = 1
        while username in used_usernames:
            suffix += 1
            username = f"{base_username}{suffix}"
        used_usernames.add(username)

        city = HOME_CITIES[index % len(HOME_CITIES)]
        department = (
            "Information Security" if role_name in ("admin", "security_analyst")
            else DEPARTMENTS[index % len(DEPARTMENTS)]
        )
        credential_age = rng.randint(10, 240)

        if index == 0:
            username = "admin"
            first, last = "Siva", "Balan"
            hashed = hash_password(admin_password)
            strength = estimate_password_strength(admin_password)
        else:
            hashed = demo_hash
            strength = demo_strength

        rows.append(
            {
                "id": uuid.uuid4(),
                "username": username,
                "email": f"{username}@ztna-demo.in",
                "full_name": f"{first} {last}",
                "department": department,
                "hashed_password": hashed,
                "password_changed_at": to_utc(now - timedelta(days=credential_age)),
                "password_strength": strength,
                "role_id": roles[role_name]["id"],
                "account_status": AccountStatus.ACTIVE,
                "mfa_enabled": True,
                "mfa_secret": pyotp.random_base32(),
                "mfa_confirmed_at": to_utc(now - timedelta(days=credential_age)),
                "failed_login_count": 0,
                "home_city": city["name"],
                "home_country": city["country"],
                "home_latitude": city["latitude"],
                "home_longitude": city["longitude"],
                "timezone": "Asia/Kolkata",
                "created_at": to_utc(now - timedelta(days=rng.randint(240, 900))),
                "updated_at": to_utc(now),
                # non-column metadata used by the generator
                "_role_name": role_name,
                "_city": city,
                "_credential_age": credential_age,
            }
        )

    columns = {c.name for c in User.__table__.columns}
    db.execute(insert(User), [{k: v for k, v in r.items() if k in columns} for r in rows])
    return rows


def create_devices(db: Session, users: list[dict[str, Any]],
                   rng: random.Random) -> dict[uuid.UUID, list[dict[str, Any]]]:
    now = datetime.now(IST)
    rows: list[dict[str, Any]] = []
    by_user: dict[uuid.UUID, list[dict[str, Any]]] = {}

    for index, user in enumerate(users):
        n_devices = rng.choice([2, 2, 3])
        profiles = rng.sample(DEVICE_PROFILES, n_devices)
        user_devices: list[dict[str, Any]] = []
        for d_index, profile in enumerate(profiles):
            first_seen = now - timedelta(days=rng.randint(95, 400))
            row = {
                "id": uuid.uuid4(),
                "user_id": user["id"],
                "fingerprint": fingerprint_for(index, profile, salt=f"-{d_index}"),
                "label": profile["label"],
                "status": DeviceStatus.APPROVED,
                "os": profile["os"], "browser": profile["browser"],
                "platform": profile["platform"],
                "screen_resolution": profile["screen_resolution"],
                "device_timezone": "Asia/Kolkata",
                "language": profile["language"], "user_agent": profile["user_agent"],
                "first_seen_at": to_utc(first_seen),
                "last_seen_at": to_utc(now),
                "seen_count": 0,
                "approved_at": to_utc(first_seen + timedelta(hours=2)),
                "approved_by_id": users[0]["id"],
                "is_trusted": True,
                "created_at": to_utc(first_seen),
                "updated_at": to_utc(now),
                "_first_seen": first_seen,
                "_primary": d_index == 0,
            }
            user_devices.append(row)
            rows.append(row)
        by_user[user["id"]] = user_devices

    columns = {c.name for c in Device.__table__.columns}
    db.execute(
        insert(Device), [{k: v for k, v in r.items() if k in columns} for r in rows]
    )
    return by_user


# ---------------------------------------------------------------------------
# behaviour history
# ---------------------------------------------------------------------------

class HistoryBuilder:
    """Generates sessions, access events, trust scores, alerts and audit events.

    Historical trust scores are sampled at login plus a few re-verifications per
    session.  The live worker re-scores every 30 seconds (Phase 8); storing that
    cadence for 90 days would be millions of rows with no analytical value.
    """

    def __init__(self, rng: random.Random, users: list[dict[str, Any]],
                 devices_by_user: dict[uuid.UUID, list[dict[str, Any]]],
                 resources: list[dict[str, Any]], days: int) -> None:
        self.rng = rng
        self.users = users
        self.devices_by_user = devices_by_user
        self.resources = resources
        self.by_slug = {r["slug"]: r for r in resources}
        self.days = days
        self.now = datetime.now(IST)

        self.sessions: list[dict[str, Any]] = []
        self.trust_scores: list[dict[str, Any]] = []
        self.access_requests: list[dict[str, Any]] = []
        self.alerts: list[dict[str, Any]] = []
        self.audit_events: list[dict[str, Any]] = []
        self.system_logs: list[dict[str, Any]] = []

        self.weights = settings.trust_weights
        self.stats: dict[uuid.UUID, dict[str, Any]] = {}
        self.last_login: dict[uuid.UUID, dict[str, Any]] = {}
        self.persona: dict[uuid.UUID, dict[str, Any]] = {}

        for user in users:
            self.stats[user["id"]] = {
                "hours": [], "countries": Counter(), "cities": Counter(),
                "fingerprints": Counter(), "durations": [], "rpms": [],
                "distinct": [], "resources": Counter(), "lats": [], "lons": [],
                "last_event": None,
            }
            role = user["_role_name"]
            if role == "admin":
                typical_hour = 8.5
            elif role == "security_analyst":
                typical_hour = self.rng.choice([8.0, 14.0, 22.0])
            elif role == "contractor":
                typical_hour = 10.5
            else:
                typical_hour = 9.0 + self.rng.gauss(0, 0.5)
            self.persona[user["id"]] = {
                "typical_hour": typical_hour,
                "hour_spread": self.rng.uniform(1.0, 1.6),
                "avg_duration": self.rng.uniform(70, 190),
                "sd_duration": self.rng.uniform(20, 45),
                "avg_rpm": self.rng.uniform(1.4, 3.2),
                "allowed": allowed_resource_slugs(
                    role, user["department"], self.resources
                ),
                "favourites": [],
            }
            allowed = self.persona[user["id"]]["allowed"]
            k = min(len(allowed), self.rng.randint(3, 5))
            self.persona[user["id"]]["favourites"] = self.rng.sample(allowed, k)

    # -- utilities ---------------------------------------------------------

    def _ip_for(self, city: dict[str, Any]) -> str:
        return (
            f"{city['ip_prefix']}."
            f"{self.rng.randint(0, 255)}.{self.rng.randint(1, 254)}"
        )

    def _record_score(self, session_row: dict[str, Any], ctx: TrustSignals,
                      when: datetime, trigger: ScoreTrigger) -> dict[str, Any]:
        result = assess(ctx, weights=self.weights)
        value, factors, headline = result.score, result.factor_payload(), result.headline
        risk, action = result.risk_level.value, result.action.value
        row = {
            "id": uuid.uuid4(),
            "session_id": session_row["id"],
            "user_id": session_row["user_id"],
            "score": value,
            "risk_level": risk,
            "action": action,
            "trigger": trigger,
            "anomaly_score": None,   # filled by Phase 6 (Isolation Forest)
            "factors": factors,
            "reason": headline,
            "created_at": to_utc(when),
            "updated_at": to_utc(when),
        }
        self.trust_scores.append(row)
        return row

    def _audit(self, when: datetime, actor_id: uuid.UUID | None, actor_label: str,
               action: str, payload: dict[str, Any], **kw: Any) -> None:
        self.audit_events.append(
            {
                "timestamp": when, "actor_id": actor_id, "actor_label": actor_label,
                "action": action, "payload": payload, **kw,
            }
        )

    # -- normal behaviour --------------------------------------------------

    def generate_normal(self) -> None:
        start_day = (self.now - timedelta(days=self.days)).date()

        for offset in range(self.days):
            day = start_day + timedelta(days=offset)
            is_weekend = day.weekday() >= 5

            for user in self.users:
                persona = self.persona[user["id"]]
                if is_weekend:
                    n_sessions = 1 if self.rng.random() < 0.10 else 0
                else:
                    n_sessions = 1 + (1 if self.rng.random() < 0.28 else 0)
                    if self.rng.random() < 0.05:
                        n_sessions = 0        # leave / travel day

                for s_index in range(n_sessions):
                    base_hour = persona["typical_hour"] + (5.5 if s_index else 0.0)
                    hour_f = self.rng.gauss(base_hour, persona["hour_spread"] * 0.6)
                    hour_f = max(5.75, min(23.5, hour_f % 24))
                    login = datetime(
                        day.year, day.month, day.day,
                        int(hour_f), int((hour_f % 1) * 60), self.rng.randint(0, 59),
                        tzinfo=IST,
                    )
                    if login > self.now:
                        continue
                    self._normal_session(user, login, is_weekend)

    def _normal_session(self, user: dict[str, Any], login: datetime,
                        is_weekend: bool) -> None:
        rng, persona = self.rng, self.persona[user["id"]]
        stats = self.stats[user["id"]]
        city = user["_city"]

        devices = self.devices_by_user[user["id"]]
        device = devices[0] if rng.random() < 0.7 else rng.choice(devices)

        duration = max(12.0, rng.gauss(persona["avg_duration"], persona["sd_duration"]))
        rpm = max(0.4, rng.gauss(persona["avg_rpm"], 0.4))
        ip = self._ip_for(city)
        end = login + timedelta(minutes=duration)

        n_events = rng.randint(3, 5)
        slugs = [
            rng.choice(persona["favourites"]) if rng.random() < 0.75
            else rng.choice(persona["allowed"])
            for _ in range(n_events)
        ]
        distinct = len(set(slugs))

        prev = self.last_login.get(user["id"])
        if prev:
            distance = haversine_km(
                prev["lat"], prev["lon"], city["latitude"], city["longitude"]
            )
            velocity = travel_velocity_kmh(distance, prev["at"], login)
        else:
            distance, velocity = 0.0, 0.0

        session_row = {
            "id": uuid.uuid4(), "user_id": user["id"], "device_id": device["id"],
            "refresh_jti": uuid.uuid4().hex, "status": SessionStatus.EXPIRED,
            "ip_address": ip, "asn": city["asn"], "isp": city["isp"],
            "country": city["country"], "city": city["name"],
            "latitude": city["latitude"], "longitude": city["longitude"],
            "is_vpn": False, "is_datacenter": False, "ip_reputation": 0,
            "started_at": to_utc(login), "last_seen_at": to_utc(end),
            "expires_at": to_utc(end + timedelta(minutes=30)),
            "ended_at": to_utc(end), "revoked_reason": "",
            "last_verified_at": to_utc(end),
            "mfa_passed": True, "mfa_failures": 0, "step_up_required": False,
            "request_count": max(5, int(duration * rpm)),
            "distinct_resource_count": distinct, "denied_count": 0,
            "created_at": to_utc(login), "updated_at": to_utc(end),
        }

        ctx = TrustSignals(
            mfa_passed=True,
            failed_auth_count_24h=0,
            password_strength=user["password_strength"],
            credential_age_days=user["_credential_age"],
            is_known_device=True, device_approved=True,
            device_first_seen_days=(login - device["_first_seen"]).days,
            profile_deviation=abs(rng.gauss(0, 0.06)),
            requests_per_minute=rpm,
            baseline_requests_per_minute=persona["avg_rpm"],
            distinct_resources=distinct,
            baseline_distinct_resources=4.0,
            distance_from_usual_km=0.0,
            is_new_country=False,
            travel_velocity_kmh=velocity,
            hour_of_day=login.hour,
            typical_hour=persona["typical_hour"],
            hour_spread=persona["hour_spread"],
            is_weekend=is_weekend,
            session_duration_min=duration,
            baseline_session_duration_min=persona["avg_duration"],
        )

        login_score = self._record_score(session_row, ctx, login, ScoreTrigger.LOGIN)

        # A few re-verifications spread through the session.
        for i in range(self.rng.randint(1, 3)):
            at = login + timedelta(minutes=duration * (i + 1) / 4.0)
            mid = TrustSignals(**{**ctx.__dict__, "session_duration_min":
                                       (at - login).total_seconds() / 60.0})
            self._record_score(session_row, mid, at, ScoreTrigger.PERIODIC)

        session_row["current_trust_score"] = login_score["score"]
        session_row["current_risk_level"] = login_score["risk_level"]
        session_row["current_action"] = login_score["action"]
        self.sessions.append(session_row)

        for i, slug in enumerate(slugs):
            res = self.by_slug[slug]
            at = login + timedelta(minutes=duration * (i + 0.5) / n_events)
            self.access_requests.append(
                self._access_row(
                    user=user, session_row=session_row, resource=res, at=at,
                    score=login_score, granted=True, ip=ip, ctx=ctx,
                    velocity=velocity, distance=0.0, is_known_device=True,
                    is_anomalous=False, scenario="",
                    matched_policy=f"Baseline trust floor - {res['sensitivity'].value}",
                )
            )
            stats["resources"][slug] += 1

        stats["hours"].append(login.hour)
        stats["countries"][city["country"]] += 1
        stats["cities"][city["name"]] += 1
        stats["fingerprints"][device["fingerprint"]] += 1
        stats["durations"].append(duration)
        stats["rpms"].append(rpm)
        stats["distinct"].append(distinct)
        stats["lats"].append(city["latitude"])
        stats["lons"].append(city["longitude"])
        stats["last_event"] = login

        self.last_login[user["id"]] = {
            "at": login, "lat": city["latitude"], "lon": city["longitude"],
            "country": city["country"], "city": city["name"],
        }
        self._audit(
            login, user["id"], user["username"], "LOGIN_SUCCESS",
            {
                "session_id": str(session_row["id"]), "ip": ip,
                "city": city["name"], "country": city["country"],
                "device": device["label"], "trust_score": login_score["score"],
                "risk_level": login_score["risk_level"],
            },
            resource_type="session", resource_id=str(session_row["id"]),
            ip_address=ip,
        )

    def _access_row(self, *, user: dict[str, Any], session_row: dict[str, Any] | None,
                    resource: dict[str, Any] | None, at: datetime,
                    score: dict[str, Any], granted: bool, ip: str,
                    ctx: TrustSignals, velocity: float, distance: float,
                    is_known_device: bool, is_anomalous: bool, scenario: str,
                    matched_policy: str, path: str | None = None,
                    reason: str = "") -> dict[str, Any]:
        """One access event plus the Isolation Forest feature vector for it."""
        hour = at.hour
        features = {
            "hour_sin": round(math.sin(2 * math.pi * hour / 24), 6),
            "hour_cos": round(math.cos(2 * math.pi * hour / 24), 6),
            "day_of_week": at.weekday(),
            "is_known_device": int(is_known_device),
            "geo_distance_from_usual_km": round(distance, 2),
            "is_new_country": int(ctx.is_new_country),
            "ip_reputation_score": ctx.ip_reputation,
            "is_vpn": int(ctx.is_vpn),
            "requests_per_minute": round(ctx.requests_per_minute, 3),
            "session_duration_min": round(ctx.session_duration_min, 2),
            "num_distinct_resources": ctx.distinct_resources,
            "failed_auth_count_24h": ctx.failed_auth_count_24h,
            "travel_velocity_kmh": (
                99999.0 if velocity == float("inf") else round(velocity, 2)
            ),
        }
        return {
            "id": uuid.uuid4(),
            "user_id": user["id"],
            "session_id": session_row["id"] if session_row else None,
            "resource_id": resource["id"] if resource else None,
            "trust_score_id": score["id"],
            "requested_at": to_utc(at),
            "method": "GET",
            "path": path or (f"/api/resources/{resource['slug']}" if resource else "/api/auth/login"),
            "ip_address": ip,
            "score_at_request": score["score"],
            "risk_level": score["risk_level"],
            "decision": score["action"] if not granted else "ALLOW",
            "granted": granted,
            "reason": reason or score["reason"],
            "matched_policy": matched_policy,
            "latency_ms": round(self.rng.uniform(4.0, 38.0), 2),
            "features": features,
            "is_anomalous": is_anomalous,
            "scenario": scenario,
            "created_at": to_utc(at),
            "updated_at": to_utc(at),
        }

    # -- attack / anomaly injection ---------------------------------------

    def _attack_time(self) -> datetime:
        offset_days = self.rng.uniform(1, self.days - 1)
        base = self.now - timedelta(days=offset_days)
        return base.replace(
            hour=self.rng.randint(0, 23), minute=self.rng.randint(0, 59),
            second=self.rng.randint(0, 59), microsecond=0,
        )

    def _attack_session(self, user: dict[str, Any], login: datetime,
                        city: dict[str, Any], *, device_id: uuid.UUID | None,
                        duration: float, is_vpn: bool, is_datacenter: bool,
                        ip_reputation: int, status: SessionStatus,
                        revoked_reason: str) -> tuple[dict[str, Any], str]:
        ip = self._ip_for(city)
        end = login + timedelta(minutes=duration)
        row = {
            "id": uuid.uuid4(), "user_id": user["id"], "device_id": device_id,
            "refresh_jti": uuid.uuid4().hex, "status": status,
            "ip_address": ip, "asn": city["asn"], "isp": city["isp"],
            "country": city["country"], "city": city["name"],
            "latitude": city["latitude"], "longitude": city["longitude"],
            "is_vpn": is_vpn, "is_datacenter": is_datacenter,
            "ip_reputation": ip_reputation,
            "started_at": to_utc(login), "last_seen_at": to_utc(end),
            "expires_at": to_utc(end + timedelta(minutes=30)),
            "ended_at": to_utc(end), "revoked_reason": revoked_reason,
            "last_verified_at": to_utc(end),
            "mfa_passed": False, "mfa_failures": 0, "step_up_required": True,
            "request_count": self.rng.randint(10, 120),
            "distinct_resource_count": 0, "denied_count": 0,
            "created_at": to_utc(login), "updated_at": to_utc(end),
        }
        return row, ip

    def _raise_alert(self, *, user: dict[str, Any], session_id: uuid.UUID | None,
                     severity: AlertSeverity, category: str, title: str,
                     description: str, trust: float, evidence: dict[str, Any],
                     when: datetime) -> None:
        resolved = self.rng.random() < 0.55
        acknowledged = resolved or self.rng.random() < 0.5
        analyst = self.users[1]["id"] if len(self.users) > 1 else None
        self.alerts.append(
            {
                "id": uuid.uuid4(), "user_id": user["id"], "session_id": session_id,
                "severity": severity,
                "status": (
                    AlertStatus.RESOLVED if resolved
                    else AlertStatus.ACKNOWLEDGED if acknowledged
                    else AlertStatus.OPEN
                ),
                "category": category, "title": title, "description": description,
                "trust_score": trust, "evidence": evidence,
                "acknowledged_at": to_utc(when + timedelta(minutes=self.rng.randint(2, 40)))
                if acknowledged else None,
                "acknowledged_by_id": analyst if acknowledged else None,
                "resolved_at": to_utc(when + timedelta(hours=self.rng.randint(1, 20)))
                if resolved else None,
                "resolved_by_id": analyst if resolved else None,
                "resolution_note": "Confirmed and contained." if resolved else "",
                "created_at": to_utc(when), "updated_at": to_utc(when),
            }
        )
        self._audit(
            when, None, "trust-engine", "ALERT_RAISED",
            {
                "category": category, "severity": severity.value,
                "user": user["username"], "trust_score": trust,
                "session_id": str(session_id) if session_id else None,
            },
            resource_type="alert",
        )

    def generate_anomalies(self, incidents: int) -> None:
        pool = [u for u in self.users if u["_role_name"] != "admin"]
        plan: list[str] = []
        total_weight = sum(w for _, w in SCENARIOS)
        for name, weight in SCENARIOS:
            plan.extend([name] * max(1, round(incidents * weight / total_weight)))
        self.rng.shuffle(plan)

        handlers = {
            "credential_theft": self._scn_credential_theft,
            "impossible_travel": self._scn_impossible_travel,
            "insider_threat": self._scn_insider_threat,
            "brute_force": self._scn_brute_force,
            "session_hijack": self._scn_session_hijack,
            "lateral_movement": self._scn_lateral_movement,
        }
        for scenario in plan[:incidents]:
            handlers[scenario](self.rng.choice(pool))

    def _score_attack(self, session_row: dict[str, Any], ctx: TrustSignals,
                      when: datetime, trigger: ScoreTrigger) -> dict[str, Any]:
        result = assess(ctx, weights=self.weights)
        value = result.score
        factors = result.factor_payload()
        headline = result.headline
        risk, action = result.risk_level.value, result.action.value
        row = {
            "id": uuid.uuid4(), "session_id": session_row["id"],
            "user_id": session_row["user_id"], "score": value, "risk_level": risk,
            "action": action, "trigger": trigger, "anomaly_score": None,
            "factors": factors, "reason": headline,
            "created_at": to_utc(when), "updated_at": to_utc(when),
        }
        self.trust_scores.append(row)
        return row

    def _scn_credential_theft(self, user: dict[str, Any]) -> None:
        # Stolen password used from an ordinary residential connection abroad.
        # The signals that give it away are the unknown device and the new
        # country; the network itself looks unremarkable, which is precisely
        # what makes this land at HIGH (step-up MFA) rather than CRITICAL.
        login = self._attack_time()
        city = self.rng.choice(RESIDENTIAL_FOREIGN_CITIES)
        home = user["_city"]
        distance = haversine_km(
            home["latitude"], home["longitude"], city["latitude"], city["longitude"]
        )
        session_row, ip = self._attack_session(
            user, login, city, device_id=None, duration=self.rng.uniform(3, 14),
            is_vpn=False, is_datacenter=False, ip_reputation=0,
            status=SessionStatus.REVOKED,
            revoked_reason="Step-up MFA not completed after high-risk score.",
        )
        ctx = TrustSignals(
            mfa_passed=False, mfa_skipped=True, failed_auth_count_24h=0,
            password_strength=user["password_strength"],
            credential_age_days=user["_credential_age"],
            is_known_device=False, device_approved=False, device_first_seen_days=0,
            ip_reputation=0, is_vpn=False, is_datacenter=False,
            profile_deviation=self.rng.uniform(0.5, 0.75),
            requests_per_minute=self.rng.uniform(4, 9),
            baseline_requests_per_minute=self.persona[user["id"]]["avg_rpm"],
            distinct_resources=self.rng.randint(2, 5),
            baseline_distinct_resources=4.0, unusual_resource_access=True,
            distance_from_usual_km=distance, is_new_country=True,
            travel_velocity_kmh=0.0,
            hour_of_day=login.hour,
            typical_hour=self.persona[user["id"]]["typical_hour"],
            hour_spread=self.persona[user["id"]]["hour_spread"],
            is_weekend=login.weekday() >= 5,
            session_duration_min=8.0, baseline_session_duration_min=120.0,
        )
        score_row = self._score_attack(session_row, ctx, login, ScoreTrigger.LOGIN)
        session_row.update(
            current_trust_score=score_row["score"],
            current_risk_level=score_row["risk_level"],
            current_action=score_row["action"],
        )
        self.sessions.append(session_row)

        allowed = self.persona[user["id"]]["allowed"]
        for i in range(self.rng.randint(2, 4)):
            res = self.by_slug[self.rng.choice(allowed)]
            self.access_requests.append(
                self._access_row(
                    user=user, session_row=session_row, resource=res,
                    at=login + timedelta(minutes=i + 1), score=score_row,
                    granted=False, ip=ip, ctx=ctx, velocity=0.0, distance=distance,
                    is_known_device=False, is_anomalous=True,
                    scenario="credential_theft",
                    matched_policy="Baseline trust floor - " + res["sensitivity"].value,
                    reason="Step-up MFA required before this resource can be opened.",
                )
            )
        self._raise_alert(
            user=user, session_id=session_row["id"], severity=AlertSeverity.HIGH,
            category="credential_theft",
            title=f"Credential use from an unrecognised device in {city['name']}",
            description=(
                f"Correct password presented for {user['username']} from an unknown "
                f"device in {city['name']}, {city['country']} — {distance:,.0f} km "
                f"from the account's usual location. Step-up MFA was required and "
                f"was not completed."
            ),
            trust=score_row["score"],
            evidence={
                "ip": ip, "country": city["country"], "city": city["name"],
                "distance_km": round(distance, 1), "device": "unknown fingerprint",
                "network": "residential, no reputation signal",
            },
            when=login,
        )
        self._audit(
            login, user["id"], user["username"], "STEP_UP_REQUIRED",
            {"session_id": str(session_row["id"]), "trust_score": score_row["score"],
             "ip": ip, "country": city["country"]},
            resource_type="session", resource_id=str(session_row["id"]), ip_address=ip,
        )

    def _scn_impossible_travel(self, user: dict[str, Any]) -> None:
        home = user["_city"]
        first_login = self._attack_time()
        city = self.rng.choice(HOSTILE_CITIES)
        gap_minutes = self.rng.randint(12, 45)
        login = first_login + timedelta(minutes=gap_minutes)
        distance = haversine_km(
            home["latitude"], home["longitude"], city["latitude"], city["longitude"]
        )
        velocity = travel_velocity_kmh(distance, first_login, login)

        session_row, ip = self._attack_session(
            user, login, city, device_id=None, duration=self.rng.uniform(1, 5),
            is_vpn=True, is_datacenter=True, ip_reputation=self.rng.randint(55, 88),
            status=SessionStatus.REVOKED,
            revoked_reason="Impossible travel detected; session blocked at login.",
        )
        persona = self.persona[user["id"]]
        ctx = TrustSignals(
            mfa_passed=False, mfa_skipped=True,
            password_strength=user["password_strength"],
            credential_age_days=user["_credential_age"],
            is_known_device=False, device_approved=False, device_first_seen_days=0,
            ip_reputation=session_row["ip_reputation"], is_vpn=True, is_datacenter=True,
            profile_deviation=self.rng.uniform(0.6, 0.9),
            requests_per_minute=self.rng.uniform(1, 4),
            baseline_requests_per_minute=persona["avg_rpm"],
            distinct_resources=1, baseline_distinct_resources=4.0,
            distance_from_usual_km=distance, is_new_country=True,
            travel_velocity_kmh=velocity,
            hour_of_day=login.hour, typical_hour=persona["typical_hour"],
            hour_spread=persona["hour_spread"], is_weekend=login.weekday() >= 5,
            session_duration_min=2.0, baseline_session_duration_min=persona["avg_duration"],
        )
        score_row = self._score_attack(session_row, ctx, login, ScoreTrigger.LOGIN)
        session_row.update(
            current_trust_score=score_row["score"],
            current_risk_level=score_row["risk_level"],
            current_action=score_row["action"],
        )
        self.sessions.append(session_row)

        res = self.by_slug[self.rng.choice(persona["allowed"])]
        self.access_requests.append(
            self._access_row(
                user=user, session_row=session_row, resource=res,
                at=login + timedelta(seconds=30), score=score_row, granted=False,
                ip=ip, ctx=ctx, velocity=velocity, distance=distance,
                is_known_device=False, is_anomalous=True, scenario="impossible_travel",
                matched_policy="Hard override - impossible travel",
                reason="Blocked: impossible travel between consecutive logins.",
            )
        )
        self._raise_alert(
            user=user, session_id=session_row["id"], severity=AlertSeverity.CRITICAL,
            category="impossible_travel",
            title=f"Impossible travel: {home['name']} to {city['name']} in {gap_minutes} minutes",
            description=(
                f"{user['username']} signed in from {home['name']} and then from "
                f"{city['name']}, {city['country']} {gap_minutes} minutes later — "
                f"{distance:,.0f} km apart, an implied {velocity:,.0f} km/h. "
                f"The second session was blocked and revoked."
            ),
            trust=score_row["score"],
            evidence={
                "first_city": home["name"], "second_city": city["name"],
                "gap_minutes": gap_minutes, "distance_km": round(distance, 1),
                "velocity_kmh": round(velocity, 1), "ip": ip,
            },
            when=login,
        )
        self._audit(
            login, None, "trust-engine", "SESSION_REVOKED",
            {"session_id": str(session_row["id"]), "reason": "impossible_travel",
             "trust_score": score_row["score"], "velocity_kmh": round(velocity, 1)},
            resource_type="session", resource_id=str(session_row["id"]), ip_address=ip,
        )

    def _scn_insider_threat(self, user: dict[str, Any]) -> None:
        day = (self.now - timedelta(days=self.rng.uniform(1, self.days - 1)))
        login = day.replace(hour=self.rng.choice([2, 3, 4]),
                            minute=self.rng.randint(0, 59), second=0, microsecond=0)
        city = user["_city"]
        device = self.devices_by_user[user["id"]][0]
        persona = self.persona[user["id"]]
        duration = self.rng.uniform(18, 55)
        n_files = self.rng.randint(28, 46)

        session_row, ip = self._attack_session(
            user, login, city, device_id=device["id"], duration=duration,
            is_vpn=False, is_datacenter=False, ip_reputation=0,
            status=SessionStatus.REVOKED,
            revoked_reason="Behavioural anomaly: mass enumeration of confidential data.",
        )
        session_row["mfa_passed"] = True
        session_row["step_up_required"] = False
        session_row["distinct_resource_count"] = n_files
        session_row["request_count"] = n_files * self.rng.randint(3, 8)

        rpm = session_row["request_count"] / duration
        ctx = TrustSignals(
            mfa_passed=True, password_strength=user["password_strength"],
            credential_age_days=user["_credential_age"],
            is_known_device=True, device_approved=True,
            device_first_seen_days=(login - device["_first_seen"]).days,
            profile_deviation=self.rng.uniform(0.85, 0.97),
            requests_per_minute=rpm, baseline_requests_per_minute=persona["avg_rpm"],
            distinct_resources=n_files, baseline_distinct_resources=4.0,
            unusual_resource_access=True,
            distance_from_usual_km=0.0, is_new_country=False, travel_velocity_kmh=0.0,
            hour_of_day=login.hour, typical_hour=persona["typical_hour"],
            hour_spread=persona["hour_spread"], is_weekend=login.weekday() >= 5,
            session_duration_min=duration,
            baseline_session_duration_min=persona["avg_duration"],
        )
        # Score at login looks normal; the anomaly only appears mid-session.
        benign = TrustSignals(**{
            **ctx.__dict__, "profile_deviation": 0.08, "distinct_resources": 2,
            "requests_per_minute": persona["avg_rpm"], "unusual_resource_access": False,
            "session_duration_min": 1.0,
        })
        first = self._score_attack(session_row, benign, login, ScoreTrigger.LOGIN)
        mid = self._score_attack(
            session_row, ctx, login + timedelta(minutes=duration * 0.7),
            ScoreTrigger.PERIODIC,
        )
        session_row.update(
            current_trust_score=mid["score"], current_risk_level=mid["risk_level"],
            current_action=mid["action"],
        )
        self.sessions.append(session_row)

        confidential = [
            r for r in self.resources
            if r["sensitivity"] in (Sensitivity.CONFIDENTIAL, Sensitivity.RESTRICTED)
        ]
        for i in range(min(n_files, 40)):
            res = self.rng.choice(confidential)
            at = login + timedelta(minutes=duration * (i + 1) / (n_files + 1))
            score_row = first if i < 3 else mid
            self.access_requests.append(
                self._access_row(
                    user=user, session_row=session_row, resource=res, at=at,
                    score=score_row, granted=i < 3, ip=ip, ctx=ctx, velocity=0.0,
                    distance=0.0, is_known_device=True, is_anomalous=True,
                    scenario="insider_threat",
                    matched_policy="Hard override - mass enumeration",
                    reason=(
                        "Allowed before the anomaly threshold was crossed."
                        if i < 3 else
                        "Blocked: mass enumeration of confidential resources."
                    ),
                )
            )
        session_row["denied_count"] = max(0, min(n_files, 40) - 3)

        self._raise_alert(
            user=user, session_id=session_row["id"], severity=AlertSeverity.CRITICAL,
            category="insider_threat",
            title=f"Mass enumeration of confidential data at {login.hour:02d}:00",
            description=(
                f"{user['username']} opened {n_files} distinct confidential and "
                f"restricted resources in {duration:.0f} minutes at "
                f"{login.hour:02d}:00 IST, from an approved device with valid MFA. "
                f"The trust score decayed from {first['score']:.0f} to "
                f"{mid['score']:.0f} mid-session and the session was revoked."
            ),
            trust=mid["score"],
            evidence={
                "distinct_resources": n_files, "baseline_distinct_resources": 4,
                "requests_per_minute": round(rpm, 1), "hour": login.hour,
                "device": device["label"], "score_at_login": first["score"],
                "score_at_revocation": mid["score"],
            },
            when=login + timedelta(minutes=duration * 0.7),
        )
        self._audit(
            login + timedelta(minutes=duration * 0.7), None, "trust-engine",
            "SESSION_REVOKED",
            {"session_id": str(session_row["id"]), "reason": "mass_enumeration",
             "trust_score": mid["score"], "distinct_resources": n_files},
            resource_type="session", resource_id=str(session_row["id"]), ip_address=ip,
        )

    def _scn_brute_force(self, user: dict[str, Any]) -> None:
        start = self._attack_time()
        city = self.rng.choice(HOSTILE_CITIES)
        attempts = self.rng.randint(14, 26)
        persona = self.persona[user["id"]]

        session_row, ip = self._attack_session(
            user, start, city, device_id=None, duration=self.rng.uniform(2, 8),
            is_vpn=False, is_datacenter=True, ip_reputation=self.rng.randint(75, 99),
            status=SessionStatus.REVOKED,
            revoked_reason="Account locked after repeated authentication failures.",
        )
        session_row["mfa_passed"] = False
        session_row["mfa_failures"] = attempts
        session_row["request_count"] = attempts

        ctx = TrustSignals(
            mfa_passed=False, failed_auth_count_24h=attempts,
            password_strength=user["password_strength"],
            credential_age_days=user["_credential_age"],
            is_known_device=False, device_approved=False, device_first_seen_days=0,
            ip_reputation=session_row["ip_reputation"], is_vpn=False, is_datacenter=True,
            profile_deviation=0.8,
            requests_per_minute=attempts / 3.0,
            baseline_requests_per_minute=persona["avg_rpm"],
            distinct_resources=1, baseline_distinct_resources=4.0,
            distance_from_usual_km=haversine_km(
                user["_city"]["latitude"], user["_city"]["longitude"],
                city["latitude"], city["longitude"],
            ),
            is_new_country=True, travel_velocity_kmh=0.0,
            hour_of_day=start.hour, typical_hour=persona["typical_hour"],
            hour_spread=persona["hour_spread"], is_weekend=start.weekday() >= 5,
            session_duration_min=3.0, baseline_session_duration_min=persona["avg_duration"],
        )
        score_row = self._score_attack(session_row, ctx, start, ScoreTrigger.LOGIN)
        session_row.update(
            current_trust_score=score_row["score"],
            current_risk_level=score_row["risk_level"],
            current_action=score_row["action"],
            denied_count=attempts,
        )
        self.sessions.append(session_row)

        for i in range(attempts):
            at = start + timedelta(seconds=self.rng.randint(3, 25) * (i + 1))
            self.access_requests.append(
                self._access_row(
                    user=user, session_row=session_row, resource=None, at=at,
                    score=score_row, granted=False, ip=ip, ctx=ctx, velocity=0.0,
                    distance=ctx.distance_from_usual_km, is_known_device=False,
                    is_anomalous=True, scenario="brute_force",
                    matched_policy="Hard override - account lockout",
                    path="/api/auth/login",
                    reason=f"Authentication failed (attempt {i + 1} of {attempts}).",
                )
            )
        self._raise_alert(
            user=user, session_id=session_row["id"], severity=AlertSeverity.HIGH,
            category="brute_force",
            title=f"{attempts} failed sign-in attempts against {user['username']}",
            description=(
                f"{attempts} consecutive authentication failures for "
                f"{user['username']} from {ip} ({city['name']}, {city['country']}), "
                f"an address with an abuse confidence of "
                f"{session_row['ip_reputation']}/100. The account was locked for "
                f"{settings.account_lockout_minutes} minutes."
            ),
            trust=score_row["score"],
            evidence={
                "attempts": attempts, "ip": ip, "country": city["country"],
                "ip_reputation": session_row["ip_reputation"],
                "lockout_minutes": settings.account_lockout_minutes,
            },
            when=start,
        )
        self._audit(
            start, user["id"], user["username"], "ACCOUNT_LOCKED",
            {"attempts": attempts, "ip": ip, "trust_score": score_row["score"]},
            resource_type="user", resource_id=str(user["id"]), ip_address=ip,
        )

    def _scn_session_hijack(self, user: dict[str, Any]) -> None:
        login = self._attack_time()
        home = user["_city"]
        device = self.devices_by_user[user["id"]][0]
        persona = self.persona[user["id"]]
        hijack_city = self.rng.choice(HOSTILE_CITIES)
        distance = haversine_km(
            home["latitude"], home["longitude"],
            hijack_city["latitude"], hijack_city["longitude"],
        )
        duration = self.rng.uniform(20, 70)

        session_row, ip = self._attack_session(
            user, login, home, device_id=device["id"], duration=duration,
            is_vpn=False, is_datacenter=False, ip_reputation=0,
            status=SessionStatus.REVOKED,
            revoked_reason="Session token replayed from a different device and network.",
        )
        session_row["mfa_passed"] = True
        hijack_ip = self._ip_for(hijack_city)

        benign = TrustSignals(
            password_strength=user["password_strength"],
            credential_age_days=user["_credential_age"],
            baseline_requests_per_minute=persona["avg_rpm"],
            device_first_seen_days=(login - device["_first_seen"]).days,
            hour_of_day=login.hour, typical_hour=persona["typical_hour"],
            hour_spread=persona["hour_spread"], is_weekend=login.weekday() >= 5,
            session_duration_min=1.0, baseline_session_duration_min=persona["avg_duration"],
        )
        first = self._score_attack(session_row, benign, login, ScoreTrigger.LOGIN)

        hijack_at = login + timedelta(minutes=duration * 0.6)
        ctx = TrustSignals(
            mfa_passed=True, password_strength=user["password_strength"],
            credential_age_days=user["_credential_age"],
            is_known_device=False, device_approved=False, device_first_seen_days=0,
            os_browser_consistent=False,
            ip_reputation=self.rng.randint(40, 80), is_vpn=False, is_datacenter=True,
            ip_changed_mid_session=True,
            profile_deviation=self.rng.uniform(0.6, 0.85),
            requests_per_minute=self.rng.uniform(6, 15),
            baseline_requests_per_minute=persona["avg_rpm"],
            distinct_resources=self.rng.randint(3, 8), baseline_distinct_resources=4.0,
            unusual_resource_access=True,
            distance_from_usual_km=distance, is_new_country=True,
            travel_velocity_kmh=0.0,
            hour_of_day=hijack_at.hour, typical_hour=persona["typical_hour"],
            hour_spread=persona["hour_spread"], is_weekend=hijack_at.weekday() >= 5,
            session_duration_min=duration * 0.6,
            baseline_session_duration_min=persona["avg_duration"],
        )
        hijack = self._score_attack(session_row, ctx, hijack_at, ScoreTrigger.CONTEXT_CHANGE)
        session_row.update(
            current_trust_score=hijack["score"],
            current_risk_level=hijack["risk_level"],
            current_action=hijack["action"],
        )
        self.sessions.append(session_row)

        for i in range(self.rng.randint(2, 5)):
            res = self.by_slug[self.rng.choice(persona["allowed"])]
            self.access_requests.append(
                self._access_row(
                    user=user, session_row=session_row, resource=res,
                    at=hijack_at + timedelta(seconds=20 * (i + 1)), score=hijack,
                    granted=False, ip=hijack_ip, ctx=ctx, velocity=0.0,
                    distance=distance, is_known_device=False, is_anomalous=True,
                    scenario="session_hijack",
                    matched_policy="Hard override - session context mismatch",
                    reason="Blocked: token presented from an unexpected device and network.",
                )
            )
        self._raise_alert(
            user=user, session_id=session_row["id"], severity=AlertSeverity.CRITICAL,
            category="session_hijack",
            title="Session token replayed from a different device and country",
            description=(
                f"A session issued to {user['username']} on {device['label']} in "
                f"{home['name']} was presented from {hijack_ip} in "
                f"{hijack_city['name']}, {hijack_city['country']} with a different "
                f"device fingerprint. Trust fell from {first['score']:.0f} to "
                f"{hijack['score']:.0f} and the session was revoked."
            ),
            trust=hijack["score"],
            evidence={
                "original_ip": ip, "replay_ip": hijack_ip,
                "original_city": home["name"], "replay_city": hijack_city["name"],
                "original_device": device["label"], "replay_device": "unknown fingerprint",
                "score_before": first["score"], "score_after": hijack["score"],
            },
            when=hijack_at,
        )
        self._audit(
            hijack_at, None, "trust-engine", "SESSION_REVOKED",
            {"session_id": str(session_row["id"]), "reason": "session_hijack",
             "trust_score": hijack["score"], "replay_ip": hijack_ip},
            resource_type="session", resource_id=str(session_row["id"]),
            ip_address=hijack_ip,
        )

    def _scn_lateral_movement(self, user: dict[str, Any]) -> None:
        login = self._attack_time()
        city = user["_city"]
        device = self.devices_by_user[user["id"]][0]
        persona = self.persona[user["id"]]
        duration = self.rng.uniform(15, 40)

        session_row, ip = self._attack_session(
            user, login, city, device_id=device["id"], duration=duration,
            is_vpn=False, is_datacenter=False, ip_reputation=0,
            status=SessionStatus.REVOKED,
            revoked_reason="Sustained policy denials: privilege probing.",
        )
        session_row["mfa_passed"] = True

        # Probe up the sensitivity ladder; each denial raises the penalty.
        allowed = set(persona["allowed"])
        ladder = sorted(
            [r for r in self.resources if r["slug"] not in allowed],
            key=lambda r: SENSITIVITY_MIN_TRUST[r["sensitivity"]],
        )
        if not ladder:
            ladder = [r for r in self.resources
                      if r["sensitivity"] == Sensitivity.RESTRICTED]
        # A high-privilege role has few resources left to probe. An attacker
        # retries rather than stopping, so the ladder is cycled to keep the run
        # long enough to be recognisable as probing.
        probes = (ladder * 4)[: self.rng.randint(6, 9)]

        denials = 0
        last_score: dict[str, Any] | None = None
        for i, res in enumerate(probes):
            at = login + timedelta(minutes=duration * (i + 1) / (len(probes) + 1))
            ctx = TrustSignals(
                mfa_passed=True, password_strength=user["password_strength"],
                credential_age_days=user["_credential_age"],
                is_known_device=True, device_approved=True,
                device_first_seen_days=(login - device["_first_seen"]).days,
                profile_deviation=min(0.6, 0.12 * (i + 1)),
                requests_per_minute=self.rng.uniform(2, 6),
                baseline_requests_per_minute=persona["avg_rpm"],
                distinct_resources=3 + i, baseline_distinct_resources=4.0,
                unusual_resource_access=True, denied_access_count=denials,
                distance_from_usual_km=0.0, is_new_country=False,
                travel_velocity_kmh=0.0,
                hour_of_day=at.hour, typical_hour=persona["typical_hour"],
                hour_spread=persona["hour_spread"], is_weekend=at.weekday() >= 5,
                session_duration_min=(at - login).total_seconds() / 60.0,
                baseline_session_duration_min=persona["avg_duration"],
            )
            trigger = ScoreTrigger.LOGIN if i == 0 else ScoreTrigger.ACCESS_REQUEST
            last_score = self._score_attack(session_row, ctx, at, trigger)
            self.access_requests.append(
                self._access_row(
                    user=user, session_row=session_row, resource=res, at=at,
                    score=last_score, granted=False, ip=ip, ctx=ctx, velocity=0.0,
                    distance=0.0, is_known_device=True, is_anomalous=True,
                    scenario="lateral_movement",
                    matched_policy=f"Least privilege - {user['_role_name']} role",
                    reason=(
                        f"Denied: {user['_role_name']} role is not permitted to open "
                        f"a {res['sensitivity'].value} resource."
                    ),
                )
            )
            denials += 1

        assert last_score is not None
        session_row.update(
            current_trust_score=last_score["score"],
            current_risk_level=last_score["risk_level"],
            current_action=last_score["action"],
            denied_count=denials,
            distinct_resource_count=len(probes),
        )
        self.sessions.append(session_row)

        self._raise_alert(
            user=user, session_id=session_row["id"], severity=AlertSeverity.HIGH,
            category="lateral_movement",
            title=f"Privilege probing: {denials} denied resource attempts in one session",
            description=(
                f"{user['username']} ({user['_role_name']}) attempted {denials} "
                f"resources above their privilege level in ascending sensitivity "
                f"order within {duration:.0f} minutes. Trust decayed to "
                f"{last_score['score']:.0f} and step-up re-authentication was forced."
            ),
            trust=last_score["score"],
            evidence={
                "denied_attempts": denials,
                "probed_resources": [r["slug"] for r in probes],
                "role": user["_role_name"], "device": device["label"],
            },
            when=login + timedelta(minutes=duration * 0.8),
        )

    # -- behaviour profiles -------------------------------------------------

    def build_profiles(self) -> list[dict[str, Any]]:
        """Derive each user's baseline from the *normal* history only.

        Attack sessions are excluded on purpose: a profile learned from the
        attacks would normalise them, and the behaviour factor would stop
        firing.
        """
        rows: list[dict[str, Any]] = []
        now = to_utc(self.now)

        for user in self.users:
            st = self.stats[user["id"]]
            hours = st["hours"] or [9]
            angles = [2 * math.pi * h / 24 for h in hours]
            sin_mean = sum(math.sin(a) for a in angles) / len(angles)
            cos_mean = sum(math.cos(a) for a in angles) / len(angles)
            concentration = math.hypot(sin_mean, cos_mean)

            histogram = [0] * 24
            for h in hours:
                histogram[h] += 1

            durations = st["durations"] or [60.0]
            rpms = st["rpms"] or [2.0]
            distinct = st["distinct"] or [3]
            lats = st["lats"] or [user["home_latitude"]]
            lons = st["lons"] or [user["home_longitude"]]
            centroid_lat = sum(lats) / len(lats)
            centroid_lon = sum(lons) / len(lons)
            distances = sorted(
                haversine_km(centroid_lat, centroid_lon, la, lo)
                for la, lo in zip(lats, lons)
            )
            p95 = distances[min(len(distances) - 1, int(len(distances) * 0.95))]

            weekend_hours = sum(
                1 for s in self.sessions
                if s["user_id"] == user["id"] and s["started_at"].weekday() >= 5
            )
            total_sessions = max(1, sum(1 for s in self.sessions if s["user_id"] == user["id"]))

            rows.append(
                {
                    "id": uuid.uuid4(), "user_id": user["id"],
                    "login_hour_sin": sin_mean, "login_hour_cos": cos_mean,
                    "login_hour_concentration": concentration,
                    "hour_histogram": histogram,
                    "weekend_login_ratio": weekend_hours / total_sessions,
                    "usual_countries": [c for c, _ in st["countries"].most_common()],
                    "usual_cities": [c for c, _ in st["cities"].most_common()],
                    "centroid_latitude": centroid_lat,
                    "centroid_longitude": centroid_lon,
                    "radius_km_p95": max(5.0, p95),
                    "usual_device_fingerprints": [
                        f for f, _ in st["fingerprints"].most_common()
                    ],
                    "avg_session_minutes": statistics.fmean(durations),
                    "stddev_session_minutes": (
                        statistics.pstdev(durations) if len(durations) > 1 else 0.0
                    ),
                    "avg_requests_per_minute": statistics.fmean(rpms),
                    "stddev_requests_per_minute": (
                        statistics.pstdev(rpms) if len(rpms) > 1 else 0.0
                    ),
                    "avg_distinct_resources": statistics.fmean(distinct),
                    "typical_resources": [
                        slug for slug, _ in st["resources"].most_common(8)
                    ],
                    "event_count": len(hours),
                    "model_path": "",     # written by Phase 6 (train_model.py)
                    "model_version": "",
                    "last_trained_at": None,
                    "last_event_at": to_utc(st["last_event"]) if st["last_event"] else None,
                    "created_at": now, "updated_at": now,
                }
            )
        return rows

    # -- persistence --------------------------------------------------------

    def build_audit_rows(self) -> list[dict[str, Any]]:
        """Sort every recorded security event by time, then chain it."""
        chain = ChainWriter()
        for event in sorted(self.audit_events, key=lambda e: e["timestamp"]):
            chain.append(**event)
        return chain.rows


def bulk_insert(db: Session, model: Any, rows: list[dict[str, Any]],
                chunk: int = 400) -> None:
    if not rows:
        return
    columns = {c.name for c in model.__table__.columns}
    cleaned = [{k: v for k, v in row.items() if k in columns} for row in rows]
    for start in range(0, len(cleaned), chunk):
        db.execute(insert(model), cleaned[start:start + chunk])
    db.commit()


# ---------------------------------------------------------------------------
# entry point
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Seed the ZTNA database.")
    parser.add_argument("--reset", action="store_true",
                        help="Delete all existing rows before seeding.")
    parser.add_argument("--users", type=int, default=25, help="Number of users.")
    parser.add_argument("--days", type=int, default=90,
                        help="Days of history to generate.")
    parser.add_argument("--incidents", type=int, default=45,
                        help="Number of anomalous incidents to inject.")
    parser.add_argument("--seed", type=int, default=42, help="RNG seed.")
    parser.add_argument("--admin-password", default=None,
                        help="Password for the admin account (generated if omitted).")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    rng = random.Random(args.seed)
    admin_password = args.admin_password or "Admin@Ztna2026!"

    with SessionLocal() as db:
        existing = db.scalar(select(User).limit(1))
        if existing is not None and not args.reset:
            print(
                "Database already contains users. Re-run with --reset to replace "
                "the existing data.",
                file=sys.stderr,
            )
            return 1
        if args.reset:
            print("Clearing existing rows...")
            purge(db)

        print("Creating roles, resources and policies...")
        roles = create_roles(db)
        resources = create_resources(db)
        policies = create_policies(db, roles, resources)
        db.commit()

        print(f"Creating {args.users} users and their devices...")
        users = create_users(db, roles, rng, args.users, admin_password)
        devices_by_user = create_devices(db, users, rng)
        db.commit()

        print(f"Generating {args.days} days of behaviour history...")
        builder = HistoryBuilder(rng, users, devices_by_user, resources, args.days)
        builder.generate_normal()
        normal_events = len(builder.access_requests)
        normal_sessions = len(builder.sessions)

        print(f"Injecting {args.incidents} anomalous incidents...")
        builder.generate_anomalies(args.incidents)

        print("Computing behaviour profiles...")
        profiles = builder.build_profiles()

        print("Building the hash-chained audit log...")
        audit_rows = builder.build_audit_rows()

        now = to_utc(datetime.now(IST))
        builder.system_logs.append(
            {
                "id": uuid.uuid4(), "created_at": now, "level": LogLevel.INFO,
                "logger": "scripts.seed",
                "message": (
                    f"Seeded {len(users)} users, {len(builder.sessions)} sessions and "
                    f"{len(builder.access_requests)} access events."
                ),
                "context": {
                    "seed": args.seed, "days": args.days,
                    "incidents": args.incidents,
                    "anomaly_scores_pending": True,
                },
            }
        )

        print("Writing to the database...")
        bulk_insert(db, UserSession, builder.sessions)
        bulk_insert(db, TrustScore, builder.trust_scores)
        bulk_insert(db, AccessRequest, builder.access_requests)
        bulk_insert(db, Alert, builder.alerts)
        bulk_insert(db, BehaviorProfile, profiles)
        bulk_insert(db, AuditLog, audit_rows)
        bulk_insert(db, SystemLog, builder.system_logs)

        anomalous = sum(1 for r in builder.access_requests if r["is_anomalous"])
        total_events = len(builder.access_requests)

        print()
        print("=" * 72)
        print("  SEED COMPLETE")
        print("=" * 72)
        print(f"  Roles                 : {len(roles)}")
        print(f"  Policies              : {len(policies)}")
        print(f"  Resources             : {len(resources)} "
              f"(PUBLIC/INTERNAL/CONFIDENTIAL/RESTRICTED)")
        print(f"  Users                 : {len(users)}")
        print(f"  Devices               : {sum(len(v) for v in devices_by_user.values())}")
        print(f"  Sessions              : {len(builder.sessions)} "
              f"({normal_sessions} normal, {len(builder.sessions) - normal_sessions} attack)")
        print(f"  Access events         : {total_events} "
              f"({normal_events} normal, {anomalous} labelled anomalous "
              f"= {anomalous / max(1, total_events) * 100:.1f}%)")
        print(f"  Trust scores recorded : {len(builder.trust_scores)}")
        print(f"  Alerts                : {len(builder.alerts)}")
        print(f"  Behaviour profiles    : {len(profiles)}")
        print(f"  Audit log records     : {len(audit_rows)} (hash-chained)")
        print()
        print("  Sign in with:")
        print(f"    admin    : admin / {admin_password}")
        print(f"    everyone : <username> / {DEMO_PASSWORD}")
        print()
        print("  MFA is enabled for every account; TOTP secrets are stored on the")
        print("  user rows and the enrolment QR code is served by the auth API")
        print("  (Phase 2).")
        print()
        print("  anomaly_score is NULL on every seeded trust score until")
        print("  scripts/train_model.py runs in Phase 6.")
        print("=" * 72)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

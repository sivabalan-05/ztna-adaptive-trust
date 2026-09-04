"""Shared harness for the attack demonstrations.

Every demo drives the **running API over HTTP**, exactly as a browser would.
Nothing reaches into the database to fake a result: the scores you see are the
scores the engine produced, and the dashboard updates live while the script
runs. That is the whole point — a demo that wrote its own conclusions would
prove nothing.

Usage:

    python scripts/demo/credential_theft.py
    python scripts/demo/run_all.py
"""

from __future__ import annotations

import hashlib
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

ROOT_DIR = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT_DIR / "backend"))

import httpx  # noqa: E402
from sqlalchemy import select  # noqa: E402

from app.core.database import SessionLocal  # noqa: E402
from app.external import mfa  # noqa: E402
from app.models import User  # noqa: E402

API = "http://127.0.0.1:8000"

DEMO_PASSWORD = "Ztna@Demo2026"
ADMIN_PASSWORD = "Admin@Ztna2026!"

# --- known contexts, so a demo can say where it is coming from ---------------

CONTEXTS: dict[str, dict[str, str]] = {
    "office_coimbatore": {"ip": "117.192.10.20", "label": "office, Coimbatore"},
    "office_chennai": {"ip": "106.51.30.9", "label": "office, Chennai"},
    "office_bangalore": {"ip": "49.207.11.2", "label": "office, Bangalore"},
    "home_dubai": {"ip": "5.32.44.7", "label": "residential, Dubai"},
    "hosting_kyiv": {"ip": "185.234.9.1", "label": "hosting provider, Kyiv"},
    "hosting_brazil": {"ip": "191.96.4.4", "label": "datacenter, Sao Paulo"},
    "tor_lagos": {"ip": "197.210.44.9", "label": "Tor exit node, Lagos"},
    "vpn_amsterdam": {"ip": "45.83.91.7", "label": "commercial VPN, Amsterdam"},
}

MAC_UA = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/18.0 Safari/605.1.15"
)
WINDOWS_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36"
)


# --- presentation -----------------------------------------------------------

BOLD, DIM, RESET = "\033[1m", "\033[2m", "\033[0m"
GREEN, YELLOW, ORANGE, RED = "\033[32m", "\033[33m", "\033[38;5;208m", "\033[31m"

BAND_COLOR = {
    "LOW": GREEN, "MEDIUM": YELLOW, "HIGH": ORANGE, "CRITICAL": RED,
}


def header(number: int, title: str, expectation: str) -> None:
    print()
    print("=" * 78)
    print(f"  SCENARIO {number} — {BOLD}{title}{RESET}")
    print(f"  Expected outcome: {expectation}")
    print("=" * 78)


def step(text: str) -> None:
    print(f"\n  {BOLD}▸{RESET} {text}")


def detail(text: str) -> None:
    print(f"      {DIM}{text}{RESET}")


def score_line(score: float, band: str, action: str, reason: str = "") -> None:
    colour = BAND_COLOR.get(band, "")
    print(
        f"      trust {colour}{BOLD}{score:5.1f}{RESET}  "
        f"{colour}{band:<9}{RESET} {action.replace('_', ' ').lower()}"
    )
    if reason:
        print(f"      {DIM}{reason[:110]}{RESET}")


def verdict(passed: bool, message: str) -> bool:
    mark = f"{GREEN}PASS{RESET}" if passed else f"{RED}FAIL{RESET}"
    print(f"\n  [{mark}] {message}")
    return passed


def fingerprint(seed: str) -> str:
    return hashlib.sha256(seed.encode()).hexdigest()


def totp_for(username: str) -> str:
    """The code that user's authenticator app would be showing."""
    with SessionLocal() as db:
        user = db.scalar(select(User).where(User.username == username))
        if user is None or not user.mfa_secret:
            raise RuntimeError(f"{username} has no MFA secret; run scripts/seed.py")
        secret = user.mfa_secret
    # Never hand back a code about to roll over mid-request.
    remaining = mfa.TOTP_INTERVAL_SECONDS - int(time.time()) % mfa.TOTP_INTERVAL_SECONDS
    if remaining < 3:
        time.sleep(remaining + 1)
    return mfa.current_code(secret)


def pick_user(role: str = "employee", index: int = 0) -> str:
    """A seeded username with the given role.

    ``index`` lets each scenario take a different account. The login limiter
    keys on the username as well as the address, so seven scenarios sharing one
    employee would throttle each other.
    """
    from app.models import Role

    with SessionLocal() as db:
        rows = db.scalars(
            select(User).join(Role).where(Role.name == role).order_by(User.username)
        ).all()
    if not rows:
        raise RuntimeError(f"No seeded user with role '{role}'")
    return rows[index % len(rows)].username


def unlock_user(username: str) -> bool:
    """Clear a lockout, as an administrator would.

    The brute-force scenario locks its target for 15 minutes. Leaving it locked
    would make the demo runnable exactly once, so the script tidies up after
    itself — and says so, because silently undoing a security control in a
    security demo would be the wrong lesson.
    """
    admin = DemoClient(device_seed="demo-operator-console", host=99)
    try:
        admin.sign_in("admin", ADMIN_PASSWORD)
        found = admin.http.get(
            "/api/users", headers=admin.headers(), params={"q": username}
        )
        found.raise_for_status()
        rows = found.json()
        if not rows:
            return False
        response = admin.http.patch(
            f"/api/users/{rows[0]['id']}",
            headers=admin.headers(),
            json={"unlock": True},
        )
        return response.status_code == 200
    except Exception:
        return False
    finally:
        admin.close()


# --- the client -------------------------------------------------------------

@dataclass
class Session:
    """One authenticated session, as a client would hold it."""

    access_token: str
    refresh_token: str
    session_id: str
    username: str
    trust_score: float
    risk_level: str
    action: str
    reason: str


@dataclass
class DemoClient:
    """An HTTP client that can claim any device and any source address.

    Being able to set both is what makes the attack scenarios expressible: a
    stolen credential replayed from another machine in another country is
    exactly a different fingerprint and a different X-Forwarded-For.
    """

    device_seed: str
    context: str = "office_coimbatore"
    #: Last octet of the source address. Scenarios use distinct values so the
    #: per-IP login limiter does not make them throttle one another — the
    #: limiter is doing its job, they simply are not the same client.
    host: int = 20
    user_agent: str = MAC_UA
    platform: str = "MacIntel"
    screen: str = "2560x1664"
    timezone: str = "Asia/Kolkata"
    session: Session | None = None
    http: httpx.Client = field(
        default_factory=lambda: httpx.Client(base_url=API, timeout=20.0)
    )

    @property
    def ip(self) -> str:
        prefix = CONTEXTS[self.context]["ip"].rsplit(".", 1)[0]
        return f"{prefix}.{self.host}"

    @property
    def where(self) -> str:
        return CONTEXTS[self.context]["label"]

    def headers(self, authed: bool = True) -> dict[str, str]:
        out = {
            "Content-Type": "application/json",
            "X-Device-Fingerprint": fingerprint(self.device_seed),
            "X-Forwarded-For": self.ip,
            "User-Agent": self.user_agent,
            "X-Device-Platform": self.platform,
            "X-Device-Screen": self.screen,
            "X-Device-Timezone": self.timezone,
        }
        if authed and self.session:
            out["Authorization"] = f"Bearer {self.session.access_token}"
        return out

    # -- auth ---------------------------------------------------------------

    def password_step(self, username: str, password: str) -> httpx.Response:
        return self.http.post(
            "/api/auth/login",
            headers=self.headers(authed=False),
            json={"username": username, "password": password},
        )

    def sign_in(self, username: str, password: str = DEMO_PASSWORD) -> Session:
        first = self.password_step(username, password)
        first.raise_for_status()
        challenge = first.json()

        second = self.http.post(
            "/api/auth/mfa/verify",
            headers=self.headers(authed=False),
            json={"mfa_token": challenge["mfa_token"], "code": totp_for(username)},
        )
        second.raise_for_status()
        body = second.json()

        self.session = Session(
            access_token=body["access_token"],
            refresh_token=body["refresh_token"],
            session_id=body["session_id"],
            username=username,
            trust_score=body.get("trust_score") or 0.0,
            risk_level=body.get("risk_level") or "UNKNOWN",
            action=body.get("action") or "",
            reason=body.get("trust_reason") or "",
        )
        return self.session

    # -- activity -----------------------------------------------------------

    def access(self, slug: str) -> tuple[int, dict[str, Any]]:
        response = self.http.post(
            f"/api/resources/{slug}/access", headers=self.headers()
        )
        try:
            return response.status_code, response.json()
        except ValueError:
            return response.status_code, {}

    def current_score(self) -> tuple[float, str]:
        """Read the live score.

        A denied access request returns the error envelope, not the decision
        body, so the score has to come from the trust API rather than from
        whatever the last 403 happened to contain.
        """
        response = self.http.get("/api/trust/me", headers=self.headers())
        if response.status_code != 200:
            return 0.0, "TERMINATED"
        body = response.json()
        return float(body["score"]), str(body["risk_level"])

    def rescore(self) -> dict[str, Any]:
        response = self.http.post("/api/trust/me/evaluate", headers=self.headers())
        response.raise_for_status()
        return response.json()

    def me(self) -> httpx.Response:
        return self.http.get("/api/auth/me", headers=self.headers())

    def resources(self) -> list[dict[str, Any]]:
        response = self.http.get("/api/resources", headers=self.headers())
        response.raise_for_status()
        return response.json()

    def close(self) -> None:
        self.http.close()


def approve_devices_for(username: str) -> int:
    """Approve every pending device for one user, as an administrator would.

    A genuinely *established* user has approved devices. Without this the happy
    path would be measuring a first-day employee on a brand-new laptop, which is
    a different scenario and legitimately scores lower.
    """
    admin = DemoClient(device_seed="demo-operator-console", host=99)
    try:
        admin.sign_in("admin", ADMIN_PASSWORD)
        response = admin.http.get(
            "/api/users", headers=admin.headers(), params={"q": username}
        )
        response.raise_for_status()
        rows = response.json()
        if not rows:
            return 0
        user_id = rows[0]["id"]

        devices = admin.http.get("/api/devices", headers=admin.headers())
        devices.raise_for_status()
        approved = 0
        for device in devices.json():
            if device["status"] == "PENDING":
                result = admin.http.post(
                    f"/api/devices/{device['id']}/approve", headers=admin.headers()
                )
                if result.status_code == 200:
                    approved += 1
        return approved
    finally:
        admin.close()


def require_api() -> bool:
    """The demos need the server running; say so plainly if it is not."""
    try:
        response = httpx.get(f"{API}/health", timeout=3.0)
        response.raise_for_status()
    except Exception:
        print(
            f"\n  {RED}The API is not answering at {API}.{RESET}\n"
            f"  Start it first:  make api    (or  docker compose up)\n"
        )
        return False
    return True

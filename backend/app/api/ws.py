"""Live event stream over WebSocket.

Browsers cannot set an ``Authorization`` header on a WebSocket handshake. The
usual workaround is to put the access token in the query string, which then
lands in proxy logs, browser history and Referer headers — a 15-minute bearer
token sitting in plain text on disk.

So the handshake uses a **ticket** instead: the client exchanges its normal
bearer token for a single-use, 30-second string over ordinary HTTP, and spends
that on the WebSocket. A leaked ticket is worth almost nothing; it is bound to
one session, expires in half a minute, and is consumed on first use.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import secrets
import uuid

from fastapi import APIRouter, Depends, Query, WebSocket, WebSocketDisconnect
from sqlalchemy.orm import Session

from app.core.cache import cache
from app.core.database import get_session_factory
from app.core.dependencies import Principal, get_principal
from app.models.base import utcnow
from app.models.enums import SessionStatus
from app.models.session import UserSession
from app.models.user import User
from app.services.events import Event, bus

logger = logging.getLogger(__name__)
router = APIRouter(tags=["live"])

TICKET_TTL_SECONDS = 30
TICKET_PREFIX = "ws:ticket:"

#: How often an idle connection sends a keepalive. Also the interval at which
#: the server re-checks that the session is still alive, which is what closes
#: a revoked user's socket without waiting for them to send anything.
HEARTBEAT_SECONDS = 5

OPERATOR_ROLES = {"admin", "security_analyst"}


@router.post("/api/ws/ticket", summary="Exchange a bearer token for a WebSocket ticket")
def issue_ticket(principal: Principal = Depends(get_principal)) -> dict[str, object]:
    """Single-use, 30 seconds, bound to this session."""
    ticket = secrets.token_urlsafe(32)
    cache.set(
        f"{TICKET_PREFIX}{ticket}",
        json.dumps(
            {
                "user_id": str(principal.user.id),
                "session_id": str(principal.session.id),
            }
        ),
        TICKET_TTL_SECONDS,
    )
    return {
        "ticket": ticket,
        "expires_in": TICKET_TTL_SECONDS,
        "url": "/ws/live",
    }


def _consume_ticket(ticket: str) -> dict[str, str] | None:
    """Redeem a ticket exactly once."""
    key = f"{TICKET_PREFIX}{ticket}"
    raw = cache.get(key)
    if raw is None:
        return None
    cache.delete(key)          # single use: a replayed ticket finds nothing
    try:
        return json.loads(raw)
    except ValueError:
        return None


def _session_still_live(factory, session_id: uuid.UUID) -> tuple[bool, str]:
    """Re-read the session from the database.

    Checked on every heartbeat, not just at connect. A socket opened while a
    session was healthy must not survive that session being revoked.
    """
    with factory() as db:
        session = db.get(UserSession, session_id)
        if session is None:
            return False, "Session no longer exists."
        if session.status is not SessionStatus.ACTIVE:
            return False, session.revoked_reason or f"Session is {session.status.value.lower()}."
        return True, ""


@router.websocket("/ws/live")
async def live(
    websocket: WebSocket,
    ticket: str = Query(..., description="From POST /api/ws/ticket"),
    session_factory=Depends(get_session_factory),
) -> None:
    """Stream trust-score changes, revocations and alerts as they happen."""
    claims = _consume_ticket(ticket)
    if claims is None:
        # 1008 = policy violation. Closed before accept, so nothing is streamed.
        await websocket.close(code=1008, reason="Invalid or expired ticket.")
        return

    user_id = uuid.UUID(claims["user_id"])
    session_id = uuid.UUID(claims["session_id"])

    with session_factory() as db:
        user = db.get(User, user_id)
        session = db.get(UserSession, session_id)
        if user is None or session is None or session.status is not SessionStatus.ACTIVE:
            await websocket.close(code=1008, reason="Session is not active.")
            return
        is_operator = user.role.name in OPERATOR_ROLES or user.role.is_admin
        username = user.username

    await websocket.accept()
    logger.info(
        "WebSocket open for %s (%s)", username, "operator" if is_operator else "self"
    )

    await websocket.send_text(
        Event(
            type="connected",
            payload={
                "username": username,
                "session_id": str(session_id),
                "scope": "all-sessions" if is_operator else "own-session",
                "heartbeat_seconds": HEARTBEAT_SECONDS,
            },
        ).to_json()
    )

    try:
        async with bus.subscribe() as queue:
            while True:
                try:
                    event = await asyncio.wait_for(
                        queue.get(), timeout=HEARTBEAT_SECONDS
                    )
                except TimeoutError:
                    alive, reason = await asyncio.to_thread(
                        _session_still_live, session_factory, session_id
                    )
                    if not alive:
                        await websocket.send_text(
                            Event(
                                type="session.terminated",
                                payload={"session_id": str(session_id), "reason": reason},
                            ).to_json()
                        )
                        await websocket.close(code=1000, reason="Session revoked.")
                        return
                    await websocket.send_text(
                        Event(type="heartbeat", payload={"at": utcnow().isoformat()}).to_json()
                    )
                    continue

                if not event.visible_to(str(user_id), is_operator):
                    continue

                await websocket.send_text(event.to_json())

                # A revocation aimed at this session ends the connection now,
                # rather than at the next heartbeat.
                if (
                    event.type in ("session.revoked", "session.expired")
                    and event.payload.get("session_id") == str(session_id)
                ):
                    await websocket.close(code=1000, reason="Session revoked.")
                    return
    except WebSocketDisconnect:
        logger.info("WebSocket closed by %s", username)
    except Exception:
        logger.exception("WebSocket error for %s", username)
        with contextlib.suppress(Exception):
            await websocket.close(code=1011, reason="Internal error.")

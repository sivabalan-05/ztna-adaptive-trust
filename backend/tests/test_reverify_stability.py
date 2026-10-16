"""Re-verifying a session must not, by itself, move its trust score."""

from __future__ import annotations

from fastapi.testclient import TestClient

from app.models import User
from tests.conftest import auth_headers, sign_in


def test_repeated_reverification_does_not_lower_the_score(
    client: TestClient, user: User
) -> None:
    """Every "Re-verify now" is an authenticated request. If those requests were
    counted as the user's behavioural request rate, each click would raise the
    measured rate and the score would fall a little more every time."""
    headers = auth_headers(sign_in(client, user))

    scores = [
        client.post("/api/trust/me/evaluate", headers=headers).json()["score"]
        for _ in range(12)
    ]

    assert len(set(scores)) == 1, f"score drifted across re-verifications: {scores}"

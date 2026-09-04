#!/usr/bin/env python3
"""Print the TOTP code a seeded user's authenticator app would be showing.

Demo and testing aid: the seeded accounts have MFA secrets in the database but
nobody has scanned their QR codes, so there is no phone to read a code from.

    python scripts/totp.py admin
    python scripts/totp.py admin --watch

Real enrolment goes through POST /api/auth/mfa/enrol, which returns a QR code
for Google Authenticator; this script never touches that path.
"""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR / "backend"))

from sqlalchemy import select  # noqa: E402

from app.core.database import SessionLocal  # noqa: E402
from app.external import mfa  # noqa: E402
from app.models import User  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("username", help="Username or email address")
    parser.add_argument(
        "--watch", action="store_true",
        help="Keep printing as the 30-second window rolls over.",
    )
    args = parser.parse_args()

    with SessionLocal() as db:
        user = db.scalar(
            select(User).where(
                (User.username == args.username) | (User.email == args.username)
            )
        )
        if user is None:
            print(f"No such user: {args.username}", file=sys.stderr)
            return 1
        if not user.mfa_secret:
            print(
                f"{user.username} has no MFA secret. Enrol via "
                f"POST /api/auth/mfa/enrol.",
                file=sys.stderr,
            )
            return 1
        secret = user.mfa_secret
        username = user.username

    if not args.watch:
        remaining = mfa.TOTP_INTERVAL_SECONDS - int(time.time()) % mfa.TOTP_INTERVAL_SECONDS
        print(f"{username}: {mfa.current_code(secret)}  (valid for {remaining}s)")
        return 0

    print(f"Watching codes for {username}. Press Ctrl+C to stop.")
    last = ""
    try:
        while True:
            code = mfa.current_code(secret)
            if code != last:
                remaining = (
                    mfa.TOTP_INTERVAL_SECONDS
                    - int(time.time()) % mfa.TOTP_INTERVAL_SECONDS
                )
                print(f"  {code}  (valid for {remaining}s)")
                last = code
            time.sleep(1)
    except KeyboardInterrupt:
        return 0


if __name__ == "__main__":
    raise SystemExit(main())

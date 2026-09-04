"""Background worker entry point.

Started by Compose as ``python -m app.workers.runner``. Runs every scheduled
job in one process on independent loops:

* **retrain** — rebuilds the Isolation Forest nightly (Phase 6).
* **continuous verification** — re-scores every active session on the
  configured interval (Phase 8, not yet wired in).

Each loop catches its own exceptions: one failing job must never take the
others down with it.
"""

from __future__ import annotations

import asyncio
import logging
import signal
from datetime import datetime, timezone

from app.core.config import settings
from app.workers import continuous_verification, retrain

logging.basicConfig(
    level=logging.DEBUG if settings.debug else logging.INFO,
    format="%(asctime)s %(levelname)-8s %(name)s :: %(message)s",
)
logger = logging.getLogger("ztna.worker")

RETRAIN_HOUR_UTC = 2
RETRAIN_CHECK_SECONDS = 900   # 15 minutes


async def retrain_loop(stop: asyncio.Event) -> None:
    """Retrain once per day, during the retrain hour."""
    last_run_date: str | None = None

    while not stop.is_set():
        try:
            now = datetime.now(timezone.utc)
            today = now.date().isoformat()
            if retrain.due(now, RETRAIN_HOUR_UTC) and last_run_date != today:
                logger.info("Starting the nightly retrain.")
                result = await asyncio.to_thread(retrain.retrain_and_log)
                last_run_date = today
                logger.info("Nightly retrain finished: %s", result.message)
        except Exception:
            logger.exception("Retrain loop error; continuing.")

        try:
            await asyncio.wait_for(stop.wait(), timeout=RETRAIN_CHECK_SECONDS)
        except TimeoutError:
            continue


async def verification_loop(stop: asyncio.Event) -> None:
    """Re-score every active session on the configured interval.

    Only runs here when Redis is configured. Without it the in-process event
    bus cannot reach the API's WebSocket clients, so the API runs the sweep
    itself and this process stands down rather than scoring sessions whose
    results nobody would ever see.
    """
    if settings.verification_in_api:
        logger.info(
            "Continuous verification is running inside the API process "
            "(no REDIS_URL); this worker will not duplicate it."
        )
        await stop.wait()
        return

    await continuous_verification.verification_loop(stop)


async def main() -> None:
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        with_handler = getattr(loop, "add_signal_handler", None)
        if with_handler is not None:
            try:
                loop.add_signal_handler(sig, stop.set)
            except NotImplementedError:      # pragma: no cover - Windows
                pass

    logger.info("Worker starting (env=%s)", settings.app_env)
    await asyncio.gather(retrain_loop(stop), verification_loop(stop))
    logger.info("Worker stopped.")


if __name__ == "__main__":
    asyncio.run(main())

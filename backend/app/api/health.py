"""Liveness / readiness endpoints, also used by the Compose healthcheck."""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends
from sqlalchemy import inspect, text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.core.cache import cache_kind
from app.core.config import settings
from app.core.database import engine, get_db
from app.ai import anomaly
from app.external import geoip, ip_reputation, notification
from app.schemas.common import HealthResponse

logger = logging.getLogger(__name__)
router = APIRouter(tags=["health"])

VERSION = "0.1.0"


@router.get("/health", response_model=HealthResponse, summary="Service health")
def health(db: Session = Depends(get_db)) -> HealthResponse:
    reachable = True
    table_count = 0
    try:
        db.execute(text("SELECT 1"))
        table_count = len(inspect(engine).get_table_names())
    except SQLAlchemyError:
        logger.exception("Health check could not reach the database")
        reachable = False

    return HealthResponse(
        status="ok" if reachable else "degraded",
        app=settings.app_name,
        version=VERSION,
        environment=settings.app_env,
        database=engine.dialect.name,
        database_reachable=reachable,
        cache=cache_kind(),
        tables=table_count,
        providers={
            "geoip": geoip.get_provider().info.name,
            "ip_reputation": ip_reputation.get_provider().info.name,
            "notification": notification.get_provider().info.name,
            "anomaly_model": (
                (anomaly.model_info() or {}).get("version") or "not trained"
            ),
        },
    )

"""SQLAlchemy engine, session factory and declarative base.

The same models run on PostgreSQL (Docker Compose, the graded deployment) and
on SQLite (a laptop with no Docker).  Dialect differences are confined to this
module plus the ``JSONColumn`` helper in ``app.models.base``.
"""

from __future__ import annotations

from collections.abc import Generator
from typing import Any

from sqlalchemy import MetaData, create_engine, event
from sqlalchemy.engine import Engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from app.core.config import settings

# Deterministic constraint names, so Alembic can ALTER them on both dialects
# (SQLite in particular cannot drop an unnamed constraint).
NAMING_CONVENTION = {
    "ix": "ix_%(column_0_label)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}


class Base(DeclarativeBase):
    """Declarative base shared by every ORM model."""

    metadata = MetaData(naming_convention=NAMING_CONVENTION)


def _engine_kwargs() -> dict[str, Any]:
    kwargs: dict[str, Any] = {"echo": settings.sql_echo, "future": True}
    if settings.is_sqlite:
        # FastAPI serves sync endpoints from a threadpool, so a connection may
        # legitimately move between threads.
        kwargs["connect_args"] = {"check_same_thread": False}
    else:
        kwargs.update(pool_pre_ping=True, pool_size=10, max_overflow=20)
    return kwargs


engine: Engine = create_engine(settings.database_url, **_engine_kwargs())


@event.listens_for(Engine, "connect")
def _sqlite_pragmas(dbapi_connection: Any, _record: Any) -> None:
    """Enable foreign keys and WAL on SQLite (both are off by default)."""
    if not settings.is_sqlite:
        return
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.execute("PRAGMA journal_mode=WAL")
    cursor.close()


SessionLocal = sessionmaker(
    bind=engine,
    autoflush=False,
    autocommit=False,
    expire_on_commit=False,
    class_=Session,
)


def get_session_factory() -> sessionmaker:
    """The session factory, as an injectable dependency.

    WebSocket handlers and background sweeps cannot hold a request-scoped
    session for their whole lifetime — they open short-lived ones as needed.
    Going through this dependency means a test can point them at its own
    database instead of the real one.
    """
    return SessionLocal


def get_db() -> Generator[Session, None, None]:
    """FastAPI dependency yielding a request-scoped session."""
    db = SessionLocal()
    try:
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()

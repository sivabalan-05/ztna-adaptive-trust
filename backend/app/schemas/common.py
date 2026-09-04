"""Response envelopes shared across routers."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from app.models.base import utcnow


class ORMModel(BaseModel):
    """Base for schemas read directly from SQLAlchemy objects."""

    model_config = ConfigDict(from_attributes=True)


class ErrorResponse(BaseModel):
    """The only error shape the API ever returns — never a stack trace."""

    detail: str = Field(description="Human-readable, safe-to-display message")
    code: str = Field(default="error", description="Stable machine-readable code")
    request_id: str | None = None


class HealthResponse(BaseModel):
    status: Literal["ok", "degraded"] = "ok"
    app: str
    version: str
    environment: str
    database: str = Field(description="Dialect in use, e.g. postgresql or sqlite")
    database_reachable: bool
    cache: str = Field(description="redis or in-memory")
    tables: int = Field(description="Number of tables present in the schema")
    providers: dict[str, str] = Field(
        default_factory=dict,
        description="Which implementation is answering for each external service",
    )
    time: datetime = Field(default_factory=utcnow)

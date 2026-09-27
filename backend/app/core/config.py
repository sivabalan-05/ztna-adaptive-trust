"""Application configuration.

Every value is sourced from the environment (see ``.env.example``); nothing
security-relevant is hardcoded.  The defaults are chosen so that the project
boots on a laptop with no Docker, no PostgreSQL and no internet connection.
"""

from __future__ import annotations

import secrets
from functools import lru_cache
from pathlib import Path
from typing import Literal
from urllib.parse import urlsplit

from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

BACKEND_DIR: Path = Path(__file__).resolve().parents[2]
ROOT_DIR: Path = BACKEND_DIR.parent


class Settings(BaseSettings):
    """Typed, validated runtime configuration."""

    model_config = SettingsConfigDict(
        env_file=(ROOT_DIR / ".env", BACKEND_DIR / ".env"),
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # --- Application --------------------------------------------------------
    app_name: str = "AI-Based Zero Trust Network Access"
    app_env: Literal["development", "test", "production"] = "development"
    debug: bool = True
    api_port: int = 8000

    # --- Security -----------------------------------------------------------
    secret_key: str = Field(default_factory=lambda: secrets.token_urlsafe(64))
    jwt_algorithm: str = "HS256"
    access_token_expire_minutes: int = 15
    refresh_token_expire_days: int = 30
    mfa_issuer: str = "ZTNA Platform"

    # --- Persistence --------------------------------------------------------
    database_url: str = f"sqlite:///{(ROOT_DIR / 'ztna.db').as_posix()}"
    sql_echo: bool = False
    redis_url: str | None = None
    #: Where uploaded resource files are written. Kept out of the database so
    #: ztna.db stays small and portable; never served statically.
    resource_storage_dir: Path = ROOT_DIR / "storage" / "resources"
    #: Set to `s3` to use an S3-compatible provider such as Cloudflare R2.
    resource_storage_backend: Literal["local", "s3"] = "local"
    s3_bucket_name: str = ""
    s3_endpoint_url: str = ""
    s3_region: str = "auto"
    s3_addressing_style: Literal["auto", "path", "virtual"] = "auto"
    s3_access_key_id: str = ""
    s3_secret_access_key: str = ""
    s3_key_prefix: str = "ztna/resources"

    # --- Trust scoring weights (sum must be 100) ----------------------------
    trust_weight_identity: int = 25
    trust_weight_device: int = 20
    trust_weight_network: int = 20
    trust_weight_behavior: int = 20
    trust_weight_location: int = 10
    trust_weight_temporal: int = 5

    # --- Risk bands (inclusive lower bound of each band) --------------------
    risk_low_min: int = 80
    risk_medium_min: int = 60
    risk_high_min: int = 40

    # --- Continuous verification -------------------------------------------
    continuous_verification_interval_seconds: int = 30
    #: Where the verification sweep runs. Left unset it follows REDIS_URL: with
    #: Redis the separate worker process owns it and publishes over pub/sub;
    #: without Redis the in-process event bus cannot cross a process boundary,
    #: so the API runs it itself. Set explicitly to override.
    run_verification_in_api: bool | None = None
    session_idle_timeout_minutes: int = 480
    impossible_travel_kmh: float = 900.0
    max_failed_logins: int = 5
    account_lockout_minutes: int = 15

    # --- AI models ----------------------------------------------------------
    model_dir: Path = ROOT_DIR / "models"
    isolation_forest_contamination: float = 0.05
    isolation_forest_estimators: int = 200
    isolation_forest_random_state: int = 42
    per_user_model_min_events: int = 50
    #: Off by default: per-user models measure worse than the global one on the
    #: seeded corpus (see docs and scripts/train_model.py).
    use_per_user_models: bool = False

    # --- External services (optional; mocks are used when unset) ------------
    geoip_db_path: Path = ROOT_DIR / "data" / "GeoLite2-City.mmdb"
    abuseipdb_api_key: str | None = None
    smtp_host: str | None = None
    smtp_port: int = 587
    smtp_user: str | None = None
    smtp_password: str | None = None
    smtp_from: str = "ztna-alerts@example.com"

    # --- CORS ---------------------------------------------------------------
    cors_origins: list[str] = [
        "https://ztna-adaptive-trust.vercel.app",
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:4173",
    ]

    @field_validator("cors_origins", mode="before")
    @classmethod
    def _split_origins(cls, value: object) -> object:
        if isinstance(value, str):
            return [item.strip() for item in value.split(",") if item.strip()]
        return value

    @model_validator(mode="after")
    def _check_invariants(self) -> "Settings":
        total = (
            self.trust_weight_identity
            + self.trust_weight_device
            + self.trust_weight_network
            + self.trust_weight_behavior
            + self.trust_weight_location
            + self.trust_weight_temporal
        )
        if total != 100:
            raise ValueError(f"Trust factor weights must total 100, got {total}")
        if not (self.risk_high_min < self.risk_medium_min < self.risk_low_min <= 100):
            raise ValueError(
                "Risk thresholds must satisfy RISK_HIGH_MIN < RISK_MEDIUM_MIN "
                "< RISK_LOW_MIN <= 100"
            )
        if self.resource_storage_backend == "s3":
            missing = [
                name for name, value in (
                    ("S3_BUCKET_NAME", self.s3_bucket_name),
                    ("S3_ENDPOINT_URL", self.s3_endpoint_url),
                    ("S3_ACCESS_KEY_ID", self.s3_access_key_id),
                    ("S3_SECRET_ACCESS_KEY", self.s3_secret_access_key),
                ) if not value.strip()
            ]
            if missing:
                raise ValueError(
                    "S3 storage is enabled but required settings are missing: "
                    + ", ".join(missing)
                )
            endpoint = urlsplit(self.s3_endpoint_url)
            if endpoint.scheme not in {"https", "http"} or not endpoint.netloc:
                raise ValueError("S3_ENDPOINT_URL must be an HTTP(S) endpoint URL")
            if self.app_env == "production" and endpoint.scheme != "https":
                raise ValueError("S3_ENDPOINT_URL must use HTTPS in production")
            prefix_parts = self.s3_key_prefix.strip("/").split("/")
            if not self.s3_key_prefix.strip() or any(
                part in {"", ".", ".."} for part in prefix_parts
            ):
                raise ValueError("S3_KEY_PREFIX must be a safe, non-empty path")
        return self

    @property
    def verification_in_api(self) -> bool:
        """True when the API process should run the verification sweep itself.

        Never under APP_ENV=test: the sweep opens its own database session from
        the global factory, which is bound to the real database, not to
        whatever a test fixture set up. A background loop that quietly writes
        to production while the suite runs is worse than no loop at all.
        """
        if self.app_env == "test":
            return False
        if self.run_verification_in_api is not None:
            return self.run_verification_in_api
        return not self.redis_url

    @property
    def is_sqlite(self) -> bool:
        return self.database_url.startswith("sqlite")

    @property
    def trust_weights(self) -> dict[str, int]:
        """Factor name -> weight, as used by the scoring engine."""
        return {
            "identity": self.trust_weight_identity,
            "device": self.trust_weight_device,
            "network": self.trust_weight_network,
            "behavior": self.trust_weight_behavior,
            "location": self.trust_weight_location,
            "temporal": self.trust_weight_temporal,
        }


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Process-wide singleton so the .env file is parsed exactly once."""
    return Settings()


settings: Settings = get_settings()

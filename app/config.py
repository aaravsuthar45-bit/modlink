"""
app/config.py — Centralised settings loaded from .env
"""
from __future__ import annotations

from functools import lru_cache
from typing import Optional

from pydantic import Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ── Discord ──────────────────────────────────────────────
    discord_token: str = Field(..., description="Discord bot token")
    discord_client_id: Optional[str] = Field(None, description="Discord Application / Client ID for OAuth2")
    discord_client_secret: Optional[str] = Field(None, description="Discord OAuth2 Client Secret")
    discord_redirect_uri: Optional[str] = Field(None, description="OAuth2 callback URL, e.g. https://your-domain.onrender.com/auth/discord/callback")

    # ── Database ─────────────────────────────────────────────
    database_url: str = Field(
        "sqlite+aiosqlite:///./modlink.db",
        description="SQLAlchemy async connection string (SQLite or Supabase Postgres)",
    )

    # ── MCP Gateway ──────────────────────────────────────────
    mcp_public_url: str = Field(
        "http://localhost:8000/mcp",
        description="Publicly reachable MCP endpoint URL",
    )
    mcp_host: str = "0.0.0.0"
    mcp_port: int = 8000
    port: Optional[int] = Field(None, validation_alias="PORT")

    @property
    def server_port(self) -> int:
        return self.port if self.port is not None else self.mcp_port

    # ── OIDC (optional) ──────────────────────────────────────
    oidc_issuer_url: Optional[str] = None
    oidc_introspection_url: Optional[str] = None
    oidc_client_id: Optional[str] = None
    oidc_client_secret: Optional[str] = None

    # ── Dashboard ────────────────────────────────────────────
    dashboard_host: str = "127.0.0.1"
    dashboard_port: int = 8080
    dashboard_secret: str = "change-me-in-production"

    # ── Redis (optional) ─────────────────────────────────────
    redis_url: Optional[str] = None

    # ── Logging ──────────────────────────────────────────────
    log_level: str = "INFO"

    # ── Computed helpers ─────────────────────────────────────
    @property
    def normalized_database_url(self) -> str:
        url = self.database_url
        # Supabase and Render give urls like postgres:// or postgresql://
        if url.startswith("postgres://"):
            url = "postgresql+asyncpg://" + url[len("postgres://"):]
        elif url.startswith("postgresql://") and not url.startswith("postgresql+asyncpg://"):
            url = "postgresql+asyncpg://" + url[len("postgresql://"):]
        return url

    @property
    def use_oidc(self) -> bool:
        return bool(self.oidc_introspection_url and self.oidc_client_secret)

    @property
    def is_sqlite(self) -> bool:
        return self.normalized_database_url.startswith("sqlite")


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()


settings = get_settings()

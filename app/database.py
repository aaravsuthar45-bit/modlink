"""
app/database.py — SQLAlchemy async engine, session factory, and all ORM models
"""
from __future__ import annotations

import enum
import uuid
from datetime import datetime, timezone
from typing import AsyncIterator

from sqlalchemy import (
    BigInteger,
    Boolean,
    Column,
    DateTime,
    Enum,
    ForeignKey,
    Integer,
    JSON,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.ext.asyncio import (
    AsyncAttrs,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase, relationship

from app.config import settings


# ── Engine & session factory ─────────────────────────────────────────────────

def _make_engine():
    connect_args = {}
    if settings.is_sqlite:
        connect_args = {"check_same_thread": False}
    return create_async_engine(
        settings.normalized_database_url,
        echo=False,
        connect_args=connect_args,
    )


engine = _make_engine()
AsyncSessionLocal = async_sessionmaker(engine, expire_on_commit=False)


async def get_db() -> AsyncIterator[AsyncSession]:
    """FastAPI / Starlette dependency that yields an async DB session."""
    async with AsyncSessionLocal() as session:
        yield session


async def init_db() -> None:
    """Create all tables (dev convenience; use Alembic in production)."""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


# ── Base ─────────────────────────────────────────────────────────────────────

class Base(AsyncAttrs, DeclarativeBase):
    pass


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _new_uuid() -> str:
    return str(uuid.uuid4())


# ── Enums ────────────────────────────────────────────────────────────────────

class ConnectionStatus(str, enum.Enum):
    active = "active"
    revoked = "revoked"
    suspended = "suspended"


class AuditResult(str, enum.Enum):
    success = "success"
    denied = "denied"
    error = "error"


class PermissionLevel(str, enum.Enum):
    read = "read"            # list_servers, get_server_info, read messages
    moderate = "moderate"    # timeout, delete message
    manage = "manage"        # kick, change nickname
    admin = "admin"          # ban (still subject to per-action approval)


# ── Models ───────────────────────────────────────────────────────────────────

class AIConnection(Base):
    """
    Represents a registered AI client (Claude, ChatGPT, custom agent, …).
    Each connection has its own bearer token and an allowlist of guild IDs.
    """
    __tablename__ = "ai_connections"

    id = Column(String(36), primary_key=True, default=_new_uuid)
    name = Column(String(100), nullable=False)
    description = Column(Text, nullable=True)

    # Hashed API key used when OIDC is not configured
    api_key_hash = Column(String(128), nullable=True)

    # JSON list of Discord guild IDs (as strings) this connection can touch
    allowed_guild_ids: Column = Column(JSON, nullable=False, default=list)

    # Maximum permission level granted to this connection
    permission_level = Column(
        Enum(PermissionLevel), nullable=False, default=PermissionLevel.read
    )

    # Whether this connection may act without per-action human approval
    autonomous_mode = Column(Boolean, nullable=False, default=False)

    status = Column(
        Enum(ConnectionStatus), nullable=False, default=ConnectionStatus.active
    )

    created_at = Column(DateTime(timezone=True), default=_utcnow, nullable=False)
    last_seen_at = Column(DateTime(timezone=True), nullable=True)

    audit_logs = relationship("AuditLog", back_populates="connection", lazy="raise")

    def __repr__(self) -> str:
        return f"<AIConnection id={self.id!r} name={self.name!r}>"


class GuildConfig(Base):
    """
    Per-Discord-guild configuration stored in ModLink.
    """
    __tablename__ = "guild_configs"

    guild_id = Column(String(20), primary_key=True)   # Discord snowflake as str
    name = Column(String(100), nullable=False, default="Unknown Guild")

    # AutoMod thresholds
    automod_enabled = Column(Boolean, nullable=False, default=True)
    spam_message_threshold = Column(Integer, nullable=False, default=6)
    spam_window_seconds = Column(Integer, nullable=False, default=12)

    # Role IDs exempt from AutoMod (JSON list of str)
    automod_exempt_role_ids: Column = Column(JSON, nullable=False, default=list)

    # Moderation limits for autonomous AI actions
    max_timeout_minutes = Column(Integer, nullable=False, default=60)
    ban_requires_approval = Column(Boolean, nullable=False, default=True)
    kick_requires_approval = Column(Boolean, nullable=False, default=False)

    created_at = Column(DateTime(timezone=True), default=_utcnow, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=_utcnow, onupdate=_utcnow, nullable=False)

    def __repr__(self) -> str:
        return f"<GuildConfig guild_id={self.guild_id!r} name={self.name!r}>"


class AuditLog(Base):
    """
    Immutable record of every action taken through the MCP gateway or AutoMod.
    """
    __tablename__ = "audit_logs"

    id = Column(String(36), primary_key=True, default=_new_uuid)

    # Which AI connection triggered the action (None → AutoMod system)
    connection_id = Column(
        String(36), ForeignKey("ai_connections.id", ondelete="SET NULL"), nullable=True
    )

    guild_id = Column(String(20), nullable=False)
    tool_name = Column(String(100), nullable=False)   # e.g. "timeout_member"
    arguments = Column(JSON, nullable=True)           # sanitised tool arguments
    result = Column(Enum(AuditResult), nullable=False)
    result_detail = Column(Text, nullable=True)       # human-readable outcome / error
    target_user_id = Column(String(20), nullable=True)
    created_at = Column(DateTime(timezone=True), default=_utcnow, nullable=False)

    connection = relationship("AIConnection", back_populates="audit_logs", lazy="raise")

    def __repr__(self) -> str:
        return (
            f"<AuditLog id={self.id!r} tool={self.tool_name!r} "
            f"result={self.result!r}>"
        )


class PendingApproval(Base):
    """
    Actions that require human review before execution.
    """
    __tablename__ = "pending_approvals"

    id = Column(String(36), primary_key=True, default=_new_uuid)
    connection_id = Column(String(36), ForeignKey("ai_connections.id", ondelete="CASCADE"))
    guild_id = Column(String(20), nullable=False)
    tool_name = Column(String(100), nullable=False)
    arguments = Column(JSON, nullable=True)
    reason = Column(Text, nullable=True)             # AI-provided justification

    approved = Column(Boolean, nullable=True)         # None = pending
    reviewed_by = Column(String(100), nullable=True)  # dashboard user
    reviewed_at = Column(DateTime(timezone=True), nullable=True)

    created_at = Column(DateTime(timezone=True), default=_utcnow, nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=False)

    def __repr__(self) -> str:
        return f"<PendingApproval id={self.id!r} tool={self.tool_name!r}>"


class UserSession(Base):
    """
    Stores authenticated Discord user sessions for web dashboard and cookie persistence.
    """
    __tablename__ = "user_sessions"

    id = Column(String(64), primary_key=True)  # Secure session token
    discord_user_id = Column(String(32), nullable=False, index=True)
    discord_username = Column(String(100), nullable=False)
    avatar_url = Column(String(255), nullable=True)
    admin_guilds = Column(JSON, nullable=False, default=list)  # list of {id, name, icon, bot_joined}
    api_key = Column(String(128), nullable=True)  # Raw user API key for dashboard one-click copy
    created_at = Column(DateTime(timezone=True), default=_utcnow, nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=False)

    def __repr__(self) -> str:
        return f"<UserSession id={self.id!r} user={self.discord_username!r}>"


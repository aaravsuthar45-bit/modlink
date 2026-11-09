"""
app/dashboard.py — ModLink web dashboard & REST API
"""
from __future__ import annotations

import hashlib
import hmac
import logging
import secrets
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

from fastapi import APIRouter, Depends, FastAPI, HTTPException, Security
from fastapi.responses import HTMLResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel
from sqlalchemy import desc, select

from app.config import settings
from app.database import (
    AIConnection,
    AuditLog,
    AsyncSessionLocal,
    ConnectionStatus,
    GuildConfig,
    PermissionLevel,
    PendingApproval,
    init_db,
)

from contextlib import asynccontextmanager

logger = logging.getLogger(__name__)

TEMPLATE_PATH = Path(__file__).parent / "templates" / "dashboard.html"


@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    yield


app = FastAPI(
    title="ModLink MCP Dashboard",
    description="Manage AI connections, permissions, and moderation history.",
    version="1.0.0",
    lifespan=lifespan,
)

bearer_scheme = HTTPBearer(auto_error=False)


# ── Dashboard auth dependency ─────────────────────────────────────────────────

def _require_dashboard_auth(
    credentials: Optional[HTTPAuthorizationCredentials] = Security(bearer_scheme),
) -> None:
    if credentials is None or not hmac.compare_digest(
        credentials.credentials, settings.dashboard_secret
    ):
        raise HTTPException(status_code=401, detail="Invalid dashboard token.")


DashboardAuth = Depends(_require_dashboard_auth)


# ── Schemas ───────────────────────────────────────────────────────────────────

class ConnectionCreate(BaseModel):
    name: str
    description: Optional[str] = None
    allowed_guild_ids: List[str] = []
    permission_level: PermissionLevel = PermissionLevel.read
    autonomous_mode: bool = False


class GuildConfigUpdate(BaseModel):
    automod_enabled: Optional[bool] = None
    spam_message_threshold: Optional[int] = None
    spam_window_seconds: Optional[int] = None
    max_timeout_minutes: Optional[int] = None
    ban_requires_approval: Optional[bool] = None
    kick_requires_approval: Optional[bool] = None
    automod_exempt_role_ids: Optional[List[str]] = None


# ── Helpers ───────────────────────────────────────────────────────────────────

def _hash_key(raw: str) -> str:
    return hmac.new(
        settings.dashboard_secret.encode(), raw.encode(), hashlib.sha256
    ).hexdigest()


# ── Router & Handlers ─────────────────────────────────────────────────────────

router = APIRouter()


@router.get("/")
@router.get("/dashboard")
async def dashboard_page() -> HTMLResponse:
    if TEMPLATE_PATH.exists():
        return HTMLResponse(TEMPLATE_PATH.read_text(encoding="utf-8"))
    return HTMLResponse("<h2>Dashboard template not found.</h2>", status_code=500)


@router.get("/status")
@router.get("/api/status")
async def api_status() -> dict:
    """Public status endpoint — no auth required."""
    return {
        "status": "ok",
        "service": "modlink-mcp-dashboard",
        "time": datetime.now(timezone.utc).isoformat(),
        "version": "1.0.0",
    }


# ── AI Connections ────────────────────────────────────────────────────────────

@router.get("/connections", dependencies=[DashboardAuth])
@router.get("/api/connections", dependencies=[DashboardAuth])
async def list_connections() -> dict:
    async with AsyncSessionLocal() as session:
        result = await session.execute(select(AIConnection))
        connections = result.scalars().all()

    return {
        "connections": [
            {
                "id": c.id,
                "name": c.name,
                "description": c.description,
                "allowed_guild_ids": c.allowed_guild_ids,
                "permission_level": c.permission_level.value,
                "autonomous_mode": c.autonomous_mode,
                "status": c.status.value,
                "created_at": c.created_at.isoformat(),
                "last_seen_at": c.last_seen_at.isoformat() if c.last_seen_at else None,
            }
            for c in connections
        ]
    }


@router.post("/connections", dependencies=[DashboardAuth], status_code=201)
@router.post("/api/connections", dependencies=[DashboardAuth], status_code=201)
async def create_connection(body: ConnectionCreate) -> dict:
    raw_key = secrets.token_urlsafe(48)
    key_hash = _hash_key(raw_key)

    conn = AIConnection(
        name=body.name,
        description=body.description,
        api_key_hash=key_hash,
        allowed_guild_ids=body.allowed_guild_ids,
        permission_level=body.permission_level,
        autonomous_mode=body.autonomous_mode,
    )
    async with AsyncSessionLocal() as session:
        session.add(conn)
        await session.commit()
        await session.refresh(conn)

    return {
        "id": conn.id,
        "name": conn.name,
        "api_key": raw_key,  # Only shown ONCE at creation
        "message": "Store this API key securely — it will not be shown again.",
    }


@router.delete("/connections/{connection_id}", dependencies=[DashboardAuth])
@router.delete("/api/connections/{connection_id}", dependencies=[DashboardAuth])
async def revoke_connection(connection_id: str) -> dict:
    async with AsyncSessionLocal() as session:
        result = await session.execute(
            select(AIConnection).where(AIConnection.id == connection_id)
        )
        conn = result.scalar_one_or_none()
        if conn is None:
            raise HTTPException(status_code=404, detail="Connection not found.")
        conn.status = ConnectionStatus.revoked
        await session.commit()
    return {"status": "revoked", "id": connection_id}


# ── Audit log ─────────────────────────────────────────────────────────────────

@router.get("/audit", dependencies=[DashboardAuth])
@router.get("/api/audit", dependencies=[DashboardAuth])
async def list_audit(limit: int = 50, guild_id: Optional[str] = None) -> dict:
    limit = max(1, min(limit, 500))
    async with AsyncSessionLocal() as session:
        q = select(AuditLog).order_by(desc(AuditLog.created_at)).limit(limit)
        if guild_id:
            q = q.where(AuditLog.guild_id == guild_id)
        result = await session.execute(q)
        logs = result.scalars().all()

    return {
        "logs": [
            {
                "id": log.id,
                "connection_id": log.connection_id,
                "guild_id": log.guild_id,
                "tool_name": log.tool_name,
                "arguments": log.arguments,
                "result": log.result.value,
                "result_detail": log.result_detail,
                "target_user_id": log.target_user_id,
                "created_at": log.created_at.isoformat(),
            }
            for log in logs
        ],
        "returned": len(logs),
    }


# ── Pending approvals ─────────────────────────────────────────────────────────

@router.get("/pending", dependencies=[DashboardAuth])
@router.get("/api/pending", dependencies=[DashboardAuth])
async def list_pending() -> dict:
    now = datetime.now(timezone.utc)
    async with AsyncSessionLocal() as session:
        result = await session.execute(
            select(PendingApproval)
            .where(PendingApproval.approved.is_(None))
            .where(PendingApproval.expires_at > now)
            .order_by(PendingApproval.created_at)
        )
        items = result.scalars().all()

    return {
        "pending": [
            {
                "id": p.id,
                "connection_id": p.connection_id,
                "guild_id": p.guild_id,
                "tool_name": p.tool_name,
                "arguments": p.arguments,
                "reason": p.reason,
                "expires_at": p.expires_at.isoformat(),
            }
            for p in items
        ]
    }


@router.post("/pending/{approval_id}/approve", dependencies=[DashboardAuth])
@router.post("/api/pending/{approval_id}/approve", dependencies=[DashboardAuth])
async def approve_action(approval_id: str) -> dict:
    async with AsyncSessionLocal() as session:
        result = await session.execute(
            select(PendingApproval).where(PendingApproval.id == approval_id)
        )
        pa = result.scalar_one_or_none()
        if pa is None:
            raise HTTPException(404, "Approval request not found.")
        if pa.approved is not None:
            raise HTTPException(409, "Already reviewed.")

        pa.approved = True
        pa.reviewed_at = datetime.now(timezone.utc)
        await session.commit()

    # Execute the action now that it's approved
    try:
        import sys
        mcp_mod = sys.modules.get("app.mcp_server")
        if not mcp_mod:
            import app.mcp_server as mcp_mod
            
        from app.auth import AccessToken
        token = AccessToken(
            connection_id=pa.connection_id or "dashboard",
            name="dashboard-approver",
            allowed_guild_ids=[pa.guild_id],
            permission_level=PermissionLevel.admin,
            autonomous_mode=True,
        )
        mcp_mod.current_ml_token_var.set(token)
        handler = getattr(mcp_mod, pa.tool_name, None)
        if callable(handler):
            await handler(**pa.arguments)
    except Exception as exc:
        logger.error("Failed to execute approved action %s: %s", approval_id, exc)
        return {"status": "approved_but_execution_failed", "error": str(exc)}

    return {"status": "approved_and_executed", "id": approval_id}


@router.post("/pending/{approval_id}/reject", dependencies=[DashboardAuth])
@router.post("/api/pending/{approval_id}/reject", dependencies=[DashboardAuth])
async def reject_action(approval_id: str) -> dict:
    async with AsyncSessionLocal() as session:
        result = await session.execute(
            select(PendingApproval).where(PendingApproval.id == approval_id)
        )
        pa = result.scalar_one_or_none()
        if pa is None:
            raise HTTPException(404, "Approval request not found.")
        if pa.approved is not None:
            raise HTTPException(409, "Already reviewed.")

        pa.approved = False
        pa.reviewed_at = datetime.now(timezone.utc)
        await session.commit()

    return {"status": "rejected", "id": approval_id}


# ── Guild configs ─────────────────────────────────────────────────────────────

@router.get("/guilds", dependencies=[DashboardAuth])
@router.get("/api/guilds", dependencies=[DashboardAuth])
async def list_guilds() -> dict:
    from app.discord_bot import bot

    async with AsyncSessionLocal() as session:
        result = await session.execute(select(GuildConfig))
        db_guilds = {g.guild_id: g for g in result.scalars().all()}

    guild_items = []
    seen_ids = set()
    for bg in bot.guilds:
        gid = str(bg.id)
        seen_ids.add(gid)
        cfg = db_guilds.get(gid)
        guild_items.append({
            "guild_id": gid,
            "name": bg.name,
            "automod_enabled": cfg.automod_enabled if cfg else True,
            "spam_threshold": cfg.spam_message_threshold if cfg else 5,
        })
    for gid, cfg in db_guilds.items():
        if gid not in seen_ids:
            guild_items.append({
                "guild_id": gid,
                "name": cfg.name or gid,
                "automod_enabled": cfg.automod_enabled,
                "spam_threshold": cfg.spam_message_threshold,
            })

    return {"guilds": guild_items}


@router.get("/guilds/{guild_id}/config", dependencies=[DashboardAuth])
@router.get("/api/guilds/{guild_id}/config", dependencies=[DashboardAuth])
async def get_guild_config(guild_id: str) -> dict:
    async with AsyncSessionLocal() as session:
        result = await session.execute(
            select(GuildConfig).where(GuildConfig.guild_id == guild_id)
        )
        g = result.scalar_one_or_none()
    if g is None:
        raise HTTPException(404, "Guild config not found.")
    return {
        "guild_id": g.guild_id,
        "name": g.name,
        "automod_enabled": g.automod_enabled,
        "spam_message_threshold": g.spam_message_threshold,
        "spam_window_seconds": g.spam_window_seconds,
        "automod_exempt_role_ids": g.automod_exempt_role_ids,
        "max_timeout_minutes": g.max_timeout_minutes,
        "ban_requires_approval": g.ban_requires_approval,
        "kick_requires_approval": g.kick_requires_approval,
    }


@router.patch("/guilds/{guild_id}/config", dependencies=[DashboardAuth])
@router.patch("/api/guilds/{guild_id}/config", dependencies=[DashboardAuth])
async def update_guild_config(guild_id: str, body: GuildConfigUpdate) -> dict:
    async with AsyncSessionLocal() as session:
        result = await session.execute(
            select(GuildConfig).where(GuildConfig.guild_id == guild_id)
        )
        g = result.scalar_one_or_none()
        if g is None:
            raise HTTPException(404, "Guild config not found.")

        updates = body.model_dump(exclude_none=True)
        for key, val in updates.items():
            setattr(g, key, val)

        await session.commit()
        await session.refresh(g)

    return {"status": "updated", "guild_id": guild_id}


app.include_router(router)

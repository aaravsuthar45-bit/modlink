"""
app/mcp_server.py — ModLink MCP Gateway (MCP 2.x, Streamable HTTP transport)

Uses MCPServer (renamed from FastMCP in MCP 2.x) with the @mcp.tool() decorator.
Auth is wired through MCPServer's token_verifier parameter so the SDK handles
the Authorization header extraction and injects our AccessToken into every request
context automatically.

Start with:
    python -m app.mcp_server
"""
from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime, timedelta, timezone
from typing import Annotated, Any, Dict, List, Optional

import discord
import httpx
import uvicorn
from mcp.server.auth.provider import AccessToken as MCPAccessToken, TokenVerifier
from mcp.server.auth.settings import AuthSettings
from mcp.server.context import Context
from mcp.server.mcpserver import MCPServer
from mcp.server.request_state import get_access_token
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Mount, Route

from app.auth import (
    AccessToken as ModLinkToken,
    has_permission,
    verify_bearer,
    get_current_token,
    set_current_token,
    register_session_token,
)
from app.config import settings
from app.custom_tools import get_custom_tool, get_custom_tools
from app.database import (
    AIConnection,
    AuditLog,
    AuditResult,
    AsyncSessionLocal,
    GuildConfig,
    PermissionLevel,
    PendingApproval,
    init_db,
)
from app.discord_bot import bot, get_channel, get_any_channel, get_guild, get_member, get_role, start_bot
from sqlalchemy import select, update

logger = logging.getLogger(__name__)


# ── Request authentication context ───────────────────────────────────────────

def _get_ml_token() -> Optional[ModLinkToken]:
    """Retrieve the authenticated ModLinkToken for the current request from unified auth context."""
    return get_current_token()


# ── MCPServer instance ────────────────────────────────────────────────────────
# Static API-key / Custom-header mode: no external OAuth RS dynamic registration
mcp = MCPServer(
    name="modlink-mcp",
    title="ModLink MCP",
    description="AI-accessible Discord moderation platform. Manage multiple Discord servers through natural language.",
    version="1.0.0",
)


# ── Audit helper ──────────────────────────────────────────────────────────────

async def _audit(
    *,
    connection_id: Optional[str],
    guild_id: str,
    tool_name: str,
    arguments: Optional[dict],
    result: AuditResult,
    result_detail: Optional[str] = None,
    target_user_id: Optional[str] = None,
) -> None:
    try:
        async with AsyncSessionLocal() as session:
            log = AuditLog(
                connection_id=connection_id,
                guild_id=guild_id,
                tool_name=tool_name,
                arguments=arguments,
                result=result,
                result_detail=result_detail,
                target_user_id=target_user_id,
            )
            session.add(log)
            if connection_id:
                await session.execute(
                    update(AIConnection)
                    .where(AIConnection.id == connection_id)
                    .values(last_seen_at=datetime.now(timezone.utc))
                )
            await session.commit()
    except Exception as exc:
        logger.error("Failed to write audit log: %s", exc)


# ── Permission helpers ────────────────────────────────────────────────────────

def _require_guild_access(token: ModLinkToken, guild_id: str) -> None:
    if not token.allowed_guild_ids or "*" in token.allowed_guild_ids:
        return
    allowed_str = [str(g).strip() for g in token.allowed_guild_ids]
    if str(guild_id).strip() not in allowed_str:
        raise PermissionError(
            f"Your connection is not authorized for guild {guild_id!r}."
        )


def _require_permission(token: ModLinkToken, required: PermissionLevel) -> None:
    if not has_permission(token, required):
        raise PermissionError(
            f"This action requires {required.value!r} permission; "
            f"your connection has {token.permission_level.value!r}."
        )


# ── Approval helper ───────────────────────────────────────────────────────────

async def _create_pending_approval(
    *,
    token: ModLinkToken,
    guild_id: str,
    tool_name: str,
    arguments: dict,
    reason: str,
) -> dict:
    expires = datetime.now(timezone.utc) + timedelta(hours=24)
    async with AsyncSessionLocal() as session:
        pa = PendingApproval(
            connection_id=token.connection_id,
            guild_id=guild_id,
            tool_name=tool_name,
            arguments=arguments,
            reason=reason,
            expires_at=expires,
        )
        session.add(pa)
        await session.commit()
        await session.refresh(pa)

    return {
        "status": "pending_approval",
        "approval_id": pa.id,
        "message": (
            f"Action {tool_name!r} requires human approval. "
            f"Approval request id={pa.id} created. "
            f"A dashboard administrator must approve it within 24 hours."
        ),
    }


# ── MCP Tools ─────────────────────────────────────────────────────────────────

@mcp.tool(
    name="list_authorized_servers",
    description="List all Discord servers (guilds) this AI connection is authorized to manage.",
)
async def list_authorized_servers() -> str:
    token = _get_ml_token()
    if token is None:
        return json.dumps({"error": "Unauthenticated"})

    guilds = []
    for gid in token.allowed_guild_ids:
        guild = bot.get_guild(int(gid))
        if guild:
            guilds.append({
                "guild_id": gid,
                "name": guild.name,
                "member_count": guild.member_count,
                "icon_url": str(guild.icon.url) if guild.icon else None,
            })
        else:
            guilds.append({"guild_id": gid, "name": "Not found / bot not member"})

    await _audit(
        connection_id=token.connection_id,
        guild_id="n/a",
        tool_name="list_authorized_servers",
        arguments={},
        result=AuditResult.success,
    )
    return json.dumps({"authorized_guilds": guilds, "total": len(guilds)}, indent=2)


@mcp.tool(
    name="get_server_info",
    description="Get detailed information about a specific Discord server.",
)
async def get_server_info(guild_id: str) -> str:
    token = _get_ml_token()
    if token is None:
        return json.dumps({"error": "Unauthenticated"})

    try:
        _require_guild_access(token, guild_id)
        _require_permission(token, PermissionLevel.read)
        guild = await get_guild(guild_id)

        async with AsyncSessionLocal() as session:
            result = await session.execute(
                select(GuildConfig).where(GuildConfig.guild_id == guild_id)
            )
            config = result.scalar_one_or_none()

        data = {
            "guild_id": guild_id,
            "name": guild.name,
            "member_count": guild.member_count,
            "owner_id": str(guild.owner_id),
            "created_at": guild.created_at.isoformat(),
            "text_channel_count": len(guild.text_channels),
            "voice_channel_count": len(guild.voice_channels),
            "role_count": len(guild.roles),
            "modlink_config": {
                "automod_enabled": config.automod_enabled if config else True,
                "spam_threshold": config.spam_message_threshold if config else 6,
                "spam_window_seconds": config.spam_window_seconds if config else 12,
                "ban_requires_approval": config.ban_requires_approval if config else True,
                "max_timeout_minutes": config.max_timeout_minutes if config else 60,
            },
        }
        await _audit(
            connection_id=token.connection_id, guild_id=guild_id,
            tool_name="get_server_info", arguments={"guild_id": guild_id},
            result=AuditResult.success,
        )
        return json.dumps(data, indent=2)

    except PermissionError as exc:
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="get_server_info", arguments={"guild_id": guild_id},
                     result=AuditResult.denied, result_detail=str(exc))
        return json.dumps({"error": "Permission denied", "detail": str(exc)})
    except Exception as exc:
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="get_server_info", arguments={"guild_id": guild_id},
                     result=AuditResult.error, result_detail=str(exc))
        return json.dumps({"error": str(exc)})


@mcp.tool(
    name="read_recent_messages",
    description="Read recent messages from a text channel. limit: 1-100 (default 25).",
)
async def read_recent_messages(guild_id: str, channel_id: str, limit: int = 25) -> str:
    token = _get_ml_token()
    if token is None:
        return json.dumps({"error": "Unauthenticated"})

    args = {"guild_id": guild_id, "channel_id": channel_id, "limit": limit}
    try:
        _require_guild_access(token, guild_id)
        _require_permission(token, PermissionLevel.read)
        limit = max(1, min(limit, 100))
        channel = await get_channel(guild_id, channel_id)
        messages = []
        async for msg in channel.history(limit=limit):
            messages.append({
                "message_id": str(msg.id),
                "author_id": str(msg.author.id),
                "author_name": str(msg.author),
                "content": msg.content,
                "timestamp": msg.created_at.isoformat(),
                "edited": msg.edited_at is not None,
                "attachments": len(msg.attachments),
                "embeds": len(msg.embeds),
            })
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="read_recent_messages", arguments=args,
                     result=AuditResult.success)
        return json.dumps({"guild_id": guild_id, "channel_id": channel_id,
                           "messages": messages, "returned": len(messages)}, indent=2)
    except PermissionError as exc:
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="read_recent_messages", arguments=args,
                     result=AuditResult.denied, result_detail=str(exc))
        return json.dumps({"error": "Permission denied", "detail": str(exc)})
    except Exception as exc:
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="read_recent_messages", arguments=args,
                     result=AuditResult.error, result_detail=str(exc))
        return json.dumps({"error": str(exc)})


@mcp.tool(
    name="timeout_member",
    description=(
        "Apply a timeout (communication disable) to a guild member. "
        "Duration in minutes is capped by the guild's ModLink configuration."
    ),
)
async def timeout_member(
    guild_id: str,
    user_id: str,
    minutes: int,
    reason: str = "Moderation action via ModLink MCP",
) -> str:
    token = _get_ml_token()
    if token is None:
        return json.dumps({"error": "Unauthenticated"})

    args = {"guild_id": guild_id, "user_id": user_id, "minutes": minutes, "reason": reason}
    try:
        _require_guild_access(token, guild_id)
        _require_permission(token, PermissionLevel.moderate)

        async with AsyncSessionLocal() as session:
            result = await session.execute(
                select(GuildConfig).where(GuildConfig.guild_id == guild_id)
            )
            config = result.scalar_one_or_none()

        max_minutes = config.max_timeout_minutes if config else 60
        if minutes > max_minutes:
            raise ValueError(
                f"Requested timeout of {minutes}m exceeds guild limit of {max_minutes}m."
            )

        member = await get_member(guild_id, user_id)
        await member.timeout(timedelta(minutes=minutes), reason=reason)

        data = {"status": "success", "user_id": user_id, "username": str(member),
                "timeout_minutes": minutes, "reason": reason}
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="timeout_member", arguments=args,
                     result=AuditResult.success, target_user_id=user_id)
        return json.dumps(data, indent=2)

    except PermissionError as exc:
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="timeout_member", arguments=args,
                     result=AuditResult.denied, result_detail=str(exc),
                     target_user_id=user_id)
        return json.dumps({"error": "Permission denied", "detail": str(exc)})
    except Exception as exc:
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="timeout_member", arguments=args,
                     result=AuditResult.error, result_detail=str(exc),
                     target_user_id=user_id)
        return json.dumps({"error": str(exc)})


@mcp.tool(
    name="delete_message",
    description="Delete a specific message from a text channel.",
)
async def delete_message(
    guild_id: str,
    channel_id: str,
    message_id: str,
    reason: str = "Deleted via ModLink MCP",
) -> str:
    token = _get_ml_token()
    if token is None:
        return json.dumps({"error": "Unauthenticated"})

    args = {"guild_id": guild_id, "channel_id": channel_id,
            "message_id": message_id, "reason": reason}
    try:
        _require_guild_access(token, guild_id)
        _require_permission(token, PermissionLevel.moderate)
        channel = await get_channel(guild_id, channel_id)
        try:
            msg = await channel.fetch_message(int(message_id))
        except discord.NotFound:
            raise ValueError(f"Message {message_id!r} not found.")
        await msg.delete(reason=reason)

        data = {"status": "deleted", "message_id": message_id,
                "channel_id": channel_id, "guild_id": guild_id}
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="delete_message", arguments=args,
                     result=AuditResult.success)
        return json.dumps(data, indent=2)

    except PermissionError as exc:
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="delete_message", arguments=args,
                     result=AuditResult.denied, result_detail=str(exc))
        return json.dumps({"error": "Permission denied", "detail": str(exc)})
    except Exception as exc:
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="delete_message", arguments=args,
                     result=AuditResult.error, result_detail=str(exc))
        return json.dumps({"error": str(exc)})


@mcp.tool(
    name="kick_member",
    description=(
        "Kick a member from the guild. "
        "May create a pending approval request depending on guild configuration."
    ),
)
async def kick_member(
    guild_id: str,
    user_id: str,
    reason: str = "Kicked via ModLink MCP",
) -> str:
    token = _get_ml_token()
    if token is None:
        return json.dumps({"error": "Unauthenticated"})

    args = {"guild_id": guild_id, "user_id": user_id, "reason": reason}
    try:
        _require_guild_access(token, guild_id)
        _require_permission(token, PermissionLevel.manage)

        async with AsyncSessionLocal() as session:
            result = await session.execute(
                select(GuildConfig).where(GuildConfig.guild_id == guild_id)
            )
            config = result.scalar_one_or_none()

        if config and config.kick_requires_approval and not token.autonomous_mode:
            data = await _create_pending_approval(
                token=token, guild_id=guild_id, tool_name="kick_member",
                arguments=args, reason=reason,
            )
            await _audit(connection_id=token.connection_id, guild_id=guild_id,
                         tool_name="kick_member", arguments=args,
                         result=AuditResult.success,
                         result_detail="Pending approval created",
                         target_user_id=user_id)
            return json.dumps(data, indent=2)

        member = await get_member(guild_id, user_id)
        await member.kick(reason=reason)

        data = {"status": "kicked", "user_id": user_id,
                "username": str(member), "reason": reason}
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="kick_member", arguments=args,
                     result=AuditResult.success, target_user_id=user_id)
        return json.dumps(data, indent=2)

    except PermissionError as exc:
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="kick_member", arguments=args,
                     result=AuditResult.denied, result_detail=str(exc),
                     target_user_id=user_id)
        return json.dumps({"error": "Permission denied", "detail": str(exc)})
    except Exception as exc:
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="kick_member", arguments=args,
                     result=AuditResult.error, result_detail=str(exc),
                     target_user_id=user_id)
        return json.dumps({"error": str(exc)})


@mcp.tool(
    name="ban_member",
    description=(
        "Ban a member from the guild. "
        "ALWAYS creates a pending human-approval request by default. "
        "delete_message_days: days of message history to delete (0-7)."
    ),
)
async def ban_member(
    guild_id: str,
    user_id: str,
    reason: str = "Banned via ModLink MCP",
    delete_message_days: int = 0,
) -> str:
    token = _get_ml_token()
    if token is None:
        return json.dumps({"error": "Unauthenticated"})

    args = {"guild_id": guild_id, "user_id": user_id,
            "reason": reason, "delete_message_days": delete_message_days}
    try:
        _require_guild_access(token, guild_id)
        _require_permission(token, PermissionLevel.admin)

        async with AsyncSessionLocal() as session:
            result = await session.execute(
                select(GuildConfig).where(GuildConfig.guild_id == guild_id)
            )
            config = result.scalar_one_or_none()

        ban_needs_approval = config.ban_requires_approval if config else True

        if ban_needs_approval:
            data = await _create_pending_approval(
                token=token, guild_id=guild_id, tool_name="ban_member",
                arguments=args, reason=reason,
            )
            await _audit(connection_id=token.connection_id, guild_id=guild_id,
                         tool_name="ban_member", arguments=args,
                         result=AuditResult.success,
                         result_detail="Pending approval created",
                         target_user_id=user_id)
            return json.dumps(data, indent=2)

        guild = await get_guild(guild_id)
        await guild.ban(
            discord.Object(id=int(user_id)),
            reason=reason,
            delete_message_days=max(0, min(delete_message_days, 7)),
        )

        data = {"status": "banned", "user_id": user_id, "reason": reason}
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="ban_member", arguments=args,
                     result=AuditResult.success, target_user_id=user_id)
        return json.dumps(data, indent=2)

    except PermissionError as exc:
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="ban_member", arguments=args,
                     result=AuditResult.denied, result_detail=str(exc),
                     target_user_id=user_id)
        return json.dumps({"error": "Permission denied", "detail": str(exc)})
    except Exception as exc:
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="ban_member", arguments=args,
                     result=AuditResult.error, result_detail=str(exc),
                     target_user_id=user_id)
        return json.dumps({"error": str(exc)})



# ══════════════════════════════════════════════════════════════════════════════
# MEMBER MANAGEMENT TOOLS
# ══════════════════════════════════════════════════════════════════════════════

@mcp.tool(
    name="get_member_info",
    description="Get detailed information about a guild member including roles, join date, permissions, and status.",
)
async def get_member_info(guild_id: str, user_id: str) -> str:
    token = _get_ml_token()
    if token is None:
        return json.dumps({"error": "Unauthenticated"})
    args = {"guild_id": guild_id, "user_id": user_id}
    try:
        _require_guild_access(token, guild_id)
        _require_permission(token, PermissionLevel.read)
        member = await get_member(guild_id, user_id)
        data = {
            "user_id": str(member.id),
            "username": str(member),
            "display_name": member.display_name,
            "nickname": member.nick,
            "avatar_url": str(member.display_avatar.url),
            "bot": member.bot,
            "joined_at": member.joined_at.isoformat() if member.joined_at else None,
            "account_created_at": member.created_at.isoformat(),
            "roles": [{"id": str(r.id), "name": r.name} for r in member.roles if r.name != "@everyone"],
            "top_role": str(member.top_role),
            "timed_out_until": member.timed_out_until.isoformat() if member.timed_out_until else None,
            "pending": member.pending,
        }
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="get_member_info", arguments=args, result=AuditResult.success)
        return json.dumps(data, indent=2)
    except PermissionError as exc:
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="get_member_info", arguments=args, result=AuditResult.denied, result_detail=str(exc))
        return json.dumps({"error": "Permission denied", "detail": str(exc)})
    except Exception as exc:
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="get_member_info", arguments=args, result=AuditResult.error, result_detail=str(exc))
        return json.dumps({"error": str(exc)})


@mcp.tool(
    name="list_members",
    description="List members of a guild. limit: max members to return (default 50, max 100).",
)
async def list_members(guild_id: str, limit: int = 50) -> str:
    token = _get_ml_token()
    if token is None:
        return json.dumps({"error": "Unauthenticated"})
    args = {"guild_id": guild_id, "limit": limit}
    try:
        _require_guild_access(token, guild_id)
        _require_permission(token, PermissionLevel.read)
        guild = await get_guild(guild_id)
        limit = max(1, min(limit, 100))
        members = []
        async for member in guild.fetch_members(limit=limit):
            members.append({
                "user_id": str(member.id),
                "username": str(member),
                "display_name": member.display_name,
                "bot": member.bot,
                "joined_at": member.joined_at.isoformat() if member.joined_at else None,
                "top_role": str(member.top_role),
            })
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="list_members", arguments=args, result=AuditResult.success)
        return json.dumps({"guild_id": guild_id, "members": members, "returned": len(members)}, indent=2)
    except PermissionError as exc:
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="list_members", arguments=args, result=AuditResult.denied, result_detail=str(exc))
        return json.dumps({"error": "Permission denied", "detail": str(exc)})
    except Exception as exc:
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="list_members", arguments=args, result=AuditResult.error, result_detail=str(exc))
        return json.dumps({"error": str(exc)})


@mcp.tool(
    name="add_member_role",
    description="Add a role to a guild member.",
)
async def add_member_role(guild_id: str, user_id: str, role_id: str, reason: str = "Role added via ModLink MCP") -> str:
    token = _get_ml_token()
    if token is None:
        return json.dumps({"error": "Unauthenticated"})
    args = {"guild_id": guild_id, "user_id": user_id, "role_id": role_id, "reason": reason}
    try:
        _require_guild_access(token, guild_id)
        _require_permission(token, PermissionLevel.moderate)
        guild = await get_guild(guild_id)
        member = await get_member(guild_id, user_id)
        role = guild.get_role(int(role_id))
        if role is None:
            raise ValueError(f"Role {role_id!r} not found.")
        await member.add_roles(role, reason=reason)
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="add_member_role", arguments=args, result=AuditResult.success, target_user_id=user_id)
        return json.dumps({"status": "success", "user_id": user_id, "role_id": role_id, "role_name": role.name})
    except PermissionError as exc:
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="add_member_role", arguments=args, result=AuditResult.denied, result_detail=str(exc))
        return json.dumps({"error": "Permission denied", "detail": str(exc)})
    except Exception as exc:
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="add_member_role", arguments=args, result=AuditResult.error, result_detail=str(exc))
        return json.dumps({"error": str(exc)})


@mcp.tool(
    name="remove_member_role",
    description="Remove a role from a guild member.",
)
async def remove_member_role(guild_id: str, user_id: str, role_id: str, reason: str = "Role removed via ModLink MCP") -> str:
    token = _get_ml_token()
    if token is None:
        return json.dumps({"error": "Unauthenticated"})
    args = {"guild_id": guild_id, "user_id": user_id, "role_id": role_id, "reason": reason}
    try:
        _require_guild_access(token, guild_id)
        _require_permission(token, PermissionLevel.moderate)
        guild = await get_guild(guild_id)
        member = await get_member(guild_id, user_id)
        role = guild.get_role(int(role_id))
        if role is None:
            raise ValueError(f"Role {role_id!r} not found.")
        await member.remove_roles(role, reason=reason)
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="remove_member_role", arguments=args, result=AuditResult.success, target_user_id=user_id)
        return json.dumps({"status": "success", "user_id": user_id, "role_id": role_id, "role_name": role.name})
    except PermissionError as exc:
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="remove_member_role", arguments=args, result=AuditResult.denied, result_detail=str(exc))
        return json.dumps({"error": "Permission denied", "detail": str(exc)})
    except Exception as exc:
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="remove_member_role", arguments=args, result=AuditResult.error, result_detail=str(exc))
        return json.dumps({"error": str(exc)})


@mcp.tool(
    name="set_member_nickname",
    description="Set or clear a member's nickname. Pass empty string to clear.",
)
async def set_member_nickname(guild_id: str, user_id: str, nickname: str, reason: str = "Nickname changed via ModLink MCP") -> str:
    token = _get_ml_token()
    if token is None:
        return json.dumps({"error": "Unauthenticated"})
    args = {"guild_id": guild_id, "user_id": user_id, "nickname": nickname}
    try:
        _require_guild_access(token, guild_id)
        _require_permission(token, PermissionLevel.moderate)
        member = await get_member(guild_id, user_id)
        await member.edit(nick=nickname or None, reason=reason)
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="set_member_nickname", arguments=args, result=AuditResult.success, target_user_id=user_id)
        return json.dumps({"status": "success", "user_id": user_id, "new_nickname": nickname or None})
    except PermissionError as exc:
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="set_member_nickname", arguments=args, result=AuditResult.denied, result_detail=str(exc))
        return json.dumps({"error": "Permission denied", "detail": str(exc)})
    except Exception as exc:
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="set_member_nickname", arguments=args, result=AuditResult.error, result_detail=str(exc))
        return json.dumps({"error": str(exc)})


@mcp.tool(
    name="unban_member",
    description="Unban a user from the guild by their user ID.",
)
async def unban_member(guild_id: str, user_id: str, reason: str = "Unbanned via ModLink MCP") -> str:
    token = _get_ml_token()
    if token is None:
        return json.dumps({"error": "Unauthenticated"})
    args = {"guild_id": guild_id, "user_id": user_id, "reason": reason}
    try:
        _require_guild_access(token, guild_id)
        _require_permission(token, PermissionLevel.admin)
        guild = await get_guild(guild_id)
        await guild.unban(discord.Object(id=int(user_id)), reason=reason)
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="unban_member", arguments=args, result=AuditResult.success, target_user_id=user_id)
        return json.dumps({"status": "unbanned", "user_id": user_id})
    except PermissionError as exc:
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="unban_member", arguments=args, result=AuditResult.denied, result_detail=str(exc))
        return json.dumps({"error": "Permission denied", "detail": str(exc)})
    except Exception as exc:
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="unban_member", arguments=args, result=AuditResult.error, result_detail=str(exc))
        return json.dumps({"error": str(exc)})


@mcp.tool(
    name="remove_timeout",
    description="Remove an active timeout from a guild member.",
)
async def remove_timeout(guild_id: str, user_id: str, reason: str = "Timeout removed via ModLink MCP") -> str:
    token = _get_ml_token()
    if token is None:
        return json.dumps({"error": "Unauthenticated"})
    args = {"guild_id": guild_id, "user_id": user_id}
    try:
        _require_guild_access(token, guild_id)
        _require_permission(token, PermissionLevel.moderate)
        member = await get_member(guild_id, user_id)
        await member.timeout(None, reason=reason)
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="remove_timeout", arguments=args, result=AuditResult.success, target_user_id=user_id)
        return json.dumps({"status": "timeout_removed", "user_id": user_id, "username": str(member)})
    except PermissionError as exc:
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="remove_timeout", arguments=args, result=AuditResult.denied, result_detail=str(exc))
        return json.dumps({"error": "Permission denied", "detail": str(exc)})
    except Exception as exc:
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="remove_timeout", arguments=args, result=AuditResult.error, result_detail=str(exc))
        return json.dumps({"error": str(exc)})


@mcp.tool(
    name="move_member_to_voice",
    description="Move a member to a different voice channel. Pass null channel_id to disconnect.",
)
async def move_member_to_voice(guild_id: str, user_id: str, channel_id: str) -> str:
    token = _get_ml_token()
    if token is None:
        return json.dumps({"error": "Unauthenticated"})
    args = {"guild_id": guild_id, "user_id": user_id, "channel_id": channel_id}
    try:
        _require_guild_access(token, guild_id)
        _require_permission(token, PermissionLevel.moderate)
        guild = await get_guild(guild_id)
        member = await get_member(guild_id, user_id)
        channel = guild.get_channel(int(channel_id)) if channel_id else None
        await member.move_to(channel)
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="move_member_to_voice", arguments=args, result=AuditResult.success, target_user_id=user_id)
        return json.dumps({"status": "moved", "user_id": user_id, "channel_id": channel_id})
    except PermissionError as exc:
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="move_member_to_voice", arguments=args, result=AuditResult.denied, result_detail=str(exc))
        return json.dumps({"error": "Permission denied", "detail": str(exc)})
    except Exception as exc:
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="move_member_to_voice", arguments=args, result=AuditResult.error, result_detail=str(exc))
        return json.dumps({"error": str(exc)})


# ══════════════════════════════════════════════════════════════════════════════
# MODERATION TOOLS
# ══════════════════════════════════════════════════════════════════════════════

@mcp.tool(
    name="purge_messages",
    description="Bulk delete up to 100 recent messages from a channel. limit: number of messages (1-100).",
)
async def purge_messages(guild_id: str, channel_id: str, limit: int = 10, reason: str = "Purged via ModLink MCP") -> str:
    token = _get_ml_token()
    if token is None:
        return json.dumps({"error": "Unauthenticated"})
    args = {"guild_id": guild_id, "channel_id": channel_id, "limit": limit}
    try:
        _require_guild_access(token, guild_id)
        _require_permission(token, PermissionLevel.moderate)
        limit = max(1, min(limit, 100))
        channel = await get_channel(guild_id, channel_id)
        deleted = await channel.purge(limit=limit, reason=reason)
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="purge_messages", arguments=args, result=AuditResult.success)
        return json.dumps({"status": "purged", "deleted_count": len(deleted), "channel_id": channel_id})
    except PermissionError as exc:
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="purge_messages", arguments=args, result=AuditResult.denied, result_detail=str(exc))
        return json.dumps({"error": "Permission denied", "detail": str(exc)})
    except Exception as exc:
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="purge_messages", arguments=args, result=AuditResult.error, result_detail=str(exc))
        return json.dumps({"error": str(exc)})


@mcp.tool(
    name="purge_user_messages",
    description="Bulk delete messages from a specific user in a channel. limit: 1-100.",
)
async def purge_user_messages(guild_id: str, channel_id: str, user_id: str, limit: int = 10) -> str:
    token = _get_ml_token()
    if token is None:
        return json.dumps({"error": "Unauthenticated"})
    args = {"guild_id": guild_id, "channel_id": channel_id, "user_id": user_id, "limit": limit}
    try:
        _require_guild_access(token, guild_id)
        _require_permission(token, PermissionLevel.moderate)
        limit = max(1, min(limit, 100))
        channel = await get_channel(guild_id, channel_id)
        deleted = await channel.purge(limit=limit, check=lambda m: str(m.author.id) == user_id)
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="purge_user_messages", arguments=args, result=AuditResult.success, target_user_id=user_id)
        return json.dumps({"status": "purged", "deleted_count": len(deleted), "user_id": user_id})
    except PermissionError as exc:
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="purge_user_messages", arguments=args, result=AuditResult.denied, result_detail=str(exc))
        return json.dumps({"error": "Permission denied", "detail": str(exc)})
    except Exception as exc:
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="purge_user_messages", arguments=args, result=AuditResult.error, result_detail=str(exc))
        return json.dumps({"error": str(exc)})


@mcp.tool(
    name="get_bans",
    description="List banned users in a guild. limit: max bans to fetch (default 50, max 1000).",
)
async def get_bans(guild_id: str, limit: int = 50) -> str:
    token = _get_ml_token()
    if token is None:
        return json.dumps({"error": "Unauthenticated"})
    args = {"guild_id": guild_id, "limit": limit}
    try:
        _require_guild_access(token, guild_id)
        _require_permission(token, PermissionLevel.moderate)
        guild = await get_guild(guild_id)
        bans = []
        async for ban_entry in guild.bans(limit=max(1, min(limit, 1000))):
            bans.append({
                "user_id": str(ban_entry.user.id),
                "username": str(ban_entry.user),
                "reason": ban_entry.reason,
            })
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="get_bans", arguments=args, result=AuditResult.success)
        return json.dumps({"guild_id": guild_id, "bans": bans, "total": len(bans)}, indent=2)
    except PermissionError as exc:
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="get_bans", arguments=args, result=AuditResult.denied, result_detail=str(exc))
        return json.dumps({"error": "Permission denied", "detail": str(exc)})
    except Exception as exc:
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="get_bans", arguments=args, result=AuditResult.error, result_detail=str(exc))
        return json.dumps({"error": str(exc)})


@mcp.tool(
    name="get_audit_log",
    description="Retrieve the guild audit log. limit: entries to fetch (1-100). action_type: optional Discord audit log action integer (e.g. 20=kick, 22=ban).",
)
async def get_audit_log(guild_id: str, limit: int = 25, action_type: Optional[int] = None) -> str:
    token = _get_ml_token()
    if token is None:
        return json.dumps({"error": "Unauthenticated"})
    args = {"guild_id": guild_id, "limit": limit, "action_type": action_type}
    try:
        _require_guild_access(token, guild_id)
        _require_permission(token, PermissionLevel.moderate)
        guild = await get_guild(guild_id)
        limit = max(1, min(limit, 100))
        action = discord.AuditLogAction(action_type) if action_type is not None else discord.utils.MISSING
        entries = []
        async for entry in guild.audit_logs(limit=limit, action=action):
            entries.append({
                "id": str(entry.id),
                "action": str(entry.action),
                "user": str(entry.user) if entry.user else None,
                "user_id": str(entry.user.id) if entry.user else None,
                "target": str(entry.target) if entry.target else None,
                "reason": entry.reason,
                "created_at": entry.created_at.isoformat(),
            })
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="get_audit_log", arguments=args, result=AuditResult.success)
        return json.dumps({"guild_id": guild_id, "entries": entries, "returned": len(entries)}, indent=2)
    except PermissionError as exc:
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="get_audit_log", arguments=args, result=AuditResult.denied, result_detail=str(exc))
        return json.dumps({"error": "Permission denied", "detail": str(exc)})
    except Exception as exc:
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="get_audit_log", arguments=args, result=AuditResult.error, result_detail=str(exc))
        return json.dumps({"error": str(exc)})


@mcp.tool(
    name="lock_channel",
    description="Lock a text channel so @everyone cannot send messages.",
)
async def lock_channel(guild_id: str, channel_id: str, reason: str = "Channel locked via ModLink MCP") -> str:
    token = _get_ml_token()
    if token is None:
        return json.dumps({"error": "Unauthenticated"})
    args = {"guild_id": guild_id, "channel_id": channel_id}
    try:
        _require_guild_access(token, guild_id)
        _require_permission(token, PermissionLevel.manage)
        channel = await get_channel(guild_id, channel_id)
        guild = await get_guild(guild_id)
        await channel.set_permissions(guild.default_role, send_messages=False, reason=reason)
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="lock_channel", arguments=args, result=AuditResult.success)
        return json.dumps({"status": "locked", "channel_id": channel_id, "channel_name": channel.name})
    except PermissionError as exc:
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="lock_channel", arguments=args, result=AuditResult.denied, result_detail=str(exc))
        return json.dumps({"error": "Permission denied", "detail": str(exc)})
    except Exception as exc:
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="lock_channel", arguments=args, result=AuditResult.error, result_detail=str(exc))
        return json.dumps({"error": str(exc)})


@mcp.tool(
    name="unlock_channel",
    description="Unlock a text channel so @everyone can send messages again.",
)
async def unlock_channel(guild_id: str, channel_id: str, reason: str = "Channel unlocked via ModLink MCP") -> str:
    token = _get_ml_token()
    if token is None:
        return json.dumps({"error": "Unauthenticated"})
    args = {"guild_id": guild_id, "channel_id": channel_id}
    try:
        _require_guild_access(token, guild_id)
        _require_permission(token, PermissionLevel.manage)
        channel = await get_channel(guild_id, channel_id)
        guild = await get_guild(guild_id)
        await channel.set_permissions(guild.default_role, send_messages=None, reason=reason)
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="unlock_channel", arguments=args, result=AuditResult.success)
        return json.dumps({"status": "unlocked", "channel_id": channel_id, "channel_name": channel.name})
    except PermissionError as exc:
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="unlock_channel", arguments=args, result=AuditResult.denied, result_detail=str(exc))
        return json.dumps({"error": "Permission denied", "detail": str(exc)})
    except Exception as exc:
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="unlock_channel", arguments=args, result=AuditResult.error, result_detail=str(exc))
        return json.dumps({"error": str(exc)})


@mcp.tool(
    name="slowmode_channel",
    description="Set the slowmode delay (in seconds) for a text channel. 0 disables slowmode. Max 21600 (6 hours).",
)
async def slowmode_channel(guild_id: str, channel_id: str, seconds: int) -> str:
    token = _get_ml_token()
    if token is None:
        return json.dumps({"error": "Unauthenticated"})
    args = {"guild_id": guild_id, "channel_id": channel_id, "seconds": seconds}
    try:
        _require_guild_access(token, guild_id)
        _require_permission(token, PermissionLevel.manage)
        channel = await get_channel(guild_id, channel_id)
        seconds = max(0, min(seconds, 21600))
        await channel.edit(slowmode_delay=seconds)
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="slowmode_channel", arguments=args, result=AuditResult.success)
        return json.dumps({"status": "success", "channel_id": channel_id, "slowmode_seconds": seconds})
    except PermissionError as exc:
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="slowmode_channel", arguments=args, result=AuditResult.denied, result_detail=str(exc))
        return json.dumps({"error": "Permission denied", "detail": str(exc)})
    except Exception as exc:
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="slowmode_channel", arguments=args, result=AuditResult.error, result_detail=str(exc))
        return json.dumps({"error": str(exc)})


@mcp.tool(
    name="warn_member",
    description="Issue a warning to a member (stored in ModLink DB and optionally DMed).",
)
async def warn_member(guild_id: str, user_id: str, reason: str, notify_via_dm: bool = True) -> str:
    token = _get_ml_token()
    if token is None:
        return json.dumps({"error": "Unauthenticated"})
    args = {"guild_id": guild_id, "user_id": user_id, "reason": reason}
    try:
        _require_guild_access(token, guild_id)
        _require_permission(token, PermissionLevel.moderate)
        member = await get_member(guild_id, user_id)
        # Store warning in audit log
        async with AsyncSessionLocal() as session:
            log = AuditLog(
                connection_id=token.connection_id,
                guild_id=guild_id,
                tool_name="warn_member",
                arguments=args,
                result=AuditResult.success,
                result_detail=f"Warning: {reason}",
                target_user_id=user_id,
            )
            session.add(log)
            await session.commit()
        dm_sent = False
        if notify_via_dm:
            try:
                await member.send(f"⚠️ You have received a warning in **{member.guild.name}**:\n> {reason}")
                dm_sent = True
            except Exception:
                dm_sent = False
        return json.dumps({"status": "warned", "user_id": user_id, "username": str(member),
                           "reason": reason, "dm_sent": dm_sent})
    except PermissionError as exc:
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="warn_member", arguments=args, result=AuditResult.denied, result_detail=str(exc))
        return json.dumps({"error": "Permission denied", "detail": str(exc)})
    except Exception as exc:
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="warn_member", arguments=args, result=AuditResult.error, result_detail=str(exc))
        return json.dumps({"error": str(exc)})


@mcp.tool(
    name="get_warnings",
    description="Get warning history for a specific member from the ModLink audit log.",
)
async def get_warnings(guild_id: str, user_id: str) -> str:
    token = _get_ml_token()
    if token is None:
        return json.dumps({"error": "Unauthenticated"})
    args = {"guild_id": guild_id, "user_id": user_id}
    try:
        _require_guild_access(token, guild_id)
        _require_permission(token, PermissionLevel.read)
        async with AsyncSessionLocal() as session:
            result = await session.execute(
                select(AuditLog).where(
                    AuditLog.guild_id == guild_id,
                    AuditLog.target_user_id == user_id,
                    AuditLog.tool_name == "warn_member",
                ).order_by(AuditLog.created_at.desc())
            )
            logs = result.scalars().all()
        warnings = [
            {
                "id": str(log.id),
                "reason": log.result_detail,
                "issued_at": log.created_at.isoformat() if log.created_at else None,
                "issued_by_connection": log.connection_id,
            }
            for log in logs
        ]
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="get_warnings", arguments=args, result=AuditResult.success)
        return json.dumps({"user_id": user_id, "warnings": warnings, "total": len(warnings)}, indent=2)
    except PermissionError as exc:
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="get_warnings", arguments=args, result=AuditResult.denied, result_detail=str(exc))
        return json.dumps({"error": "Permission denied", "detail": str(exc)})
    except Exception as exc:
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="get_warnings", arguments=args, result=AuditResult.error, result_detail=str(exc))
        return json.dumps({"error": str(exc)})


# ══════════════════════════════════════════════════════════════════════════════
# ROLE MANAGEMENT TOOLS
# ══════════════════════════════════════════════════════════════════════════════

@mcp.tool(
    name="list_roles",
    description="List all roles in a guild with their IDs, colors, permissions, and member counts.",
)
async def list_roles(guild_id: str) -> str:
    token = _get_ml_token()
    if token is None:
        return json.dumps({"error": "Unauthenticated"})
    args = {"guild_id": guild_id}
    try:
        _require_guild_access(token, guild_id)
        _require_permission(token, PermissionLevel.read)
        guild = await get_guild(guild_id)
        roles = [
            {
                "role_id": str(r.id),
                "name": r.name,
                "color": str(r.color),
                "hoist": r.hoist,
                "mentionable": r.mentionable,
                "position": r.position,
                "managed": r.managed,
                "member_count": len(r.members),
            }
            for r in sorted(guild.roles, key=lambda r: -r.position)
        ]
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="list_roles", arguments=args, result=AuditResult.success)
        return json.dumps({"guild_id": guild_id, "roles": roles, "total": len(roles)}, indent=2)
    except PermissionError as exc:
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="list_roles", arguments=args, result=AuditResult.denied, result_detail=str(exc))
        return json.dumps({"error": "Permission denied", "detail": str(exc)})
    except Exception as exc:
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="list_roles", arguments=args, result=AuditResult.error, result_detail=str(exc))
        return json.dumps({"error": str(exc)})


@mcp.tool(
    name="create_role",
    description="Create a new role in the guild. color: hex string like '#ff0000'. hoist: show separately in member list.",
)
async def create_role(
    guild_id: str,
    name: str,
    color: str = "#000000",
    hoist: bool = False,
    mentionable: bool = False,
    reason: str = "Role created via ModLink MCP",
) -> str:
    token = _get_ml_token()
    if token is None:
        return json.dumps({"error": "Unauthenticated"})
    args = {"guild_id": guild_id, "name": name, "color": color, "hoist": hoist, "mentionable": mentionable}
    try:
        _require_guild_access(token, guild_id)
        _require_permission(token, PermissionLevel.manage)
        guild = await get_guild(guild_id)
        c = discord.Color(int(color.lstrip("#"), 16)) if color and color != "#000000" else discord.Color.default()
        role = await guild.create_role(name=name, color=c, hoist=hoist, mentionable=mentionable, reason=reason)
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="create_role", arguments=args, result=AuditResult.success)
        return json.dumps({"status": "created", "role_id": str(role.id), "name": role.name, "color": str(role.color)})
    except PermissionError as exc:
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="create_role", arguments=args, result=AuditResult.denied, result_detail=str(exc))
        return json.dumps({"error": "Permission denied", "detail": str(exc)})
    except Exception as exc:
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="create_role", arguments=args, result=AuditResult.error, result_detail=str(exc))
        return json.dumps({"error": str(exc)})


@mcp.tool(
    name="check_role_hierarchy",
    description="Preflight check comparing the bot's highest role against a target role. Explains if the bot can edit/delete/assign it, with actionable hints. [Requires: read]",
)
async def check_role_hierarchy(guild_id: str, role_id: str) -> str:
    token = _get_ml_token()
    if token is None:
        return json.dumps({
            "status": "error", "error": "unauthenticated",
            "code": "missing_or_invalid_api_key",
            "message": "Valid ModLink API key is required.",
            "hint": "Set Authorization: Bearer <key> in headers.",
        }, indent=2)
    try:
        _require_guild_access(token, guild_id)
        _require_permission(token, PermissionLevel.read)
        guild = await get_guild(guild_id)
        role = guild.get_role(int(role_id))
        if role is None:
            return json.dumps({
                "status": "error", "error": "not_found", "code": "role_not_found",
                "message": f"Role ID '{role_id}' was not found in guild '{guild.name}'.",
                "hint": "Use list_roles to retrieve active role IDs.",
            }, indent=2)

        bot_member = guild.me or guild.get_member(bot.user.id)
        bot_top = bot_member.top_role if bot_member else None
        is_owner = guild.owner_id == bot.user.id

        if role.managed:
            return json.dumps({
                "status": "ok", "can_manage": False, "reason": "managed_role",
                "role_name": role.name, "role_position": role.position,
                "bot_top_role": bot_top.name if bot_top else None,
                "bot_top_role_position": bot_top.position if bot_top else 0,
                "explanation": f"Role '{role.name}' is managed by an external integration and cannot be edited by bots.",
                "hint": "Managed roles cannot be manually edited or assigned.",
            }, indent=2)

        can_manage = is_owner or (bot_top is not None and bot_top.position > role.position)
        if not can_manage:
            return json.dumps({
                "status": "ok", "can_manage": False, "reason": "bot_role_too_low",
                "role_name": role.name, "role_position": role.position,
                "bot_top_role": bot_top.name if bot_top else None,
                "bot_top_role_position": bot_top.position if bot_top else 0,
                "hierarchy_difference": (bot_top.position - role.position) if bot_top else -999,
                "explanation": f"Bot's top role '{bot_top.name if bot_top else 'None'}' (position {bot_top.position if bot_top else 0}) is not higher than target role '{role.name}' (position {role.position}).",
                "hint": f"In Discord Server Settings > Roles, drag the bot's role '{bot_top.name if bot_top else 'ModLink'}' above '{role.name}'.",
            }, indent=2)

        return json.dumps({
            "status": "ok", "can_manage": True, "reason": "ok",
            "role_name": role.name, "role_position": role.position,
            "bot_top_role": bot_top.name if bot_top else None,
            "bot_top_role_position": bot_top.position if bot_top else 0,
            "hierarchy_difference": (bot_top.position - role.position) if bot_top else 0,
            "explanation": f"Bot has hierarchy clearance to manage role '{role.name}'.",
            "hint": "Role is safe to edit, delete, or assign.",
        }, indent=2)
    except Exception as exc:
        from app.modules.common import format_discord_error
        return format_discord_error(exc, action_context=f"checking hierarchy for role {role_id}")


@mcp.tool(
    name="delete_role",
    description="Delete a role from the guild by role ID. [Requires: manage]",
)
async def delete_role(guild_id: str, role_id: str, reason: str = "Role deleted via ModLink MCP") -> str:
    token = _get_ml_token()
    if token is None:
        return json.dumps({
            "status": "error", "error": "unauthenticated",
            "code": "missing_or_invalid_api_key",
            "message": "Valid ModLink API key is required.",
            "hint": "Set Authorization: Bearer <key> in headers.",
        }, indent=2)
    args = {"guild_id": guild_id, "role_id": role_id}
    try:
        _require_guild_access(token, guild_id)
        _require_permission(token, PermissionLevel.manage)
        guild = await get_guild(guild_id)
        role = guild.get_role(int(role_id))
        if role is None:
            return json.dumps({
                "status": "error", "error": "not_found", "code": "role_not_found",
                "message": f"Role {role_id!r} not found.",
                "hint": "Check list_roles for valid IDs.",
            }, indent=2)

        bot_member = guild.me or guild.get_member(bot.user.id)
        if bot_member and bot_member.top_role.position <= role.position and guild.owner_id != bot.user.id:
            from app.modules.common import make_error
            return make_error(
                code="bot_role_too_low",
                message=f"Cannot delete role '{role.name}' (position {role.position}): The bot's top role '{bot_member.top_role.name}' (position {bot_member.top_role.position}) is lower or equal.",
                hint=f"In Discord Server Settings > Roles, drag the bot's role '{bot_member.top_role.name}' above '{role.name}'.",
            )

        role_name = role.name
        await role.delete(reason=reason)
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="delete_role", arguments=args, result=AuditResult.success)
        return json.dumps({"status": "deleted", "role_id": role_id, "name": role_name}, indent=2)
    except PermissionError as exc:
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="delete_role", arguments=args, result=AuditResult.denied, result_detail=str(exc))
        return json.dumps({"status": "error", "error": "insufficient_permission", "code": "insufficient_permission", "message": str(exc), "hint": "Upgrade connection permission level to manage or admin."}, indent=2)
    except Exception as exc:
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="delete_role", arguments=args, result=AuditResult.error, result_detail=str(exc))
        from app.modules.common import format_discord_error
        return format_discord_error(exc, action_context=f"deleting role {role_id}")


@mcp.tool(
    name="edit_role",
    description="Edit a role's name, color, hoist, and mentionable settings. Pass only the fields you want to change. [Requires: manage]",
)
async def edit_role(
    guild_id: str,
    role_id: str,
    name: Optional[str] = None,
    color: Optional[str] = None,
    hoist: Optional[bool] = None,
    mentionable: Optional[bool] = None,
    reason: str = "Role edited via ModLink MCP",
) -> str:
    token = _get_ml_token()
    if token is None:
        return json.dumps({
            "status": "error", "error": "unauthenticated",
            "code": "missing_or_invalid_api_key",
            "message": "Valid ModLink API key is required.",
            "hint": "Set Authorization: Bearer <key> in headers.",
        }, indent=2)
    args = {"guild_id": guild_id, "role_id": role_id, "name": name, "color": color}
    try:
        _require_guild_access(token, guild_id)
        _require_permission(token, PermissionLevel.manage)
        guild = await get_guild(guild_id)
        role = guild.get_role(int(role_id))
        if role is None:
            return json.dumps({
                "status": "error", "error": "not_found", "code": "role_not_found",
                "message": f"Role {role_id!r} not found.",
                "hint": "Check list_roles for valid IDs.",
            }, indent=2)

        bot_member = guild.me or guild.get_member(bot.user.id)
        if bot_member and bot_member.top_role.position <= role.position and guild.owner_id != bot.user.id:
            from app.modules.common import make_error
            return make_error(
                code="bot_role_too_low",
                message=f"Cannot edit role '{role.name}' (position {role.position}): The bot's top role '{bot_member.top_role.name}' (position {bot_member.top_role.position}) is lower or equal.",
                hint=f"In Discord Server Settings > Roles, drag the bot's role '{bot_member.top_role.name}' above '{role.name}'.",
            )

        kwargs: dict = {}
        if name is not None:
            kwargs["name"] = name
        if color is not None:
            kwargs["color"] = discord.Color(int(color.lstrip("#"), 16))
        if hoist is not None:
            kwargs["hoist"] = hoist
        if mentionable is not None:
            kwargs["mentionable"] = mentionable
        await role.edit(reason=reason, **kwargs)
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="edit_role", arguments=args, result=AuditResult.success)
        return json.dumps({"status": "updated", "role_id": role_id, "name": role.name, "color": str(role.color)}, indent=2)
    except PermissionError as exc:
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="edit_role", arguments=args, result=AuditResult.denied, result_detail=str(exc))
        return json.dumps({"status": "error", "error": "insufficient_permission", "code": "insufficient_permission", "message": str(exc), "hint": "Upgrade connection permission level to manage or admin."}, indent=2)
    except Exception as exc:
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="edit_role", arguments=args, result=AuditResult.error, result_detail=str(exc))
        from app.modules.common import format_discord_error
        return format_discord_error(exc, action_context=f"editing role {role_id}")


@mcp.tool(
    name="get_role_members",
    description="List all members who have a specific role.",
)
async def get_role_members(guild_id: str, role_id: str) -> str:
    token = _get_ml_token()
    if token is None:
        return json.dumps({"error": "Unauthenticated"})
    args = {"guild_id": guild_id, "role_id": role_id}
    try:
        _require_guild_access(token, guild_id)
        _require_permission(token, PermissionLevel.read)
        guild = await get_guild(guild_id)
        role = guild.get_role(int(role_id))
        if role is None:
            raise ValueError(f"Role {role_id!r} not found.")
        members = [{"user_id": str(m.id), "username": str(m), "display_name": m.display_name} for m in role.members]
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="get_role_members", arguments=args, result=AuditResult.success)
        return json.dumps({"role_id": role_id, "role_name": role.name, "members": members, "total": len(members)}, indent=2)
    except PermissionError as exc:
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="get_role_members", arguments=args, result=AuditResult.denied, result_detail=str(exc))
        return json.dumps({"error": "Permission denied", "detail": str(exc)})
    except Exception as exc:
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="get_role_members", arguments=args, result=AuditResult.error, result_detail=str(exc))
        return json.dumps({"error": str(exc)})


# ══════════════════════════════════════════════════════════════════════════════
# CHANNEL MANAGEMENT TOOLS
# ══════════════════════════════════════════════════════════════════════════════

@mcp.tool(
    name="list_channels",
    description="List all channels in a guild including their IDs, types, and categories.",
)
async def list_channels(guild_id: str) -> str:
    token = _get_ml_token()
    if token is None:
        return json.dumps({"error": "Unauthenticated"})
    args = {"guild_id": guild_id}
    try:
        _require_guild_access(token, guild_id)
        _require_permission(token, PermissionLevel.read)
        guild = await get_guild(guild_id)
        channels = []
        for ch in sorted(guild.channels, key=lambda c: (c.position if hasattr(c, "position") else 0)):
            entry = {
                "channel_id": str(ch.id),
                "name": ch.name,
                "type": str(ch.type),
                "position": getattr(ch, "position", None),
                "category": ch.category.name if hasattr(ch, "category") and ch.category else None,
            }
            if isinstance(ch, discord.TextChannel):
                entry["topic"] = ch.topic
                entry["slowmode"] = ch.slowmode_delay
                entry["nsfw"] = ch.is_nsfw()
            channels.append(entry)
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="list_channels", arguments=args, result=AuditResult.success)
        return json.dumps({"guild_id": guild_id, "channels": channels, "total": len(channels)}, indent=2)
    except PermissionError as exc:
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="list_channels", arguments=args, result=AuditResult.denied, result_detail=str(exc))
        return json.dumps({"error": "Permission denied", "detail": str(exc)})
    except Exception as exc:
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="list_channels", arguments=args, result=AuditResult.error, result_detail=str(exc))
        return json.dumps({"error": str(exc)})


@mcp.tool(
    name="create_text_channel",
    description="Create a new text channel in the guild. category_id is optional.",
)
async def create_text_channel(
    guild_id: str,
    name: str,
    topic: str = "",
    category_id: Optional[str] = None,
    reason: str = "Channel created via ModLink MCP",
) -> str:
    token = _get_ml_token()
    if token is None:
        return json.dumps({"error": "Unauthenticated"})
    args = {"guild_id": guild_id, "name": name, "topic": topic, "category_id": category_id}
    try:
        _require_guild_access(token, guild_id)
        _require_permission(token, PermissionLevel.manage)
        guild = await get_guild(guild_id)
        category = guild.get_channel(int(category_id)) if category_id else None
        channel = await guild.create_text_channel(name=name, topic=topic or None, category=category, reason=reason)
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="create_text_channel", arguments=args, result=AuditResult.success)
        return json.dumps({"status": "created", "channel_id": str(channel.id), "name": channel.name})
    except PermissionError as exc:
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="create_text_channel", arguments=args, result=AuditResult.denied, result_detail=str(exc))
        return json.dumps({"error": "Permission denied", "detail": str(exc)})
    except Exception as exc:
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="create_text_channel", arguments=args, result=AuditResult.error, result_detail=str(exc))
        return json.dumps({"error": str(exc)})


@mcp.tool(
    name="delete_channel",
    description="Delete a channel from the guild by channel ID.",
)
async def delete_channel(guild_id: str, channel_id: str, reason: str = "Channel deleted via ModLink MCP") -> str:
    token = _get_ml_token()
    if token is None:
        return json.dumps({"error": "Unauthenticated"})
    args = {"guild_id": guild_id, "channel_id": channel_id}
    try:
        _require_guild_access(token, guild_id)
        _require_permission(token, PermissionLevel.admin)
        guild = await get_guild(guild_id)
        channel = guild.get_channel(int(channel_id))
        if channel is None:
            raise ValueError(f"Channel {channel_id!r} not found.")
        channel_name = channel.name
        await channel.delete(reason=reason)
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="delete_channel", arguments=args, result=AuditResult.success)
        return json.dumps({"status": "deleted", "channel_id": channel_id, "name": channel_name})
    except PermissionError as exc:
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="delete_channel", arguments=args, result=AuditResult.denied, result_detail=str(exc))
        return json.dumps({"error": "Permission denied", "detail": str(exc)})
    except Exception as exc:
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="delete_channel", arguments=args, result=AuditResult.error, result_detail=str(exc))
        return json.dumps({"error": str(exc)})


@mcp.tool(
    name="edit_channel",
    description="Edit a channel's properties (supports text, voice, stage, and forum channels). [Requires: manage]",
)
async def edit_channel(
    guild_id: str,
    channel_id: str,
    name: Optional[str] = None,
    topic: Optional[str] = None,
    slowmode_delay: Optional[int] = None,
    nsfw: Optional[bool] = None,
    user_limit: Optional[int] = None,
    bitrate: Optional[int] = None,
    category_id: Optional[str] = None,
    reason: str = "Channel edited via ModLink MCP",
) -> str:
    token = _get_ml_token()
    if token is None:
        return json.dumps({
            "status": "error", "error": "unauthenticated",
            "code": "missing_or_invalid_api_key",
            "message": "Valid ModLink API key is required.",
            "hint": "Set Authorization: Bearer <key> in headers.",
        }, indent=2)
    args = {"guild_id": guild_id, "channel_id": channel_id, "name": name, "topic": topic}
    try:
        _require_guild_access(token, guild_id)
        _require_permission(token, PermissionLevel.manage)
        channel = await get_any_channel(guild_id, channel_id)
        kwargs: dict = {}
        if name is not None:
            kwargs["name"] = name
        if topic is not None and hasattr(channel, "topic"):
            kwargs["topic"] = topic
        if slowmode_delay is not None and hasattr(channel, "slowmode_delay"):
            kwargs["slowmode_delay"] = max(0, min(slowmode_delay, 21600))
        if nsfw is not None and hasattr(channel, "nsfw"):
            kwargs["nsfw"] = nsfw
        if user_limit is not None and hasattr(channel, "user_limit"):
            kwargs["user_limit"] = max(0, min(user_limit, 99))
        if bitrate is not None and hasattr(channel, "bitrate"):
            kwargs["bitrate"] = max(8000, min(bitrate, 384000))
        if category_id is not None:
            if category_id.lower() in ("none", "null", "0", ""):
                kwargs["category"] = None
            else:
                guild = await get_guild(guild_id)
                cat = guild.get_channel(int(category_id))
                if isinstance(cat, discord.CategoryChannel):
                    kwargs["category"] = cat

        await channel.edit(reason=reason, **kwargs)
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="edit_channel", arguments=args, result=AuditResult.success)
        return json.dumps({
            "status": "updated",
            "channel_id": channel_id,
            "name": channel.name,
            "type": str(channel.type),
        }, indent=2)
    except PermissionError as exc:
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="edit_channel", arguments=args, result=AuditResult.denied, result_detail=str(exc))
        return json.dumps({"status": "error", "error": "insufficient_permission", "code": "insufficient_permission", "message": str(exc), "hint": "Upgrade connection permission level to manage or admin."}, indent=2)
    except Exception as exc:
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="edit_channel", arguments=args, result=AuditResult.error, result_detail=str(exc))
        from app.modules.common import format_discord_error
        return format_discord_error(exc, action_context=f"editing channel {channel_id}")


# ══════════════════════════════════════════════════════════════════════════════
# MESSAGE MANAGEMENT TOOLS
# ══════════════════════════════════════════════════════════════════════════════

@mcp.tool(
    name="send_message",
    description="Send a message to a text channel.",
)
async def send_message(guild_id: str, channel_id: str, content: str) -> str:
    token = _get_ml_token()
    if token is None:
        return json.dumps({"error": "Unauthenticated"})
    args = {"guild_id": guild_id, "channel_id": channel_id, "content": content}
    try:
        _require_guild_access(token, guild_id)
        _require_permission(token, PermissionLevel.moderate)
        channel = await get_channel(guild_id, channel_id)
        msg = await channel.send(content)
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="send_message", arguments=args, result=AuditResult.success)
        return json.dumps({"status": "sent", "message_id": str(msg.id), "channel_id": channel_id})
    except PermissionError as exc:
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="send_message", arguments=args, result=AuditResult.denied, result_detail=str(exc))
        return json.dumps({"error": "Permission denied", "detail": str(exc)})
    except Exception as exc:
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="send_message", arguments=args, result=AuditResult.error, result_detail=str(exc))
        return json.dumps({"error": str(exc)})


@mcp.tool(
    name="send_embed",
    description="Send a rich embed message to a channel. color: hex like '#5865f2'.",
)
async def send_embed(
    guild_id: str,
    channel_id: str,
    title: str,
    description: str,
    color: str = "#5865f2",
    footer: str = "",
) -> str:
    token = _get_ml_token()
    if token is None:
        return json.dumps({"error": "Unauthenticated"})
    args = {"guild_id": guild_id, "channel_id": channel_id, "title": title}
    try:
        _require_guild_access(token, guild_id)
        _require_permission(token, PermissionLevel.moderate)
        channel = await get_channel(guild_id, channel_id)
        embed = discord.Embed(
            title=title,
            description=description,
            color=discord.Color(int(color.lstrip("#"), 16)),
        )
        if footer:
            embed.set_footer(text=footer)
        msg = await channel.send(embed=embed)
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="send_embed", arguments=args, result=AuditResult.success)
        return json.dumps({"status": "sent", "message_id": str(msg.id), "channel_id": channel_id})
    except PermissionError as exc:
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="send_embed", arguments=args, result=AuditResult.denied, result_detail=str(exc))
        return json.dumps({"error": "Permission denied", "detail": str(exc)})
    except Exception as exc:
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="send_embed", arguments=args, result=AuditResult.error, result_detail=str(exc))
        return json.dumps({"error": str(exc)})


@mcp.tool(
    name="send_dm",
    description="Send a direct message to a guild member.",
)
async def send_dm(guild_id: str, user_id: str, content: str) -> str:
    token = _get_ml_token()
    if token is None:
        return json.dumps({"error": "Unauthenticated"})
    args = {"guild_id": guild_id, "user_id": user_id}
    try:
        _require_guild_access(token, guild_id)
        _require_permission(token, PermissionLevel.moderate)
        member = await get_member(guild_id, user_id)
        await member.send(content)
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="send_dm", arguments=args, result=AuditResult.success, target_user_id=user_id)
        return json.dumps({"status": "sent", "user_id": user_id, "username": str(member)})
    except PermissionError as exc:
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="send_dm", arguments=args, result=AuditResult.denied, result_detail=str(exc))
        return json.dumps({"error": "Permission denied", "detail": str(exc)})
    except Exception as exc:
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="send_dm", arguments=args, result=AuditResult.error, result_detail=str(exc))
        return json.dumps({"error": str(exc)})


@mcp.tool(
    name="pin_message",
    description="Pin a message in a text channel.",
)
async def pin_message(guild_id: str, channel_id: str, message_id: str) -> str:
    token = _get_ml_token()
    if token is None:
        return json.dumps({"error": "Unauthenticated"})
    args = {"guild_id": guild_id, "channel_id": channel_id, "message_id": message_id}
    try:
        _require_guild_access(token, guild_id)
        _require_permission(token, PermissionLevel.moderate)
        channel = await get_channel(guild_id, channel_id)
        msg = await channel.fetch_message(int(message_id))
        await msg.pin()
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="pin_message", arguments=args, result=AuditResult.success)
        return json.dumps({"status": "pinned", "message_id": message_id, "channel_id": channel_id})
    except PermissionError as exc:
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="pin_message", arguments=args, result=AuditResult.denied, result_detail=str(exc))
        return json.dumps({"error": "Permission denied", "detail": str(exc)})
    except Exception as exc:
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="pin_message", arguments=args, result=AuditResult.error, result_detail=str(exc))
        return json.dumps({"error": str(exc)})


@mcp.tool(
    name="add_reaction",
    description="Add a reaction to a message. emoji: unicode emoji or custom emoji string like '<:name:id>'.",
)
async def add_reaction(guild_id: str, channel_id: str, message_id: str, emoji: str) -> str:
    token = _get_ml_token()
    if token is None:
        return json.dumps({"error": "Unauthenticated"})
    args = {"guild_id": guild_id, "channel_id": channel_id, "message_id": message_id, "emoji": emoji}
    try:
        _require_guild_access(token, guild_id)
        _require_permission(token, PermissionLevel.moderate)
        channel = await get_channel(guild_id, channel_id)
        msg = await channel.fetch_message(int(message_id))
        await msg.add_reaction(emoji)
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="add_reaction", arguments=args, result=AuditResult.success)
        return json.dumps({"status": "reacted", "message_id": message_id, "emoji": emoji})
    except PermissionError as exc:
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="add_reaction", arguments=args, result=AuditResult.denied, result_detail=str(exc))
        return json.dumps({"error": "Permission denied", "detail": str(exc)})
    except Exception as exc:
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="add_reaction", arguments=args, result=AuditResult.error, result_detail=str(exc))
        return json.dumps({"error": str(exc)})


# ══════════════════════════════════════════════════════════════════════════════
# SERVER MANAGEMENT TOOLS
# ══════════════════════════════════════════════════════════════════════════════

@mcp.tool(
    name="get_server_statistics",
    description="Get statistics about a guild: member count, channel count, role count, boost level, online status.",
)
async def get_server_statistics(guild_id: str) -> str:
    token = _get_ml_token()
    if token is None:
        return json.dumps({"error": "Unauthenticated"})
    args = {"guild_id": guild_id}
    try:
        _require_guild_access(token, guild_id)
        _require_permission(token, PermissionLevel.read)
        guild = await get_guild(guild_id)
        data = {
            "guild_id": guild_id,
            "name": guild.name,
            "member_count": guild.member_count,
            "online_count": sum(1 for m in guild.members if m.status != discord.Status.offline and not m.bot),
            "bot_count": sum(1 for m in guild.members if m.bot),
            "text_channels": len(guild.text_channels),
            "voice_channels": len(guild.voice_channels),
            "categories": len(guild.categories),
            "roles": len(guild.roles),
            "emojis": len(guild.emojis),
            "boost_level": guild.premium_tier,
            "boost_count": guild.premium_subscription_count,
            "verification_level": str(guild.verification_level),
            "created_at": guild.created_at.isoformat(),
        }
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="get_server_statistics", arguments=args, result=AuditResult.success)
        return json.dumps(data, indent=2)
    except PermissionError as exc:
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="get_server_statistics", arguments=args, result=AuditResult.denied, result_detail=str(exc))
        return json.dumps({"error": "Permission denied", "detail": str(exc)})
    except Exception as exc:
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="get_server_statistics", arguments=args, result=AuditResult.error, result_detail=str(exc))
        return json.dumps({"error": str(exc)})


@mcp.tool(
    name="get_server_emojis",
    description="List all custom emojis in a guild.",
)
async def get_server_emojis(guild_id: str) -> str:
    token = _get_ml_token()
    if token is None:
        return json.dumps({"error": "Unauthenticated"})
    args = {"guild_id": guild_id}
    try:
        _require_guild_access(token, guild_id)
        _require_permission(token, PermissionLevel.read)
        guild = await get_guild(guild_id)
        emojis = [
            {"emoji_id": str(e.id), "name": e.name, "animated": e.animated,
             "url": str(e.url), "managed": e.managed}
            for e in guild.emojis
        ]
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="get_server_emojis", arguments=args, result=AuditResult.success)
        return json.dumps({"guild_id": guild_id, "emojis": emojis, "total": len(emojis)}, indent=2)
    except PermissionError as exc:
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="get_server_emojis", arguments=args, result=AuditResult.denied, result_detail=str(exc))
        return json.dumps({"error": "Permission denied", "detail": str(exc)})
    except Exception as exc:
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="get_server_emojis", arguments=args, result=AuditResult.error, result_detail=str(exc))
        return json.dumps({"error": str(exc)})


@mcp.tool(
    name="get_server_invites",
    description="List all active invites for a guild.",
)
async def get_server_invites(guild_id: str) -> str:
    token = _get_ml_token()
    if token is None:
        return json.dumps({"error": "Unauthenticated"})
    args = {"guild_id": guild_id}
    try:
        _require_guild_access(token, guild_id)
        _require_permission(token, PermissionLevel.manage)
        guild = await get_guild(guild_id)
        invites = await guild.invites()
        data = [
            {
                "code": inv.code,
                "url": inv.url,
                "inviter": str(inv.inviter) if inv.inviter else None,
                "uses": inv.uses,
                "max_uses": inv.max_uses,
                "channel": str(inv.channel) if inv.channel else None,
                "expires_at": inv.expires_at.isoformat() if inv.expires_at else None,
            }
            for inv in invites
        ]
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="get_server_invites", arguments=args, result=AuditResult.success)
        return json.dumps({"guild_id": guild_id, "invites": data, "total": len(data)}, indent=2)
    except PermissionError as exc:
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="get_server_invites", arguments=args, result=AuditResult.denied, result_detail=str(exc))
        return json.dumps({"error": "Permission denied", "detail": str(exc)})
    except Exception as exc:
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="get_server_invites", arguments=args, result=AuditResult.error, result_detail=str(exc))
        return json.dumps({"error": str(exc)})


@mcp.tool(
    name="create_invite",
    description="Create an invite link for a channel. max_age: seconds (0=never). max_uses: 0=unlimited.",
)
async def create_invite(
    guild_id: str,
    channel_id: str,
    max_age: int = 86400,
    max_uses: int = 0,
    unique: bool = True,
) -> str:
    token = _get_ml_token()
    if token is None:
        return json.dumps({"error": "Unauthenticated"})
    args = {"guild_id": guild_id, "channel_id": channel_id, "max_age": max_age, "max_uses": max_uses}
    try:
        _require_guild_access(token, guild_id)
        _require_permission(token, PermissionLevel.manage)
        channel = await get_channel(guild_id, channel_id)
        invite = await channel.create_invite(max_age=max_age, max_uses=max_uses, unique=unique)
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="create_invite", arguments=args, result=AuditResult.success)
        return json.dumps({"status": "created", "code": invite.code, "url": invite.url,
                           "channel": channel.name, "max_age": max_age, "max_uses": max_uses})
    except PermissionError as exc:
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="create_invite", arguments=args, result=AuditResult.denied, result_detail=str(exc))
        return json.dumps({"error": "Permission denied", "detail": str(exc)})
    except Exception as exc:
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="create_invite", arguments=args, result=AuditResult.error, result_detail=str(exc))
        return json.dumps({"error": str(exc)})


# ══════════════════════════════════════════════════════════════════════════════
# VOICE CHANNEL TOOLS
# ══════════════════════════════════════════════════════════════════════════════

@mcp.tool(
    name="list_voice_channels",
    description="List all voice channels in a guild and show who is currently connected.",
)
async def list_voice_channels(guild_id: str) -> str:
    token = _get_ml_token()
    if token is None:
        return json.dumps({"error": "Unauthenticated"})
    args = {"guild_id": guild_id}
    try:
        _require_guild_access(token, guild_id)
        _require_permission(token, PermissionLevel.read)
        guild = await get_guild(guild_id)
        channels = []
        for vc in guild.voice_channels:
            channels.append({
                "channel_id": str(vc.id),
                "name": vc.name,
                "user_limit": vc.user_limit,
                "bitrate": vc.bitrate,
                "category": vc.category.name if vc.category else None,
                "connected_members": [
                    {"user_id": str(m.id), "username": str(m), "muted": m.voice.mute, "deafened": m.voice.deaf}
                    for m in vc.members
                ],
                "connected_count": len(vc.members),
            })
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="list_voice_channels", arguments=args, result=AuditResult.success)
        return json.dumps({"guild_id": guild_id, "voice_channels": channels, "total": len(channels)}, indent=2)
    except PermissionError as exc:
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="list_voice_channels", arguments=args, result=AuditResult.denied, result_detail=str(exc))
        return json.dumps({"error": "Permission denied", "detail": str(exc)})
    except Exception as exc:
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="list_voice_channels", arguments=args, result=AuditResult.error, result_detail=str(exc))
        return json.dumps({"error": str(exc)})


@mcp.tool(
    name="disconnect_from_voice",
    description="Disconnect a member from whatever voice channel they are currently in.",
)
async def disconnect_from_voice(guild_id: str, user_id: str, reason: str = "Disconnected via ModLink MCP") -> str:
    token = _get_ml_token()
    if token is None:
        return json.dumps({"error": "Unauthenticated"})
    args = {"guild_id": guild_id, "user_id": user_id}
    try:
        _require_guild_access(token, guild_id)
        _require_permission(token, PermissionLevel.moderate)
        member = await get_member(guild_id, user_id)
        if not member.voice:
            return json.dumps({"error": "Member is not in a voice channel."})
        await member.move_to(None, reason=reason)
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="disconnect_from_voice", arguments=args, result=AuditResult.success, target_user_id=user_id)
        return json.dumps({"status": "disconnected", "user_id": user_id, "username": str(member)})
    except PermissionError as exc:
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="disconnect_from_voice", arguments=args, result=AuditResult.denied, result_detail=str(exc))
        return json.dumps({"error": "Permission denied", "detail": str(exc)})
    except Exception as exc:
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="disconnect_from_voice", arguments=args, result=AuditResult.error, result_detail=str(exc))
        return json.dumps({"error": str(exc)})


# ══════════════════════════════════════════════════════════════════════════════
# BOT STATUS / AI-SPECIFIC TOOLS
# ══════════════════════════════════════════════════════════════════════════════

@mcp.tool(
    name="get_bot_status",
    description="Get the bot's current status, latency, connected guilds, and uptime.",
)
async def get_bot_status() -> str:
    token = _get_ml_token()
    if token is None:
        return json.dumps({"error": "Unauthenticated"})
    try:
        # SECURITY: Only expose guilds this API key is authorized for.
        # Never leak other servers the bot is in globally.
        allowed_ids = set(token.allowed_guild_ids or [])
        if allowed_ids:
            visible_guilds = [g for g in bot.guilds if str(g.id) in allowed_ids]
        else:
            visible_guilds = []  # No access if no guilds are explicitly allowed

        data = {
            "bot_user": str(bot.user) if bot.user else "Not logged in",
            "bot_id": str(bot.user.id) if bot.user else None,
            "is_ready": bot.is_ready(),
            "latency_ms": round(bot.latency * 1000, 2),
            "guild_count": len(visible_guilds),
            "guilds": [{"guild_id": str(g.id), "name": g.name} for g in visible_guilds],
        }
        await _audit(connection_id=token.connection_id, guild_id="n/a",
                     tool_name="get_bot_status", arguments={}, result=AuditResult.success)
        return json.dumps(data, indent=2)
    except Exception as exc:
        return json.dumps({"error": str(exc)})


@mcp.tool(
    name="analyze_server",
    description="Run a comprehensive analysis of a guild: active channels, top roles, member breakdown, recent audit events, and security notes.",
)
async def analyze_server(guild_id: str) -> str:
    token = _get_ml_token()
    if token is None:
        return json.dumps({"error": "Unauthenticated"})
    args = {"guild_id": guild_id}
    try:
        _require_guild_access(token, guild_id)
        _require_permission(token, PermissionLevel.read)
        guild = await get_guild(guild_id)
        bot_member = guild.me
        bot_perms = bot_member.guild_permissions if bot_member else None
        analysis = {
            "guild_id": guild_id,
            "name": guild.name,
            "summary": {
                "member_count": guild.member_count,
                "bot_count": sum(1 for m in guild.members if m.bot),
                "human_count": sum(1 for m in guild.members if not m.bot),
                "online_humans": sum(1 for m in guild.members if not m.bot and m.status != discord.Status.offline),
                "text_channels": len(guild.text_channels),
                "voice_channels": len(guild.voice_channels),
                "roles": len(guild.roles),
                "boost_level": guild.premium_tier,
            },
            "top_roles_by_members": [
                {"role": r.name, "members": len(r.members)}
                for r in sorted(guild.roles, key=lambda r: -len(r.members))[:5]
                if r.name != "@everyone"
            ],
            "bot_permissions": {
                "ban_members": bot_perms.ban_members if bot_perms else False,
                "kick_members": bot_perms.kick_members if bot_perms else False,
                "manage_roles": bot_perms.manage_roles if bot_perms else False,
                "manage_channels": bot_perms.manage_channels if bot_perms else False,
                "moderate_members": bot_perms.moderate_members if bot_perms else False,
                "administrator": bot_perms.administrator if bot_perms else False,
            },
            "security_notes": [],
        }
        if guild.verification_level == discord.VerificationLevel.none:
            analysis["security_notes"].append("Verification level is set to NONE — anyone can join and post.")
        if not guild.explicit_content_filter:
            analysis["security_notes"].append("Explicit content filter is disabled.")
        if guild.mfa_level == 0:
            analysis["security_notes"].append("2FA for moderation actions is not required.")
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="analyze_server", arguments=args, result=AuditResult.success)
        return json.dumps(analysis, indent=2)
    except PermissionError as exc:
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="analyze_server", arguments=args, result=AuditResult.denied, result_detail=str(exc))
        return json.dumps({"error": "Permission denied", "detail": str(exc)})
    except Exception as exc:
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="analyze_server", arguments=args, result=AuditResult.error, result_detail=str(exc))
        return json.dumps({"error": str(exc)})


@mcp.tool(
    name="find_inactive_members",
    description="Find members who have not sent any messages recently based on available data. Returns members with no visible roles beyond @everyone.",
)
async def find_inactive_members(guild_id: str, min_days_since_join: int = 30) -> str:
    token = _get_ml_token()
    if token is None:
        return json.dumps({"error": "Unauthenticated"})
    args = {"guild_id": guild_id, "min_days_since_join": min_days_since_join}
    try:
        _require_guild_access(token, guild_id)
        _require_permission(token, PermissionLevel.read)
        guild = await get_guild(guild_id)
        cutoff = datetime.now(timezone.utc) - timedelta(days=min_days_since_join)
        inactive = []
        for member in guild.members:
            if member.bot:
                continue
            if member.joined_at and member.joined_at < cutoff:
                role_count = len([r for r in member.roles if r.name != "@everyone"])
                inactive.append({
                    "user_id": str(member.id),
                    "username": str(member),
                    "joined_at": member.joined_at.isoformat(),
                    "days_since_join": (datetime.now(timezone.utc) - member.joined_at).days,
                    "role_count": role_count,
                })
        inactive.sort(key=lambda x: x["days_since_join"], reverse=True)
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="find_inactive_members", arguments=args, result=AuditResult.success)
        return json.dumps({"guild_id": guild_id, "inactive_members": inactive[:50], "total_found": len(inactive)}, indent=2)
    except PermissionError as exc:
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="find_inactive_members", arguments=args, result=AuditResult.denied, result_detail=str(exc))
        return json.dumps({"error": "Permission denied", "detail": str(exc)})
    except Exception as exc:
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="find_inactive_members", arguments=args, result=AuditResult.error, result_detail=str(exc))
        return json.dumps({"error": str(exc)})


@mcp.tool(
    name="get_action_history",
    description="Get the history of all ModLink MCP actions for a guild. limit: entries to return (default 50).",
)
async def get_action_history(guild_id: str, limit: int = 50) -> str:
    token = _get_ml_token()
    if token is None:
        return json.dumps({"error": "Unauthenticated"})
    args = {"guild_id": guild_id, "limit": limit}
    try:
        _require_guild_access(token, guild_id)
        _require_permission(token, PermissionLevel.read)
        async with AsyncSessionLocal() as session:
            result = await session.execute(
                select(AuditLog)
                .where(AuditLog.guild_id == guild_id)
                .order_by(AuditLog.created_at.desc())
                .limit(max(1, min(limit, 500)))
            )
            logs = result.scalars().all()
        entries = [
            {
                "id": str(log.id),
                "tool": log.tool_name,
                "result": log.result.value if log.result else None,
                "detail": log.result_detail,
                "target_user_id": log.target_user_id,
                "created_at": log.created_at.isoformat() if log.created_at else None,
            }
            for log in logs
        ]
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="get_action_history", arguments=args, result=AuditResult.success)
        return json.dumps({"guild_id": guild_id, "entries": entries, "returned": len(entries)}, indent=2)
    except PermissionError as exc:
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="get_action_history", arguments=args, result=AuditResult.denied, result_detail=str(exc))
        return json.dumps({"error": "Permission denied", "detail": str(exc)})
    except Exception as exc:
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="get_action_history", arguments=args, result=AuditResult.error, result_detail=str(exc))
        return json.dumps({"error": str(exc)})


# ══════════════════════════════════════════════════════════════════════════════
# THREAD MANAGEMENT TOOLS
# ══════════════════════════════════════════════════════════════════════════════

@mcp.tool(
    name="list_threads",
    description="List active and public threads in a channel or across the entire guild.",
)
async def list_threads(guild_id: str, channel_id: Optional[str] = None) -> str:
    token = _get_ml_token()
    if token is None:
        return json.dumps({"error": "Unauthenticated"})
    args = {"guild_id": guild_id, "channel_id": channel_id}
    try:
        _require_guild_access(token, guild_id)
        _require_permission(token, PermissionLevel.read)
        guild = await get_guild(guild_id)
        if channel_id:
            channel = await get_channel(guild_id, channel_id)
            threads = channel.threads
        else:
            threads = guild.threads
        data = [
            {
                "thread_id": str(t.id),
                "name": t.name,
                "parent_id": str(t.parent_id),
                "archived": t.archived,
                "locked": t.locked,
                "message_count": t.message_count,
                "member_count": t.member_count,
                "auto_archive_duration": t.auto_archive_duration,
            }
            for t in threads
        ]
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="list_threads", arguments=args, result=AuditResult.success)
        return json.dumps({"guild_id": guild_id, "threads": data, "total": len(data)}, indent=2)
    except PermissionError as exc:
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="list_threads", arguments=args, result=AuditResult.denied, result_detail=str(exc))
        return json.dumps({"error": "Permission denied", "detail": str(exc)})
    except Exception as exc:
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="list_threads", arguments=args, result=AuditResult.error, result_detail=str(exc))
        return json.dumps({"error": str(exc)})


@mcp.tool(
    name="get_thread",
    description="Get detailed information about a thread by its thread ID.",
)
async def get_thread(guild_id: str, thread_id: str) -> str:
    token = _get_ml_token()
    if token is None:
        return json.dumps({"error": "Unauthenticated"})
    args = {"guild_id": guild_id, "thread_id": thread_id}
    try:
        _require_guild_access(token, guild_id)
        _require_permission(token, PermissionLevel.read)
        guild = await get_guild(guild_id)
        thread = guild.get_thread(int(thread_id))
        if thread is None:
            try:
                ch = await guild.fetch_channel(int(thread_id))
                if isinstance(ch, discord.Thread):
                    thread = ch
            except discord.NotFound:
                pass
        if thread is None:
            raise ValueError(f"Thread {thread_id!r} not found.")
        data = {
            "thread_id": str(thread.id),
            "name": thread.name,
            "parent_id": str(thread.parent_id),
            "owner_id": str(thread.owner_id),
            "archived": thread.archived,
            "locked": thread.locked,
            "message_count": thread.message_count,
            "member_count": thread.member_count,
            "slowmode_delay": thread.slowmode_delay,
            "created_at": thread.created_at.isoformat() if thread.created_at else None,
        }
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="get_thread", arguments=args, result=AuditResult.success)
        return json.dumps(data, indent=2)
    except PermissionError as exc:
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="get_thread", arguments=args, result=AuditResult.denied, result_detail=str(exc))
        return json.dumps({"error": "Permission denied", "detail": str(exc)})
    except Exception as exc:
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="get_thread", arguments=args, result=AuditResult.error, result_detail=str(exc))
        return json.dumps({"error": str(exc)})


@mcp.tool(
    name="create_thread",
    description="Create a thread in a channel, optionally attached to a specific message ID.",
)
async def create_thread(
    guild_id: str,
    channel_id: str,
    name: str,
    message_id: Optional[str] = None,
    auto_archive_duration: int = 1440,
    reason: str = "Thread created via ModLink MCP",
) -> str:
    token = _get_ml_token()
    if token is None:
        return json.dumps({"error": "Unauthenticated"})
    args = {"guild_id": guild_id, "channel_id": channel_id, "name": name, "message_id": message_id}
    try:
        _require_guild_access(token, guild_id)
        _require_permission(token, PermissionLevel.moderate)
        channel = await get_channel(guild_id, channel_id)
        if message_id:
            msg = await channel.fetch_message(int(message_id))
            thread = await msg.create_thread(name=name, auto_archive_duration=auto_archive_duration, reason=reason)
        else:
            thread = await channel.create_thread(name=name, auto_archive_duration=auto_archive_duration, reason=reason)
        data = {"status": "created", "thread_id": str(thread.id), "name": thread.name, "parent_id": channel_id}
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="create_thread", arguments=args, result=AuditResult.success)
        return json.dumps(data, indent=2)
    except PermissionError as exc:
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="create_thread", arguments=args, result=AuditResult.denied, result_detail=str(exc))
        return json.dumps({"error": "Permission denied", "detail": str(exc)})
    except Exception as exc:
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="create_thread", arguments=args, result=AuditResult.error, result_detail=str(exc))
        return json.dumps({"error": str(exc)})


@mcp.tool(
    name="archive_thread",
    description="Archive (and optionally lock) a thread.",
)
async def archive_thread(guild_id: str, thread_id: str, locked: bool = False, reason: str = "Archived via ModLink MCP") -> str:
    token = _get_ml_token()
    if token is None:
        return json.dumps({"error": "Unauthenticated"})
    args = {"guild_id": guild_id, "thread_id": thread_id, "locked": locked}
    try:
        _require_guild_access(token, guild_id)
        _require_permission(token, PermissionLevel.moderate)
        guild = await get_guild(guild_id)
        thread = guild.get_thread(int(thread_id))
        if thread is None:
            thread = await guild.fetch_channel(int(thread_id))
        await thread.edit(archived=True, locked=locked, reason=reason)
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="archive_thread", arguments=args, result=AuditResult.success)
        return json.dumps({"status": "archived", "thread_id": thread_id, "locked": locked})
    except PermissionError as exc:
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="archive_thread", arguments=args, result=AuditResult.denied, result_detail=str(exc))
        return json.dumps({"error": "Permission denied", "detail": str(exc)})
    except Exception as exc:
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="archive_thread", arguments=args, result=AuditResult.error, result_detail=str(exc))
        return json.dumps({"error": str(exc)})


@mcp.tool(
    name="unarchive_thread",
    description="Unarchive a thread so conversation can continue.",
)
async def unarchive_thread(guild_id: str, thread_id: str, reason: str = "Unarchived via ModLink MCP") -> str:
    token = _get_ml_token()
    if token is None:
        return json.dumps({"error": "Unauthenticated"})
    args = {"guild_id": guild_id, "thread_id": thread_id}
    try:
        _require_guild_access(token, guild_id)
        _require_permission(token, PermissionLevel.moderate)
        guild = await get_guild(guild_id)
        thread = guild.get_thread(int(thread_id))
        if thread is None:
            thread = await guild.fetch_channel(int(thread_id))
        await thread.edit(archived=False, reason=reason)
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="unarchive_thread", arguments=args, result=AuditResult.success)
        return json.dumps({"status": "unarchived", "thread_id": thread_id})
    except PermissionError as exc:
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="unarchive_thread", arguments=args, result=AuditResult.denied, result_detail=str(exc))
        return json.dumps({"error": "Permission denied", "detail": str(exc)})
    except Exception as exc:
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="unarchive_thread", arguments=args, result=AuditResult.error, result_detail=str(exc))
        return json.dumps({"error": str(exc)})


@mcp.tool(
    name="delete_thread",
    description="Permanently delete a thread by ID.",
)
async def delete_thread(guild_id: str, thread_id: str, reason: str = "Thread deleted via ModLink MCP") -> str:
    token = _get_ml_token()
    if token is None:
        return json.dumps({"error": "Unauthenticated"})
    args = {"guild_id": guild_id, "thread_id": thread_id}
    try:
        _require_guild_access(token, guild_id)
        _require_permission(token, PermissionLevel.manage)
        guild = await get_guild(guild_id)
        thread = guild.get_thread(int(thread_id))
        if thread is None:
            thread = await guild.fetch_channel(int(thread_id))
        name = thread.name
        await thread.delete(reason=reason)
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="delete_thread", arguments=args, result=AuditResult.success)
        return json.dumps({"status": "deleted", "thread_id": thread_id, "name": name})
    except PermissionError as exc:
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="delete_thread", arguments=args, result=AuditResult.denied, result_detail=str(exc))
        return json.dumps({"error": "Permission denied", "detail": str(exc)})
    except Exception as exc:
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="delete_thread", arguments=args, result=AuditResult.error, result_detail=str(exc))
        return json.dumps({"error": str(exc)})


# ══════════════════════════════════════════════════════════════════════════════
# ADDITIONAL MESSAGE TOOLS
# ══════════════════════════════════════════════════════════════════════════════

@mcp.tool(
    name="get_message",
    description="Retrieve a single message by ID, including its content, author, attachments, and reactions.",
)
async def get_message(guild_id: str, channel_id: str, message_id: str) -> str:
    token = _get_ml_token()
    if token is None:
        return json.dumps({"error": "Unauthenticated"})
    args = {"guild_id": guild_id, "channel_id": channel_id, "message_id": message_id}
    try:
        _require_guild_access(token, guild_id)
        _require_permission(token, PermissionLevel.read)
        channel = await get_channel(guild_id, channel_id)
        msg = await channel.fetch_message(int(message_id))
        data = {
            "message_id": str(msg.id),
            "author_id": str(msg.author.id),
            "author_name": str(msg.author),
            "content": msg.content,
            "created_at": msg.created_at.isoformat(),
            "edited_at": msg.edited_at.isoformat() if msg.edited_at else None,
            "pinned": msg.pinned,
            "jump_url": msg.jump_url,
            "reactions": [{"emoji": str(r.emoji), "count": r.count} for r in msg.reactions],
            "attachments": [a.url for a in msg.attachments],
            "embed_count": len(msg.embeds),
        }
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="get_message", arguments=args, result=AuditResult.success)
        return json.dumps(data, indent=2)
    except PermissionError as exc:
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="get_message", arguments=args, result=AuditResult.denied, result_detail=str(exc))
        return json.dumps({"error": "Permission denied", "detail": str(exc)})
    except Exception as exc:
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="get_message", arguments=args, result=AuditResult.error, result_detail=str(exc))
        return json.dumps({"error": str(exc)})


@mcp.tool(
    name="search_messages",
    description="Search recent message history in a channel by text query. limit: 1-100 (default 50).",
)
async def search_messages(guild_id: str, channel_id: str, query: str, limit: int = 50) -> str:
    token = _get_ml_token()
    if token is None:
        return json.dumps({"error": "Unauthenticated"})
    args = {"guild_id": guild_id, "channel_id": channel_id, "query": query, "limit": limit}
    try:
        _require_guild_access(token, guild_id)
        _require_permission(token, PermissionLevel.read)
        channel = await get_channel(guild_id, channel_id)
        limit = max(1, min(limit, 100))
        results = []
        q_lower = query.lower()
        async for msg in channel.history(limit=limit):
            if q_lower in msg.content.lower():
                results.append({
                    "message_id": str(msg.id),
                    "author": str(msg.author),
                    "author_id": str(msg.author.id),
                    "content": msg.content,
                    "created_at": msg.created_at.isoformat(),
                })
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="search_messages", arguments=args, result=AuditResult.success)
        return json.dumps({"channel_id": channel_id, "query": query, "matches": results, "total": len(results)}, indent=2)
    except PermissionError as exc:
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="search_messages", arguments=args, result=AuditResult.denied, result_detail=str(exc))
        return json.dumps({"error": "Permission denied", "detail": str(exc)})
    except Exception as exc:
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="search_messages", arguments=args, result=AuditResult.error, result_detail=str(exc))
        return json.dumps({"error": str(exc)})


@mcp.tool(
    name="unpin_message",
    description="Unpin a message from a text channel.",
)
async def unpin_message(guild_id: str, channel_id: str, message_id: str) -> str:
    token = _get_ml_token()
    if token is None:
        return json.dumps({"error": "Unauthenticated"})
    args = {"guild_id": guild_id, "channel_id": channel_id, "message_id": message_id}
    try:
        _require_guild_access(token, guild_id)
        _require_permission(token, PermissionLevel.moderate)
        channel = await get_channel(guild_id, channel_id)
        msg = await channel.fetch_message(int(message_id))
        await msg.unpin()
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="unpin_message", arguments=args, result=AuditResult.success)
        return json.dumps({"status": "unpinned", "message_id": message_id, "channel_id": channel_id})
    except PermissionError as exc:
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="unpin_message", arguments=args, result=AuditResult.denied, result_detail=str(exc))
        return json.dumps({"error": "Permission denied", "detail": str(exc)})
    except Exception as exc:
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="unpin_message", arguments=args, result=AuditResult.error, result_detail=str(exc))
        return json.dumps({"error": str(exc)})


@mcp.tool(
    name="remove_reaction",
    description="Remove a specific reaction from a message. If user_id is provided, removes that member's reaction; otherwise removes the bot's reaction.",
)
async def remove_reaction(
    guild_id: str,
    channel_id: str,
    message_id: str,
    emoji: str,
    user_id: Optional[str] = None,
) -> str:
    token = _get_ml_token()
    if token is None:
        return json.dumps({"error": "Unauthenticated"})
    args = {"guild_id": guild_id, "channel_id": channel_id, "message_id": message_id, "emoji": emoji, "user_id": user_id}
    try:
        _require_guild_access(token, guild_id)
        _require_permission(token, PermissionLevel.moderate)
        channel = await get_channel(guild_id, channel_id)
        msg = await channel.fetch_message(int(message_id))
        if user_id:
            member = await get_member(guild_id, user_id)
            await msg.remove_reaction(emoji, member)
        else:
            await msg.remove_reaction(emoji, bot.user)
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="remove_reaction", arguments=args, result=AuditResult.success)
        return json.dumps({"status": "reaction_removed", "message_id": message_id, "emoji": emoji})
    except PermissionError as exc:
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="remove_reaction", arguments=args, result=AuditResult.denied, result_detail=str(exc))
        return json.dumps({"error": "Permission denied", "detail": str(exc)})
    except Exception as exc:
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="remove_reaction", arguments=args, result=AuditResult.error, result_detail=str(exc))
        return json.dumps({"error": str(exc)})


@mcp.tool(
    name="clear_reactions",
    description="Clear all reactions from a message.",
)
async def clear_reactions(guild_id: str, channel_id: str, message_id: str) -> str:
    token = _get_ml_token()
    if token is None:
        return json.dumps({"error": "Unauthenticated"})
    args = {"guild_id": guild_id, "channel_id": channel_id, "message_id": message_id}
    try:
        _require_guild_access(token, guild_id)
        _require_permission(token, PermissionLevel.moderate)
        channel = await get_channel(guild_id, channel_id)
        msg = await channel.fetch_message(int(message_id))
        await msg.clear_reactions()
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="clear_reactions", arguments=args, result=AuditResult.success)
        return json.dumps({"status": "reactions_cleared", "message_id": message_id})
    except PermissionError as exc:
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="clear_reactions", arguments=args, result=AuditResult.denied, result_detail=str(exc))
        return json.dumps({"error": "Permission denied", "detail": str(exc)})
    except Exception as exc:
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="clear_reactions", arguments=args, result=AuditResult.error, result_detail=str(exc))
        return json.dumps({"error": str(exc)})


@mcp.tool(
    name="reply_to_message",
    description="Reply directly to a specific message in a channel.",
)
async def reply_to_message(guild_id: str, channel_id: str, message_id: str, content: str) -> str:
    token = _get_ml_token()
    if token is None:
        return json.dumps({"error": "Unauthenticated"})
    args = {"guild_id": guild_id, "channel_id": channel_id, "message_id": message_id, "content": content}
    try:
        _require_guild_access(token, guild_id)
        _require_permission(token, PermissionLevel.moderate)
        channel = await get_channel(guild_id, channel_id)
        msg = await channel.fetch_message(int(message_id))
        reply = await msg.reply(content)
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="reply_to_message", arguments=args, result=AuditResult.success)
        return json.dumps({"status": "replied", "reply_id": str(reply.id), "original_message_id": message_id})
    except PermissionError as exc:
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="reply_to_message", arguments=args, result=AuditResult.denied, result_detail=str(exc))
        return json.dumps({"error": "Permission denied", "detail": str(exc)})
    except Exception as exc:
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="reply_to_message", arguments=args, result=AuditResult.error, result_detail=str(exc))
        return json.dumps({"error": str(exc)})


@mcp.tool(
    name="crosspost_message",
    description="Publish / crosspost an announcement message to follower channels.",
)
async def crosspost_message(guild_id: str, channel_id: str, message_id: str) -> str:
    token = _get_ml_token()
    if token is None:
        return json.dumps({"error": "Unauthenticated"})
    args = {"guild_id": guild_id, "channel_id": channel_id, "message_id": message_id}
    try:
        _require_guild_access(token, guild_id)
        _require_permission(token, PermissionLevel.moderate)
        channel = await get_channel(guild_id, channel_id)
        msg = await channel.fetch_message(int(message_id))
        await msg.publish()
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="crosspost_message", arguments=args, result=AuditResult.success)
        return json.dumps({"status": "crossposted", "message_id": message_id})
    except PermissionError as exc:
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="crosspost_message", arguments=args, result=AuditResult.denied, result_detail=str(exc))
        return json.dumps({"error": "Permission denied", "detail": str(exc)})
    except Exception as exc:
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="crosspost_message", arguments=args, result=AuditResult.error, result_detail=str(exc))
        return json.dumps({"error": str(exc)})


# ══════════════════════════════════════════════════════════════════════════════
# SERVER MANAGEMENT EXTENSIONS
# ══════════════════════════════════════════════════════════════════════════════

@mcp.tool(
    name="edit_server_name",
    description="Change the server name.",
)
async def edit_server_name(guild_id: str, name: str, reason: str = "Renamed via ModLink MCP") -> str:
    token = _get_ml_token()
    if token is None:
        return json.dumps({"error": "Unauthenticated"})
    args = {"guild_id": guild_id, "name": name}
    try:
        _require_guild_access(token, guild_id)
        _require_permission(token, PermissionLevel.admin)
        guild = await get_guild(guild_id)
        old_name = guild.name
        await guild.edit(name=name, reason=reason)
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="edit_server_name", arguments=args, result=AuditResult.success)
        return json.dumps({"status": "updated", "old_name": old_name, "new_name": name})
    except PermissionError as exc:
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="edit_server_name", arguments=args, result=AuditResult.denied, result_detail=str(exc))
        return json.dumps({"error": "Permission denied", "detail": str(exc)})
    except Exception as exc:
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="edit_server_name", arguments=args, result=AuditResult.error, result_detail=str(exc))
        return json.dumps({"error": str(exc)})


@mcp.tool(
    name="edit_server_description",
    description="Change the server description (for community/discoverable servers).",
)
async def edit_server_description(guild_id: str, description: str, reason: str = "Description updated via ModLink MCP") -> str:
    token = _get_ml_token()
    if token is None:
        return json.dumps({"error": "Unauthenticated"})
    args = {"guild_id": guild_id, "description": description}
    try:
        _require_guild_access(token, guild_id)
        _require_permission(token, PermissionLevel.admin)
        guild = await get_guild(guild_id)
        await guild.edit(description=description, reason=reason)
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="edit_server_description", arguments=args, result=AuditResult.success)
        return json.dumps({"status": "updated", "description": description})
    except PermissionError as exc:
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="edit_server_description", arguments=args, result=AuditResult.denied, result_detail=str(exc))
        return json.dumps({"error": "Permission denied", "detail": str(exc)})
    except Exception as exc:
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="edit_server_description", arguments=args, result=AuditResult.error, result_detail=str(exc))
        return json.dumps({"error": str(exc)})


@mcp.tool(
    name="delete_invite",
    description="Revoke an invite link by its invite code.",
)
async def delete_invite(guild_id: str, code: str, reason: str = "Revoked via ModLink MCP") -> str:
    token = _get_ml_token()
    if token is None:
        return json.dumps({"error": "Unauthenticated"})
    args = {"guild_id": guild_id, "code": code}
    try:
        _require_guild_access(token, guild_id)
        _require_permission(token, PermissionLevel.manage)
        guild = await get_guild(guild_id)
        invites = await guild.invites()
        target_inv = None
        for inv in invites:
            if inv.code == code:
                target_inv = inv
                break
        if target_inv is None:
            raise ValueError(f"Invite code {code!r} not found.")
        await target_inv.delete(reason=reason)
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="delete_invite", arguments=args, result=AuditResult.success)
        return json.dumps({"status": "deleted", "code": code})
    except PermissionError as exc:
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="delete_invite", arguments=args, result=AuditResult.denied, result_detail=str(exc))
        return json.dumps({"error": "Permission denied", "detail": str(exc)})
    except Exception as exc:
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="delete_invite", arguments=args, result=AuditResult.error, result_detail=str(exc))
        return json.dumps({"error": str(exc)})


@mcp.tool(
    name="create_emoji",
    description="Create a custom emoji in the guild by providing a name and an image URL (PNG/JPEG/GIF).",
)
async def create_emoji(guild_id: str, name: str, image_url: str, reason: str = "Emoji created via ModLink MCP") -> str:
    token = _get_ml_token()
    if token is None:
        return json.dumps({"error": "Unauthenticated"})
    args = {"guild_id": guild_id, "name": name, "image_url": image_url}
    try:
        _require_guild_access(token, guild_id)
        _require_permission(token, PermissionLevel.manage)
        guild = await get_guild(guild_id)
        async with httpx.AsyncClient() as client:
            resp = await client.get(image_url, timeout=15.0)
            if resp.status_code != 200:
                raise ValueError(f"Failed to fetch image from URL: HTTP {resp.status_code}")
            image_data = resp.content
        emoji = await guild.create_custom_emoji(name=name, image=image_data, reason=reason)
        data = {"status": "created", "emoji_id": str(emoji.id), "name": emoji.name, "url": str(emoji.url)}
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="create_emoji", arguments=args, result=AuditResult.success)
        return json.dumps(data, indent=2)
    except PermissionError as exc:
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="create_emoji", arguments=args, result=AuditResult.denied, result_detail=str(exc))
        return json.dumps({"error": "Permission denied", "detail": str(exc)})
    except Exception as exc:
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="create_emoji", arguments=args, result=AuditResult.error, result_detail=str(exc))
        return json.dumps({"error": str(exc)})


@mcp.tool(
    name="delete_emoji",
    description="Delete a custom emoji from the guild by its emoji ID.",
)
async def delete_emoji(guild_id: str, emoji_id: str, reason: str = "Emoji deleted via ModLink MCP") -> str:
    token = _get_ml_token()
    if token is None:
        return json.dumps({"error": "Unauthenticated"})
    args = {"guild_id": guild_id, "emoji_id": emoji_id}
    try:
        _require_guild_access(token, guild_id)
        _require_permission(token, PermissionLevel.manage)
        guild = await get_guild(guild_id)
        emoji = discord.utils.get(guild.emojis, id=int(emoji_id))
        if emoji is None:
            raise ValueError(f"Emoji {emoji_id!r} not found.")
        name = emoji.name
        await emoji.delete(reason=reason)
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="delete_emoji", arguments=args, result=AuditResult.success)
        return json.dumps({"status": "deleted", "emoji_id": emoji_id, "name": name})
    except PermissionError as exc:
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="delete_emoji", arguments=args, result=AuditResult.denied, result_detail=str(exc))
        return json.dumps({"error": "Permission denied", "detail": str(exc)})
    except Exception as exc:
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="delete_emoji", arguments=args, result=AuditResult.error, result_detail=str(exc))
        return json.dumps({"error": str(exc)})


@mcp.tool(
    name="list_stickers",
    description="List all custom stickers in a guild.",
)
async def list_stickers(guild_id: str) -> str:
    token = _get_ml_token()
    if token is None:
        return json.dumps({"error": "Unauthenticated"})
    args = {"guild_id": guild_id}
    try:
        _require_guild_access(token, guild_id)
        _require_permission(token, PermissionLevel.read)
        guild = await get_guild(guild_id)
        stickers = await guild.fetch_stickers()
        data = [
            {
                "id": str(s.id),
                "name": s.name,
                "description": s.description,
                "format": str(s.format),
                "url": s.url,
            }
            for s in stickers
        ]
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="list_stickers", arguments=args, result=AuditResult.success)
        return json.dumps({"guild_id": guild_id, "stickers": data, "total": len(data)}, indent=2)
    except PermissionError as exc:
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="list_stickers", arguments=args, result=AuditResult.denied, result_detail=str(exc))
        return json.dumps({"error": "Permission denied", "detail": str(exc)})
    except Exception as exc:
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="list_stickers", arguments=args, result=AuditResult.error, result_detail=str(exc))
        return json.dumps({"error": str(exc)})


# ══════════════════════════════════════════════════════════════════════════════
# AUTOMOD & SERVER SECURITY TOOLS
# ══════════════════════════════════════════════════════════════════════════════

@mcp.tool(
    name="get_automod_rules",
    description="List all Discord AutoMod rules configured on the guild.",
)
async def get_automod_rules(guild_id: str) -> str:
    token = _get_ml_token()
    if token is None:
        return json.dumps({"error": "Unauthenticated"})
    args = {"guild_id": guild_id}
    try:
        _require_guild_access(token, guild_id)
        _require_permission(token, PermissionLevel.manage)
        guild = await get_guild(guild_id)
        rules = await guild.fetch_automod_rules()
        data = [
            {
                "id": str(r.id),
                "name": r.name,
                "enabled": r.enabled,
                "event_type": str(r.event_type),
                "trigger_type": str(r.trigger_type),
                "actions": [str(a.type) for a in r.actions],
            }
            for r in rules
        ]
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="get_automod_rules", arguments=args, result=AuditResult.success)
        return json.dumps({"guild_id": guild_id, "rules": data, "total": len(data)}, indent=2)
    except PermissionError as exc:
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="get_automod_rules", arguments=args, result=AuditResult.denied, result_detail=str(exc))
        return json.dumps({"error": "Permission denied", "detail": str(exc)})
    except Exception as exc:
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="get_automod_rules", arguments=args, result=AuditResult.error, result_detail=str(exc))
        return json.dumps({"error": str(exc)})


@mcp.tool(
    name="create_automod_keyword_rule",
    description="Create an AutoMod keyword filter rule. keywords: list of words/phrases to block. block_message: whether to delete matching message. alert_channel_id: optional channel to send alert.",
)
async def create_automod_keyword_rule(
    guild_id: str,
    name: str,
    keywords: List[str],
    block_message: bool = True,
    alert_channel_id: Optional[str] = None,
    reason: str = "AutoMod rule created via ModLink MCP",
) -> str:
    token = _get_ml_token()
    if token is None:
        return json.dumps({"error": "Unauthenticated"})
    args = {"guild_id": guild_id, "name": name, "keywords": keywords}
    try:
        _require_guild_access(token, guild_id)
        _require_permission(token, PermissionLevel.manage)
        guild = await get_guild(guild_id)
        trigger = discord.AutoModTrigger(
            type=discord.AutoModRuleTriggerType.keyword,
            keyword_filter=keywords,
        )
        actions = []
        if block_message:
            actions.append(discord.AutoModRuleAction(type=discord.AutoModRuleActionType.block_message))
        if alert_channel_id:
            actions.append(discord.AutoModRuleAction(
                type=discord.AutoModRuleActionType.send_alert_message,
                channel_id=int(alert_channel_id),
            ))
        rule = await guild.create_automod_rule(
            name=name,
            event_type=discord.AutoModRuleEventType.message_send,
            trigger=trigger,
            actions=actions,
            enabled=True,
            reason=reason,
        )
        data = {"status": "created", "rule_id": str(rule.id), "name": rule.name, "enabled": rule.enabled}
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="create_automod_keyword_rule", arguments=args, result=AuditResult.success)
        return json.dumps(data, indent=2)
    except PermissionError as exc:
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="create_automod_keyword_rule", arguments=args, result=AuditResult.denied, result_detail=str(exc))
        return json.dumps({"error": "Permission denied", "detail": str(exc)})
    except Exception as exc:
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="create_automod_keyword_rule", arguments=args, result=AuditResult.error, result_detail=str(exc))
        return json.dumps({"error": str(exc)})


@mcp.tool(
    name="delete_automod_rule",
    description="Delete an AutoMod rule by its ID.",
)
async def delete_automod_rule(guild_id: str, rule_id: str, reason: str = "Deleted via ModLink MCP") -> str:
    token = _get_ml_token()
    if token is None:
        return json.dumps({"error": "Unauthenticated"})
    args = {"guild_id": guild_id, "rule_id": rule_id}
    try:
        _require_guild_access(token, guild_id)
        _require_permission(token, PermissionLevel.manage)
        guild = await get_guild(guild_id)
        rule = await guild.fetch_automod_rule(int(rule_id))
        name = rule.name
        await rule.delete(reason=reason)
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="delete_automod_rule", arguments=args, result=AuditResult.success)
        return json.dumps({"status": "deleted", "rule_id": rule_id, "name": name})
    except PermissionError as exc:
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="delete_automod_rule", arguments=args, result=AuditResult.denied, result_detail=str(exc))
        return json.dumps({"error": "Permission denied", "detail": str(exc)})
    except Exception as exc:
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="delete_automod_rule", arguments=args, result=AuditResult.error, result_detail=str(exc))
        return json.dumps({"error": str(exc)})


@mcp.tool(
    name="enable_emergency_lockdown",
    description="Emergency lockdown: instantly lock all public text channels so @everyone cannot send messages.",
)
async def enable_emergency_lockdown(guild_id: str, reason: str = "Emergency lockdown triggered via ModLink MCP") -> str:
    token = _get_ml_token()
    if token is None:
        return json.dumps({"error": "Unauthenticated"})
    args = {"guild_id": guild_id, "reason": reason}
    try:
        _require_guild_access(token, guild_id)
        _require_permission(token, PermissionLevel.admin)
        guild = await get_guild(guild_id)
        locked_channels = []
        for ch in guild.text_channels:
            try:
                await ch.set_permissions(guild.default_role, send_messages=False, reason=reason)
                locked_channels.append({"channel_id": str(ch.id), "name": ch.name})
            except Exception:
                pass
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="enable_emergency_lockdown", arguments=args, result=AuditResult.success)
        return json.dumps({"status": "lockdown_active", "locked_channels": locked_channels, "total": len(locked_channels)}, indent=2)
    except PermissionError as exc:
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="enable_emergency_lockdown", arguments=args, result=AuditResult.denied, result_detail=str(exc))
        return json.dumps({"error": "Permission denied", "detail": str(exc)})
    except Exception as exc:
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="enable_emergency_lockdown", arguments=args, result=AuditResult.error, result_detail=str(exc))
        return json.dumps({"error": str(exc)})


@mcp.tool(
    name="disable_emergency_lockdown",
    description="Lift emergency lockdown: restore text channels so @everyone can send messages again.",
)
async def disable_emergency_lockdown(guild_id: str, reason: str = "Emergency lockdown lifted via ModLink MCP") -> str:
    token = _get_ml_token()
    if token is None:
        return json.dumps({"error": "Unauthenticated"})
    args = {"guild_id": guild_id, "reason": reason}
    try:
        _require_guild_access(token, guild_id)
        _require_permission(token, PermissionLevel.admin)
        guild = await get_guild(guild_id)
        unlocked_channels = []
        for ch in guild.text_channels:
            try:
                await ch.set_permissions(guild.default_role, send_messages=None, reason=reason)
                unlocked_channels.append({"channel_id": str(ch.id), "name": ch.name})
            except Exception:
                pass
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="disable_emergency_lockdown", arguments=args, result=AuditResult.success)
        return json.dumps({"status": "lockdown_lifted", "unlocked_channels": unlocked_channels, "total": len(unlocked_channels)}, indent=2)
    except PermissionError as exc:
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="disable_emergency_lockdown", arguments=args, result=AuditResult.denied, result_detail=str(exc))
        return json.dumps({"error": "Permission denied", "detail": str(exc)})
    except Exception as exc:
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="disable_emergency_lockdown", arguments=args, result=AuditResult.error, result_detail=str(exc))
        return json.dumps({"error": str(exc)})


# ══════════════════════════════════════════════════════════════════════════════
# SCHEDULED EVENTS TOOLS
# ══════════════════════════════════════════════════════════════════════════════

@mcp.tool(
    name="list_events",
    description="List all scheduled events in a guild.",
)
async def list_events(guild_id: str) -> str:
    token = _get_ml_token()
    if token is None:
        return json.dumps({"error": "Unauthenticated"})
    args = {"guild_id": guild_id}
    try:
        _require_guild_access(token, guild_id)
        _require_permission(token, PermissionLevel.read)
        guild = await get_guild(guild_id)
        events = await guild.fetch_scheduled_events()
        data = [
            {
                "id": str(ev.id),
                "name": ev.name,
                "description": ev.description,
                "start_time": ev.start_time.isoformat() if ev.start_time else None,
                "end_time": ev.end_time.isoformat() if ev.end_time else None,
                "status": str(ev.status),
                "user_count": ev.user_count,
                "location": ev.location,
            }
            for ev in events
        ]
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="list_events", arguments=args, result=AuditResult.success)
        return json.dumps({"guild_id": guild_id, "events": data, "total": len(data)}, indent=2)
    except PermissionError as exc:
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="list_events", arguments=args, result=AuditResult.denied, result_detail=str(exc))
        return json.dumps({"error": "Permission denied", "detail": str(exc)})
    except Exception as exc:
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="list_events", arguments=args, result=AuditResult.error, result_detail=str(exc))
        return json.dumps({"error": str(exc)})


@mcp.tool(
    name="create_scheduled_event",
    description="Create a scheduled event in the guild. start_time_iso: ISO 8601 string (e.g. '2026-12-01T18:00:00Z'). channel_id: optional voice/stage channel ID. location: optional external location string.",
)
async def create_scheduled_event(
    guild_id: str,
    name: str,
    start_time_iso: str,
    end_time_iso: Optional[str] = None,
    description: str = "",
    channel_id: Optional[str] = None,
    location: Optional[str] = None,
    reason: str = "Event created via ModLink MCP",
) -> str:
    token = _get_ml_token()
    if token is None:
        return json.dumps({"error": "Unauthenticated"})
    args = {"guild_id": guild_id, "name": name, "start_time_iso": start_time_iso}
    try:
        _require_guild_access(token, guild_id)
        _require_permission(token, PermissionLevel.manage)
        guild = await get_guild(guild_id)
        start_time = datetime.fromisoformat(start_time_iso.replace("Z", "+00:00"))
        end_time = datetime.fromisoformat(end_time_iso.replace("Z", "+00:00")) if end_time_iso else (start_time + timedelta(hours=2))
        if channel_id:
            channel = guild.get_channel(int(channel_id))
            entity_type = discord.EntityType.stage_instance if isinstance(channel, discord.StageChannel) else discord.EntityType.voice
            event = await guild.create_scheduled_event(
                name=name,
                start_time=start_time,
                end_time=end_time,
                entity_type=entity_type,
                channel=channel,
                description=description,
                reason=reason,
            )
        else:
            event = await guild.create_scheduled_event(
                name=name,
                start_time=start_time,
                end_time=end_time,
                entity_type=discord.EntityType.external,
                location=location or "Online",
                description=description,
                reason=reason,
            )
        data = {"status": "created", "event_id": str(event.id), "name": event.name, "start_time": event.start_time.isoformat()}
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="create_scheduled_event", arguments=args, result=AuditResult.success)
        return json.dumps(data, indent=2)
    except PermissionError as exc:
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="create_scheduled_event", arguments=args, result=AuditResult.denied, result_detail=str(exc))
        return json.dumps({"error": "Permission denied", "detail": str(exc)})
    except Exception as exc:
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="create_scheduled_event", arguments=args, result=AuditResult.error, result_detail=str(exc))
        return json.dumps({"error": str(exc)})


@mcp.tool(
    name="delete_scheduled_event",
    description="Delete a scheduled event by its ID.",
)
async def delete_scheduled_event(guild_id: str, event_id: str) -> str:
    token = _get_ml_token()
    if token is None:
        return json.dumps({"error": "Unauthenticated"})
    args = {"guild_id": guild_id, "event_id": event_id}
    try:
        _require_guild_access(token, guild_id)
        _require_permission(token, PermissionLevel.manage)
        guild = await get_guild(guild_id)
        event = await guild.fetch_scheduled_event(int(event_id))
        name = event.name
        await event.delete()
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="delete_scheduled_event", arguments=args, result=AuditResult.success)
        return json.dumps({"status": "deleted", "event_id": event_id, "name": name})
    except PermissionError as exc:
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="delete_scheduled_event", arguments=args, result=AuditResult.denied, result_detail=str(exc))
        return json.dumps({"error": "Permission denied", "detail": str(exc)})
    except Exception as exc:
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="delete_scheduled_event", arguments=args, result=AuditResult.error, result_detail=str(exc))
        return json.dumps({"error": str(exc)})


# ══════════════════════════════════════════════════════════════════════════════
# WEBHOOK MANAGEMENT TOOLS
# ══════════════════════════════════════════════════════════════════════════════

@mcp.tool(
    name="list_webhooks",
    description="List webhooks for a channel or the entire guild.",
)
async def list_webhooks(guild_id: str, channel_id: Optional[str] = None) -> str:
    token = _get_ml_token()
    if token is None:
        return json.dumps({"error": "Unauthenticated"})
    args = {"guild_id": guild_id, "channel_id": channel_id}
    try:
        _require_guild_access(token, guild_id)
        _require_permission(token, PermissionLevel.manage)
        if channel_id:
            channel = await get_channel(guild_id, channel_id)
            webhooks = await channel.webhooks()
        else:
            guild = await get_guild(guild_id)
            webhooks = await guild.webhooks()
        data = [
            {
                "webhook_id": str(w.id),
                "name": w.name,
                "channel_id": str(w.channel_id),
                "url": w.url,
            }
            for w in webhooks
        ]
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="list_webhooks", arguments=args, result=AuditResult.success)
        return json.dumps({"guild_id": guild_id, "webhooks": data, "total": len(data)}, indent=2)
    except PermissionError as exc:
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="list_webhooks", arguments=args, result=AuditResult.denied, result_detail=str(exc))
        return json.dumps({"error": "Permission denied", "detail": str(exc)})
    except Exception as exc:
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="list_webhooks", arguments=args, result=AuditResult.error, result_detail=str(exc))
        return json.dumps({"error": str(exc)})


@mcp.tool(
    name="create_webhook",
    description="Create a webhook in a text channel.",
)
async def create_webhook(guild_id: str, channel_id: str, name: str, reason: str = "Webhook created via ModLink MCP") -> str:
    token = _get_ml_token()
    if token is None:
        return json.dumps({"error": "Unauthenticated"})
    args = {"guild_id": guild_id, "channel_id": channel_id, "name": name}
    try:
        _require_guild_access(token, guild_id)
        _require_permission(token, PermissionLevel.manage)
        channel = await get_channel(guild_id, channel_id)
        webhook = await channel.create_webhook(name=name, reason=reason)
        data = {"status": "created", "webhook_id": str(webhook.id), "name": webhook.name, "url": webhook.url}
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="create_webhook", arguments=args, result=AuditResult.success)
        return json.dumps(data, indent=2)
    except PermissionError as exc:
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="create_webhook", arguments=args, result=AuditResult.denied, result_detail=str(exc))
        return json.dumps({"error": "Permission denied", "detail": str(exc)})
    except Exception as exc:
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="create_webhook", arguments=args, result=AuditResult.error, result_detail=str(exc))
        return json.dumps({"error": str(exc)})


@mcp.tool(
    name="delete_webhook",
    description="Delete a webhook by its ID.",
)
async def delete_webhook(guild_id: str, webhook_id: str, reason: str = "Webhook deleted via ModLink MCP") -> str:
    token = _get_ml_token()
    if token is None:
        return json.dumps({"error": "Unauthenticated"})
    args = {"guild_id": guild_id, "webhook_id": webhook_id}
    try:
        _require_guild_access(token, guild_id)
        _require_permission(token, PermissionLevel.manage)
        webhook = await bot.fetch_webhook(int(webhook_id))
        name = webhook.name
        await webhook.delete(reason=reason)
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="delete_webhook", arguments=args, result=AuditResult.success)
        return json.dumps({"status": "deleted", "webhook_id": webhook_id, "name": name})
    except PermissionError as exc:
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="delete_webhook", arguments=args, result=AuditResult.denied, result_detail=str(exc))
        return json.dumps({"error": "Permission denied", "detail": str(exc)})
    except Exception as exc:
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="delete_webhook", arguments=args, result=AuditResult.error, result_detail=str(exc))
        return json.dumps({"error": str(exc)})


@mcp.tool(
    name="send_webhook_message",
    description="Send a message using an existing webhook.",
)
async def send_webhook_message(
    guild_id: str,
    webhook_id: str,
    content: str,
    username: Optional[str] = None,
    avatar_url: Optional[str] = None,
) -> str:
    token = _get_ml_token()
    if token is None:
        return json.dumps({"error": "Unauthenticated"})
    args = {"guild_id": guild_id, "webhook_id": webhook_id, "content": content}
    try:
        _require_guild_access(token, guild_id)
        _require_permission(token, PermissionLevel.moderate)
        webhook = await bot.fetch_webhook(int(webhook_id))
        await webhook.send(content=content, username=username, avatar_url=avatar_url)
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="send_webhook_message", arguments=args, result=AuditResult.success)
        return json.dumps({"status": "sent", "webhook_id": webhook_id})
    except PermissionError as exc:
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="send_webhook_message", arguments=args, result=AuditResult.denied, result_detail=str(exc))
        return json.dumps({"error": "Permission denied", "detail": str(exc)})
    except Exception as exc:
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="send_webhook_message", arguments=args, result=AuditResult.error, result_detail=str(exc))
        return json.dumps({"error": str(exc)})


# ══════════════════════════════════════════════════════════════════════════════
# AI & SERVER OVERVIEW TOOLS
# ══════════════════════════════════════════════════════════════════════════════

@mcp.tool(
    name="get_server_overview",
    description="Get a complete overview and resource map of the server: categories, text & voice channels, roles hierarchy, and member counts.",
)
async def get_server_overview(guild_id: str) -> str:
    token = _get_ml_token()
    if token is None:
        return json.dumps({"error": "Unauthenticated"})
    args = {"guild_id": guild_id}
    try:
        _require_guild_access(token, guild_id)
        _require_permission(token, PermissionLevel.read)
        guild = await get_guild(guild_id)
        structure: dict = {"categories": [], "uncategorized_channels": []}
        for cat in guild.categories:
            structure["categories"].append({
                "category_id": str(cat.id),
                "name": cat.name,
                "channels": [{"id": str(c.id), "name": c.name, "type": str(c.type)} for c in cat.channels],
            })
        for ch in guild.channels:
            if getattr(ch, "category", None) is None and not isinstance(ch, discord.CategoryChannel):
                structure["uncategorized_channels"].append({"id": str(ch.id), "name": ch.name, "type": str(ch.type)})
        data = {
            "guild_id": guild_id,
            "name": guild.name,
            "owner_id": str(guild.owner_id),
            "member_count": guild.member_count,
            "roles": [{"id": str(r.id), "name": r.name, "members": len(r.members)} for r in reversed(guild.roles) if r.name != "@everyone"],
            "structure": structure,
        }
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="get_server_overview", arguments=args, result=AuditResult.success)
        return json.dumps(data, indent=2)
    except PermissionError as exc:
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="get_server_overview", arguments=args, result=AuditResult.denied, result_detail=str(exc))
        return json.dumps({"error": "Permission denied", "detail": str(exc)})
    except Exception as exc:
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="get_server_overview", arguments=args, result=AuditResult.error, result_detail=str(exc))
        return json.dumps({"error": str(exc)})


@mcp.tool(
    name="get_bot_permissions",
    description="Inspect the bot's own Discord permissions in the guild or in a specific channel.",
)
async def get_bot_permissions(guild_id: str, channel_id: Optional[str] = None) -> str:
    token = _get_ml_token()
    if token is None:
        return json.dumps({"error": "Unauthenticated"})
    args = {"guild_id": guild_id, "channel_id": channel_id}
    try:
        _require_guild_access(token, guild_id)
        _require_permission(token, PermissionLevel.read)
        guild = await get_guild(guild_id)
        me = guild.me
        if channel_id:
            channel = await get_channel(guild_id, channel_id)
            perms = channel.permissions_for(me)
            context = f"channel {channel.name}"
        else:
            perms = me.guild_permissions
            context = "guild wide"
        data = {
            "guild_id": guild_id,
            "context": context,
            "bot_user": str(me),
            "administrator": perms.administrator,
            "manage_guild": perms.manage_guild,
            "manage_roles": perms.manage_roles,
            "manage_channels": perms.manage_channels,
            "kick_members": perms.kick_members,
            "ban_members": perms.ban_members,
            "moderate_members": perms.moderate_members,
            "manage_messages": perms.manage_messages,
            "view_audit_log": perms.view_audit_log,
            "send_messages": perms.send_messages,
            "mention_everyone": perms.mention_everyone,
        }
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="get_bot_permissions", arguments=args, result=AuditResult.success)
        return json.dumps(data, indent=2)
    except PermissionError as exc:
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="get_bot_permissions", arguments=args, result=AuditResult.denied, result_detail=str(exc))
        return json.dumps({"error": "Permission denied", "detail": str(exc)})
    except Exception as exc:
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="get_bot_permissions", arguments=args, result=AuditResult.error, result_detail=str(exc))
        return json.dumps({"error": str(exc)})


@mcp.tool(
    name="summarize_channel",
    description="Retrieve recent channel chat formatted into a structured conversation transcript ready for AI summarization.",
)
async def summarize_channel(guild_id: str, channel_id: str, limit: int = 50) -> str:
    token = _get_ml_token()
    if token is None:
        return json.dumps({"error": "Unauthenticated"})
    args = {"guild_id": guild_id, "channel_id": channel_id, "limit": limit}
    try:
        _require_guild_access(token, guild_id)
        _require_permission(token, PermissionLevel.read)
        channel = await get_channel(guild_id, channel_id)
        limit = max(1, min(limit, 100))
        lines = []
        async for msg in channel.history(limit=limit, oldest_first=True):
            if not msg.content and not msg.attachments:
                continue
            time_str = msg.created_at.strftime("%Y-%m-%d %H:%M")
            author = msg.author.display_name
            content = msg.clean_content
            if msg.attachments:
                content += f" [Attached: {', '.join(a.filename for a in msg.attachments)}]"
            lines.append(f"[{time_str}] {author}: {content}")
        transcript = "\n".join(lines)
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="summarize_channel", arguments=args, result=AuditResult.success)
        return json.dumps({
            "guild_id": guild_id,
            "channel_id": channel_id,
            "channel_name": channel.name,
            "message_count": len(lines),
            "transcript": transcript,
        }, indent=2)
    except PermissionError as exc:
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="summarize_channel", arguments=args, result=AuditResult.denied, result_detail=str(exc))
        return json.dumps({"error": "Permission denied", "detail": str(exc)})
    except Exception as exc:
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="summarize_channel", arguments=args, result=AuditResult.error, result_detail=str(exc))
        return json.dumps({"error": str(exc)})


@mcp.tool(
    name="recommend_server_improvements",
    description="Evaluate server configuration, safety settings, and permissions, returning actionable security and management recommendations.",
)
async def recommend_server_improvements(guild_id: str) -> str:
    token = _get_ml_token()
    if token is None:
        return json.dumps({"error": "Unauthenticated"})
    args = {"guild_id": guild_id}
    try:
        _require_guild_access(token, guild_id)
        _require_permission(token, PermissionLevel.read)
        guild = await get_guild(guild_id)
        recommendations = []
        # Check verification
        if guild.verification_level == discord.VerificationLevel.none:
            recommendations.append({
                "severity": "HIGH",
                "area": "Security",
                "finding": "Verification level is set to None.",
                "recommendation": "Set verification level to at least 'Low' (verified email) to prevent mass account spam.",
            })
        # Check 2FA
        if guild.mfa_level == 0:
            recommendations.append({
                "severity": "MEDIUM",
                "area": "Staff Security",
                "finding": "Server 2FA requirement is disabled.",
                "recommendation": "Require 2FA for moderators and admins to protect against account compromises.",
            })
        # Check AutoMod rules
        automod_rules = await guild.fetch_automod_rules()
        if not automod_rules:
            recommendations.append({
                "severity": "HIGH",
                "area": "AutoMod",
                "finding": "No Discord AutoMod rules are configured.",
                "recommendation": "Use create_automod_keyword_rule to block common slurs, raid keywords, and invite spam.",
            })
        # Check slowmode in main channels
        fast_channels = [c.name for c in guild.text_channels if c.slowmode_delay == 0 and ("general" in c.name or "chat" in c.name)]
        if fast_channels:
            recommendations.append({
                "severity": "LOW",
                "area": "Chat Flow",
                "finding": f"General chat channels ({', '.join(fast_channels)}) have no slowmode.",
                "recommendation": "Consider setting a 3-5 second slowmode to reduce message flooding during active hours.",
            })
        # Audit log check
        if not guild.me.guild_permissions.view_audit_log:
            recommendations.append({
                "severity": "MEDIUM",
                "area": "Bot Permissions",
                "finding": "Bot does not have 'View Audit Log' permission.",
                "recommendation": "Grant 'View Audit Log' permission so ModLink can track administrative events and actions.",
            })
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="recommend_server_improvements", arguments=args, result=AuditResult.success)
        return json.dumps({
            "guild_id": guild_id,
            "guild_name": guild.name,
            "recommendations": recommendations,
            "total": len(recommendations),
        }, indent=2)
    except PermissionError as exc:
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="recommend_server_improvements", arguments=args, result=AuditResult.denied, result_detail=str(exc))
        return json.dumps({"error": "Permission denied", "detail": str(exc)})
    except Exception as exc:
        await _audit(connection_id=token.connection_id, guild_id=guild_id,
                     tool_name="recommend_server_improvements", arguments=args, result=AuditResult.error, result_detail=str(exc))
        return json.dumps({"error": str(exc)})


# ── Register custom tools dynamically ─────────────────────────────────────────

def _register_custom_tools() -> None:
    """
    Register all custom tools from the registry with MCPServer.
    Called once during startup; add more tools to custom_tools.py.
    """
    for ct in get_custom_tools():
        # Build a wrapper that injects the token check
        def _make_wrapper(custom_tool_def):
            async def _wrapper(**kwargs: Any) -> str:
                token = _get_ml_token()
                if token is None:
                    return json.dumps({"error": "Unauthenticated"})
                guild_id = kwargs.get("guild_id", "n/a")
                try:
                    if guild_id != "n/a":
                        _require_guild_access(token, guild_id)
                    if not has_permission(token, custom_tool_def.required_permission):
                        raise PermissionError(
                            f"Tool {custom_tool_def.name!r} requires "
                            f"{custom_tool_def.required_permission.value!r} permission."
                        )
                    result = await custom_tool_def(**kwargs)
                    await _audit(
                        connection_id=token.connection_id, guild_id=guild_id,
                        tool_name=custom_tool_def.name, arguments=kwargs,
                        result=AuditResult.success,
                    )
                    return json.dumps(result, indent=2)
                except PermissionError as exc:
                    await _audit(connection_id=token.connection_id, guild_id=guild_id,
                                 tool_name=custom_tool_def.name, arguments=kwargs,
                                 result=AuditResult.denied, result_detail=str(exc))
                    return json.dumps({"error": "Permission denied", "detail": str(exc)})
                except Exception as exc:
                    await _audit(connection_id=token.connection_id, guild_id=guild_id,
                                 tool_name=custom_tool_def.name, arguments=kwargs,
                                 result=AuditResult.error, result_detail=str(exc))
                    return json.dumps({"error": str(exc)})
            _wrapper.__name__ = custom_tool_def.name
            return _wrapper

        mcp.add_tool(
            fn=_make_wrapper(ct),
            name=ct.name,
            description=ct.description,
        )
        logger.debug("Registered custom tool with MCPServer: %s", ct.name)


# ── Register all modular tool categories ──────────────────────────────────────
from app.modules import register_all_modules
register_all_modules(mcp)


async def _migrate_key_hashes() -> None:
    """
    Idempotent startup migration: rehash all AIConnection records whose
    api_key_hash does not match the SHA-256 of the user's raw API key.
    Runs in O(n) where n = number of active UserSession rows with an api_key.
    Safe to run on every startup.
    """
    import hashlib as _hl
    from app.database import AIConnection, UserSession, ConnectionStatus, PermissionLevel
    from sqlalchemy import select as _sel

    def _sha256(raw: str) -> str:
        return _hl.sha256(raw.encode("utf-8")).hexdigest()

    migrated = 0
    async with AsyncSessionLocal() as session:
        sess_res = await session.execute(
            _sel(UserSession).where(UserSession.api_key.isnot(None))
        )
        user_sessions = sess_res.scalars().all()

        for us in user_sessions:
            if not us.api_key:
                continue
            correct_hash = _sha256(us.api_key)
            conn_name = f"{us.discord_username}\'s AI Connector"

            conn_res = await session.execute(
                _sel(AIConnection).where(
                    AIConnection.name == conn_name,
                    AIConnection.status == ConnectionStatus.active,
                )
            )
            conns = conn_res.scalars().all()

            if not conns:
                # Recreate missing connection
                admin_guild_ids = [str(g.get("id")) for g in (us.admin_guilds or []) if g.get("id")]
                new_conn = AIConnection(
                    name=conn_name,
                    description=f"Auto-recovered for {us.discord_username}",
                    api_key_hash=correct_hash,
                    allowed_guild_ids=admin_guild_ids,
                    permission_level=PermissionLevel.admin,
                    autonomous_mode=False,
                    status=ConnectionStatus.active,
                )
                session.add(new_conn)
                migrated += 1
            else:
                primary = conns[0]
                if primary.api_key_hash != correct_hash:
                    primary.api_key_hash = correct_hash
                    migrated += 1
                # Revoke duplicate connections
                for dup in conns[1:]:
                    dup.status = ConnectionStatus.revoked

        if migrated:
            await session.commit()
            logger.info("Startup migration: updated %d API key hashes to SHA-256.", migrated)
        else:
            logger.info("Startup migration: all %d API key hashes are current.", len(user_sessions))


# ── Build Starlette ASGI app ──────────────────────────────────────────────────

def build_app() -> Starlette:
    # Register custom tools before building the app
    _register_custom_tools()

    from mcp.server.transport_security import TransportSecuritySettings

    # Get the MCP Starlette app (handles /mcp path internally)
    # DNS rebinding protection disabled so public tunnels (ngrok/cloudflare) work
    mcp_starlette = mcp.streamable_http_app(
        streamable_http_path="/mcp",
        stateless_http=False,
        transport_security=TransportSecuritySettings(enable_dns_rebinding_protection=False),
    )

    import time, secrets
    from starlette.responses import RedirectResponse

    async def health(request: Request) -> JSONResponse:
        # SECURITY: Don't expose total guild count — it leaks info about other users' servers
        return JSONResponse({
            "status": "ok",
            "service": "modlink-mcp",
            "version": "1.0.0",
            "discord_connected": bot.is_ready(),
        })

    def _get_public_base(request: Request) -> str:
        if settings.mcp_public_url and "yourdomain.com" not in settings.mcp_public_url:
            url = settings.mcp_public_url
            if url.endswith("/mcp"):
                return url[:-4]
            return url.rstrip("/")
        # Use Host header from reverse proxy (e.g. ngrok)
        host = request.headers.get("x-forwarded-host") or request.headers.get("host") or "localhost:8000"
        proto = request.headers.get("x-forwarded-proto") or ("https" if "render" in host or "ngrok" in host else "http")
        base = f"{proto}://{host}"
        import re
        base = re.sub(r"\.onrender\.co(?:m+)?(?=/|$)", ".onrender.com", base)
        return base.rstrip("/")

    async def well_known(request: Request) -> JSONResponse:
        """MCP discovery document."""
        base = _get_public_base(request)
        return JSONResponse({
            "resource": f"{base}/mcp",
            "authorization_servers": [base],
            "scopes_supported": [
                "modlink:access",
                "modlink:read",
                "modlink:moderate",
                "modlink:manage",
                "modlink:admin",
                "modlink:autonomous",
            ],
        })

    async def oauth_protected_resource(request: Request) -> JSONResponse:
        base = _get_public_base(request)
        return JSONResponse({
            "resource": f"{base}/mcp",
            "authorization_servers": [base],
            "bearer_methods_supported": ["header"],
        })

    async def oauth_authorization_server(request: Request) -> JSONResponse:
        base = _get_public_base(request)
        return JSONResponse({
            "issuer": base,
            "authorization_endpoint": f"{base}/authorize",
            "token_endpoint": f"{base}/token",
            "registration_endpoint": f"{base}/register",
            "response_types_supported": ["code"],
            "grant_types_supported": ["authorization_code", "refresh_token"],
            "token_endpoint_auth_methods_supported": ["client_secret_post", "client_secret_basic", "none"],
        })

    async def oauth_register(request: Request) -> JSONResponse:
        """Dynamic Client Registration (RFC 7591)."""
        try:
            data = await request.json()
        except Exception:
            data = {}
        from app.oauth import register_client
        client_info = register_client(data)
        return JSONResponse(client_info, status_code=201)

    async def oauth_authorize(request: Request) -> RedirectResponse:
        """
        OAuth 2.0 Authorization Endpoint (RFC 6749 + RFC 7636).
        Authenticates the user via Discord, then returns an authorization_code to Claude/Cursor.

        Security requirements enforced here:
        - redirect_uri must be registered for the client (prevents open redirect / code theft).
        - PKCE with S256 is mandatory for all clients (prevents code interception).
        - client_id must be provided.
        """
        params = request.query_params
        redirect_uri = params.get("redirect_uri", "")
        state = params.get("state", "")
        client_id = params.get("client_id", "")
        code_challenge = params.get("code_challenge", "")
        code_challenge_method = params.get("code_challenge_method", "S256")

        if not redirect_uri:
            return RedirectResponse("/?error=missing_redirect_uri", status_code=302)

        if not client_id:
            return RedirectResponse("/?error=missing_client_id", status_code=302)

        # PKCE S256 is mandatory — reject flows that don't send a code_challenge.
        if not code_challenge:
            return RedirectResponse(
                f"/?error=pkce_required&error_description=PKCE+code_challenge+is+required",
                status_code=302,
            )
        if code_challenge_method.upper() not in ("S256",):
            return RedirectResponse(
                f"/?error=invalid_pkce_method&error_description=Only+S256+is+supported",
                status_code=302,
            )

        # Validate redirect_uri against the registered client's allowed list.
        from app.oauth import get_client
        client_meta = get_client(client_id)
        if client_meta:
            allowed_uris = client_meta.get("redirect_uris", [])
            normalized_req = redirect_uri.rstrip("/")
            if allowed_uris and not any(u.rstrip("/") == normalized_req for u in allowed_uris):
                return RedirectResponse(
                    "/?error=redirect_uri_not_registered",
                    status_code=302,
                )
        # (If the client is not registered via DCR, we allow the request but
        #  PKCE is already enforced above. Registered clients get strict URI checks.)

        # 1. Check if user already has an active ModLink Discord session
        session_token = request.cookies.get("modlink_session")
        if session_token:
            from datetime import datetime, timezone
            now = datetime.now(timezone.utc)
            async with AsyncSessionLocal() as session:
                from app.database import UserSession
                res = await session.execute(
                    select(UserSession).where(
                        UserSession.id == session_token,
                        UserSession.expires_at > now,
                    )
                )
                user_sess = res.scalars().first()
                if user_sess and user_sess.api_key:
                    from app.oauth import issue_authorization_code
                    auth_code = issue_authorization_code(
                        client_id=client_id,
                        redirect_uri=redirect_uri,
                        api_key=user_sess.api_key,
                        discord_user_id=user_sess.discord_user_id,
                        discord_username=user_sess.discord_username,
                        code_challenge=code_challenge,
                        code_challenge_method=code_challenge_method,
                    )
                    from urllib.parse import urlencode as _qenc
                    sep = "&" if "?" in redirect_uri else "?"
                    cb_data = {"code": auth_code}
                    if state:
                        cb_data["state"] = state
                    logger.info("Instantly authorized active user %s for MCP client", user_sess.discord_username)
                    return RedirectResponse(f"{redirect_uri}{sep}{_qenc(cb_data)}", status_code=302)

        # 2. User is not yet logged in: store the MCP OAuth request in a cookie and redirect to Discord login
        from app.portal import _get_public_base
        base = _get_public_base(request)
        flow_data = {
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "state": state,
            "code_challenge": code_challenge,
            "code_challenge_method": code_challenge_method,
        }
        encoded_flow = base64.urlsafe_b64encode(json.dumps(flow_data).encode("utf-8")).decode("ascii")

        response = RedirectResponse(f"{base}/auth/discord/login", status_code=302)
        response.set_cookie(
            "mcp_oauth_flow",
            encoded_flow,
            httponly=True,
            samesite="lax",
            secure=base.startswith("https"),
            path="/",
            max_age=600,
        )
        return response

    async def oauth_token(request: Request) -> JSONResponse:
        """
        OAuth 2.0 Token Endpoint (RFC 6749 + RFC 7636).
        Exchanges authorization_code for a Bearer AccessToken containing the user's real API key.
        """
        content_type = request.headers.get("content-type", "")
        params = {}
        if "application/json" in content_type:
            try:
                params = await request.json()
            except Exception:
                params = {}
        else:
            try:
                form = await request.form()
                params = dict(form)
            except Exception:
                params = {}

        grant_type = params.get("grant_type")
        code = params.get("code")
        redirect_uri = params.get("redirect_uri")
        code_verifier = params.get("code_verifier")
        client_id = params.get("client_id")

        if grant_type != "authorization_code":
            return JSONResponse(
                {"error": "unsupported_grant_type", "error_description": "Only authorization_code grant is supported."},
                status_code=400,
            )

        if not code:
            return JSONResponse(
                {"error": "invalid_request", "error_description": "Missing code parameter."},
                status_code=400,
            )

        from app.oauth import consume_authorization_code
        record, err_msg = consume_authorization_code(
            code=code,
            client_id=client_id,
            redirect_uri=redirect_uri,
            code_verifier=code_verifier,
        )

        if err_msg or not record:
            return JSONResponse(
                {"error": "invalid_grant", "error_description": err_msg or "Invalid authorization code."},
                status_code=400,
            )

        api_key = record["api_key"]
        logger.info("Successfully issued AccessToken for Discord user %s", record.get("discord_username"))
        return JSONResponse({
            "access_token": api_key,
            "token_type": "Bearer",
            "expires_in": 30 * 86400,
            "scope": "modlink:access modlink:admin",
            "user": {
                "id": record.get("discord_user_id"),
                "username": record.get("discord_username"),
            },
        })

    from contextlib import asynccontextmanager

    @asynccontextmanager
    async def lifespan(app):
        # Fail closed if DASHBOARD_SECRET is weak or missing
        settings.validate_secrets()
        # Startup DB and Discord bot
        await init_db()
        asyncio.create_task(start_bot())
        await asyncio.sleep(1)

        # Migrate any stale key hashes to plain SHA-256 (idempotent, safe)
        try:
            await _migrate_key_hashes()
        except Exception as _mig_exc:
            logger.warning("Key hash migration failed: %s", _mig_exc)

        # Run MCP StreamableHTTP session manager task group
        session_mgr = getattr(mcp._lowlevel_server, "_session_manager", None)
        if session_mgr:
            async with session_mgr.run():
                yield
        else:
            yield

        logger.info("ModLink MCP shutting down...")

    from starlette.middleware import Middleware

    # Middleware to enforce API Key auth on /mcp, and render custom 404 for website
    class ModLinkAuthMiddleware:
        def __init__(self, inner_app):
            self.inner_app = inner_app

        async def __call__(self, scope, receive, send):
            if scope["type"] != "http":
                await self.inner_app(scope, receive, send)
                return

            path = scope.get("path", "")
            # Enforce API key auth on /mcp endpoints
            if path.startswith("/mcp"):
                raw_token = None
                session_id = None
                cookie_str = ""

                # 1. Search headers for token, session ID, and cookies
                for key, val in scope.get("headers", []):
                    k = key.decode("latin-1").lower()
                    if k in ("x-api-key", "x-modlink-token", "x-auth-token", "authorization", "api-key", "apikey", "token", "x-token"):
                        v = val.decode("latin-1").strip("'\" \t\r\n")
                        candidate = v[7:].strip("'\" \t\r\n") if v.lower().startswith("bearer ") else v
                        if candidate and candidate.lower() not in ("null", "undefined", "none"):
                            raw_token = candidate
                    elif k in ("mcp-session-id", "x-mcp-session-id"):
                        session_id = val.decode("latin-1").strip()
                    elif k == "cookie":
                        cookie_str = val.decode("latin-1")

                # 2. Search query parameters for MCP session ID only.
                # NOTE: API keys/tokens are intentionally NOT accepted via query string.
                # URLs can be logged by proxies, CDNs, and browsers, exposing secrets.
                # Clients must supply credentials exclusively in Authorization headers.
                from urllib.parse import parse_qs
                qs_str = scope.get("query_string", b"").decode("latin-1")
                if qs_str:
                    params = parse_qs(qs_str)
                    if not session_id:
                        for s_key in ("sessionId", "session_id", "mcp-session-id", "mcp_session_id"):
                            if s_key in params and params[s_key]:
                                session_id = params[s_key][0].strip()
                                break

                # 3. If session ID was already authenticated in a previous request, reuse its token
                if not raw_token and session_id:
                    from app.auth import get_session_token
                    session_tok = get_session_token(session_id)
                    if session_tok:
                        # Explicitly pin this token to the current request's ContextVar
                        set_current_token(session_tok, session_id=session_id)
                        await self.inner_app(scope, receive, send)
                        return

                # 4. If still no token, check session cookie (e.g. user interacting via browser/dashboard)
                if not raw_token and "modlink_session=" in cookie_str:
                    from http.cookies import SimpleCookie
                    try:
                        c = SimpleCookie()
                        c.load(cookie_str)
                        if "modlink_session" in c:
                            s_val = c["modlink_session"].value
                            from app.database import UserSession
                            from datetime import datetime, timezone
                            now = datetime.now(timezone.utc)
                            async with AsyncSessionLocal() as session:
                                s_res = await session.execute(
                                    select(UserSession).where(
                                        UserSession.id == s_val,
                                        UserSession.expires_at > now,
                                    )
                                )
                                u_sess = s_res.scalars().first()
                                if u_sess and u_sess.api_key:
                                    raw_token = u_sess.api_key
                    except Exception as exc:
                        logger.debug("Could not extract token from cookie: %s", exc)

                if raw_token:
                    ml_token = await verify_bearer(raw_token)
                    if not ml_token:
                        res = JSONResponse(
                            {"status": "error", "error": "Unauthorized", "code": "missing_or_invalid_api_key", "detail": "Invalid or revoked API Key"},
                            status_code=401,
                        )
                        await res(scope, receive, send)
                        return
                    set_current_token(ml_token, session_id=session_id)
                else:
                    # No token found by any means — explicitly clear context so this request
                    # cannot inherit a previous request's token (cross-user access prevention).
                    set_current_token(None)

                # Capture session-id emitted in response headers so future requests with that session-id authenticate seamlessly
                async def mcp_send(message):
                    if message["type"] == "http.response.start":
                        for k, v in message.get("headers", []):
                            if k.decode("latin-1").lower() in ("mcp-session-id", "x-mcp-session-id"):
                                resp_sid = v.decode("latin-1").strip()
                                active_tok = get_current_token()
                                if resp_sid and active_tok:
                                    register_session_token(resp_sid, active_tok)
                    await send(message)

                await self.inner_app(scope, receive, mcp_send)
                return

            # For non-mcp routes, capture 404s to render 404.html
            status_code = None
            resp_headers = []
            resp_chunks = []

            async def custom_send(message):
                nonlocal status_code, resp_headers
                if message["type"] == "http.response.start":
                    status_code = message.get("status")
                    resp_headers = message.get("headers", [])
                elif message["type"] == "http.response.body":
                    resp_chunks.append(message.get("body", b""))

            await self.inner_app(scope, receive, custom_send)

            if status_code == 404 and not path.startswith("/api") and not path.startswith("/static"):
                from starlette.requests import Request
                req = Request(scope)
                res = await not_found_page(req)
                await res(scope, receive, send)
            else:
                if status_code is not None:
                    await send({"type": "http.response.start", "status": status_code, "headers": resp_headers})
                    for chunk in resp_chunks:
                        await send({"type": "http.response.body", "body": chunk})

    from app.portal import portal_routes, not_found_page
    from app.dashboard import app as dashboard_api_app
    from starlette.staticfiles import StaticFiles
    from starlette.responses import FileResponse
    from pathlib import Path

    static_dir = Path(__file__).parent / "static"

    async def favicon_route(request: Request) -> FileResponse:
        return FileResponse(str(static_dir / "favicon.png"), media_type="image/png")

    # Wrap the mcp app in an outer Starlette app so we can add /health, OAuth, portal, static, etc.
    app = Starlette(
        lifespan=lifespan,
        routes=[
            Route("/favicon.ico", favicon_route),
            Mount("/static", app=StaticFiles(directory=str(static_dir)), name="static"),
            Mount("/api", app=dashboard_api_app),
            *portal_routes,
            Route("/health", health),
            Route("/.well-known/mcp", well_known),
            Route("/.well-known/oauth-protected-resource", oauth_protected_resource),
            Route("/.well-known/oauth-protected-resource/mcp", oauth_protected_resource),
            Route("/.well-known/oauth-authorization-server", oauth_authorization_server),
            Route("/register", oauth_register, methods=["POST"]),
            Route("/authorize", oauth_authorize, methods=["GET", "POST"]),
            Route("/token", oauth_token, methods=["POST"]),
            Mount("/", app=mcp_starlette),
        ],
        exception_handlers={404: not_found_page},
        middleware=[Middleware(ModLinkAuthMiddleware)],
    )
    return app


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import sys
    logging.basicConfig(
        level=settings.log_level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )
    app = build_app()
    uvicorn.run(
        app,
        host=settings.mcp_host,
        port=settings.server_port,
        log_level=settings.log_level.lower(),
    )

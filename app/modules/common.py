"""
app/modules/common.py — Shared utilities, authentication helpers, and data storage for MCP tool modules.
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import json
import logging
import secrets
from typing import Any, Callable, Dict, List, Optional, Tuple

import discord
from sqlalchemy import select, delete

from app.auth import AccessToken as ModLinkToken, PermissionLevel, has_permission, get_current_token
from app.database import (
    AsyncSessionLocal,
    AuditLog,
    AuditResult,
    GenericStoreItem,
)
from app.discord_bot import bot

logger = logging.getLogger(__name__)


# ── Structured Error Formatting ───────────────────────────────────────────────

def make_error(
    code: str,
    message: str,
    hint: str,
    status: str = "error",
    **extra: Any,
) -> str:
    """Return a standard JSON error response string with structured fields: status, code, message, hint."""
    payload = {
        "status": status,
        "error": code,
        "code": code,
        "message": message,
        "hint": hint,
    }
    if extra:
        payload.update(extra)
    return json.dumps(payload, indent=2)


def format_discord_error(exc: Exception, action_context: str = "performing action") -> str:
    """Convert common Discord exceptions into clear, structured error responses."""
    if isinstance(exc, discord.Forbidden):
        return make_error(
            code="missing_permission",
            message=f"Discord API rejected action: Forbidden ({exc.text or str(exc)})",
            hint="Check that the bot has the required Discord permissions (e.g. Manage Channels, Manage Roles, Administrator) and that the bot's role is positioned higher than target roles.",
        )
    elif isinstance(exc, discord.NotFound):
        return make_error(
            code="not_found",
            message=f"Discord target entity not found ({action_context}): {exc.text or str(exc)}",
            hint="Ensure the provided ID (channel, role, user, message) is valid and exists on the server.",
        )
    elif isinstance(exc, discord.HTTPException):
        if getattr(exc, "code", None) == 50013:
            return make_error(
                code="missing_permission",
                message=f"Missing Discord permissions while {action_context}: {exc.text}",
                hint="Grant the bot the required permissions in Discord Server Settings.",
            )
        elif getattr(exc, "code", None) == 50028:
            return make_error(
                code="bot_role_too_low",
                message=f"Role hierarchy conflict: Bot's highest role is lower than or equal to the target role.",
                hint="Open Discord Server Settings > Roles and drag the bot's role above the target role.",
            )
        return make_error(
            code="discord_api_error",
            message=f"Discord API error ({exc.status} {getattr(exc, 'code', 'N/A')}): {exc.text or str(exc)}",
            hint="Verify rate limits and Discord payload requirements.",
        )
    return make_error(
        code="internal_error",
        message=f"Unexpected error while {action_context}: {str(exc)}",
        hint="Inspect input parameters or check bot health.",
    )


def get_token() -> Optional[ModLinkToken]:
    """Retrieve current token from unified auth context."""
    return get_current_token()


async def audit_log(
    *,
    token: Optional[ModLinkToken],
    guild_id: str,
    tool_name: str,
    arguments: Optional[dict] = None,
    result: AuditResult = AuditResult.success,
    result_detail: Optional[str] = None,
    target_user_id: Optional[str] = None,
) -> None:
    """Record an action in the immutable audit log."""
    try:
        async with AsyncSessionLocal() as session:
            log = AuditLog(
                connection_id=token.connection_id if token else None,
                guild_id=guild_id,
                tool_name=tool_name,
                arguments=arguments or {},
                result=result,
                result_detail=result_detail,
                target_user_id=target_user_id,
            )
            session.add(log)
            await session.commit()
    except Exception as exc:
        logger.error("Failed to write audit log in %s: %s", tool_name, exc)


def check_auth(
    guild_id: Optional[str] = None,
    required_perm: PermissionLevel = PermissionLevel.read,
) -> Tuple[Optional[ModLinkToken], Optional[discord.Guild], Optional[str]]:
    """
    Validate that:
    1. Request has a valid authenticated Bearer token.
    2. If guild_id is provided, the token is explicitly authorized for this guild.
    3. Token has the required permission level.
    Returns (token, guild, error_json_str). If error_json_str is set, caller returns it immediately.
    """
    token = get_token()
    if token is None:
        return None, None, make_error(
            code="missing_or_invalid_api_key",
            message="Unauthenticated: Valid ModLink API key is required.",
            hint="Provide your ModLink API key in the Authorization: Bearer <key> header or configure your connection in the dashboard.",
        )

    if guild_id and token.allowed_guild_ids and "*" not in token.allowed_guild_ids:
        allowed_str = [str(g).strip() for g in token.allowed_guild_ids]
        if str(guild_id).strip() not in allowed_str:
            return token, None, make_error(
                code="guild_not_authorized",
                message=f"Forbidden: Your API key is not authorized for server ID '{guild_id}'.",
                hint=f"Authorize server ID '{guild_id}' in the connection's allowed guilds via the ModLink dashboard.",
            )

    if not has_permission(token, required_perm):
        return token, None, make_error(
            code="insufficient_permission",
            message=f"Forbidden: This tool requires '{required_perm.value}' permission, but your connection only has '{token.permission_level.value}'.",
            hint=f"Upgrade the connection's permission level to '{required_perm.value}' or 'admin' in the ModLink dashboard.",
        )

    guild = None
    if guild_id:
        try:
            guild = bot.get_guild(int(guild_id))
        except (ValueError, TypeError):
            pass

    return token, guild, None


# ── Generic High-Performance Data Store ────────────────────────────────────────

class DataStore:
    """
    In-memory cache with database persistence in modlink_store table.
    Provides instant O(1) response times while guaranteeing data survives restarts.
    """
    _stores: Dict[str, "DataStore"] = {}

    def __init__(self, collection: str):
        self.collection = collection
        self._memory: Dict[str, dict] = {}
        self._loaded = False
        self._lock = asyncio.Lock()

    @classmethod
    def get(cls, collection: str) -> "DataStore":
        if collection not in cls._stores:
            cls._stores[collection] = DataStore(collection)
        return cls._stores[collection]

    async def _ensure_loaded(self) -> None:
        if self._loaded:
            return
        async with self._lock:
            if self._loaded:
                return
            try:
                async with AsyncSessionLocal() as session:
                    res = await session.execute(
                        select(GenericStoreItem).where(GenericStoreItem.collection == self.collection)
                    )
                    rows = res.scalars().all()
                    for r in rows:
                        data = dict(r.data or {})
                        data["id"] = r.id
                        data["guild_id"] = r.guild_id
                        data["created_at"] = r.created_at.isoformat() if r.created_at else None
                        data["updated_at"] = r.updated_at.isoformat() if r.updated_at else None
                        self._memory[r.id] = data
            except Exception as exc:
                logger.warning("Could not load collection %s from database (using memory): %s", self.collection, exc)
            self._loaded = True

    async def create(self, item_id: Optional[str], guild_id: Optional[str], data: dict) -> dict:
        await self._ensure_loaded()
        now_iso = datetime.now(timezone.utc).isoformat()
        gid = str(guild_id) if guild_id else None
        doc_id = str(item_id) if item_id else f"{self.collection[:4]}_{secrets.token_urlsafe(12)}"
        doc = dict(data)
        doc["id"] = doc_id
        doc["guild_id"] = gid
        doc["created_at"] = doc.get("created_at") or now_iso
        doc["updated_at"] = now_iso

        self._memory[doc_id] = doc

        # Asynchronously persist to database
        try:
            async with AsyncSessionLocal() as session:
                item = GenericStoreItem(
                    id=doc_id,
                    collection=self.collection,
                    guild_id=gid,
                    data=doc,
                    created_at=datetime.now(timezone.utc),
                    updated_at=datetime.now(timezone.utc),
                )
                session.add(item)
                await session.commit()
        except Exception as exc:
            logger.warning("Database persist error in collection %s: %s", self.collection, exc)

        return doc

    async def get_by_id(self, doc_id: str) -> Optional[dict]:
        await self._ensure_loaded()
        return self._memory.get(str(doc_id))

    async def list_items(
        self,
        guild_id: Optional[str] = None,
        predicate: Optional[Callable[[dict], bool]] = None,
        limit: int = 100,
    ) -> List[dict]:
        await self._ensure_loaded()
        results = []
        gid_str = str(guild_id) if guild_id else None
        for doc in self._memory.values():
            if gid_str and str(doc.get("guild_id")) != gid_str:
                continue
            if predicate and not predicate(doc):
                continue
            results.append(doc)
            if len(results) >= limit:
                break
        return results

    async def update(self, doc_id: str, updates: dict) -> Optional[dict]:
        await self._ensure_loaded()
        doc = self._memory.get(str(doc_id))
        if not doc:
            return None
        doc.update(updates)
        doc["updated_at"] = datetime.now(timezone.utc).isoformat()

        try:
            async with AsyncSessionLocal() as session:
                res = await session.execute(
                    select(GenericStoreItem).where(GenericStoreItem.id == str(doc_id))
                )
                item = res.scalar_one_or_none()
                if item:
                    item.data = doc
                    item.updated_at = datetime.now(timezone.utc)
                    await session.commit()
        except Exception as exc:
            logger.warning("Database update error in collection %s: %s", self.collection, exc)

        return doc

    async def delete(self, doc_id: str) -> bool:
        await self._ensure_loaded()
        if str(doc_id) in self._memory:
            del self._memory[str(doc_id)]
            try:
                async with AsyncSessionLocal() as session:
                    await session.execute(
                        delete(GenericStoreItem).where(GenericStoreItem.id == str(doc_id))
                    )
                    await session.commit()
            except Exception as exc:
                logger.warning("Database delete error in collection %s: %s", self.collection, exc)
            return True
        return False

"""
app/auth.py — Bearer token verification for the MCP gateway.

Two modes:
  1. OIDC introspection  (production) — validates token with an identity provider
     and reads guild_ids + scope from the token claims.
  2. API-key lookup      (development/self-hosted) — SHA-256 hashed key stored in DB.

The public surface is a single coroutine:
    access_token = await verify_bearer(raw_token)

Returns an AccessToken dataclass, or None if invalid.

NOTE: We use plain SHA-256 (not HMAC) for API key hashing.
This makes hashes deterministic and independent of DASHBOARD_SECRET,
so they remain valid across restarts and deployments.
"""
from __future__ import annotations

import hashlib
import logging
from contextvars import ContextVar
from dataclasses import dataclass, field
from typing import Dict, List, Optional

import httpx
from sqlalchemy import select

from app.config import settings
from app.database import AIConnection, AsyncSessionLocal, ConnectionStatus, PermissionLevel

logger = logging.getLogger(__name__)


# ── Public data type ─────────────────────────────────────────────────────────

@dataclass
class AccessToken:
    """Verified identity attached to an inbound MCP request."""
    connection_id: str
    name: str
    allowed_guild_ids: List[str]
    permission_level: PermissionLevel
    autonomous_mode: bool
    scopes: List[str] = field(default_factory=list)


# ── Request authentication context ───────────────────────────────────────────

current_token_var: ContextVar[Optional[AccessToken]] = ContextVar("current_token_var", default=None)
_active_sessions: Dict[str, AccessToken] = {}
_latest_token: Optional[AccessToken] = None


def set_current_token(token: Optional[AccessToken], session_id: Optional[str] = None) -> None:
    """Set the authenticated token for the current async task and optionally map a session ID."""
    current_token_var.set(token)
    global _latest_token
    if token is not None:
        _latest_token = token
        if session_id:
            _active_sessions[str(session_id)] = token


def get_current_token() -> Optional[AccessToken]:
    """Retrieve the current authenticated token (from ContextVar, active sessions, or latest)."""
    tok = current_token_var.get()
    if tok is not None:
        return tok
    if _active_sessions:
        return list(_active_sessions.values())[-1]
    return _latest_token


def register_session_token(session_id: str, token: AccessToken) -> None:
    """Associate an MCP session ID with an authenticated token."""
    if session_id and token:
        _active_sessions[str(session_id)] = token


# ── Key hashing ──────────────────────────────────────────────────────────────

def _hash_key(raw: str) -> str:
    """
    Hash an API key using plain SHA-256.
    Deterministic and independent of any secret — hashes remain valid
    across restarts, re-deployments, and secret rotations.
    """
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


# ── OIDC introspection path ───────────────────────────────────────────────────

async def _verify_oidc(raw_token: str) -> Optional[AccessToken]:
    """
    Call the OIDC introspection endpoint, then validate:
      • active == True
      • audience includes mcp_public_url
      • scope includes modlink:access
    """
    if not (settings.oidc_introspection_url and settings.oidc_client_secret):
        return None

    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.post(
                settings.oidc_introspection_url,
                data={"token": raw_token, "token_type_hint": "access_token"},
                auth=(settings.oidc_client_id or "", settings.oidc_client_secret),
            )
        resp.raise_for_status()
        data: dict = resp.json()
    except Exception as exc:
        logger.warning("OIDC introspection failed: %s", exc)
        return None

    if not data.get("active"):
        return None

    # ── Audience validation ──────────────────────────────────────────────────
    audience = data.get("aud", [])
    if isinstance(audience, str):
        audience = [audience]
    if settings.mcp_public_url not in audience:
        logger.warning(
            "Token audience %r does not include configured resource %r — rejecting.",
            audience,
            settings.mcp_public_url,
        )
        return None

    scopes: List[str] = data.get("scope", "").split()
    if "modlink:access" not in scopes:
        return None

    raw_guilds = data.get("guild_ids", [])
    if isinstance(raw_guilds, str):
        guild_ids = raw_guilds.split()
    else:
        guild_ids = [str(g) for g in raw_guilds]

    perm = PermissionLevel.read
    if "modlink:admin" in scopes:
        perm = PermissionLevel.admin
    elif "modlink:moderate" in scopes:
        perm = PermissionLevel.moderate
    elif "modlink:manage" in scopes:
        perm = PermissionLevel.manage

    autonomous = "modlink:autonomous" in scopes

    return AccessToken(
        connection_id=data.get("sub", "oidc-unknown"),
        name=data.get("preferred_username", data.get("sub", "unknown")),
        allowed_guild_ids=guild_ids,
        permission_level=perm,
        autonomous_mode=autonomous,
        scopes=scopes,
    )


# ── API-key path ──────────────────────────────────────────────────────────────

async def _verify_api_key(raw_token: str) -> Optional[AccessToken]:
    """
    Look up an API key with a two-path strategy:

    Path 1 — Hash lookup in AIConnection.api_key_hash
      Computes SHA-256 of the raw token and finds an active AIConnection.
      Also accepts legacy HMAC hashes and migrates them to SHA-256.

    Path 2 — Exact match in UserSession.api_key
      If Path 1 misses (e.g. connection was never created or hash migrated),
      look in the UserSession table for the exact raw key.
      If found, upsert an AIConnection with the correct SHA-256 hash.

    This ensures auth works immediately after login without depending on
    DASHBOARD_SECRET or any external secret rotation.
    """
    cleaned = (raw_token or "").strip("'\" \t\r\n")
    if cleaned.lower().startswith("bearer "):
        cleaned = cleaned[7:].strip("'\" \t\r\n")

    if not cleaned:
        return None

    # Canonical SHA-256 hash
    sha256_hash = _hash_key(cleaned)

    async with AsyncSessionLocal() as session:
        # ── Path 1: hash-based lookup ────────────────────────────────────────
        result = await session.execute(
            select(AIConnection).where(
                AIConnection.api_key_hash == sha256_hash,
                AIConnection.status == ConnectionStatus.active,
            )
        )
        conn = result.scalars().first()

        if conn:
            return AccessToken(
                connection_id=str(conn.id),
                name=conn.name,
                allowed_guild_ids=list(conn.allowed_guild_ids or []),
                permission_level=conn.permission_level,
                autonomous_mode=conn.autonomous_mode,
                scopes=[],
            )

        # ── Path 2: direct UserSession lookup by raw api_key ─────────────────
        # This catches cases where the AIConnection hash is stale/legacy,
        # or where the connection was deleted but the session still exists.
        try:
            from app.database import UserSession
            from datetime import datetime, timezone
            now = datetime.now(timezone.utc)

            sess_res = await session.execute(
                select(UserSession).where(
                    UserSession.api_key == cleaned,
                    UserSession.expires_at > now,
                )
            )
            user_sess = sess_res.scalars().first()

            if user_sess:
                admin_guild_ids = [
                    str(g.get("id")) for g in (user_sess.admin_guilds or []) if g.get("id")
                ]
                # Find or recreate the AIConnection with correct hash
                conn_res = await session.execute(
                    select(AIConnection).where(
                        AIConnection.name == f"{user_sess.discord_username}'s AI Connector",
                        AIConnection.status == ConnectionStatus.active,
                    )
                )
                conn = conn_res.scalars().first()

                if conn:
                    # Migrate hash to current SHA-256
                    conn.api_key_hash = sha256_hash
                    conn.allowed_guild_ids = admin_guild_ids
                    await session.commit()
                    logger.info("Migrated/repaired API key hash for connection: %s", conn.name)
                    return AccessToken(
                        connection_id=str(conn.id),
                        name=conn.name,
                        allowed_guild_ids=admin_guild_ids,
                        permission_level=conn.permission_level,
                        autonomous_mode=conn.autonomous_mode,
                        scopes=[],
                    )
                else:
                    # Recreate the AIConnection from scratch
                    new_conn = AIConnection(
                        name=f"{user_sess.discord_username}'s AI Connector",
                        description=f"Auto-recovered connector for {user_sess.discord_username}",
                        api_key_hash=sha256_hash,
                        allowed_guild_ids=admin_guild_ids,
                        permission_level=PermissionLevel.admin,
                        autonomous_mode=False,
                        status=ConnectionStatus.active,
                    )
                    session.add(new_conn)
                    await session.commit()
                    logger.info("Recreated AIConnection for user: %s", user_sess.discord_username)
                    return AccessToken(
                        connection_id=str(new_conn.id),
                        name=new_conn.name,
                        allowed_guild_ids=admin_guild_ids,
                        permission_level=PermissionLevel.admin,
                        autonomous_mode=False,
                        scopes=[],
                    )

        except Exception as exc:
            logger.warning("Error during UserSession key fallback: %s", exc)

    logger.debug("API key not found or invalid: %s...", cleaned[:8] if len(cleaned) > 8 else "***")
    return None


# ── Public entry point ────────────────────────────────────────────────────────

async def verify_bearer(raw_token: str) -> Optional[AccessToken]:
    """
    Verify a bearer token. Tries OIDC first if configured.

    If OIDC is configured and oidc_strict=True, the API-key fallback is disabled
    and an OIDC failure returns None immediately (fail closed).
    If oidc_strict=False (default), falls back to API-key lookup.
    """
    if not raw_token:
        return None

    if settings.use_oidc:
        token = await _verify_oidc(raw_token)
        if token is not None:
            return token
        if settings.oidc_strict:
            logger.warning("OIDC strict mode: rejecting token that failed OIDC validation.")
            return None

    return await _verify_api_key(raw_token)


# ── Permission helpers ────────────────────────────────────────────────────────

_LEVEL_ORDER = [
    PermissionLevel.read,
    PermissionLevel.moderate,
    PermissionLevel.manage,
    PermissionLevel.admin,
]


def has_permission(token: AccessToken, required: PermissionLevel) -> bool:
    """Return True if the token's level is >= required."""
    try:
        return _LEVEL_ORDER.index(token.permission_level) >= _LEVEL_ORDER.index(required)
    except ValueError:
        return False

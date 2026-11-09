"""
app/auth.py — Bearer token verification for the MCP gateway.

Two modes:
  1. OIDC introspection  (production) — validates token with an identity provider
     and reads guild_ids + scope from the token claims.
  2. API-key lookup      (development) — simple HMAC-hashed key stored in DB.

The public surface is a single coroutine:
    access_token = await verify_bearer(raw_token)

Returns an AccessToken dataclass, or None if invalid.
"""
from __future__ import annotations

import hashlib
import hmac
import logging
from dataclasses import dataclass, field
from typing import List, Optional

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


# ── Helpers ──────────────────────────────────────────────────────────────────

def _hash_key(raw: str) -> str:
    """Deterministic HMAC-SHA256 of an API key using the dashboard secret."""
    return hmac.new(
        settings.dashboard_secret.encode(),
        raw.encode(),
        hashlib.sha256,
    ).hexdigest()  # hmac.new(key, msg, digestmod)


# ── OIDC introspection path ───────────────────────────────────────────────────

async def _verify_oidc(raw_token: str) -> Optional[AccessToken]:
    """
    Call the OIDC introspection endpoint, then validate:
      • active == True
      • audience includes mcp_public_url   ← MANDATORY security patch
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

    # ── Audience validation (mandatory security correction) ──────────────────
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
    # ── End audience validation ───────────────────────────────────────────────

    scopes: List[str] = data.get("scope", "").split()
    if "modlink:access" not in scopes:
        return None

    # guild_ids should be a space-separated string or a JSON list in the token
    raw_guilds = data.get("guild_ids", [])
    if isinstance(raw_guilds, str):
        guild_ids = raw_guilds.split()
    else:
        guild_ids = [str(g) for g in raw_guilds]

    # Map scope to permission level (highest wins)
    perm = PermissionLevel.read
    if "modlink:admin" in scopes:
        perm = PermissionLevel.admin
    elif "modlink:moderate" in scopes:
        perm = PermissionLevel.moderate
    elif "modlink:manage" in scopes:
        perm = PermissionLevel.manage

    autonomous = "modlink:autonomous" in scopes

    # We store a minimal synthetic connection_id for OIDC-originated tokens
    return AccessToken(
        connection_id=data.get("sub", "oidc-unknown"),
        name=data.get("preferred_username", data.get("sub", "unknown")),
        allowed_guild_ids=guild_ids,
        permission_level=perm,
        autonomous_mode=autonomous,
        scopes=scopes,
    )


# ── API-key path (dev / simple deployments) ──────────────────────────────────

async def _verify_api_key(raw_token: str) -> Optional[AccessToken]:
    """Look up a hashed API key in the database."""
    key_hash = _hash_key(raw_token)
    async with AsyncSessionLocal() as session:
        result = await session.execute(
            select(AIConnection).where(
                AIConnection.api_key_hash == key_hash,
                AIConnection.status == ConnectionStatus.active,
            )
        )
        conn: Optional[AIConnection] = result.scalar_one_or_none()

    if conn is None:
        return None

    return AccessToken(
        connection_id=str(conn.id),
        name=conn.name,
        allowed_guild_ids=list(conn.allowed_guild_ids or []),
        permission_level=conn.permission_level,
        autonomous_mode=conn.autonomous_mode,
        scopes=[],
    )


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
        # In strict mode: OIDC configured but token not accepted → reject entirely
        if settings.oidc_strict:
            logger.warning("OIDC strict mode: rejecting token that failed OIDC validation.")
            return None

    # API-key path (only reached when OIDC is not configured, or oidc_strict=False)
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

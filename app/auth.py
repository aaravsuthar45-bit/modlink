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

    @property
    def client_name(self) -> str:
        return self.name


# ── Request authentication context ───────────────────────────────────────────

current_token_var: ContextVar[Optional[AccessToken]] = ContextVar("current_token_var", default=None)
_active_sessions: Dict[str, AccessToken] = {}
# _latest_token removed: falling back to a process-wide token would let an
# unauthenticated request inherit another user's identity (cross-user access risk).


def set_current_token(token: Optional[AccessToken], session_id: Optional[str] = None) -> None:
    """Set the authenticated token for the current async task and optionally map a session ID."""
    current_token_var.set(token)
    if token is not None and session_id:
        _active_sessions[str(session_id)] = token


def get_current_token() -> Optional[AccessToken]:
    """Retrieve the current authenticated token from the per-request ContextVar ONLY.

    SECURITY: This function never falls back to _active_sessions or any
    process-wide variable. Cross-request token leakage (where an unauthenticated
    or differently-authenticated request would inherit another user's identity) is
    prevented by design. Session-ID resumption is handled explicitly in the ASGI
    middleware via get_session_token() before this is called.
    """
    return current_token_var.get()


def get_session_token(session_id: str) -> Optional[AccessToken]:
    """Look up a previously registered MCP session token by its session ID.

    This is the ONLY sanctioned way to access _active_sessions outside this
    module, and must only be called from the middleware after the session ID
    has been verified as present in the request headers.
    """
    return _active_sessions.get(str(session_id))


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
    Look up an API key by its SHA-256 hash in AIConnection.api_key_hash.

    Only active connections are accepted; revoked or deleted connections are
    never resurrected from a UserSession fallback.  Revocation is final.
    """
    cleaned = (raw_token or "").strip("'\" \t\r\n")
    if cleaned.lower().startswith("bearer "):
        cleaned = cleaned[7:].strip("'\" \t\r\n")

    if not cleaned:
        return None

    # Canonical SHA-256 hash
    sha256_hash = _hash_key(cleaned)

    async with AsyncSessionLocal() as session:
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

    logger.debug("API key not found or connection inactive: %s...", cleaned[:8] if len(cleaned) > 8 else "***")
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

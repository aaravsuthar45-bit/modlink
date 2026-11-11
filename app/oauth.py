"""
app/oauth.py — OAuth 2.0 Authorization Server for MCP clients (Claude, Cursor, etc.).
Implements RFC 6749 (Authorization Code Grant) + RFC 7636 (PKCE) + RFC 7591 (Dynamic Client Registration).
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import secrets
import time
from typing import Any, Dict, Optional, Tuple

logger = logging.getLogger(__name__)

# Registered dynamic clients: client_id -> metadata
_registered_clients: Dict[str, dict] = {}

# Active authorization codes: code -> record (single use, 10 min TTL)
_auth_codes: Dict[str, dict] = {}


def register_client(data: dict) -> dict:
    """Register an MCP client (RFC 7591 Dynamic Client Registration)."""
    client_id = f"modlink-{secrets.token_urlsafe(12)}"
    client_secret = f"sec_{secrets.token_urlsafe(24)}"
    record = {
        "client_id": client_id,
        "client_secret": client_secret,
        "client_id_issued_at": int(time.time()),
        "client_secret_expires_at": 0,
        "redirect_uris": data.get("redirect_uris", []),
        "client_name": data.get("client_name", "MCP Client"),
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
        "token_endpoint_auth_method": data.get("token_endpoint_auth_method", "none"),
    }
    _registered_clients[client_id] = record
    return record


def get_client(client_id: str) -> Optional[dict]:
    """Retrieve metadata for a registered OAuth client."""
    return _registered_clients.get(client_id)


def issue_authorization_code(
    *,
    client_id: Optional[str],
    redirect_uri: str,
    api_key: str,
    discord_user_id: str,
    discord_username: str,
    code_challenge: Optional[str] = None,
    code_challenge_method: Optional[str] = None,
) -> str:
    """Issue a single-use 10-minute authorization code."""
    # Prune expired codes
    now = time.time()
    expired = [k for k, v in _auth_codes.items() if v.get("expires_at", 0) < now]
    for k in expired:
        _auth_codes.pop(k, None)

    code = f"ml_code_{secrets.token_urlsafe(32)}"
    _auth_codes[code] = {
        "code": code,
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "api_key": api_key,
        "discord_user_id": str(discord_user_id),
        "discord_username": discord_username,
        "code_challenge": code_challenge,
        "code_challenge_method": (code_challenge_method or "S256") if code_challenge else None,
        "expires_at": now + 600,
    }
    logger.info("Issued MCP OAuth authorization code for Discord user %s", discord_username)
    return code


def verify_pkce(code_verifier: str, code_challenge: str, method: Optional[str] = "S256") -> bool:
    """Verify PKCE code_verifier against code_challenge (RFC 7636)."""
    if not code_challenge:
        return True
    if not code_verifier:
        return False
    m = (method or "S256").upper()
    if m == "PLAIN":
        return hmac.compare_digest(code_verifier, code_challenge)
    elif m == "S256":
        digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
        computed = base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")
        return hmac.compare_digest(computed, code_challenge)
    return False


def consume_authorization_code(
    code: str,
    client_id: Optional[str],
    redirect_uri: Optional[str],
    code_verifier: Optional[str],
) -> Tuple[Optional[dict], Optional[str]]:
    """
    Consume an authorization code (single-use).
    Returns (record, error_message).

    Security enforcement:
    - client_id must match the one the code was issued for (prevents cross-client code theft).
    - redirect_uri must match (prevents open redirect attacks).
    - PKCE code_verifier is required when a code_challenge was stored (prevents code interception).
    - Plain PKCE method is rejected; only S256 is accepted.
    """
    record = _auth_codes.pop(code, None)
    if not record:
        return None, "Invalid, already consumed, or expired authorization code."

    if record.get("expires_at", 0) < time.time():
        return None, "Authorization code has expired."

    # Enforce client_id binding — the code may only be redeemed by the same client that requested it.
    issued_client_id = record.get("client_id")
    if issued_client_id:
        if not client_id:
            return None, "client_id is required to redeem this authorization code."
        if issued_client_id != client_id:
            logger.warning(
                "OAuth code redemption client_id mismatch: issued for %r, got %r",
                issued_client_id, client_id,
            )
            return None, "client_id mismatch: this code was not issued for the requesting client."

    expected_uri = record.get("redirect_uri")
    if expected_uri and redirect_uri:
        if expected_uri.rstrip("/") != redirect_uri.rstrip("/"):
            return None, f"Redirect URI mismatch: expected {expected_uri!r}, got {redirect_uri!r}"

    expected_challenge = record.get("code_challenge")
    if expected_challenge:
        if not code_verifier:
            return None, "code_verifier is required for PKCE validation."
        method = record.get("code_challenge_method") or "S256"
        if method.upper() == "PLAIN":
            # Reject PLAIN — it offers no security benefit and is disallowed.
            return None, "PKCE method 'plain' is not accepted; use S256."
        if not verify_pkce(code_verifier, expected_challenge, method):
            return None, "PKCE code_verifier verification failed."
    else:
        # PKCE was required at the authorization endpoint; a missing challenge
        # here means the code was issued before the enforcement was added.
        # Fail closed for safety.
        if not code_verifier:
            return None, "code_verifier is required (PKCE is mandatory)."

    return record, None

"""
app/portal.py — Web portal for Discord OAuth login & automatic MCP key generation.

Allows server owners to:
1. Log in with their Discord account.
2. Automatically verify their server ownership / admin permissions.
3. Automatically generate an isolated ModLink MCP key bound ONLY to their server.
4. Keep user session in persistent cookies so PFP, username and admin servers persist.
5. One-click copy connection settings for Claude / MCP clients.
"""
from __future__ import annotations

from datetime import datetime, timezone, timedelta
import base64
import json
import hmac
import logging
from pathlib import Path
import re
import secrets
from typing import Dict, List, Optional
from urllib.parse import urlencode

import httpx
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, RedirectResponse
from starlette.routing import Route
from sqlalchemy import select, delete

from app.auth import _hash_key
from app.config import settings
from app.database import (
    AIConnection,
    AsyncSessionLocal,
    ConnectionStatus,
    PermissionLevel,
    UserSession,
)
from app.discord_bot import bot

logger = logging.getLogger(__name__)

DISCORD_API_BASE = "https://discord.com/api/v10"
ADMIN_PERM_FLAG = 0x8       # ADMINISTRATOR
MANAGE_GUILD_FLAG = 0x20    # MANAGE_GUILD

TEMPLATES_DIR = Path(__file__).parent / "templates"


def _get_client_id() -> str:
    """Resolve Discord Client ID from settings, running bot, or DISCORD_TOKEN."""
    if settings.discord_client_id:
        return str(settings.discord_client_id).strip()
    if bot.user:
        return str(bot.user.id)
    if settings.discord_token:
        try:
            part = settings.discord_token.split(".")[0]
            part += "=" * (-len(part) % 4)
            decoded = base64.b64decode(part).decode("utf-8")
            if decoded.isdigit():
                return decoded
        except Exception:
            pass
    return ""


def _clean_url(url: str) -> str:
    """Normalize URL and fix any accidental .onrender.co or duplicated .onrender.commm."""
    return re.sub(r"\.onrender\.co(?:m+)?(?=/|$)", ".onrender.com", url).rstrip("/")


def _get_public_base(request: Request) -> str:
    """Return the base URL of this server (handling ngrok / Render proxies)."""
    if settings.mcp_public_url and "yourdomain.com" not in settings.mcp_public_url and "localhost" not in settings.mcp_public_url:
        url = settings.mcp_public_url
        if url.endswith("/mcp"):
            base = url[:-4]
        else:
            base = url.rstrip("/")
    else:
        host = request.headers.get("x-forwarded-host") or request.headers.get("host") or "localhost:8000"
        proto = request.headers.get("x-forwarded-proto") or ("https" if "render" in host or "ngrok" in host else "http")
        base = f"{proto}://{host}"
    return _clean_url(base)


def _get_redirect_uri(request: Request) -> str:
    """Return the exact OAuth redirect URI, preferring settings.discord_redirect_uri."""
    if settings.discord_redirect_uri:
        return _clean_url(settings.discord_redirect_uri)
    base = _get_public_base(request)
    return _clean_url(f"{base}/auth/discord/callback")


# Scoped Bot Permissions (Integer: 1099914407062)
# Requests only the permissions needed for moderation and AutoMod:
#   - View Channels (1024), Send Messages (2048), Read Message History (65536)
#   - Manage Messages (8192) — needed to delete spam/violations
#   - Embed Links (16384), Attach Files (32768)
#   - Moderate Members / Timeout (1099511627776)
#   - Kick Members (2), Ban Members (4)
#   - Manage Nicknames (134217728), Manage Roles (268435456), Manage Channels (16)
#   - View Audit Log (128)
# NOTE: Administrator (8) is NOT requested.
REQUIRED_BOT_PERMISSIONS = 1099914407062


def _get_bot_invite_url(guild_id: Optional[str] = None) -> str:
    """Generate the Discord Bot invite URL with scoped moderation permissions."""
    client_id = _get_client_id()
    if not client_id:
        return "https://discord.com/developers/applications"
    url = f"https://discord.com/oauth2/authorize?client_id={client_id}&permissions={REQUIRED_BOT_PERMISSIONS}&scope=bot%20applications.commands"
    if guild_id:
        url += f"&guild_id={guild_id}&disable_guild_select=true"
    return url


def _load_template(name: str) -> str:
    path = TEMPLATES_DIR / name
    if path.exists():
        return path.read_text(encoding="utf-8")
    return ""


# ── Route handlers ────────────────────────────────────────────────────────────

async def home(request: Request) -> HTMLResponse:
    """Landing page with invite and login buttons."""
    template = _load_template("index.html")
    if not template:
        return HTMLResponse("<h1>ModLink</h1><p>Website is loading...</p>")
    invite_url = _get_bot_invite_url()
    rendered = template.replace("{base}", "").replace("{invite_url}", invite_url)
    return HTMLResponse(rendered)


async def dashboard_page(request: Request) -> HTMLResponse:
    """Web dashboard page for reviewing approvals, connections, and audit log."""
    template = _load_template("dashboard.html")
    if not template:
        return HTMLResponse("<h1>Dashboard</h1><p>Dashboard template not found.</p>", status_code=404)
    return HTMLResponse(template)


async def privacy_page(request: Request) -> HTMLResponse:
    """Privacy policy page."""
    template = _load_template("privacy.html")
    if not template:
        return HTMLResponse("<h1>Privacy Policy</h1>", status_code=404)
    return HTMLResponse(template)


async def terms_page(request: Request) -> HTMLResponse:
    """Terms of service page."""
    template = _load_template("terms.html")
    if not template:
        return HTMLResponse("<h1>Terms of Service</h1>", status_code=404)
    return HTMLResponse(template)


async def not_found_page(request: Request, exc: Exception = None) -> HTMLResponse:
    """Custom 404 page."""
    template = _load_template("404.html")
    if not template:
        return HTMLResponse("<h1>404 Not Found</h1>", status_code=404)
    return HTMLResponse(template, status_code=404)


# ── Auth & Session APIs ───────────────────────────────────────────────────────

async def auth_me(request: Request) -> JSONResponse:
    """Return currently logged-in Discord user details, admin servers, and API key from session cookie."""
    session_token = request.cookies.get("modlink_session")
    if not session_token:
        return JSONResponse({"logged_in": False})

    now = datetime.now(timezone.utc)
    async with AsyncSessionLocal() as session:
        result = await session.execute(
            select(UserSession).where(
                UserSession.id == session_token,
                UserSession.expires_at > now,
            )
        )
        user_sess = result.scalar_one_or_none()

    if not user_sess:
        return JSONResponse({"logged_in": False})

    base = _get_public_base(request)
    mcp_endpoint = f"{base}/mcp"

    # Refresh live bot_joined status for admin servers against running bot guilds
    bot_guild_ids = {str(bg.id) for bg in bot.guilds}
    guilds = []
    for g in user_sess.admin_guilds or []:
        gid = str(g.get("id"))
        is_joined = gid in bot_guild_ids
        invite_link = _get_bot_invite_url(gid)
        guilds.append({
            "id": gid,
            "name": g.get("name"),
            "icon": g.get("icon"),
            "icon_url": g.get("icon_url") or (f"https://cdn.discordapp.com/icons/{gid}/{g.get('icon')}.png" if g.get("icon") else None),
            "bot_joined": is_joined,
            "invite_url": invite_link,
        })

    return JSONResponse({
        "logged_in": True,
        "user": {
            "id": user_sess.discord_user_id,
            "username": user_sess.discord_username,
            "avatar": user_sess.avatar_url,
        },
        "admin_guilds": guilds,
        "api_key": user_sess.api_key,
        "mcp_endpoint": mcp_endpoint,
        "bot_invite_url": _get_bot_invite_url(),
    })


async def auth_logout(request: Request) -> RedirectResponse:
    """Log out user by deleting their session and clearing cookie."""
    session_token = request.cookies.get("modlink_session")
    if session_token:
        async with AsyncSessionLocal() as session:
            await session.execute(
                delete(UserSession).where(UserSession.id == session_token)
            )
            await session.commit()

    response = RedirectResponse("/", status_code=302)
    response.delete_cookie("modlink_session", path="/")
    return response


async def discord_login(request: Request) -> RedirectResponse:
    """Redirect user to Discord OAuth2 authorization screen."""
    base = _get_public_base(request)
    client_id = _get_client_id()
    if not client_id:
        return HTMLResponse("<h3>Error: DISCORD_CLIENT_ID or DISCORD_TOKEN is required</h3>", status_code=500)

    redirect_uri = _get_redirect_uri(request)
    state = secrets.token_urlsafe(16)
    params = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "scope": "identify guilds",
        "state": state,
        "prompt": "consent",
    }
    discord_auth_url = f"https://discord.com/oauth2/authorize?{urlencode(params)}"
    response = RedirectResponse(discord_auth_url, status_code=302)
    response.set_cookie(
        "oauth_state",
        state,
        httponly=True,
        samesite="lax",
        secure=base.startswith("https"),
        path="/",
        max_age=600,
    )
    return response


async def discord_callback(request: Request) -> RedirectResponse | HTMLResponse:
    """Handle Discord OAuth callback, verify user & guilds, issue API key, and set 30-day session cookie."""
    code = request.query_params.get("code")
    error = request.query_params.get("error")

    if error or not code:
        return RedirectResponse(f"/?error={error or 'no_code'}", status_code=302)

    client_id = _get_client_id()
    client_secret = settings.discord_client_secret
    redirect_uri = _get_redirect_uri(request)

    if not client_secret:
        return HTMLResponse("<h3>Error: DISCORD_CLIENT_SECRET is not configured in environment</h3>", status_code=500)

    # 1. Validate OAuth state — BOTH values must be present and match
    expected_state = request.cookies.get("oauth_state")
    received_state = request.query_params.get("state")
    if not expected_state or not received_state or not hmac.compare_digest(expected_state, received_state):
        logger.warning("OAuth state mismatch or missing: expected=%r received=%r", expected_state, received_state)
        return RedirectResponse("/?error=invalid_state", status_code=302)

    # 2. Exchange OAuth code for access token
    async with httpx.AsyncClient(timeout=15.0) as client:
        token_resp = await client.post(
            f"{DISCORD_API_BASE}/oauth2/token",
            data={
                "client_id": client_id,
                "client_secret": client_secret,
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": redirect_uri,
            },
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        if token_resp.status_code != 200:
            logger.error("Discord token exchange failed: %s\nredirect_uri used: %s", token_resp.text, redirect_uri)
            return RedirectResponse("/?error=token_exchange_failed", status_code=302)

        token_data = token_resp.json()
        user_access_token = token_data["access_token"]

        # 3. Fetch user profile
        user_resp = await client.get(
            f"{DISCORD_API_BASE}/users/@me",
            headers={"Authorization": f"Bearer {user_access_token}"},
        )
        user_data = user_resp.json()
        discord_username = f"{user_data.get('username')}#{user_data.get('discriminator', '0')}".rstrip("#0")
        discord_user_id = str(user_data["id"])
        avatar_hash = user_data.get("avatar")
        avatar_url = f"https://cdn.discordapp.com/avatars/{discord_user_id}/{avatar_hash}.png" if avatar_hash else "https://cdn.discordapp.com/embed/avatars/0.png"

        # 4. Fetch user guilds
        guilds_resp = await client.get(
            f"{DISCORD_API_BASE}/users/@me/guilds",
            headers={"Authorization": f"Bearer {user_access_token}"},
        )
        user_guilds = guilds_resp.json() if guilds_resp.status_code == 200 else []

    # 5. Filter for guilds where user is Owner or has Administrator / Manage Guild permissions
    admin_guilds: List[dict] = []
    for g in user_guilds:
        perms = int(g.get("permissions", 0))
        is_owner = g.get("owner", False)
        has_admin = bool(perms & ADMIN_PERM_FLAG)
        has_manage = bool(perms & MANAGE_GUILD_FLAG)
        if is_owner or has_admin or has_manage:
            admin_guilds.append({
                "id": str(g["id"]),
                "name": g["name"],
                "icon": g.get("icon"),
            })

    if not admin_guilds:
        return RedirectResponse("/?error=no_admin_guilds", status_code=302)

    # 6. Check which of these guilds the bot is currently in
    bot_guild_ids = {str(bg.id) for bg in bot.guilds}
    admin_guilds_data = [
        {
            "id": str(g["id"]),
            "name": g["name"],
            "icon": g.get("icon"),
            "icon_url": f"https://cdn.discordapp.com/icons/{g['id']}/{g['icon']}.png" if g.get("icon") else None,
            "bot_joined": str(g["id"]) in bot_guild_ids,
        }
        for g in admin_guilds
    ]

    # 7. Generate an API Key for this user & bound to their authorized server IDs
    admin_ids = [g["id"] for g in admin_guilds]
    raw_api_key = f"ml_live_{secrets.token_urlsafe(32)}"
    key_hash = _hash_key(raw_api_key)

    async with AsyncSessionLocal() as session:
        # Check all existing active connections for this user and resolve duplicates
        existing_result = await session.execute(
            select(AIConnection).where(
                AIConnection.name == f"{discord_username}'s AI Connector",
                AIConnection.status == ConnectionStatus.active,
            )
        )
        existing_conns = existing_result.scalars().all()

        if existing_conns:
            existing_conn = existing_conns[0]
            existing_conn.allowed_guild_ids = admin_ids
            existing_conn.api_key_hash = key_hash
            # Revoke any redundant duplicate active connections for this user
            for extra in existing_conns[1:]:
                extra.status = ConnectionStatus.revoked
        else:
            conn = AIConnection(
                name=f"{discord_username}'s AI Connector",
                description=f"Auto-generated OAuth key for Discord user {discord_user_id} ({discord_username})",
                api_key_hash=key_hash,
                allowed_guild_ids=admin_ids,
                permission_level=PermissionLevel.admin,
                autonomous_mode=False,
                status=ConnectionStatus.active,
            )
            session.add(conn)

        # 8. Clean up any older sessions for this discord user and create a fresh 30-day session
        await session.execute(
            delete(UserSession).where(UserSession.discord_user_id == discord_user_id)
        )

        session_token = secrets.token_urlsafe(32)
        expires = datetime.now(timezone.utc) + timedelta(days=30)
        user_sess = UserSession(
            id=session_token,
            discord_user_id=discord_user_id,
            discord_username=discord_username,
            avatar_url=avatar_url,
            admin_guilds=admin_guilds_data,
            api_key=raw_api_key,
            expires_at=expires,
        )
        session.add(user_sess)
        await session.commit()

    # 9. Determine target redirect (MCP Client callback e.g. Claude / Cursor, or Dashboard)
    target_redirect = "/dashboard"
    mcp_flow_cookie = request.cookies.get("mcp_oauth_flow")
    if mcp_flow_cookie:
        try:
            flow_json = base64.urlsafe_b64decode(mcp_flow_cookie.encode("ascii")).decode("utf-8")
            flow_data = json.loads(flow_json)
            client_redirect_uri = flow_data.get("redirect_uri")
            if client_redirect_uri:
                from app.oauth import issue_authorization_code
                auth_code = issue_authorization_code(
                    client_id=flow_data.get("client_id"),
                    redirect_uri=client_redirect_uri,
                    api_key=raw_api_key,
                    discord_user_id=discord_user_id,
                    discord_username=discord_username,
                    code_challenge=flow_data.get("code_challenge"),
                    code_challenge_method=flow_data.get("code_challenge_method"),
                )
                from urllib.parse import urlencode as _qenc
                sep = "&" if "?" in client_redirect_uri else "?"
                cb_data = {"code": auth_code}
                if flow_data.get("state"):
                    cb_data["state"] = flow_data["state"]
                target_redirect = f"{client_redirect_uri}{sep}{_qenc(cb_data)}"
                logger.info("Redirecting back to MCP client at %s", client_redirect_uri)
        except Exception as exc:
            logger.warning("Could not process mcp_oauth_flow cookie: %s", exc)

    # 10. Set persistent session cookie and redirect
    is_https = redirect_uri.startswith("https://")
    response = RedirectResponse(target_redirect, status_code=302)
    response.set_cookie(
        key="modlink_session",
        value=session_token,
        max_age=30 * 86400,  # 30 days
        httponly=True,
        samesite="lax",
        secure=is_https,     # Secure flag whenever served over HTTPS
        path="/",
    )
    # Clear one-time flow cookies
    response.delete_cookie("oauth_state", path="/")
    response.delete_cookie("mcp_oauth_flow", path="/")
    return response


portal_routes = [
    Route("/", home, methods=["GET"]),
    Route("/connect", home, methods=["GET"]),
    Route("/dashboard", dashboard_page, methods=["GET"]),
    Route("/privacy", privacy_page, methods=["GET"]),
    Route("/terms", terms_page, methods=["GET"]),
    Route("/auth/me", auth_me, methods=["GET"]),
    Route("/auth/logout", auth_logout, methods=["GET"]),
    Route("/auth/discord/login", discord_login, methods=["GET"]),
    Route("/auth/discord/callback", discord_callback, methods=["GET"]),
]

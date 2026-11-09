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


def _get_bot_invite_url(guild_id: Optional[str] = None) -> str:
    """Generate the Discord Bot invite URL with required administrator permissions."""
    client_id = settings.discord_client_id or (str(bot.user.id) if bot.user else "")
    if not client_id:
        return "https://discord.com/developers/applications"
    perms = 8  # Administrator permission integer
    url = f"https://discord.com/oauth2/authorize?client_id={client_id}&permissions={perms}&scope=bot%20applications.commands"
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
    client_id = settings.discord_client_id or (str(bot.user.id) if bot.user else "")
    if not client_id:
        return HTMLResponse("<h3>Error: DISCORD_CLIENT_ID is not configured in .env</h3>", status_code=500)

    redirect_uri = _clean_url(settings.discord_redirect_uri or f"{base}/auth/discord/callback")

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
    response.set_cookie("oauth_state", state, httponly=True, max_age=600)
    return response


async def discord_callback(request: Request) -> RedirectResponse | HTMLResponse:
    """Handle Discord OAuth callback, verify user & guilds, issue API key, and set 30-day session cookie."""
    code = request.query_params.get("code")
    error = request.query_params.get("error")
    base = _get_public_base(request)

    if error or not code:
        return RedirectResponse(f"/?error={error or 'no_code'}", status_code=302)

    client_id = settings.discord_client_id or (str(bot.user.id) if bot.user else "")
    client_secret = settings.discord_client_secret
    redirect_uri = _clean_url(settings.discord_redirect_uri or f"{base}/auth/discord/callback")

    if not client_secret:
        return HTMLResponse("<h3>Error: DISCORD_CLIENT_SECRET is not configured in environment</h3>", status_code=500)

    # 1. Exchange OAuth code for access token
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
            logger.error("Discord token exchange failed: %s", token_resp.text)
            return RedirectResponse("/?error=token_exchange_failed", status_code=302)

        token_data = token_resp.json()
        user_access_token = token_data["access_token"]

        # 2. Fetch user profile
        user_resp = await client.get(
            f"{DISCORD_API_BASE}/users/@me",
            headers={"Authorization": f"Bearer {user_access_token}"},
        )
        user_data = user_resp.json()
        discord_username = f"{user_data.get('username')}#{user_data.get('discriminator', '0')}".rstrip("#0")
        discord_user_id = str(user_data["id"])
        avatar_hash = user_data.get("avatar")
        avatar_url = f"https://cdn.discordapp.com/avatars/{discord_user_id}/{avatar_hash}.png" if avatar_hash else "https://cdn.discordapp.com/embed/avatars/0.png"

        # 3. Fetch user guilds
        guilds_resp = await client.get(
            f"{DISCORD_API_BASE}/users/@me/guilds",
            headers={"Authorization": f"Bearer {user_access_token}"},
        )
        user_guilds = guilds_resp.json() if guilds_resp.status_code == 200 else []

    # 4. Filter for guilds where user is Owner or has Administrator / Manage Guild permissions
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

    # 5. Check which of these guilds the bot is currently in
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

    # 6. Generate an API Key for this user & bound to their authorized server IDs
    admin_ids = [g["id"] for g in admin_guilds]
    raw_api_key = f"ml_live_{secrets.token_urlsafe(32)}"
    key_hash = _hash_key(raw_api_key)

    async with AsyncSessionLocal() as session:
        # Check if user already has an active connection
        existing = await session.execute(
            select(AIConnection).where(
                AIConnection.name == f"{discord_username}'s AI Connector",
                AIConnection.status == ConnectionStatus.active,
            )
        )
        existing_conn = existing.scalar_one_or_none()

        if existing_conn:
            existing_conn.allowed_guild_ids = admin_ids
            existing_conn.api_key_hash = key_hash
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

        # 7. Create or update persistent 30-day session
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

    # 8. Set persistent session cookie and redirect directly to /dashboard
    response = RedirectResponse("/dashboard", status_code=302)
    response.set_cookie(
        key="modlink_session",
        value=session_token,
        max_age=30 * 86400,  # 30 days
        httponly=True,
        samesite="lax",
        path="/",
    )
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

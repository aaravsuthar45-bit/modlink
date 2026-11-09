"""
app/portal.py — Web portal for Discord OAuth login & automatic MCP key generation.

Allows server owners to:
1. Log in with their Discord account.
2. Automatically verify their server ownership / admin permissions.
3. Automatically generate an isolated ModLink MCP key bound ONLY to their server.
4. One-click copy connection settings for Claude / MCP clients.
"""
from __future__ import annotations

import logging
from pathlib import Path
import re
import secrets
from typing import Dict, List, Optional
from urllib.parse import urlencode

import discord
import httpx
from starlette.requests import Request
from starlette.responses import HTMLResponse, RedirectResponse
from starlette.routing import Route

from app.auth import _hash_key
from app.config import settings
from app.database import (
    AIConnection,
    AsyncSessionLocal,
    ConnectionStatus,
    PermissionLevel,
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


def _get_bot_invite_url() -> str:
    """Generate the Discord Bot invite URL with required administrator permissions."""
    client_id = settings.discord_client_id or (str(bot.user.id) if bot.user else "")
    if not client_id:
        return "https://discord.com/developers/applications"
    perms = 8  # Administrator permission integer
    return f"https://discord.com/oauth2/authorize?client_id={client_id}&permissions={perms}&scope=bot%20applications.commands"


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
    # Replace {base} with empty string for root-relative paths, and set invite_url
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


async def discord_callback(request: Request) -> HTMLResponse:
    """Handle Discord OAuth callback, verify user & guilds, and issue API key."""
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
    connected_guilds = [g for g in admin_guilds if g["id"] in bot_guild_ids]
    missing_bot_guilds = [g for g in admin_guilds if g["id"] not in bot_guild_ids]

    invite_url = _get_bot_invite_url()

    if not connected_guilds:
        # User has admin on some servers, but the bot hasn't been invited to any of them yet
        missing_list_html = "".join([f"<li><strong>{g['name']}</strong> <span style='color:var(--muted)'>ID: {g['id']}</span></li>" for g in missing_bot_guilds[:5]])
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Bot Not Joined — ModLink</title>
<link rel="icon" href="/static/favicon.png" type="image/png">
<link href="https://fonts.googleapis.com/css2?family=Archivo:wght@400;500;600;800;900&display=swap" rel="stylesheet">
<link rel="stylesheet" href="/static/modlink.css">
<script src="/static/modlink.js" defer></script>
</head>
<body>
<header class="site"><div class="wrap bar">
<a class="brand" href="/" aria-label="ModLink home"><img class="brand-logo" src="/static/logo.png" alt="ModLink Logo">ModLink</a>
<nav class="nav-links"><a href="/">Home</a><a href="/dashboard">Dashboard</a></nav>
</div></header>
<main id="main"><div class="wrap" style="padding:48px 24px; max-width:680px;">
<div class="box">
<h2><i data-i="alert"></i> Bot is not in your server yet</h2>
<p style="margin:16px 0; color:var(--body)">Hi <strong>{discord_username}</strong>! We verified your administrator permissions, but the ModLink bot has not been added to your server(s) yet:</p>
<ul style="background:var(--paper); border:2px solid var(--ink); padding:16px 24px; margin-bottom:24px; line-height:1.8;">{missing_list_html}</ul>
<p style="margin-bottom:24px; color:var(--muted)">Invite the bot to your server first, then refresh this page or log in again to generate your private AI key.</p>
<div style="display:flex; gap:16px; flex-wrap:wrap;">
<a href="{invite_url}" target="_blank" class="btn btn-primary"><i data-i="plus"></i>Invite Bot to Server</a>
<a href="/auth/discord/login" class="btn btn-outline">Check Again</a>
</div>
</div>
</div></main>
<footer class="site"><div class="wrap"><p class="legal">&copy; <span data-year>2026</span> ModLink. All rights reserved.</p></div></footer>
</body></html>"""
        return HTMLResponse(html)

    # 6. Generate an API Key for this user & bound to their authorized server IDs
    allowed_ids = [g["id"] for g in connected_guilds]
    raw_api_key = f"ml_live_{secrets.token_urlsafe(32)}"
    key_hash = _hash_key(raw_api_key)

    async with AsyncSessionLocal() as session:
        conn = AIConnection(
            name=f"{discord_username}'s AI Connector",
            description=f"Auto-generated OAuth key for Discord user {discord_user_id} ({discord_username})",
            api_key_hash=key_hash,
            allowed_guild_ids=allowed_ids,
            permission_level=PermissionLevel.admin,
            autonomous_mode=False,
            status=ConnectionStatus.active,
        )
        session.add(conn)
        await session.commit()

    mcp_endpoint = f"{base}/mcp"
    servers_html = "".join([f"<span class='pill green' style='padding:4px 10px; font-size:13px; font-weight:600;'>🛡️ {g['name']}</span>" for g in connected_guilds])

    claude_desktop_json = f"""{{
  "mcpServers": {{
    "modlink": {{
      "command": "npx",
      "args": [
        "-y",
        "mcp-remote",
        "{mcp_endpoint}",
        "--header",
        "x-api-key: {raw_api_key}"
      ]
    }}
  }}
}}"""

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Connected — ModLink MCP</title>
<link rel="icon" href="/static/favicon.png" type="image/png">
<link href="https://fonts.googleapis.com/css2?family=Archivo:wght@400;500;600;800;900&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
<link rel="stylesheet" href="/static/modlink.css">
<script src="/static/modlink.js" defer></script>
<style>
.key-box {{
    background: var(--paper);
    border: 2px solid var(--ink);
    padding: 16px;
    margin: 16px 0;
}}
.key-title {{
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: 0.8px;
    font-weight: 800;
    color: var(--muted);
    margin-bottom: 8px;
}}
.code-block {{
    font-family: 'JetBrains Mono', monospace;
    font-size: 13px;
    background: var(--concrete);
    padding: 12px;
    border: 1px solid var(--line);
    word-break: break-all;
    white-space: pre-wrap;
    color: var(--ink);
}}
</style>
</head>
<body>
<header class="site"><div class="wrap bar">
<a class="brand" href="/" aria-label="ModLink home"><img class="brand-logo" src="/static/logo.png" alt="ModLink Logo">ModLink</a>
<nav class="nav-links"><a href="/">Home</a><a href="/dashboard">Dashboard</a><a href="/privacy">Privacy</a><a href="/terms">Terms</a></nav>
</div></header>

<main id="main"><div class="wrap" style="padding:48px 24px; max-width:760px;">
<div class="panel">
<div style="display:flex; align-items:center; gap:16px; margin-bottom:24px;">
    <img src="{avatar_url}" style="width:56px; height:56px; border:2px solid var(--ink);" alt="Avatar">
    <div>
        <h1 style="font-size:1.75rem; font-weight:900;">Welcome, {discord_username}!</h1>
        <span class="pill green">✓ Authorized Administrator</span>
    </div>
</div>

<p style="color:var(--body); margin-bottom:16px;">
    Your dedicated AI connection key has been generated. It is cryptographically isolated and permitted to moderate only your authorized server(s):
</p>

<div style="display:flex; gap:8px; flex-wrap:wrap; margin-bottom:24px;">
    {servers_html}
</div>

<!-- MCP URL -->
<div class="key-box">
    <div class="key-title">MCP Endpoint URL</div>
    <div class="code-block" id="mcp-url">{mcp_endpoint}</div>
    <button class="btn btn-outline btn-sm" style="margin-top:10px;" onclick="navigator.clipboard.writeText(document.getElementById('mcp-url').innerText); this.innerText='Copied!';">Copy URL</button>
</div>

<!-- API Key -->
<div class="key-box">
    <div class="key-title">Your Private API Key (x-api-key)</div>
    <div class="code-block" id="api-key">{raw_api_key}</div>
    <button class="btn btn-outline btn-sm" style="margin-top:10px;" onclick="navigator.clipboard.writeText(document.getElementById('api-key').innerText); this.innerText='Copied!';">Copy Key</button>
</div>

<!-- Claude Desktop JSON -->
<div class="key-box">
    <div class="key-title">Claude Desktop Configuration (claude_desktop_config.json)</div>
    <div class="code-block" id="claude-json">{claude_desktop_json}</div>
    <button class="btn btn-primary btn-sm" style="margin-top:10px;" onclick="navigator.clipboard.writeText(document.getElementById('claude-json').innerText); this.innerText='Copied!';">Copy Config</button>
</div>

<div class="notice ok" style="margin-top:24px;">
    <i></i><span><strong>Security Note:</strong> Please copy and save your API key now. It is stored as a secure hash in the database and will not be displayed again.</span>
</div>

<div style="margin-top:24px; text-align:center;">
    <a href="/dashboard" class="btn btn-dark">Open ModLink Dashboard &rarr;</a>
</div>
</div>
</div></main>

<footer class="site"><div class="wrap"><p class="legal">&copy; <span data-year>2026</span> ModLink. All rights reserved. ModLink is not affiliated with or endorsed by Discord Inc.</p></div></footer>
</body></html>"""
    return HTMLResponse(html)


portal_routes = [
    Route("/", home, methods=["GET"]),
    Route("/connect", home, methods=["GET"]),
    Route("/dashboard", dashboard_page, methods=["GET"]),
    Route("/privacy", privacy_page, methods=["GET"]),
    Route("/terms", terms_page, methods=["GET"]),
    Route("/auth/discord/login", discord_login, methods=["GET"]),
    Route("/auth/discord/callback", discord_callback, methods=["GET"]),
]

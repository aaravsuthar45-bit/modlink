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
import re
import secrets
from typing import Dict, List, Optional
from urllib.parse import urlencode

import discord
import httpx
from starlette.requests import Request
from starlette.responses import HTMLResponse, RedirectResponse
from starlette.routing import Route
from sqlalchemy import select

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


def _clean_url(url: str) -> str:
    """Normalize URL and fix any accidental .onrender.co or duplicated .onrender.commm."""
    return re.sub(r"\.onrender\.co(?:m+)?(?=/|$)", ".onrender.com", url).rstrip("/")


def _get_public_base(request: Request) -> str:
    """Return the base URL of this server (handling ngrok / Render proxies)."""
    if settings.mcp_public_url and "yourdomain.com" not in settings.mcp_public_url and "localhost" not in settings.mcp_public_url:
        base = settings.mcp_public_url.rstrip("/mcp")
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


# ── Route handlers ────────────────────────────────────────────────────────────

async def home(request: Request) -> HTMLResponse:
    """Landing page with login button & bot invite."""
    base = _get_public_base(request)
    invite_url = _get_bot_invite_url()
    
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ModLink — AI Discord Moderation Gateway</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap" rel="stylesheet">
    <style>
        :root {{
            --bg: #0f1117;
            --surface: #1a1d26;
            --surface-hover: #232734;
            --primary: #5865f2;
            --primary-hover: #4752c4;
            --text: #f0f2f5;
            --text-muted: #9ba1b0;
            --border: #2a2e3d;
            --success: #3ba55d;
        }}
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: 'Inter', -apple-system, sans-serif;
            background-color: var(--bg);
            color: var(--text);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 24px;
        }}
        .card {{
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 16px;
            max-width: 580px;
            width: 100%;
            padding: 40px;
            box-shadow: 0 20px 40px rgba(0,0,0,0.4);
            text-align: center;
        }}
        .logo {{
            width: 72px;
            height: 72px;
            background: linear-gradient(135deg, #5865f2, #8547f2);
            border-radius: 20px;
            display: inline-flex;
            align-items: center;
            justify-content: center;
            font-size: 36px;
            margin-bottom: 24px;
        }}
        h1 {{ font-size: 28px; font-weight: 800; margin-bottom: 12px; letter-spacing: -0.5px; }}
        p.subtitle {{ color: var(--text-muted); font-size: 15px; line-height: 1.6; margin-bottom: 32px; }}
        .btn {{
            display: inline-flex;
            align-items: center;
            justify-content: center;
            gap: 12px;
            width: 100%;
            padding: 14px 24px;
            border-radius: 10px;
            font-size: 15px;
            font-weight: 600;
            text-decoration: none;
            cursor: pointer;
            transition: all 0.2s;
            border: none;
        }}
        .btn-discord {{
            background: var(--primary);
            color: #fff;
            margin-bottom: 12px;
        }}
        .btn-discord:hover {{ background: var(--primary-hover); transform: translateY(-1px); }}
        .btn-secondary {{
            background: transparent;
            color: var(--text);
            border: 1px solid var(--border);
        }}
        .btn-secondary:hover {{ background: var(--surface-hover); }}
        .steps {{
            margin-top: 36px;
            padding-top: 28px;
            border-top: 1px solid var(--border);
            text-align: left;
        }}
        .steps h3 {{ font-size: 13px; text-transform: uppercase; letter-spacing: 1px; color: var(--text-muted); margin-bottom: 16px; }}
        .step-item {{ display: flex; gap: 14px; margin-bottom: 14px; font-size: 14px; color: var(--text-muted); }}
        .step-num {{
            background: var(--surface-hover);
            color: var(--primary);
            width: 24px;
            height: 24px;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            font-weight: 700;
            font-size: 12px;
            flex-shrink: 0;
        }}
        .badge {{
            display: inline-block;
            background: rgba(88, 101, 242, 0.15);
            color: #7983f5;
            padding: 4px 10px;
            border-radius: 20px;
            font-size: 12px;
            font-weight: 600;
            margin-bottom: 16px;
        }}
    </style>
</head>
<body>
    <div class="card">
        <div class="logo">⚡</div>
        <div><span class="badge">ModLink MCP Gateway</span></div>
        <h1>Connect Your Discord Server</h1>
        <p class="subtitle">
            Authorize your Discord account to securely generate an AI connection key for Claude or ChatGPT.
            Only servers where you have administrative access will be controllable.
        </p>

        <a href="{base}/auth/discord/login" class="btn btn-discord">
            <svg width="22" height="17" viewBox="0 0 127.14 96.36" fill="currentColor">
                <path d="M107.7,8.07A105.15,105.15,0,0,0,81.47,0a72.06,72.06,0,0,0-3.36,6.83A97.68,97.68,0,0,0,49,6.83,72.37,72.37,0,0,0,45.64,0,105.89,105.89,0,0,0,19.39,8.09C2.79,32.65-1.71,56.6.54,80.21h0A105.73,105.73,0,0,0,32.71,96.36,77.7,77.7,0,0,0,39.6,85.25a68.42,68.42,0,0,1-10.85-5.18c.91-.66,1.8-1.34,2.66-2a75.57,75.57,0,0,0,64.32,0c.87.71,1.76,1.39,2.66,2a68.68,68.68,0,0,1-10.87,5.19,77,77,0,0,0,6.89,11.1A105.25,105.25,0,0,0,126.6,80.22h0C129.24,52.84,122.09,29.11,107.7,8.07ZM42.45,65.69C36.18,65.69,31,60,31,53s5-12.74,11.43-12.74S54,45.91,53.89,53,48.84,65.69,42.45,65.69Zm42.24,0C78.41,65.69,73.25,60,73.25,53s5-12.74,11.44-12.74S96.23,45.91,96.12,53,91.08,65.69,84.69,65.69Z"/>
            </svg>
            Log in with Discord
        </a>

        <a href="{invite_url}" target="_blank" rel="noopener noreferrer" class="btn btn-secondary">
            ➕ First, invite Bot to your Server
        </a>

        <div class="steps">
            <h3>How it works</h3>
            <div class="step-item">
                <span class="step-num">1</span>
                <span>Invite the bot to your Discord server with Administrator permission.</span>
            </div>
            <div class="step-item">
                <span class="step-num">2</span>
                <span>Log in with Discord to verify your server ownership or admin permissions.</span>
            </div>
            <div class="step-item">
                <span class="step-num">3</span>
                <span>Get your private MCP endpoint and token locked strictly to your servers.</span>
            </div>
        </div>
    </div>
</body>
</html>"""
    return HTMLResponse(html)


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
        return HTMLResponse(f"<h3>Authentication canceled or failed: {error or 'No code provided'}</h3><p><a href='{base}'>Try again</a></p>", status_code=400)
    
    client_id = settings.discord_client_id or (str(bot.user.id) if bot.user else "")
    client_secret = settings.discord_client_secret
    redirect_uri = _clean_url(settings.discord_redirect_uri or f"{base}/auth/discord/callback")
    
    if not client_secret:
        return HTMLResponse("<h3>Error: DISCORD_CLIENT_SECRET is not configured in .env</h3>", status_code=500)
    
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
            return HTMLResponse(f"<h3>Failed to retrieve token from Discord</h3><pre>{token_resp.text}</pre>", status_code=400)
        
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

    # 5. Check which of these guilds the bot is currently in
    bot_guild_ids = {str(bg.id) for bg in bot.guilds}
    connected_guilds = [g for g in admin_guilds if g["id"] in bot_guild_ids]
    missing_bot_guilds = [g for g in admin_guilds if g["id"] not in bot_guild_ids]

    invite_url = _get_bot_invite_url()

    if not connected_guilds:
        # User has admin on some servers, but the bot hasn't been invited to any of them yet
        missing_list_html = "".join([f"<li><strong>{g['name']}</strong> (ID: {g['id']})</li>" for g in missing_bot_guilds[:5]])
        html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Bot Not Joined — ModLink</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700&display=swap" rel="stylesheet">
    <style>
        body {{ font-family: 'Inter', sans-serif; background: #0f1117; color: #f0f2f5; display: flex; align-items: center; justify-content: center; min-height: 100vh; padding: 20px; }}
        .card {{ background: #1a1d26; border: 1px solid #2a2e3d; border-radius: 16px; max-width: 540px; width: 100%; padding: 36px; text-align: center; }}
        h2 {{ margin-bottom: 12px; }}
        p {{ color: #9ba1b0; font-size: 15px; margin-bottom: 20px; line-height: 1.5; }}
        ul {{ text-align: left; background: #232734; padding: 16px 24px; border-radius: 10px; margin-bottom: 24px; color: #d1d5db; }}
        .btn {{ display: inline-block; padding: 12px 24px; border-radius: 10px; font-weight: 600; text-decoration: none; background: #5865f2; color: #fff; }}
    </style>
</head>
<body>
    <div class="card">
        <h2>⚠️ Bot is not in your server yet</h2>
        <p>Hi <strong>{discord_username}</strong>! We verified you have Admin permissions on your servers, but our bot is not yet a member in any of them:</p>
        <ul>{missing_list_html or "<li>No administrative servers found.</li>"}</ul>
        <p>Please invite the bot to your server first, then refresh this page to get your AI key!</p>
        <a href="{invite_url}" target="_blank" class="btn">Invite Bot to Your Server</a>
    </div>
</body>
</html>"""
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
    servers_html = "".join([f"<span class='server-pill'>🛡️ {g['name']}</span>" for g in connected_guilds])

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
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Connected — ModLink MCP</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
    <style>
        :root {{
            --bg: #0f1117;
            --surface: #1a1d26;
            --surface-hover: #232734;
            --primary: #5865f2;
            --text: #f0f2f5;
            --text-muted: #9ba1b0;
            --border: #2a2e3d;
            --success: #3ba55d;
        }}
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: 'Inter', sans-serif;
            background: var(--bg);
            color: var(--text);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 24px;
        }}
        .card {{
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 16px;
            max-width: 640px;
            width: 100%;
            padding: 40px;
            box-shadow: 0 20px 40px rgba(0,0,0,0.4);
        }}
        .header {{ display: flex; align-items: center; gap: 16px; margin-bottom: 24px; }}
        .avatar {{ width: 56px; height: 56px; border-radius: 50%; border: 2px solid var(--primary); }}
        .badge-success {{ background: rgba(59, 165, 93, 0.15); color: #4ade80; padding: 4px 10px; border-radius: 20px; font-size: 12px; font-weight: 600; }}
        .server-list {{ margin: 16px 0; display: flex; flex-wrap: wrap; gap: 8px; }}
        .server-pill {{ background: var(--surface-hover); border: 1px solid var(--border); padding: 6px 14px; border-radius: 20px; font-size: 13px; font-weight: 600; }}
        .box {{
            background: #11131a;
            border: 1px solid var(--border);
            border-radius: 10px;
            padding: 16px;
            margin: 16px 0;
            position: relative;
        }}
        .box-label {{ font-size: 11px; text-transform: uppercase; letter-spacing: 0.8px; color: var(--text-muted); margin-bottom: 6px; font-weight: 700; }}
        .code-val {{ font-family: 'JetBrains Mono', monospace; font-size: 13px; word-break: break-all; color: #a5b4fc; }}
        .copy-btn {{
            background: var(--primary);
            color: #fff;
            border: none;
            padding: 6px 12px;
            border-radius: 6px;
            font-size: 12px;
            font-weight: 600;
            cursor: pointer;
            margin-top: 8px;
            transition: all 0.2s;
        }}
        .copy-btn:hover {{ background: #4752c4; }}
        .notice {{ background: rgba(234, 179, 8, 0.1); border: 1px solid rgba(234, 179, 8, 0.2); border-radius: 8px; padding: 12px; font-size: 13px; color: #fef08a; margin-top: 20px; }}
    </style>
</head>
<body>
    <div class="card">
        <div class="header">
            <img src="{avatar_url}" class="avatar" alt="Avatar">
            <div>
                <h2>Welcome, {discord_username}!</h2>
                <span class="badge-success">✓ Authorized Administrator</span>
            </div>
        </div>

        <p style="color: var(--text-muted); font-size: 14px; line-height: 1.5;">
            Your dedicated AI API key has been created. It is cryptographically isolated and permitted to moderate only the following server(s):
        </p>
        
        <div class="server-list">
            {servers_html}
        </div>

        <!-- MCP URL -->
        <div class="box">
            <div class="box-label">MCP Endpoint URL</div>
            <div class="code-val" id="mcp-url">{mcp_endpoint}</div>
            <button class="copy-btn" onclick="navigator.clipboard.writeText(document.getElementById('mcp-url').innerText); this.innerText='Copied!';">Copy URL</button>
        </div>

        <!-- API Key -->
        <div class="box">
            <div class="box-label">Your Private API Key (x-api-key)</div>
            <div class="code-val" id="api-key">{raw_api_key}</div>
            <button class="copy-btn" onclick="navigator.clipboard.writeText(document.getElementById('api-key').innerText); this.innerText='Copied!';">Copy Key</button>
        </div>

        <!-- Claude Desktop JSON -->
        <div class="box">
            <div class="box-label">Claude Desktop Configuration (claude_desktop_config.json)</div>
            <pre class="code-val" id="claude-json" style="white-space: pre-wrap; font-size: 12px;">{claude_desktop_json}</pre>
            <button class="copy-btn" onclick="navigator.clipboard.writeText(document.getElementById('claude-json').innerText); this.innerText='Copied!';">Copy Config</button>
        </div>

        <div class="notice">
            🔒 <strong>Security Note:</strong> Please save your API key now. It is hashed in the database and will not be displayed again.
        </div>
    </div>
</body>
</html>"""
    return HTMLResponse(html)


portal_routes = [
    Route("/", home, methods=["GET"]),
    Route("/connect", home, methods=["GET"]),
    Route("/auth/discord/login", discord_login, methods=["GET"]),
    Route("/auth/discord/callback", discord_callback, methods=["GET"]),
]

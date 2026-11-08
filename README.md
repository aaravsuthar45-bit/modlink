# ModLink MCP

**AI-Accessible Discord Moderation Platform**

One installation. Any MCP-compatible AI client. Multiple Discord servers.
Moderation through natural language, with safe permission boundaries and a full audit trail.

---

## Architecture

```
AI Clients (Claude, ChatGPT, Gemini, Cursor, …)
        │  Streamable HTTP + Bearer Token
        ▼
ModLink MCP Gateway  (port 8000)
  ├─ Authentication & authorization
  ├─ Server isolation (per-connection guild allowlists)
  ├─ Tool registry & dispatch
  ├─ Permission enforcement
  ├─ Approval workflow (for risky actions)
  └─ Audit log
        │
        ├─── Discord Bot (discord.py Gateway connection)
        ├─── AutoMod Engine
        ├─── Dashboard API  (port 8080)
        └─── PostgreSQL / SQLite
```

## Quick Start (Local / Dev)

### 1. Create a Discord bot

1. Go to [Discord Developer Portal](https://discord.com/developers/applications)
2. Create an application → **Bot** section → **Reset Token**
3. Enable **Server Members Intent** and **Message Content Intent**
4. Invite the bot to your server with these permissions:
   - View Channels, Read Message History, Manage Messages, Moderate Members, Send Messages

### 2. Set up Python environment

```bash
cd modlink-mcp
python -m venv .venv

# Windows
.venv\Scripts\activate
# Linux / macOS
source .venv/bin/activate

pip install -r requirements.txt
```

### 3. Configure `.env`

```bash
cp .env.example .env
# Edit .env — set DISCORD_TOKEN and DASHBOARD_SECRET at minimum
```

### 4. Start the MCP Gateway (includes Discord bot)

```bash
python -m app.mcp_server
# MCP endpoint: http://localhost:8000/mcp
# Health check:  http://localhost:8000/health
```

### 5. Start the Dashboard (separate terminal)

```bash
uvicorn app.dashboard:app --host 127.0.0.1 --port 8080
# Dashboard: http://localhost:8080
```

### 6. Create your first AI connection

```bash
python scripts/create_connection.py \
    --name "Claude Desktop" \
    --guilds YOUR_GUILD_ID \
    --permission moderate
```

Copy the printed API key. Use it in your MCP client:

```
Authorization: Bearer <api_key>
```

---

## MCP Tools

| Tool | Permission | Description |
|---|---|---|
| `list_authorized_servers` | read | List all guilds this connection can access |
| `get_server_info` | read | Detailed info about a guild |
| `read_recent_messages` | read | Fetch messages from a text channel |
| `timeout_member` | moderate | Silence a member (capped by guild config) |
| `delete_message` | moderate | Remove a specific message |
| `kick_member` | manage | Kick a member (may need approval) |
| `ban_member` | admin | Ban a member (**always requires approval** by default) |
| `create_custom_announcement` | moderate | Send rich embed to a channel |
| `list_channels` | read | List all text channels |
| `list_roles` | read | List all roles |

## Permission Levels

| Level | What it grants |
|---|---|
| `read` | Inspect servers, channels, messages |
| `moderate` | Timeout members, delete messages, announcements |
| `manage` | Kick members, change nicknames |
| `admin` | Ban members (still subject to approval policy) |

## AutoMod Detectors

| Detector | Trigger |
|---|---|
| Spam / flood | ≥6 messages in 12 seconds (configurable per guild) |
| Repeated content | Same message 3+ times in window |
| Mention spam | >5 @mentions in one message |
| Suspicious links | Phishing / scam domain patterns |

All AutoMod actions are written to the audit log.

## Production Deployment

```bash
# Copy and fill .env (use PostgreSQL DATABASE_URL)
cp .env.example .env

# Start all services (without Caddy for now)
docker compose up -d --build

# Start with Caddy reverse proxy + TLS
docker compose --profile production up -d --build
```

Edit `Caddyfile` with your actual domain names before running with the `production` profile.

## Security Notes

- **Never expose port 8000 directly** without authentication.
- **Audience validation** is enforced: OIDC tokens must include `MCP_PUBLIC_URL` in `aud`.
- **Bans always require human approval** by default — change `ban_requires_approval=false` in the guild config only after deliberate review.
- **Mass actions** (bulk delete, mass kick) are intentionally not exposed.
- **Bot permissions** cannot be changed through MCP tools.
- API keys are **hashed with HMAC-SHA256** and never stored in plaintext.

## Adding Custom Tools

Edit [`app/custom_tools.py`](app/custom_tools.py) and use the `@custom_tool` decorator:

```python
from app.custom_tools import custom_tool
from app.database import PermissionLevel

@custom_tool(
    name="my_tool",
    description="Does something useful.",
    required_permission=PermissionLevel.moderate,
)
async def my_tool(guild_id: str, channel_id: str, message: str) -> dict:
    # your logic here
    return {"status": "done"}
```

The tool is auto-registered and will appear in `list_tools()` on next restart.

## Roadmap

- [ ] Full graphical dashboard (React / Vue)
- [ ] AI connection OAuth onboarding flow  
- [ ] Advanced AutoMod (ML-based spam, raid detection)
- [ ] Redis-backed distributed rate limiting
- [ ] Celery background jobs (scheduled reports, cleanup)
- [ ] Custom tool builder UI
- [ ] Multi-region deployment support

---

*ModLink MCP is a foundation. Test in a private server before production use.*

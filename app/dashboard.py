"""
app/dashboard.py — ModLink web dashboard (FastAPI)

Endpoints
─────────
GET  /              → Status / home page (HTML)
GET  /api/status    → JSON system status
GET  /api/connections       → List AI connections
POST /api/connections       → Create AI connection
DELETE /api/connections/{id} → Revoke AI connection
GET  /api/audit             → Recent audit log
GET  /api/pending           → Pending approval requests
POST /api/pending/{id}/approve  → Approve a pending action
POST /api/pending/{id}/reject   → Reject a pending action
GET  /api/guilds            → List monitored guilds
GET  /api/guilds/{guild_id}/config  → Get guild config
PATCH /api/guilds/{guild_id}/config → Update guild config

Authentication: Bearer token in Authorization header matching DASHBOARD_SECRET.
"""
from __future__ import annotations

import hashlib
import hmac
import logging
import secrets
import uuid
from datetime import datetime, timezone
from typing import List, Optional

from fastapi import Depends, FastAPI, HTTPException, Request, Security
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel
from sqlalchemy import desc, select, update

from app.config import settings
from app.database import (
    AIConnection,
    AuditLog,
    AuditResult,
    AsyncSessionLocal,
    ConnectionStatus,
    GuildConfig,
    PermissionLevel,
    PendingApproval,
    get_db,
    init_db,
)

from contextlib import asynccontextmanager

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    yield


app = FastAPI(
    title="ModLink MCP Dashboard",
    description="Manage AI connections, permissions, and moderation history.",
    version="1.0.0",
    lifespan=lifespan,
)

bearer_scheme = HTTPBearer(auto_error=False)


# ── Dashboard auth dependency ─────────────────────────────────────────────────

def _require_dashboard_auth(
    credentials: Optional[HTTPAuthorizationCredentials] = Security(bearer_scheme),
) -> None:
    if credentials is None or not hmac.compare_digest(
        credentials.credentials, settings.dashboard_secret
    ):
        raise HTTPException(status_code=401, detail="Invalid dashboard token.")


DashboardAuth = Depends(_require_dashboard_auth)


# ── Schemas ───────────────────────────────────────────────────────────────────

class ConnectionCreate(BaseModel):
    name: str
    description: Optional[str] = None
    allowed_guild_ids: List[str] = []
    permission_level: PermissionLevel = PermissionLevel.read
    autonomous_mode: bool = False


class GuildConfigUpdate(BaseModel):
    automod_enabled: Optional[bool] = None
    spam_message_threshold: Optional[int] = None
    spam_window_seconds: Optional[int] = None
    max_timeout_minutes: Optional[int] = None
    ban_requires_approval: Optional[bool] = None
    kick_requires_approval: Optional[bool] = None
    automod_exempt_role_ids: Optional[List[str]] = None


# ── Helpers ───────────────────────────────────────────────────────────────────

def _hash_key(raw: str) -> str:
    return hmac.new(
        settings.dashboard_secret.encode(), raw.encode(), hashlib.sha256
    ).hexdigest()  # hmac.new(key, msg, digestmod)


# ── Routes ────────────────────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse, include_in_schema=False)
async def home() -> str:
    return _DASHBOARD_HTML


@app.get("/api/status")
async def api_status() -> dict:
    """Public status endpoint — no auth required."""
    return {
        "status": "ok",
        "service": "modlink-mcp-dashboard",
        "time": datetime.now(timezone.utc).isoformat(),
        "version": "1.0.0",
    }


# ── AI Connections ────────────────────────────────────────────────────────────

@app.get("/api/connections", dependencies=[DashboardAuth])
async def list_connections() -> dict:
    async with AsyncSessionLocal() as session:
        result = await session.execute(select(AIConnection))
        connections = result.scalars().all()

    return {
        "connections": [
            {
                "id": c.id,
                "name": c.name,
                "description": c.description,
                "allowed_guild_ids": c.allowed_guild_ids,
                "permission_level": c.permission_level.value,
                "autonomous_mode": c.autonomous_mode,
                "status": c.status.value,
                "created_at": c.created_at.isoformat(),
                "last_seen_at": c.last_seen_at.isoformat() if c.last_seen_at else None,
            }
            for c in connections
        ]
    }


@app.post("/api/connections", dependencies=[DashboardAuth], status_code=201)
async def create_connection(body: ConnectionCreate) -> dict:
    raw_key = secrets.token_urlsafe(48)
    key_hash = _hash_key(raw_key)

    conn = AIConnection(
        name=body.name,
        description=body.description,
        api_key_hash=key_hash,
        allowed_guild_ids=body.allowed_guild_ids,
        permission_level=body.permission_level,
        autonomous_mode=body.autonomous_mode,
    )
    async with AsyncSessionLocal() as session:
        session.add(conn)
        await session.commit()
        await session.refresh(conn)

    return {
        "id": conn.id,
        "name": conn.name,
        "api_key": raw_key,  # Only shown ONCE at creation
        "message": "Store this API key securely — it will not be shown again.",
    }


@app.delete("/api/connections/{connection_id}", dependencies=[DashboardAuth])
async def revoke_connection(connection_id: str) -> dict:
    async with AsyncSessionLocal() as session:
        result = await session.execute(
            select(AIConnection).where(AIConnection.id == connection_id)
        )
        conn = result.scalar_one_or_none()
        if conn is None:
            raise HTTPException(status_code=404, detail="Connection not found.")
        conn.status = ConnectionStatus.revoked
        await session.commit()
    return {"status": "revoked", "id": connection_id}


# ── Audit log ─────────────────────────────────────────────────────────────────

@app.get("/api/audit", dependencies=[DashboardAuth])
async def list_audit(limit: int = 50, guild_id: Optional[str] = None) -> dict:
    limit = max(1, min(limit, 500))
    async with AsyncSessionLocal() as session:
        q = select(AuditLog).order_by(desc(AuditLog.created_at)).limit(limit)
        if guild_id:
            q = q.where(AuditLog.guild_id == guild_id)
        result = await session.execute(q)
        logs = result.scalars().all()

    return {
        "logs": [
            {
                "id": log.id,
                "connection_id": log.connection_id,
                "guild_id": log.guild_id,
                "tool_name": log.tool_name,
                "arguments": log.arguments,
                "result": log.result.value,
                "result_detail": log.result_detail,
                "target_user_id": log.target_user_id,
                "created_at": log.created_at.isoformat(),
            }
            for log in logs
        ],
        "returned": len(logs),
    }


# ── Pending approvals ─────────────────────────────────────────────────────────

@app.get("/api/pending", dependencies=[DashboardAuth])
async def list_pending() -> dict:
    now = datetime.now(timezone.utc)
    async with AsyncSessionLocal() as session:
        result = await session.execute(
            select(PendingApproval)
            .where(PendingApproval.approved.is_(None))
            .where(PendingApproval.expires_at > now)
            .order_by(PendingApproval.created_at)
        )
        items = result.scalars().all()

    return {
        "pending": [
            {
                "id": p.id,
                "connection_id": p.connection_id,
                "guild_id": p.guild_id,
                "tool_name": p.tool_name,
                "arguments": p.arguments,
                "reason": p.reason,
                "created_at": p.created_at.isoformat(),
                "expires_at": p.expires_at.isoformat(),
            }
            for p in items
        ]
    }


@app.post("/api/pending/{approval_id}/approve", dependencies=[DashboardAuth])
async def approve_action(approval_id: str) -> dict:
    async with AsyncSessionLocal() as session:
        result = await session.execute(
            select(PendingApproval).where(PendingApproval.id == approval_id)
        )
        pa = result.scalar_one_or_none()
        if pa is None:
            raise HTTPException(404, "Approval request not found.")
        if pa.approved is not None:
            raise HTTPException(409, "Already reviewed.")

        pa.approved = True
        pa.reviewed_at = datetime.now(timezone.utc)
        await session.commit()

    # Execute the action now that it's approved
    try:
        from app.mcp_server import TOOL_HANDLERS
        from app.auth import AccessToken
        # Build a minimal token for execution
        token = AccessToken(
            connection_id=pa.connection_id or "dashboard",
            name="dashboard-approver",
            allowed_guild_ids=[pa.guild_id],
            permission_level=PermissionLevel.admin,
            autonomous_mode=True,
        )
        handler, _ = TOOL_HANDLERS.get(pa.tool_name, (None, None))
        if handler:
            await handler(token=token, **pa.arguments)
    except Exception as exc:
        logger.error("Failed to execute approved action %s: %s", approval_id, exc)
        return {"status": "approved_but_execution_failed", "error": str(exc)}

    return {"status": "approved_and_executed", "id": approval_id}


@app.post("/api/pending/{approval_id}/reject", dependencies=[DashboardAuth])
async def reject_action(approval_id: str) -> dict:
    async with AsyncSessionLocal() as session:
        result = await session.execute(
            select(PendingApproval).where(PendingApproval.id == approval_id)
        )
        pa = result.scalar_one_or_none()
        if pa is None:
            raise HTTPException(404, "Approval request not found.")
        if pa.approved is not None:
            raise HTTPException(409, "Already reviewed.")

        pa.approved = False
        pa.reviewed_at = datetime.now(timezone.utc)
        await session.commit()

    return {"status": "rejected", "id": approval_id}


# ── Guild configs ─────────────────────────────────────────────────────────────

@app.get("/api/guilds", dependencies=[DashboardAuth])
async def list_guilds() -> dict:
    async with AsyncSessionLocal() as session:
        result = await session.execute(select(GuildConfig))
        guilds = result.scalars().all()
    return {
        "guilds": [
            {
                "guild_id": g.guild_id,
                "name": g.name,
                "automod_enabled": g.automod_enabled,
                "spam_threshold": g.spam_message_threshold,
            }
            for g in guilds
        ]
    }


@app.get("/api/guilds/{guild_id}/config", dependencies=[DashboardAuth])
async def get_guild_config(guild_id: str) -> dict:
    async with AsyncSessionLocal() as session:
        result = await session.execute(
            select(GuildConfig).where(GuildConfig.guild_id == guild_id)
        )
        g = result.scalar_one_or_none()
    if g is None:
        raise HTTPException(404, "Guild config not found.")
    return {
        "guild_id": g.guild_id,
        "name": g.name,
        "automod_enabled": g.automod_enabled,
        "spam_message_threshold": g.spam_message_threshold,
        "spam_window_seconds": g.spam_window_seconds,
        "automod_exempt_role_ids": g.automod_exempt_role_ids,
        "max_timeout_minutes": g.max_timeout_minutes,
        "ban_requires_approval": g.ban_requires_approval,
        "kick_requires_approval": g.kick_requires_approval,
    }


@app.patch("/api/guilds/{guild_id}/config", dependencies=[DashboardAuth])
async def update_guild_config(guild_id: str, body: GuildConfigUpdate) -> dict:
    async with AsyncSessionLocal() as session:
        result = await session.execute(
            select(GuildConfig).where(GuildConfig.guild_id == guild_id)
        )
        g = result.scalar_one_or_none()
        if g is None:
            raise HTTPException(404, "Guild config not found.")

        updates = body.model_dump(exclude_none=True)
        for key, val in updates.items():
            setattr(g, key, val)

        await session.commit()
        await session.refresh(g)

    return {"status": "updated", "guild_id": guild_id}


# ── Embedded HTML dashboard ───────────────────────────────────────────────────

_DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>ModLink MCP — Dashboard</title>
<style>
  :root {
    --bg: #1a1b1e; --surface: #25262b; --border: #373a40;
    --accent: #5865f2; --accent-h: #4752c4;
    --text: #c1c2c5; --text-bright: #e5e7eb;
    --green: #2d9e56; --red: #c94040; --yellow: #c9960c;
    --font: 'Segoe UI', system-ui, sans-serif;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { background: var(--bg); color: var(--text); font-family: var(--font);
         min-height: 100vh; display: flex; flex-direction: column; }
  header { background: var(--surface); border-bottom: 1px solid var(--border);
           padding: 16px 32px; display: flex; align-items: center; gap: 12px; }
  header h1 { color: var(--accent); font-size: 1.4rem; font-weight: 700; }
  header .badge { background: var(--accent); color: #fff;
                  border-radius: 4px; padding: 2px 8px; font-size: .75rem; }
  .container { max-width: 1100px; margin: 0 auto; padding: 32px 24px; width: 100%; flex: 1; }
  .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 16px; margin-bottom: 32px; }
  .card { background: var(--surface); border: 1px solid var(--border);
          border-radius: 10px; padding: 20px; }
  .card h3 { color: var(--text-bright); margin-bottom: 4px; font-size: 1rem; }
  .card .value { font-size: 2rem; font-weight: 700; color: var(--accent); }
  .card .label { font-size: .78rem; color: var(--text); margin-top: 4px; }
  section { margin-bottom: 36px; }
  section h2 { color: var(--text-bright); font-size: 1.1rem; margin-bottom: 14px;
               padding-bottom: 8px; border-bottom: 1px solid var(--border); }
  .token-input { display: flex; gap: 8px; margin-bottom: 16px; }
  .token-input input { flex: 1; background: var(--surface); border: 1px solid var(--border);
                       border-radius: 6px; padding: 8px 12px; color: var(--text-bright);
                       font-size: .9rem; }
  .token-input input:focus { outline: 2px solid var(--accent); }
  button { background: var(--accent); color: #fff; border: none;
           border-radius: 6px; padding: 8px 18px; cursor: pointer;
           font-size: .9rem; transition: background .15s; }
  button:hover { background: var(--accent-h); }
  button.danger { background: var(--red); }
  button.secondary { background: var(--surface); border: 1px solid var(--border); color: var(--text); }
  table { width: 100%; border-collapse: collapse; font-size: .875rem; }
  th { text-align: left; padding: 8px 12px; color: var(--text);
       background: var(--surface); border-bottom: 2px solid var(--border); }
  td { padding: 9px 12px; border-bottom: 1px solid var(--border); vertical-align: top; }
  tr:hover td { background: rgba(88,101,242,.06); }
  .pill { display: inline-block; border-radius: 100px; padding: 2px 10px;
          font-size: .72rem; font-weight: 600; }
  .pill.green { background: rgba(45,158,86,.2); color: #2d9e56; }
  .pill.red   { background: rgba(201,64,64,.2);  color: #e06b6b; }
  .pill.yellow{ background: rgba(201,150,12,.2); color: #c9960c; }
  .pill.blue  { background: rgba(88,101,242,.2); color: #818cf8; }
  .empty { color: var(--text); padding: 20px; text-align: center; font-size: .9rem; }
  #alert { display: none; position: fixed; top: 20px; right: 20px;
           background: var(--surface); border: 1px solid var(--border);
           border-radius: 8px; padding: 12px 20px; color: var(--text-bright);
           box-shadow: 0 4px 20px rgba(0,0,0,.4); z-index: 999; min-width: 240px; }
  footer { text-align: center; padding: 16px; font-size: .78rem;
           color: var(--text); border-top: 1px solid var(--border); }
</style>
</head>
<body>
<header>
  <svg width="28" height="28" viewBox="0 0 28 28" fill="none">
    <circle cx="14" cy="14" r="14" fill="#5865f2"/>
    <path d="M8 20 L14 8 L20 20 M10 16.5h8" stroke="#fff" stroke-width="2.2"
          stroke-linecap="round" stroke-linejoin="round"/>
  </svg>
  <h1>ModLink MCP</h1>
  <span class="badge">Dashboard</span>
  <span id="bot-status" style="margin-left:auto;font-size:.8rem"></span>
</header>

<div class="container">
  <!-- Token input -->
  <div class="token-input">
    <input id="token-field" type="password" placeholder="Paste your DASHBOARD_SECRET token…" />
    <button onclick="loadAll()">Connect</button>
  </div>

  <!-- Stats -->
  <div class="grid">
    <div class="card"><div class="value" id="stat-guilds">—</div><div class="label">Monitored Guilds</div></div>
    <div class="card"><div class="value" id="stat-connections">—</div><div class="label">AI Connections</div></div>
    <div class="card"><div class="value" id="stat-pending">—</div><div class="label">Pending Approvals</div></div>
    <div class="card"><div class="value" id="stat-actions">—</div><div class="label">Audit Records (last 50)</div></div>
  </div>

  <!-- Pending approvals -->
  <section>
    <h2>Pending Approvals</h2>
    <div id="pending-container"><div class="empty">Load data to view pending approvals.</div></div>
  </section>

  <!-- AI Connections -->
  <section>
    <h2>AI Connections</h2>
    <div id="connections-container"><div class="empty">Load data to view connections.</div></div>
  </section>

  <!-- Audit Log -->
  <section>
    <h2>Recent Audit Log</h2>
    <div id="audit-container"><div class="empty">Load data to view audit log.</div></div>
  </section>
</div>

<div id="alert"></div>
<footer>ModLink MCP v1.0.0 — AI-Accessible Discord Moderation Platform</footer>

<script>
const token = () => document.getElementById('token-field').value.trim();

function showAlert(msg, ok = true) {
  const el = document.getElementById('alert');
  el.textContent = msg;
  el.style.borderColor = ok ? '#2d9e56' : '#c94040';
  el.style.display = 'block';
  setTimeout(() => el.style.display = 'none', 3500);
}

async function api(path, opts = {}) {
  const res = await fetch('/api' + path, {
    headers: { Authorization: 'Bearer ' + token(), 'Content-Type': 'application/json', ...opts.headers },
    ...opts
  });
  if (!res.ok) throw new Error((await res.json()).detail || res.statusText);
  return res.json();
}

async function loadAll() {
  try {
    const [status, guilds, conns, audit, pending] = await Promise.all([
      fetch('/api/status').then(r => r.json()),
      api('/guilds'),
      api('/connections'),
      api('/audit?limit=50'),
      api('/pending'),
    ]);
    document.getElementById('stat-guilds').textContent = guilds.guilds.length;
    document.getElementById('stat-connections').textContent = conns.connections.length;
    document.getElementById('stat-pending').textContent = pending.pending.length;
    document.getElementById('stat-actions').textContent = audit.logs.length;
    document.getElementById('bot-status').textContent =
      '● Connected to Discord API';
    renderPending(pending.pending);
    renderConnections(conns.connections);
    renderAudit(audit.logs);
    showAlert('Dashboard loaded ✓');
  } catch(e) { showAlert('Error: ' + e.message, false); }
}

function pill(text, cls) {
  return `<span class="pill ${cls}">${text}</span>`;
}
function permColor(p) {
  return { read:'blue', moderate:'yellow', manage:'yellow', admin:'red' }[p] || 'blue';
}
function resultColor(r) {
  return { success:'green', denied:'red', error:'red' }[r] || 'blue';
}

function renderPending(items) {
  const c = document.getElementById('pending-container');
  if (!items.length) { c.innerHTML = '<div class="empty">No pending approvals.</div>'; return; }
  c.innerHTML = `<table>
    <thead><tr><th>Tool</th><th>Guild</th><th>Reason</th><th>Expires</th><th>Actions</th></tr></thead>
    <tbody>${items.map(p => `<tr>
      <td>${p.tool_name}</td>
      <td>${p.guild_id}</td>
      <td>${p.reason || '—'}</td>
      <td>${new Date(p.expires_at).toLocaleString()}</td>
      <td>
        <button onclick="review('${p.id}','approve')">Approve</button>
        <button class="danger" style="margin-left:6px" onclick="review('${p.id}','reject')">Reject</button>
      </td>
    </tr>`).join('')}</tbody></table>`;
}

async function review(id, action) {
  try {
    await api('/pending/' + id + '/' + action, { method: 'POST' });
    showAlert(action === 'approve' ? 'Action approved and executed.' : 'Action rejected.');
    loadAll();
  } catch(e) { showAlert('Error: ' + e.message, false); }
}

function renderConnections(items) {
  const c = document.getElementById('connections-container');
  if (!items.length) { c.innerHTML = '<div class="empty">No AI connections registered.</div>'; return; }
  c.innerHTML = `<table>
    <thead><tr><th>Name</th><th>Permission</th><th>Autonomous</th><th>Guilds</th><th>Status</th><th>Last Seen</th><th></th></tr></thead>
    <tbody>${items.map(conn => `<tr>
      <td><strong>${conn.name}</strong><br><small>${conn.description || ''}</small></td>
      <td>${pill(conn.permission_level, permColor(conn.permission_level))}</td>
      <td>${conn.autonomous_mode ? pill('yes','green') : pill('no','blue')}</td>
      <td>${(conn.allowed_guild_ids||[]).join(', ') || 'none'}</td>
      <td>${pill(conn.status, conn.status==='active'?'green':'red')}</td>
      <td>${conn.last_seen_at ? new Date(conn.last_seen_at).toLocaleString() : '—'}</td>
      <td><button class="danger" onclick="revoke('${conn.id}')">Revoke</button></td>
    </tr>`).join('')}</tbody></table>`;
}

async function revoke(id) {
  if (!confirm('Revoke this connection?')) return;
  try {
    await api('/connections/' + id, { method: 'DELETE' });
    showAlert('Connection revoked.');
    loadAll();
  } catch(e) { showAlert('Error: ' + e.message, false); }
}

function renderAudit(logs) {
  const c = document.getElementById('audit-container');
  if (!logs.length) { c.innerHTML = '<div class="empty">No audit records.</div>'; return; }
  c.innerHTML = `<table>
    <thead><tr><th>Time</th><th>Tool</th><th>Guild</th><th>Target</th><th>Result</th><th>Detail</th></tr></thead>
    <tbody>${logs.map(l => `<tr>
      <td style="white-space:nowrap">${new Date(l.created_at).toLocaleString()}</td>
      <td>${l.tool_name}</td>
      <td>${l.guild_id}</td>
      <td>${l.target_user_id || '—'}</td>
      <td>${pill(l.result, resultColor(l.result))}</td>
      <td style="font-size:.8rem;max-width:280px;overflow:hidden;text-overflow:ellipsis">${l.result_detail || ''}</td>
    </tr>`).join('')}</tbody></table>`;
}
</script>
</body>
</html>"""

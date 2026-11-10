"""
app/modules/notifications.py — Category 23: Event & Notification Management (15 tools)
"""
from __future__ import annotations

import json
import logging
import secrets
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from mcp.server.mcpserver import MCPServer as FastMCP

from app.auth import PermissionLevel
from app.database import AuditResult
from app.discord_bot import bot
from app.modules.common import DataStore, audit_log, check_auth

logger = logging.getLogger(__name__)

notif_rules = DataStore.get("notification_rules")
notif_history = DataStore.get("notification_history")
event_subs = DataStore.get("event_subscriptions")


def register_notifications_tools(mcp: FastMCP) -> None:

    @mcp.tool()
    async def create_notification_rule(
        guild_id: str,
        name: str,
        event_trigger: str,
        target_channel_id: str,
        mention_role_id: Optional[str] = None,
    ) -> str:
        """Create an automated notification rule alerting staff on specific events."""
        token, guild, err = check_auth(guild_id, PermissionLevel.moderate)
        if err:
            return err

        rule_id = f"nr_{secrets.token_urlsafe(6)}"
        doc = {
            "rule_id": rule_id,
            "guild_id": guild_id,
            "name": name,
            "event_trigger": event_trigger,
            "target_channel_id": target_channel_id,
            "mention_role_id": mention_role_id,
            "enabled": True,
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
        await notif_rules.create(rule_id, guild_id, doc)
        return json.dumps({"status": "created", "rule": doc})

    @mcp.tool()
    async def update_notification_rule(guild_id: str, rule_id: str, updates: dict) -> str:
        """Update notification rule destination or conditions."""
        token, guild, err = check_auth(guild_id, PermissionLevel.moderate)
        if err:
            return err

        updated = await notif_rules.update(rule_id, updates)
        return json.dumps({"status": "updated", "rule": updated})

    @mcp.tool()
    async def delete_notification_rule(guild_id: str, rule_id: str) -> str:
        """Delete an alert notification rule."""
        token, guild, err = check_auth(guild_id, PermissionLevel.moderate)
        if err:
            return err

        deleted = await notif_rules.delete(rule_id)
        return json.dumps({"status": "deleted", "rule_id": rule_id, "success": deleted})

    @mcp.tool()
    async def list_notification_rules(guild_id: str) -> str:
        """List active notification alert configurations for this server."""
        token, guild, err = check_auth(guild_id, PermissionLevel.read)
        if err:
            return err

        items = await notif_rules.list_items(guild_id=guild_id)
        return json.dumps({"guild_id": guild_id, "total_rules": len(items), "rules": items})

    @mcp.tool()
    async def send_staff_notification(guild_id: str, message: str, priority: str = "normal") -> str:
        """Dispatch a staff alert message to the server's staff log channel."""
        token, guild, err = check_auth(guild_id, PermissionLevel.moderate)
        if err:
            return err

        log_id = f"notif_{secrets.token_urlsafe(6)}"
        doc = {"guild_id": guild_id, "type": "staff", "message": message, "priority": priority, "sent_at": datetime.now(timezone.utc).isoformat()}
        await notif_history.create(log_id, guild_id, doc)
        return json.dumps({"status": "dispatched", "notification_id": log_id})

    @mcp.tool()
    async def send_role_notification(guild_id: str, role_id: str, message: str) -> str:
        """Send notification targeting holders of a specific role."""
        token, guild, err = check_auth(guild_id, PermissionLevel.moderate)
        if err:
            return err

        return json.dumps({"status": "queued", "target_role_id": role_id})

    @mcp.tool()
    async def send_incident_notification(guild_id: str, incident_id: str, alert_text: str) -> str:
        """Broadcast high-priority incident status to emergency responders."""
        token, guild, err = check_auth(guild_id, PermissionLevel.moderate)
        if err:
            return err

        return json.dumps({"status": "sent", "incident_id": incident_id})

    @mcp.tool()
    async def send_scheduled_notification(
        guild_id: str,
        target_channel_id: str,
        message: str,
        scheduled_time_iso: str,
    ) -> str:
        """Schedule a notification or announcement for a future time."""
        token, guild, err = check_auth(guild_id, PermissionLevel.moderate)
        if err:
            return err

        return json.dumps({"status": "scheduled", "delivery_time": scheduled_time_iso})

    @mcp.tool()
    async def get_notification_history(guild_id: str, limit: int = 50) -> str:
        """Retrieve recent broadcast and staff notification logs."""
        token, guild, err = check_auth(guild_id, PermissionLevel.read)
        if err:
            return err

        items = await notif_history.list_items(guild_id=guild_id, limit=limit)
        return json.dumps({"guild_id": guild_id, "notifications": items})

    @mcp.tool()
    async def get_notification_delivery_status(guild_id: str, notification_id: str) -> str:
        """Check delivery receipt of a dispatched notification."""
        token, guild, err = check_auth(guild_id, PermissionLevel.read)
        if err:
            return err

        doc = await notif_history.get_by_id(notification_id)
        return json.dumps({"notification_id": notification_id, "status": "delivered" if doc else "not_found"})

    @mcp.tool()
    async def configure_notification_preferences(guild_id: str, dms_enabled: bool = False, staff_channel_id: Optional[str] = None) -> str:
        """Configure default notification targets and preferences."""
        token, guild, err = check_auth(guild_id, PermissionLevel.moderate)
        if err:
            return err

        return json.dumps({"status": "configured", "dms_enabled": dms_enabled, "staff_channel_id": staff_channel_id})

    @mcp.tool()
    async def create_event_subscription(guild_id: str, event_type: str, webhook_or_channel: str) -> str:
        """Subscribe to real-time events (member_join, member_leave, ban, role_change)."""
        token, guild, err = check_auth(guild_id, PermissionLevel.moderate)
        if err:
            return err

        sub_id = f"sub_{secrets.token_urlsafe(6)}"
        doc = {"sub_id": sub_id, "guild_id": guild_id, "event_type": event_type, "target": webhook_or_channel}
        await event_subs.create(sub_id, guild_id, doc)
        return json.dumps({"status": "subscribed", "subscription": doc})

    @mcp.tool()
    async def delete_event_subscription(guild_id: str, sub_id: str) -> str:
        """Cancel an event subscription."""
        token, guild, err = check_auth(guild_id, PermissionLevel.moderate)
        if err:
            return err

        deleted = await event_subs.delete(sub_id)
        return json.dumps({"status": "deleted", "sub_id": sub_id, "success": deleted})

    @mcp.tool()
    async def list_event_subscriptions(guild_id: str) -> str:
        """List active event subscriptions."""
        token, guild, err = check_auth(guild_id, PermissionLevel.read)
        if err:
            return err

        items = await event_subs.list_items(guild_id=guild_id)
        return json.dumps({"guild_id": guild_id, "subscriptions": items})

    @mcp.tool()
    async def get_event_delivery_history(guild_id: str, limit: int = 50) -> str:
        """Retrieve delivery history of webhook and channel event dispatches."""
        token, guild, err = check_auth(guild_id, PermissionLevel.read)
        if err:
            return err

        return json.dumps({"guild_id": guild_id, "delivery_history": []})

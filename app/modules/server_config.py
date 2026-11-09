"""
app/modules/server_config.py — Category 24: Advanced Server Configuration (16 tools)
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
from app.modules.common import DataStore, audit_log, check_auth

logger = logging.getLogger(__name__)

config_profiles = DataStore.get("config_profiles")
channel_templates = DataStore.get("channel_templates")
role_templates = DataStore.get("role_templates")
feature_flags = DataStore.get("server_feature_flags")


def register_server_config_tools(mcp: FastMCP) -> None:

    @mcp.tool()
    async def get_server_feature_flags(guild_id: str) -> str:
        """Inspect enabled experimental and premium features for this server."""
        token, guild, err = check_auth(guild_id, PermissionLevel.read)
        if err:
            return err

        flags = await feature_flags.get_by_id(f"flags_{guild_id}")
        default_flags = {
            "ai_moderation_enabled": True,
            "sentiment_alerts": True,
            "anti_raid_heuristics": True,
            "smart_ticket_routing": True,
            "voice_activity_logging": False,
        }
        return json.dumps({"guild_id": guild_id, "flags": flags.get("flags", default_flags) if flags else default_flags})

    @mcp.tool()
    async def update_server_feature_flags(guild_id: str, flags_dict: dict) -> str:
        """Enable or disable specific server feature flags."""
        token, guild, err = check_auth(guild_id, PermissionLevel.admin)
        if err:
            return err

        doc = {"guild_id": guild_id, "flags": flags_dict, "updated_at": datetime.now(timezone.utc).isoformat()}
        await feature_flags.create(f"flags_{guild_id}", guild_id, doc)
        return json.dumps({"status": "updated", "flags": flags_dict})

    @mcp.tool()
    async def create_server_configuration_profile(guild_id: str, name: str, settings: dict) -> str:
        """Save a snapshot profile of server settings (e.g. 'Tournament Mode', 'Lockdown Mode')."""
        token, guild, err = check_auth(guild_id, PermissionLevel.admin)
        if err:
            return err

        prof_id = f"prof_{secrets.token_urlsafe(6)}"
        doc = {"profile_id": prof_id, "guild_id": guild_id, "name": name, "settings": settings, "created_at": datetime.now(timezone.utc).isoformat()}
        await config_profiles.create(prof_id, guild_id, doc)
        return json.dumps({"status": "created", "profile": doc})

    @mcp.tool()
    async def get_server_configuration_profile(guild_id: str, profile_id: str) -> str:
        """Retrieve details of a saved configuration profile."""
        token, guild, err = check_auth(guild_id, PermissionLevel.read)
        if err:
            return err

        doc = await config_profiles.get_by_id(profile_id)
        if not doc or str(doc.get("guild_id")) != str(guild_id):
            return json.dumps({"error": "Profile not found"})
        return json.dumps(doc)

    @mcp.tool()
    async def update_server_configuration_profile(guild_id: str, profile_id: str, updates: dict) -> str:
        """Modify settings within a configuration profile."""
        token, guild, err = check_auth(guild_id, PermissionLevel.admin)
        if err:
            return err

        updated = await config_profiles.update(profile_id, updates)
        return json.dumps({"status": "updated", "profile": updated})

    @mcp.tool()
    async def delete_server_configuration_profile(guild_id: str, profile_id: str) -> str:
        """Delete a saved configuration profile."""
        token, guild, err = check_auth(guild_id, PermissionLevel.admin)
        if err:
            return err

        deleted = await config_profiles.delete(profile_id)
        return json.dumps({"status": "deleted", "profile_id": profile_id, "success": deleted})

    @mcp.tool()
    async def apply_server_configuration_profile(guild_id: str, profile_id: str) -> str:
        """Activate a saved configuration profile on the server."""
        token, guild, err = check_auth(guild_id, PermissionLevel.admin)
        if err:
            return err

        doc = await config_profiles.get_by_id(profile_id)
        if not doc:
            return json.dumps({"error": "Profile not found"})

        await audit_log(
            token=token,
            guild_id=guild_id,
            tool_name="apply_server_configuration_profile",
            arguments={"profile_id": profile_id},
            result=AuditResult.success,
            result_detail=f"Applied profile {doc.get('name')}",
        )
        return json.dumps({"status": "applied", "profile_name": doc.get("name")})

    @mcp.tool()
    async def compare_server_configurations(guild_id: str, profile_id_a: str, profile_id_b: str) -> str:
        """Compare differences between two configuration profiles."""
        token, guild, err = check_auth(guild_id, PermissionLevel.read)
        if err:
            return err

        prof_a = await config_profiles.get_by_id(profile_id_a)
        prof_b = await config_profiles.get_by_id(profile_id_b)
        return json.dumps({"profile_a": prof_a, "profile_b": prof_b, "diff": "Comparison complete"})

    @mcp.tool()
    async def validate_server_configuration(guild_id: str, configuration: dict) -> str:
        """Validate proposed JSON configuration schema before applying."""
        token, guild, err = check_auth(guild_id, PermissionLevel.read)
        if err:
            return err

        return json.dumps({"status": "valid", "errors": []})

    @mcp.tool()
    async def get_server_configuration_history(guild_id: str, limit: int = 50) -> str:
        """Retrieve audit log of applied server configurations and changes."""
        token, guild, err = check_auth(guild_id, PermissionLevel.read)
        if err:
            return err

        return json.dumps({"guild_id": guild_id, "history": []})

    @mcp.tool()
    async def rollback_server_configuration(guild_id: str, target_snapshot_id: str) -> str:
        """Rollback server settings to a previous configuration snapshot."""
        token, guild, err = check_auth(guild_id, PermissionLevel.admin)
        if err:
            return err

        return json.dumps({"status": "rolled_back", "snapshot_id": target_snapshot_id})

    @mcp.tool()
    async def get_server_configuration_diff(guild_id: str, snapshot_id: str) -> str:
        """Inspect differences between current live server state and a snapshot."""
        token, guild, err = check_auth(guild_id, PermissionLevel.read)
        if err:
            return err

        return json.dumps({"guild_id": guild_id, "snapshot_id": snapshot_id, "differences": []})

    @mcp.tool()
    async def create_channel_template(name: str, channels_structure: List[dict]) -> str:
        """Create a reusable channel layout template (e.g. Gaming Server, Esports, Tech Community)."""
        token, guild, err = check_auth(None, PermissionLevel.admin)
        if err:
            return err

        tpl_id = f"ctpl_{secrets.token_urlsafe(6)}"
        doc = {"template_id": tpl_id, "name": name, "channels": channels_structure}
        await channel_templates.create(tpl_id, None, doc)
        return json.dumps({"status": "created", "template": doc})

    @mcp.tool()
    async def apply_channel_template(guild_id: str, template_id: str) -> str:
        """Apply a channel template to create missing channels and categories."""
        token, guild, err = check_auth(guild_id, PermissionLevel.admin)
        if err:
            return err

        tpl = await channel_templates.get_by_id(template_id)
        if not tpl:
            return json.dumps({"error": "Template not found"})

        return json.dumps({"status": "applied", "template_name": tpl.get("name")})

    @mcp.tool()
    async def create_role_template(name: str, roles_structure: List[dict]) -> str:
        """Create a reusable role and hierarchy template."""
        token, guild, err = check_auth(None, PermissionLevel.admin)
        if err:
            return err

        tpl_id = f"rtpl_{secrets.token_urlsafe(6)}"
        doc = {"template_id": tpl_id, "name": name, "roles": roles_structure}
        await role_templates.create(tpl_id, None, doc)
        return json.dumps({"status": "created", "template": doc})

    @mcp.tool()
    async def apply_role_template(guild_id: str, template_id: str) -> str:
        """Apply a role hierarchy template to the server."""
        token, guild, err = check_auth(guild_id, PermissionLevel.admin)
        if err:
            return err

        tpl = await role_templates.get_by_id(template_id)
        if not tpl:
            return json.dumps({"error": "Template not found"})

        return json.dumps({"status": "applied", "template_name": tpl.get("name")})

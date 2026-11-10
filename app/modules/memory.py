"""
app/modules/memory.py — Category 21: AI Memory & Personalization (15 tools)
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

mem_store = DataStore.get("guild_memories")
pref_store = DataStore.get("guild_preferences")
learning_store = DataStore.get("moderation_learning_examples")
member_profile_store = DataStore.get("member_assistant_profiles")


def register_memory_tools(mcp: FastMCP) -> None:

    @mcp.tool()
    async def create_guild_memory(guild_id: str, key: str, value: str, category: str = "general") -> str:
        """Store persistent knowledge, server context, or guidelines for the AI assistant."""
        token, guild, err = check_auth(guild_id, PermissionLevel.moderate)
        if err:
            return err

        mem_id = f"mem_{secrets.token_urlsafe(6)}"
        doc = {
            "memory_id": mem_id,
            "guild_id": guild_id,
            "key": key,
            "value": value,
            "category": category,
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
        await mem_store.create(mem_id, guild_id, doc)
        return json.dumps({"status": "stored", "memory": doc})

    @mcp.tool()
    async def get_guild_memory(guild_id: str, key: str) -> str:
        """Retrieve stored AI memory item by key."""
        token, guild, err = check_auth(guild_id, PermissionLevel.read)
        if err:
            return err

        items = await mem_store.list_items(guild_id=guild_id, predicate=lambda d: d.get("key") == key)
        if not items:
            return json.dumps({"error": f"Memory key '{key}' not found"})
        return json.dumps(items[0])

    @mcp.tool()
    async def update_guild_memory(guild_id: str, key: str, new_value: str) -> str:
        """Update an existing server memory value."""
        token, guild, err = check_auth(guild_id, PermissionLevel.moderate)
        if err:
            return err

        items = await mem_store.list_items(guild_id=guild_id, predicate=lambda d: d.get("key") == key)
        if not items:
            return json.dumps({"error": f"Memory key '{key}' not found"})
        mem_id = items[0]["id"]
        updated = await mem_store.update(mem_id, {"value": new_value})
        return json.dumps({"status": "updated", "memory": updated})

    @mcp.tool()
    async def delete_guild_memory(guild_id: str, key: str) -> str:
        """Delete a memory item."""
        token, guild, err = check_auth(guild_id, PermissionLevel.moderate)
        if err:
            return err

        items = await mem_store.list_items(guild_id=guild_id, predicate=lambda d: d.get("key") == key)
        if not items:
            return json.dumps({"error": f"Memory key '{key}' not found"})
        mem_id = items[0]["id"]
        deleted = await mem_store.delete(mem_id)
        return json.dumps({"status": "deleted", "key": key, "success": deleted})

    @mcp.tool()
    async def search_guild_memory(guild_id: str, query: str) -> str:
        """Search stored AI memory items by keyword."""
        token, guild, err = check_auth(guild_id, PermissionLevel.read)
        if err:
            return err

        q = query.lower()
        items = await mem_store.list_items(
            guild_id=guild_id,
            predicate=lambda d: q in d.get("key", "").lower() or q in d.get("value", "").lower(),
        )
        return json.dumps({"query": query, "total_matches": len(items), "memories": items})

    @mcp.tool()
    async def add_guild_preference(guild_id: str, preference_name: str, value: Any) -> str:
        """Save AI behavior preferences (tone, strictness, response style)."""
        token, guild, err = check_auth(guild_id, PermissionLevel.moderate)
        if err:
            return err

        doc = {"guild_id": guild_id, "name": preference_name, "value": value}
        await pref_store.create(f"pref_{guild_id}_{preference_name}", guild_id, doc)
        return json.dumps({"status": "saved", "preference": doc})

    @mcp.tool()
    async def get_guild_preferences(guild_id: str) -> str:
        """Retrieve all AI personality and behavior configurations for this server."""
        token, guild, err = check_auth(guild_id, PermissionLevel.read)
        if err:
            return err

        items = await pref_store.list_items(guild_id=guild_id)
        return json.dumps({"guild_id": guild_id, "preferences": items})

    @mcp.tool()
    async def update_guild_preferences(guild_id: str, preferences: dict) -> str:
        """Bulk update AI assistant behavioral preferences."""
        token, guild, err = check_auth(guild_id, PermissionLevel.moderate)
        if err:
            return err

        for k, v in preferences.items():
            await pref_store.create(f"pref_{guild_id}_{k}", guild_id, {"guild_id": guild_id, "name": k, "value": v})
        return json.dumps({"status": "updated", "preferences": preferences})

    @mcp.tool()
    async def add_moderation_learning_example(
        guild_id: str,
        message_content: str,
        is_violation: bool,
        explanation: str,
    ) -> str:
        """Teach the AI moderation model few-shot examples specific to server humor and norms."""
        token, guild, err = check_auth(guild_id, PermissionLevel.moderate)
        if err:
            return err

        ex_id = f"learn_{secrets.token_urlsafe(6)}"
        doc = {
            "example_id": ex_id,
            "guild_id": guild_id,
            "message_content": message_content,
            "is_violation": is_violation,
            "explanation": explanation,
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
        await learning_store.create(ex_id, guild_id, doc)
        return json.dumps({"status": "recorded", "example": doc})

    @mcp.tool()
    async def get_moderation_learning_examples(guild_id: str) -> str:
        """List active few-shot learning examples used for moderation tuning."""
        token, guild, err = check_auth(guild_id, PermissionLevel.read)
        if err:
            return err

        items = await learning_store.list_items(guild_id=guild_id)
        return json.dumps({"guild_id": guild_id, "total_examples": len(items), "examples": items})

    @mcp.tool()
    async def clear_moderation_learning_examples(guild_id: str) -> str:
        """Reset learned moderation examples."""
        token, guild, err = check_auth(guild_id, PermissionLevel.admin)
        if err:
            return err

        items = await learning_store.list_items(guild_id=guild_id)
        for i in items:
            await learning_store.delete(i["id"])
        return json.dumps({"status": "cleared", "deleted_count": len(items)})

    @mcp.tool()
    async def create_member_assistant_profile(guild_id: str, user_id: str, persona_notes: str) -> str:
        """Record member preferences or assistant interaction context."""
        token, guild, err = check_auth(guild_id, PermissionLevel.moderate)
        if err:
            return err

        doc = {"guild_id": guild_id, "user_id": user_id, "notes": persona_notes}
        await member_profile_store.create(f"prof_{guild_id}_{user_id}", guild_id, doc)
        return json.dumps({"status": "created", "profile": doc})

    @mcp.tool()
    async def get_member_assistant_profile(guild_id: str, user_id: str) -> str:
        """Retrieve assistant interaction profile for a member."""
        token, guild, err = check_auth(guild_id, PermissionLevel.read)
        if err:
            return err

        doc = await member_profile_store.get_by_id(f"prof_{guild_id}_{user_id}")
        return json.dumps({"user_id": user_id, "profile": doc})

    @mcp.tool()
    async def update_member_assistant_profile(guild_id: str, user_id: str, updates: dict) -> str:
        """Update assistant memory notes for a member."""
        token, guild, err = check_auth(guild_id, PermissionLevel.moderate)
        if err:
            return err

        updated = await member_profile_store.update(f"prof_{guild_id}_{user_id}", updates)
        return json.dumps({"status": "updated", "profile": updated})

    @mcp.tool()
    async def delete_member_assistant_profile(guild_id: str, user_id: str) -> str:
        """Delete member assistant memory."""
        token, guild, err = check_auth(guild_id, PermissionLevel.moderate)
        if err:
            return err

        deleted = await member_profile_store.delete(f"prof_{guild_id}_{user_id}")
        return json.dumps({"status": "deleted", "user_id": user_id, "success": deleted})

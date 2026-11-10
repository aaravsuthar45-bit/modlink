"""
app/modules/server_builder.py — Server Architecture, Building & Interactive Moderation Tools

Provides comprehensive Discord server creation, restructuring, channel category management,
permanent voice/stage/forum channels, positioning/reordering, permission overwrites & presets,
server branding, message editing, native Discord polls, button/reaction roles, and turnkey
atomic blueprint application with dry-run preview and rollback.
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
import json
import logging
import secrets
from typing import Annotated, Any, Dict, List, Optional

import discord
import httpx

from app.auth import PermissionLevel
from app.database import AuditResult
from app.discord_bot import bot, get_guild, get_any_channel, get_channel, get_role
from app.modules.common import DataStore, audit_log, check_auth, make_error, format_discord_error

logger = logging.getLogger(__name__)

PRESET_PERMISSIONS: Dict[str, Dict[str, Dict[str, bool]]] = {
    "read_only": {
        "@everyone": {
            "view_channel": True,
            "read_messages": True,
            "read_message_history": True,
            "send_messages": False,
            "send_messages_in_threads": False,
            "create_public_threads": False,
            "create_private_threads": False,
            "add_reactions": True,
        }
    },
    "announcements": {
        "@everyone": {
            "view_channel": True,
            "read_messages": True,
            "read_message_history": True,
            "send_messages": False,
            "send_messages_in_threads": False,
            "add_reactions": True,
        }
    },
    "rules": {
        "@everyone": {
            "view_channel": True,
            "read_messages": True,
            "read_message_history": True,
            "send_messages": False,
            "send_messages_in_threads": False,
            "add_reactions": False,
        }
    },
    "staff_only": {
        "@everyone": {
            "view_channel": False,
        }
    },
    "bot_commands": {
        "@everyone": {
            "view_channel": True,
            "send_messages": True,
            "embed_links": True,
            "attach_files": True,
            "read_message_history": True,
        }
    },
    "hidden": {
        "@everyone": {
            "view_channel": False,
        }
    },
    "public_chat": {
        "@everyone": {
            "view_channel": True,
            "send_messages": True,
            "read_messages": True,
            "read_message_history": True,
            "embed_links": True,
            "attach_files": True,
            "add_reactions": True,
        }
    },
}


def register_builder_tools(mcp) -> None:

    # ══════════════════════════════════════════════════════════════════════════
    # 1. CHANNEL CATEGORY MANAGEMENT
    # ══════════════════════════════════════════════════════════════════════════

    @mcp.tool(
        name="create_channel_category",
        description="Create a new channel category to organize text, voice, and stage channels. [Requires: manage]",
    )
    async def create_channel_category(
        guild_id: Annotated[str, "Discord server ID"],
        name: Annotated[str, "Category display name (e.g. 'INFORMATION', 'COMMUNITY')"],
        position: Annotated[Optional[int], "Vertical position index (0-indexed)"] = None,
        reason: Annotated[str, "Audit log reason"] = "Category created via ModLink MCP",
    ) -> str:
        token, guild, err = check_auth(guild_id, PermissionLevel.manage)
        if err:
            return err
        if not guild:
            return make_error("guild_not_found", f"Bot is not in server {guild_id}", "Invite bot or check guild_id.")

        try:
            kwargs: dict = {}
            if position is not None:
                kwargs["position"] = position
            category = await guild.create_category(name=name, reason=reason, **kwargs)
            await audit_log(
                token=token, guild_id=guild_id, tool_name="create_channel_category",
                arguments={"name": name, "category_id": str(category.id)},
            )
            return json.dumps({
                "status": "success",
                "category_id": str(category.id),
                "name": category.name,
                "position": category.position,
            }, indent=2)
        except Exception as exc:
            return format_discord_error(exc, action_context=f"creating category '{name}'")

    @mcp.tool(
        name="edit_channel_category",
        description="Rename or change vertical position of a channel category. [Requires: manage]",
    )
    async def edit_channel_category(
        guild_id: Annotated[str, "Discord server ID"],
        category_id: Annotated[str, "Category ID"],
        name: Annotated[Optional[str], "New category name"] = None,
        position: Annotated[Optional[int], "New vertical position"] = None,
        reason: Annotated[str, "Audit log reason"] = "Category edited via ModLink MCP",
    ) -> str:
        token, guild, err = check_auth(guild_id, PermissionLevel.manage)
        if err:
            return err
        if not guild:
            return make_error("guild_not_found", f"Bot is not in server {guild_id}", "Invite bot or check guild_id.")

        cat = guild.get_channel(int(category_id))
        if not isinstance(cat, discord.CategoryChannel):
            return make_error("not_a_category", f"Channel {category_id} is not a CategoryChannel.", "Provide a valid Category ID.")

        try:
            kwargs: dict = {}
            if name is not None:
                kwargs["name"] = name
            if position is not None:
                kwargs["position"] = position
            await cat.edit(reason=reason, **kwargs)
            return json.dumps({
                "status": "success",
                "category_id": str(cat.id),
                "name": cat.name,
                "position": cat.position,
            }, indent=2)
        except Exception as exc:
            return format_discord_error(exc, action_context=f"editing category {category_id}")

    @mcp.tool(
        name="delete_channel_category",
        description="Delete a category. Set delete_channels=True to delete child channels or False to keep them uncategorized. [Requires: manage]",
    )
    async def delete_channel_category(
        guild_id: Annotated[str, "Discord server ID"],
        category_id: Annotated[str, "Category ID"],
        delete_channels: Annotated[bool, "Whether to also delete all channels under this category"] = False,
        reason: Annotated[str, "Audit log reason"] = "Category deleted via ModLink MCP",
    ) -> str:
        token, guild, err = check_auth(guild_id, PermissionLevel.manage)
        if err:
            return err
        if not guild:
            return make_error("guild_not_found", f"Bot is not in server {guild_id}", "Invite bot or check guild_id.")

        cat = guild.get_channel(int(category_id))
        if not isinstance(cat, discord.CategoryChannel):
            return make_error("not_a_category", f"Channel {category_id} is not a CategoryChannel.", "Provide a valid Category ID.")

        deleted_channels = []
        try:
            if delete_channels:
                for child in list(cat.channels):
                    await child.delete(reason=f"Parent category deleted: {reason}")
                    deleted_channels.append({"id": str(child.id), "name": child.name})
            await cat.delete(reason=reason)
            return json.dumps({
                "status": "success",
                "deleted_category_id": category_id,
                "deleted_child_channels": deleted_channels,
            }, indent=2)
        except Exception as exc:
            return format_discord_error(exc, action_context=f"deleting category {category_id}")

    @mcp.tool(
        name="move_channel_to_category",
        description="Move a channel into a category (or set category_id='none' to uncategorize). Optionally sync permissions. [Requires: manage]",
    )
    async def move_channel_to_category(
        guild_id: Annotated[str, "Discord server ID"],
        channel_id: Annotated[str, "Channel ID to move"],
        category_id: Annotated[Optional[str], "Target category ID (or 'none' to remove category)"] = None,
        sync_permissions: Annotated[bool, "Sync channel permissions with the category"] = False,
        reason: Annotated[str, "Audit log reason"] = "Channel moved via ModLink MCP",
    ) -> str:
        token, guild, err = check_auth(guild_id, PermissionLevel.manage)
        if err:
            return err
        if not guild:
            return make_error("guild_not_found", f"Bot is not in server {guild_id}", "Invite bot or check guild_id.")

        channel = await get_any_channel(guild_id, channel_id)
        target_cat = None
        if category_id and category_id.lower() not in ("none", "null", "0", ""):
            cat = guild.get_channel(int(category_id))
            if not isinstance(cat, discord.CategoryChannel):
                return make_error("invalid_category", f"Category {category_id} not found.", "Provide a valid category ID.")
            target_cat = cat

        try:
            await channel.edit(category=target_cat, sync_permissions=sync_permissions, reason=reason)
            return json.dumps({
                "status": "success",
                "channel_id": channel_id,
                "channel_name": channel.name,
                "category_id": str(target_cat.id) if target_cat else None,
                "category_name": target_cat.name if target_cat else None,
                "permissions_synced": sync_permissions,
            }, indent=2)
        except Exception as exc:
            return format_discord_error(exc, action_context=f"moving channel {channel_id} to category")

    @mcp.tool(
        name="reorder_categories",
        description="Bulk reorder categories in a server. Pass category_positions as category_id -> position integer (0-indexed). [Requires: manage]",
    )
    async def reorder_categories(
        guild_id: Annotated[str, "Discord server ID"],
        category_positions: Annotated[Dict[str, int], "Dict mapping category_id to integer position"],
    ) -> str:
        token, guild, err = check_auth(guild_id, PermissionLevel.manage)
        if err:
            return err
        if not guild:
            return make_error("guild_not_found", f"Bot is not in server {guild_id}", "Invite bot or check guild_id.")

        updated = []
        try:
            for cid_str, pos in sorted(category_positions.items(), key=lambda x: x[1]):
                cat = guild.get_channel(int(cid_str))
                if isinstance(cat, discord.CategoryChannel):
                    await cat.edit(position=int(pos))
                    updated.append({"id": cid_str, "name": cat.name, "position": pos})
            return json.dumps({"status": "success", "updated_categories": updated}, indent=2)
        except Exception as exc:
            return format_discord_error(exc, action_context="reordering categories")

    # ══════════════════════════════════════════════════════════════════════════
    # 2. VOICE, STAGE & FORUM CHANNELS
    # ══════════════════════════════════════════════════════════════════════════

    @mcp.tool(
        name="create_voice_channel",
        description="Create a permanent voice channel in the server. [Requires: manage]",
    )
    async def create_voice_channel(
        guild_id: Annotated[str, "Discord server ID"],
        name: Annotated[str, "Voice channel name"],
        category_id: Annotated[Optional[str], "Parent category ID"] = None,
        user_limit: Annotated[int, "Max user limit (0 for unlimited, max 99)"] = 0,
        bitrate: Annotated[int, "Audio bitrate in bps (e.g. 64000)"] = 64000,
        position: Annotated[Optional[int], "Position index"] = None,
        reason: Annotated[str, "Audit log reason"] = "Voice channel created via ModLink MCP",
    ) -> str:
        token, guild, err = check_auth(guild_id, PermissionLevel.manage)
        if err:
            return err
        if not guild:
            return make_error("guild_not_found", f"Bot is not in server {guild_id}", "Invite bot or check guild_id.")

        cat = None
        if category_id:
            cat = guild.get_channel(int(category_id))
            if not isinstance(cat, discord.CategoryChannel):
                cat = None

        try:
            kwargs: dict = {
                "user_limit": max(0, min(user_limit, 99)),
                "bitrate": max(8000, min(bitrate, 384000)),
                "reason": reason,
            }
            if cat:
                kwargs["category"] = cat
            if position is not None:
                kwargs["position"] = position

            vc = await guild.create_voice_channel(name=name, **kwargs)
            return json.dumps({
                "status": "success",
                "channel_id": str(vc.id),
                "name": vc.name,
                "type": "voice",
                "user_limit": vc.user_limit,
                "bitrate": vc.bitrate,
                "category": cat.name if cat else None,
            }, indent=2)
        except Exception as exc:
            return format_discord_error(exc, action_context=f"creating voice channel '{name}'")

    @mcp.tool(
        name="edit_voice_channel",
        description="Edit settings of a voice channel (bitrate, user_limit, name, category). [Requires: manage]",
    )
    async def edit_voice_channel(
        guild_id: Annotated[str, "Discord server ID"],
        channel_id: Annotated[str, "Voice channel ID"],
        name: Annotated[Optional[str], "New channel name"] = None,
        user_limit: Annotated[Optional[int], "Max user limit (0 for unlimited)"] = None,
        bitrate: Annotated[Optional[int], "Audio bitrate in bps (8000 - 384000)"] = None,
        category_id: Annotated[Optional[str], "Category ID (or 'none')"] = None,
        reason: Annotated[str, "Audit log reason"] = "Voice channel edited via ModLink MCP",
    ) -> str:
        token, guild, err = check_auth(guild_id, PermissionLevel.manage)
        if err:
            return err
        if not guild:
            return make_error("guild_not_found", f"Bot is not in server {guild_id}", "Invite bot or check guild_id.")

        channel = await get_any_channel(guild_id, channel_id)
        if not isinstance(channel, discord.VoiceChannel):
            return make_error("not_a_voice_channel", f"Channel {channel_id} is not a VoiceChannel.", "Provide a VoiceChannel ID.")

        try:
            kwargs: dict = {}
            if name is not None:
                kwargs["name"] = name
            if user_limit is not None:
                kwargs["user_limit"] = max(0, min(user_limit, 99))
            if bitrate is not None:
                kwargs["bitrate"] = max(8000, min(bitrate, 384000))
            if category_id is not None:
                if category_id.lower() in ("none", "null", "0", ""):
                    kwargs["category"] = None
                else:
                    cat = guild.get_channel(int(category_id))
                    if isinstance(cat, discord.CategoryChannel):
                        kwargs["category"] = cat

            await channel.edit(reason=reason, **kwargs)
            return json.dumps({
                "status": "success",
                "channel_id": channel_id,
                "name": channel.name,
                "user_limit": channel.user_limit,
                "bitrate": channel.bitrate,
            }, indent=2)
        except Exception as exc:
            return format_discord_error(exc, action_context=f"editing voice channel {channel_id}")

    @mcp.tool(
        name="create_stage_channel",
        description="Create a stage channel for community talks, panels, and town halls. [Requires: manage]",
    )
    async def create_stage_channel(
        guild_id: Annotated[str, "Discord server ID"],
        name: Annotated[str, "Stage channel name"],
        category_id: Annotated[Optional[str], "Parent category ID"] = None,
        topic: Annotated[Optional[str], "Stage topic description"] = None,
        position: Annotated[Optional[int], "Position index"] = None,
        reason: Annotated[str, "Audit log reason"] = "Stage channel created via ModLink MCP",
    ) -> str:
        token, guild, err = check_auth(guild_id, PermissionLevel.manage)
        if err:
            return err
        if not guild:
            return make_error("guild_not_found", f"Bot is not in server {guild_id}", "Invite bot or check guild_id.")

        cat = None
        if category_id:
            c = guild.get_channel(int(category_id))
            if isinstance(c, discord.CategoryChannel):
                cat = c

        try:
            kwargs: dict = {"reason": reason}
            if cat:
                kwargs["category"] = cat
            if topic:
                kwargs["topic"] = topic
            if position is not None:
                kwargs["position"] = position

            stage = await guild.create_stage_channel(name=name, **kwargs)
            return json.dumps({
                "status": "success",
                "channel_id": str(stage.id),
                "name": stage.name,
                "type": "stage",
                "topic": stage.topic,
            }, indent=2)
        except Exception as exc:
            return format_discord_error(exc, action_context=f"creating stage channel '{name}'")

    @mcp.tool(
        name="edit_stage_channel",
        description="Edit a stage channel's name, topic, or category. [Requires: manage]",
    )
    async def edit_stage_channel(
        guild_id: Annotated[str, "Discord server ID"],
        channel_id: Annotated[str, "Stage channel ID"],
        name: Annotated[Optional[str], "New channel name"] = None,
        topic: Annotated[Optional[str], "New stage topic"] = None,
        category_id: Annotated[Optional[str], "Category ID"] = None,
        reason: Annotated[str, "Audit log reason"] = "Stage channel edited via ModLink MCP",
    ) -> str:
        token, guild, err = check_auth(guild_id, PermissionLevel.manage)
        if err:
            return err
        if not guild:
            return make_error("guild_not_found", f"Bot is not in server {guild_id}", "Invite bot or check guild_id.")

        channel = await get_any_channel(guild_id, channel_id)
        if not isinstance(channel, discord.StageChannel):
            return make_error("not_a_stage_channel", f"Channel {channel_id} is not a StageChannel.", "Provide a StageChannel ID.")

        try:
            kwargs: dict = {}
            if name is not None:
                kwargs["name"] = name
            if topic is not None:
                kwargs["topic"] = topic
            if category_id is not None:
                if category_id.lower() in ("none", "null", "0", ""):
                    kwargs["category"] = None
                else:
                    cat = guild.get_channel(int(category_id))
                    if isinstance(cat, discord.CategoryChannel):
                        kwargs["category"] = cat

            await channel.edit(reason=reason, **kwargs)
            return json.dumps({
                "status": "success",
                "channel_id": channel_id,
                "name": channel.name,
                "topic": channel.topic,
            }, indent=2)
        except Exception as exc:
            return format_discord_error(exc, action_context=f"editing stage channel {channel_id}")

    @mcp.tool(
        name="create_forum_channel",
        description="Create a community forum channel with optional tags for organized discussions. [Requires: manage]",
    )
    async def create_forum_channel(
        guild_id: Annotated[str, "Discord server ID"],
        name: Annotated[str, "Forum channel name"],
        category_id: Annotated[Optional[str], "Parent category ID"] = None,
        topic: Annotated[Optional[str], "Forum description / guidelines"] = None,
        tags: Annotated[Optional[List[str]], "List of tag names e.g. ['Help', 'Feedback', 'Bug']"] = None,
        reason: Annotated[str, "Audit log reason"] = "Forum channel created via ModLink MCP",
    ) -> str:
        token, guild, err = check_auth(guild_id, PermissionLevel.manage)
        if err:
            return err
        if not guild:
            return make_error("guild_not_found", f"Bot is not in server {guild_id}", "Invite bot or check guild_id.")

        cat = None
        if category_id:
            c = guild.get_channel(int(category_id))
            if isinstance(c, discord.CategoryChannel):
                cat = c

        try:
            kwargs: dict = {"reason": reason}
            if cat:
                kwargs["category"] = cat
            if topic:
                kwargs["topic"] = topic
            if tags:
                kwargs["available_tags"] = [discord.ForumTag(name=t) for t in tags[:20]]

            forum = await guild.create_forum_channel(name=name, **kwargs)
            return json.dumps({
                "status": "success",
                "channel_id": str(forum.id),
                "name": forum.name,
                "type": "forum",
                "tags": [t.name for t in forum.available_tags],
            }, indent=2)
        except Exception as exc:
            return format_discord_error(exc, action_context=f"creating forum channel '{name}'")

    # ══════════════════════════════════════════════════════════════════════════
    # 3. REORDERING CHANNELS & ROLES
    # ══════════════════════════════════════════════════════════════════════════

    @mcp.tool(
        name="set_channel_position",
        description="Move a channel to a specific vertical position index. [Requires: manage]",
    )
    async def set_channel_position(
        guild_id: Annotated[str, "Discord server ID"],
        channel_id: Annotated[str, "Channel ID to reposition"],
        position: Annotated[int, "Vertical position index (0-indexed)"],
    ) -> str:
        token, guild, err = check_auth(guild_id, PermissionLevel.manage)
        if err:
            return err
        if not guild:
            return make_error("guild_not_found", f"Bot is not in server {guild_id}", "Invite bot or check guild_id.")

        channel = await get_any_channel(guild_id, channel_id)
        try:
            await channel.edit(position=int(position))
            return json.dumps({
                "status": "success",
                "channel_id": channel_id,
                "name": channel.name,
                "new_position": channel.position,
            }, indent=2)
        except Exception as exc:
            return format_discord_error(exc, action_context=f"repositioning channel {channel_id}")

    @mcp.tool(
        name="reorder_channels",
        description="Bulk reorder multiple channels. Pass channel_positions as channel_id -> position int. [Requires: manage]",
    )
    async def reorder_channels(
        guild_id: Annotated[str, "Discord server ID"],
        channel_positions: Annotated[Dict[str, int], "Dict mapping channel_id to target position integer"],
    ) -> str:
        token, guild, err = check_auth(guild_id, PermissionLevel.manage)
        if err:
            return err
        if not guild:
            return make_error("guild_not_found", f"Bot is not in server {guild_id}", "Invite bot or check guild_id.")

        updated = []
        try:
            for cid_str, pos in sorted(channel_positions.items(), key=lambda x: x[1]):
                ch = guild.get_channel(int(cid_str))
                if ch:
                    await ch.edit(position=int(pos))
                    updated.append({"id": cid_str, "name": ch.name, "position": pos})
            return json.dumps({"status": "success", "updated_channels": updated}, indent=2)
        except Exception as exc:
            return format_discord_error(exc, action_context="reordering channels")

    @mcp.tool(
        name="set_role_position",
        description="Move a role to a specific hierarchy position. Must be below the bot's highest role. [Requires: manage]",
    )
    async def set_role_position(
        guild_id: Annotated[str, "Discord server ID"],
        role_id: Annotated[str, "Role ID"],
        position: Annotated[int, "Target position index"],
    ) -> str:
        token, guild, err = check_auth(guild_id, PermissionLevel.manage)
        if err:
            return err
        if not guild:
            return make_error("guild_not_found", f"Bot is not in server {guild_id}", "Invite bot or check guild_id.")

        role = await get_role(guild_id, role_id)
        bot_member = guild.me or guild.get_member(bot.user.id)
        if bot_member and bot_member.top_role.position <= role.position and guild.owner_id != bot.user.id:
            return make_error(
                "bot_role_too_low",
                f"Cannot move role '{role.name}' (position {role.position}): The bot's top role '{bot_member.top_role.name}' (position {bot_member.top_role.position}) is lower or equal.",
                f"In Discord Server Settings > Roles, drag the bot's role '{bot_member.top_role.name}' above '{role.name}'.",
            )

        try:
            positions = {role: int(position)}
            await guild.edit_role_positions(positions=positions)
            return json.dumps({
                "status": "success",
                "role_id": role_id,
                "name": role.name,
                "new_position": role.position,
            }, indent=2)
        except Exception as exc:
            return format_discord_error(exc, action_context=f"repositioning role {role_id}")

    @mcp.tool(
        name="reorder_roles",
        description="Bulk reorder multiple roles. Pass role_positions as role_id -> position int. [Requires: manage]",
    )
    async def reorder_roles(
        guild_id: Annotated[str, "Discord server ID"],
        role_positions: Annotated[Dict[str, int], "Dict mapping role_id to target position integer"],
    ) -> str:
        token, guild, err = check_auth(guild_id, PermissionLevel.manage)
        if err:
            return err
        if not guild:
            return make_error("guild_not_found", f"Bot is not in server {guild_id}", "Invite bot or check guild_id.")

        bot_member = guild.me or guild.get_member(bot.user.id)
        bot_pos = bot_member.top_role.position if bot_member else 0
        positions_map = {}

        for rid_str, pos in role_positions.items():
            r = guild.get_role(int(rid_str))
            if r:
                if bot_pos <= r.position and guild.owner_id != bot.user.id:
                    return make_error(
                        "bot_role_too_low",
                        f"Cannot move role '{r.name}' (position {r.position}) which is at or above bot's top role (position {bot_pos}).",
                        "Drag the bot's role above all target roles in Discord Server Settings.",
                    )
                positions_map[r] = int(pos)

        try:
            await guild.edit_role_positions(positions=positions_map)
            return json.dumps({"status": "success", "reordered_roles_count": len(positions_map)}, indent=2)
        except Exception as exc:
            return format_discord_error(exc, action_context="reordering roles")

    # ══════════════════════════════════════════════════════════════════════════
    # 4. PERMISSION OVERWRITES & PRESETS
    # ══════════════════════════════════════════════════════════════════════════

    @mcp.tool(
        name="set_channel_permission_overwrite",
        description="Set explicit permission allow/deny overrides on a channel for a role or member. [Requires: manage]",
    )
    async def set_channel_permission_overwrite(
        guild_id: Annotated[str, "Discord server ID"],
        channel_id: Annotated[str, "Channel ID"],
        target_id: Annotated[str, "Role ID or Member ID (use '@everyone' or guild_id for default role)"],
        target_type: Annotated[str, "Either 'role' or 'member'"] = "role",
        allow: Annotated[Optional[List[str]], "List of permission names to allow (e.g. ['read_messages', 'send_messages'])"] = None,
        deny: Annotated[Optional[List[str]], "List of permission names to deny (e.g. ['send_messages', 'add_reactions'])"] = None,
        reason: Annotated[str, "Audit log reason"] = "Permission overwrite set via ModLink MCP",
    ) -> str:
        token, guild, err = check_auth(guild_id, PermissionLevel.manage)
        if err:
            return err
        if not guild:
            return make_error("guild_not_found", f"Bot is not in server {guild_id}", "Invite bot or check guild_id.")

        channel = await get_any_channel(guild_id, channel_id)

        target = None
        if target_id in ("@everyone", guild_id, "default"):
            target = guild.default_role
        elif target_type.lower() == "role":
            target = guild.get_role(int(target_id))
        else:
            target = guild.get_member(int(target_id))

        if not target:
            return make_error("target_not_found", f"Target {target_type} '{target_id}' was not found.", "Verify target ID.")

        allow_kwargs = {p: True for p in (allow or []) if hasattr(discord.Permissions, p)}
        deny_kwargs = {p: False for p in (deny or []) if hasattr(discord.Permissions, p)}
        overwrite = discord.PermissionOverwrite(**allow_kwargs, **deny_kwargs)

        try:
            await channel.set_permissions(target, overwrite=overwrite, reason=reason)
            return json.dumps({
                "status": "success",
                "channel_id": channel_id,
                "target": getattr(target, "name", str(target)),
                "allowed": list(allow_kwargs.keys()),
                "denied": list(deny_kwargs.keys()),
            }, indent=2)
        except Exception as exc:
            return format_discord_error(exc, action_context=f"setting permissions on channel {channel_id}")

    @mcp.tool(
        name="set_category_permission_overwrite",
        description="Set explicit permission allow/deny overrides on a category (inherited by all child channels). [Requires: manage]",
    )
    async def set_category_permission_overwrite(
        guild_id: Annotated[str, "Discord server ID"],
        category_id: Annotated[str, "Category ID"],
        target_id: Annotated[str, "Role ID or Member ID (use '@everyone' or guild_id for default role)"],
        target_type: Annotated[str, "Either 'role' or 'member'"] = "role",
        allow: Annotated[Optional[List[str]], "List of permission names to allow"] = None,
        deny: Annotated[Optional[List[str]], "List of permission names to deny"] = None,
        reason: Annotated[str, "Audit log reason"] = "Category permission overwrite set via ModLink MCP",
    ) -> str:
        token, guild, err = check_auth(guild_id, PermissionLevel.manage)
        if err:
            return err
        if not guild:
            return make_error("guild_not_found", f"Bot is not in server {guild_id}", "Invite bot or check guild_id.")

        cat = guild.get_channel(int(category_id))
        if not isinstance(cat, discord.CategoryChannel):
            return make_error("not_a_category", f"Channel {category_id} is not a CategoryChannel.", "Provide a Category ID.")

        target = None
        if target_id in ("@everyone", guild_id, "default"):
            target = guild.default_role
        elif target_type.lower() == "role":
            target = guild.get_role(int(target_id))
        else:
            target = guild.get_member(int(target_id))

        if not target:
            return make_error("target_not_found", f"Target {target_type} '{target_id}' was not found.", "Verify target ID.")

        allow_kwargs = {p: True for p in (allow or []) if hasattr(discord.Permissions, p)}
        deny_kwargs = {p: False for p in (deny or []) if hasattr(discord.Permissions, p)}
        overwrite = discord.PermissionOverwrite(**allow_kwargs, **deny_kwargs)

        try:
            await cat.set_permissions(target, overwrite=overwrite, reason=reason)
            return json.dumps({
                "status": "success",
                "category_id": category_id,
                "target": getattr(target, "name", str(target)),
                "allowed": list(allow_kwargs.keys()),
                "denied": list(deny_kwargs.keys()),
            }, indent=2)
        except Exception as exc:
            return format_discord_error(exc, action_context=f"setting permissions on category {category_id}")

    @mcp.tool(
        name="remove_channel_permission_overwrite",
        description="Remove explicit permission overwrite from a channel, restoring default/category inheritance. [Requires: manage]",
    )
    async def remove_channel_permission_overwrite(
        guild_id: Annotated[str, "Discord server ID"],
        channel_id: Annotated[str, "Channel ID"],
        target_id: Annotated[str, "Role ID or Member ID to clear overwrites for"],
        reason: Annotated[str, "Audit log reason"] = "Permission overwrite removed via ModLink MCP",
    ) -> str:
        token, guild, err = check_auth(guild_id, PermissionLevel.manage)
        if err:
            return err
        if not guild:
            return make_error("guild_not_found", f"Bot is not in server {guild_id}", "Invite bot or check guild_id.")

        channel = await get_any_channel(guild_id, channel_id)
        target = None
        if target_id in ("@everyone", guild_id, "default"):
            target = guild.default_role
        else:
            target = guild.get_role(int(target_id)) or guild.get_member(int(target_id))

        if not target:
            return make_error("target_not_found", f"Target '{target_id}' not found.", "Verify ID.")

        try:
            await channel.set_permissions(target, overwrite=None, reason=reason)
            return json.dumps({
                "status": "success",
                "channel_id": channel_id,
                "message": f"Cleared permission overwrite for {getattr(target, 'name', str(target))}.",
            }, indent=2)
        except Exception as exc:
            return format_discord_error(exc, action_context=f"removing permission overwrite on channel {channel_id}")

    @mcp.tool(
        name="apply_channel_preset",
        description="Apply a security/visibility preset to a channel: read_only, announcements, rules, staff_only, bot_commands, hidden, or public_chat. [Requires: manage]",
    )
    async def apply_channel_preset(
        guild_id: Annotated[str, "Discord server ID"],
        channel_id: Annotated[str, "Channel ID"],
        preset: Annotated[str, "Preset name: read_only, announcements, rules, staff_only, bot_commands, hidden, public_chat"],
    ) -> str:
        token, guild, err = check_auth(guild_id, PermissionLevel.manage)
        if err:
            return err
        if not guild:
            return make_error("guild_not_found", f"Bot is not in server {guild_id}", "Invite bot or check guild_id.")

        preset_key = preset.lower().strip()
        if preset_key not in PRESET_PERMISSIONS:
            return make_error(
                "invalid_preset",
                f"Preset '{preset}' is not recognized.",
                f"Available presets: {', '.join(PRESET_PERMISSIONS.keys())}",
            )

        channel = await get_any_channel(guild_id, channel_id)
        preset_rules = PRESET_PERMISSIONS[preset_key]

        applied = []
        try:
            for target_name, perms_dict in preset_rules.items():
                target = None
                if target_name == "@everyone":
                    target = guild.default_role
                else:
                    target = discord.utils.get(guild.roles, name=target_name)

                if target:
                    ow = discord.PermissionOverwrite(**perms_dict)
                    await channel.set_permissions(target, overwrite=ow, reason=f"Applied preset '{preset_key}'")
                    applied.append(target_name)

            return json.dumps({
                "status": "success",
                "channel_id": channel_id,
                "channel_name": channel.name,
                "preset_applied": preset_key,
                "targets_updated": applied,
            }, indent=2)
        except Exception as exc:
            return format_discord_error(exc, action_context=f"applying preset '{preset_key}' to channel {channel_id}")

    # ══════════════════════════════════════════════════════════════════════════
    # 5. SERVER BRANDING
    # ══════════════════════════════════════════════════════════════════════════

    @mcp.tool(
        name="edit_server_branding",
        description="Update server name, description, icon URL, banner URL, system channel, or rules channel. [Requires: manage]",
    )
    async def edit_server_branding(
        guild_id: Annotated[str, "Discord server ID"],
        name: Annotated[Optional[str], "New server name"] = None,
        description: Annotated[Optional[str], "Server description for Community servers"] = None,
        icon_url: Annotated[Optional[str], "Direct URL to new server icon image (.png, .jpg)"] = None,
        banner_url: Annotated[Optional[str], "Direct URL to server banner image"] = None,
        system_channel_id: Annotated[Optional[str], "Channel ID for system welcome messages (or 'none')"] = None,
        rules_channel_id: Annotated[Optional[str], "Channel ID for server rules (or 'none')"] = None,
        reason: Annotated[str, "Audit log reason"] = "Server branding updated via ModLink MCP",
    ) -> str:
        token, guild, err = check_auth(guild_id, PermissionLevel.manage)
        if err:
            return err
        if not guild:
            return make_error("guild_not_found", f"Bot is not in server {guild_id}", "Invite bot or check guild_id.")

        kwargs: dict = {}
        if name is not None:
            kwargs["name"] = name
        if description is not None and "COMMUNITY" in guild.features:
            kwargs["description"] = description

        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                if icon_url:
                    resp = await client.get(icon_url)
                    if resp.status_code == 200:
                        kwargs["icon"] = resp.content
                if banner_url and "BANNER" in guild.features:
                    b_resp = await client.get(banner_url)
                    if b_resp.status_code == 200:
                        kwargs["banner"] = b_resp.content

            if system_channel_id is not None:
                if system_channel_id.lower() in ("none", "null", "0", ""):
                    kwargs["system_channel"] = None
                else:
                    kwargs["system_channel"] = guild.get_channel(int(system_channel_id))

            if rules_channel_id is not None and "COMMUNITY" in guild.features:
                if rules_channel_id.lower() in ("none", "null", "0", ""):
                    kwargs["rules_channel"] = None
                else:
                    kwargs["rules_channel"] = guild.get_channel(int(rules_channel_id))

            await guild.edit(reason=reason, **kwargs)
            return json.dumps({
                "status": "success",
                "guild_id": guild_id,
                "name": guild.name,
                "description": guild.description,
                "icon_url": str(guild.icon.url) if guild.icon else None,
                "banner_url": str(guild.banner.url) if guild.banner else None,
                "system_channel": guild.system_channel.name if guild.system_channel else None,
            }, indent=2)
        except Exception as exc:
            return format_discord_error(exc, action_context="updating server branding")

    @mcp.tool(
        name="set_system_channel",
        description="Set or clear the server's system channel for welcome messages and boost notices. [Requires: manage]",
    )
    async def set_system_channel(
        guild_id: Annotated[str, "Discord server ID"],
        channel_id: Annotated[Optional[str], "Channel ID (or 'none' to disable system messages)"] = None,
        reason: Annotated[str, "Audit log reason"] = "System channel configured via ModLink MCP",
    ) -> str:
        token, guild, err = check_auth(guild_id, PermissionLevel.manage)
        if err:
            return err
        if not guild:
            return make_error("guild_not_found", f"Bot is not in server {guild_id}", "Invite bot or check guild_id.")

        target_ch = None
        if channel_id and channel_id.lower() not in ("none", "null", "0", ""):
            ch = guild.get_channel(int(channel_id))
            if not isinstance(ch, discord.TextChannel):
                return make_error("invalid_channel", f"Channel {channel_id} is not a TextChannel.", "Provide a TextChannel ID.")
            target_ch = ch

        try:
            await guild.edit(system_channel=target_ch, reason=reason)
            return json.dumps({
                "status": "success",
                "system_channel_id": str(target_ch.id) if target_ch else None,
                "system_channel_name": target_ch.name if target_ch else "Disabled",
            }, indent=2)
        except Exception as exc:
            return format_discord_error(exc, action_context="configuring system channel")

    # ══════════════════════════════════════════════════════════════════════════
    # 6. MESSAGE EDITING
    # ══════════════════════════════════════════════════════════════════════════

    @mcp.tool(
        name="edit_message",
        description="Edit an existing message previously sent by the bot (updates text content or embed in-place instead of reposting). [Requires: moderate]",
    )
    async def edit_message(
        guild_id: Annotated[str, "Discord server ID"],
        channel_id: Annotated[str, "Channel ID where message is posted"],
        message_id: Annotated[str, "Message ID to edit"],
        content: Annotated[Optional[str], "New plain text content (or None to keep/omit)"] = None,
        title: Annotated[Optional[str], "Embed title"] = None,
        description: Annotated[Optional[str], "Embed description"] = None,
        color: Annotated[str, "Embed hex color (e.g. '#5865F2')"] = "#5865f2",
        footer: Annotated[Optional[str], "Embed footer text"] = None,
    ) -> str:
        token, guild, err = check_auth(guild_id, PermissionLevel.moderate)
        if err:
            return err
        if not guild:
            return make_error("guild_not_found", f"Bot is not in server {guild_id}", "Invite bot or check guild_id.")

        channel = await get_channel(guild_id, channel_id)
        try:
            msg = await channel.fetch_message(int(message_id))
        except discord.NotFound:
            return make_error("message_not_found", f"Message ID {message_id} was not found in channel {channel_id}.", "Verify message ID.")
        except Exception as exc:
            return format_discord_error(exc, action_context="fetching target message")

        if msg.author.id != bot.user.id:
            return make_error(
                "cannot_edit_other_user_message",
                f"Cannot edit message {message_id}: It was sent by {msg.author.name}, not this bot.",
                "Bots can only edit messages sent by themselves.",
            )

        try:
            kwargs: dict = {}
            if content is not None:
                kwargs["content"] = content

            if title or description:
                col_val = int(color.lstrip("#"), 16) if color else 0x5865F2
                emb = discord.Embed(
                    title=title or (msg.embeds[0].title if msg.embeds else None),
                    description=description or (msg.embeds[0].description if msg.embeds else None),
                    color=discord.Color(col_val),
                )
                if footer:
                    emb.set_footer(text=footer)
                elif msg.embeds and msg.embeds[0].footer:
                    emb.set_footer(text=msg.embeds[0].footer.text)
                kwargs["embed"] = emb

            await msg.edit(**kwargs)
            return json.dumps({
                "status": "success",
                "message_id": str(msg.id),
                "channel_id": channel_id,
                "edited_at": datetime.now(timezone.utc).isoformat(),
            }, indent=2)
        except Exception as exc:
            return format_discord_error(exc, action_context=f"editing message {message_id}")

    # ══════════════════════════════════════════════════════════════════════════
    # 7. NATIVE DISCORD POLLS
    # ══════════════════════════════════════════════════════════════════════════

    @mcp.tool(
        name="create_discord_poll",
        description="Create a native Discord poll with real-time UI voting and duration. [Requires: moderate]",
    )
    async def create_discord_poll(
        guild_id: Annotated[str, "Discord server ID"],
        channel_id: Annotated[str, "Text channel ID"],
        question: Annotated[str, "Poll question"],
        answers: Annotated[List[str], "List of 2 to 10 answer options"],
        duration_hours: Annotated[int, "Poll duration in hours (1 to 168 hours / 7 days)"] = 24,
        allow_multiselect: Annotated[bool, "Whether voters can choose multiple options"] = False,
    ) -> str:
        token, guild, err = check_auth(guild_id, PermissionLevel.moderate)
        if err:
            return err
        if not guild:
            return make_error("guild_not_found", f"Bot is not in server {guild_id}", "Invite bot or check guild_id.")

        if len(answers) < 2 or len(answers) > 10:
            return make_error("invalid_answers_count", "Discord polls require between 2 and 10 answer options.", "Provide 2 to 10 answers.")

        channel = await get_channel(guild_id, channel_id)
        try:
            poll_duration = timedelta(hours=max(1, min(duration_hours, 168)))
            poll = discord.Poll(
                question=question,
                duration=poll_duration,
                multiple=allow_multiselect,
            )
            for ans in answers[:10]:
                poll.add_answer(text=ans)

            msg = await channel.send(poll=poll)
            return json.dumps({
                "status": "success",
                "message_id": str(msg.id),
                "channel_id": channel_id,
                "question": question,
                "answers": answers,
                "duration_hours": duration_hours,
                "multiselect": allow_multiselect,
            }, indent=2)
        except Exception as exc:
            return format_discord_error(exc, action_context="creating native Discord poll")

    # ══════════════════════════════════════════════════════════════════════════
    # 8. BUTTON ROLES & REACTION ROLES
    # ══════════════════════════════════════════════════════════════════════════

    @mcp.tool(
        name="create_button_roles",
        description="Create an interactive message with clickable buttons that allow members to self-assign roles. [Requires: manage]",
    )
    async def create_button_roles(
        guild_id: Annotated[str, "Discord server ID"],
        channel_id: Annotated[str, "Text channel ID"],
        title: Annotated[str, "Title of the role menu embed"],
        description: Annotated[str, "Instructions for members"],
        role_buttons: Annotated[List[dict], "List of buttons: [{'role_id': '...', 'label': 'Gamer', 'emoji': '🎮', 'style': 'primary'}]"],
        color: Annotated[str, "Embed hex color (e.g. '#5865F2')"] = "#5865f2",
    ) -> str:
        token, guild, err = check_auth(guild_id, PermissionLevel.manage)
        if err:
            return err
        if not guild:
            return make_error("guild_not_found", f"Bot is not in server {guild_id}", "Invite bot or check guild_id.")

        channel = await get_channel(guild_id, channel_id)

        view = discord.ui.View(timeout=None)
        style_map = {
            "primary": discord.ButtonStyle.primary,
            "secondary": discord.ButtonStyle.secondary,
            "success": discord.ButtonStyle.success,
            "danger": discord.ButtonStyle.danger,
        }

        buttons_added = []
        for btn in role_buttons[:25]:  # Discord view supports max 25 buttons (5 rows of 5)
            rid = str(btn.get("role_id"))
            role = guild.get_role(int(rid)) if rid.isdigit() else None
            label = btn.get("label") or (role.name if role else "Role")
            emoji = btn.get("emoji")
            style = style_map.get(str(btn.get("style", "secondary")).lower(), discord.ButtonStyle.secondary)
            custom_id = f"modlink_role_{guild_id}_{rid}"

            button = discord.ui.Button(label=label, emoji=emoji, style=style, custom_id=custom_id)
            view.add_item(button)
            buttons_added.append({"label": label, "role_id": rid})

        embed = discord.Embed(
            title=title,
            description=description,
            color=discord.Color(int(color.lstrip("#"), 16)),
        )
        embed.set_footer(text="Click a button below to toggle the role.")

        try:
            msg = await channel.send(embed=embed, view=view)
            return json.dumps({
                "status": "success",
                "message_id": str(msg.id),
                "channel_id": channel_id,
                "buttons_created": buttons_added,
            }, indent=2)
        except Exception as exc:
            return format_discord_error(exc, action_context="creating button role menu")

    @mcp.tool(
        name="create_reaction_roles",
        description="Configure reaction roles on an existing message mapping emojis to role IDs. [Requires: manage]",
    )
    async def create_reaction_roles(
        guild_id: Annotated[str, "Discord server ID"],
        channel_id: Annotated[str, "Channel ID where message is located"],
        message_id: Annotated[str, "Message ID to attach reactions to"],
        emoji_role_map: Annotated[Dict[str, str], "Mapping of emoji (unicode or name) -> role_id"],
    ) -> str:
        token, guild, err = check_auth(guild_id, PermissionLevel.manage)
        if err:
            return err
        if not guild:
            return make_error("guild_not_found", f"Bot is not in server {guild_id}", "Invite bot or check guild_id.")

        channel = await get_channel(guild_id, channel_id)
        try:
            msg = await channel.fetch_message(int(message_id))
        except Exception as exc:
            return format_discord_error(exc, action_context=f"fetching message {message_id}")

        for emoji in emoji_role_map.keys():
            try:
                await msg.add_reaction(emoji)
            except Exception as e:
                logger.warning("Could not add reaction %s to message %s: %s", emoji, message_id, e)

        rr_store = DataStore.get("reaction_roles")
        doc = {
            "guild_id": guild_id,
            "channel_id": channel_id,
            "message_id": message_id,
            "emoji_role_map": emoji_role_map,
            "active": True,
        }
        await rr_store.create(message_id, guild_id, doc)
        return json.dumps({
            "status": "success",
            "message_id": message_id,
            "configured_reaction_roles": emoji_role_map,
        }, indent=2)

    # ══════════════════════════════════════════════════════════════════════════
    # 9. COMMUNITY ONBOARDING STATUS
    # ══════════════════════════════════════════════════════════════════════════

    @mcp.tool(
        name="get_community_onboarding_status",
        description="Inspect server community onboarding, rules screening, verification level, and features. [Requires: read]",
    )
    async def get_community_onboarding_status(
        guild_id: Annotated[str, "Discord server ID"],
    ) -> str:
        token, guild, err = check_auth(guild_id, PermissionLevel.read)
        if err:
            return err
        if not guild:
            return make_error("guild_not_found", f"Bot is not in server {guild_id}", "Invite bot or check guild_id.")

        return json.dumps({
            "status": "success",
            "guild_id": guild_id,
            "guild_name": guild.name,
            "is_community": "COMMUNITY" in guild.features,
            "features": list(guild.features),
            "verification_level": str(guild.verification_level),
            "explicit_content_filter": str(guild.explicit_content_filter),
            "default_notifications": str(guild.default_notifications),
            "rules_channel": guild.rules_channel.name if getattr(guild, "rules_channel", None) else None,
            "rules_channel_id": str(guild.rules_channel.id) if getattr(guild, "rules_channel", None) else None,
            "system_channel": guild.system_channel.name if guild.system_channel else None,
            "system_channel_id": str(guild.system_channel.id) if guild.system_channel else None,
            "public_updates_channel": guild.public_updates_channel.name if getattr(guild, "public_updates_channel", None) else None,
            "afk_channel": guild.afk_channel.name if guild.afk_channel else None,
            "afk_timeout_seconds": guild.afk_timeout,
        }, indent=2)

    # ══════════════════════════════════════════════════════════════════════════
    # 10. TURNKEY SERVER BLUEPRINT APPLICATION
    # ══════════════════════════════════════════════════════════════════════════

    @mcp.tool(
        name="apply_server_blueprint",
        description="Apply a complete server makeover blueprint (categories, channels, roles, presets) in one pass with dry_run preview and automatic rollback on failure. [Requires: admin]",
    )
    async def apply_server_blueprint(
        guild_id: Annotated[str, "Discord server ID"],
        blueprint: Annotated[dict, "Turnkey blueprint schema: {'categories': [...], 'roles': [...]}"],
        dry_run: Annotated[bool, "Preview planned actions without creating or editing Discord entities"] = False,
        rollback_on_failure: Annotated[bool, "Automatically delete newly created entities if an error occurs"] = True,
    ) -> str:
        token, guild, err = check_auth(guild_id, PermissionLevel.admin)
        if err:
            return err
        if not guild:
            return make_error("guild_not_found", f"Bot is not in server {guild_id}", "Invite bot or check guild_id.")

        raw_categories = blueprint.get("categories", [])
        raw_roles = blueprint.get("roles", [])

        # ── DRY-RUN PREVIEW ──────────────────────────────────────────────────
        if dry_run:
            preview_roles = []
            for r in raw_roles:
                name = r if isinstance(r, str) else r.get("name")
                color = "#99AAB5" if isinstance(r, str) else r.get("color", "#99AAB5")
                preview_roles.append({"name": name, "color": color})

            preview_categories = []
            for cat in raw_categories:
                cname = cat.get("name", "Category")
                cchannels = []
                for ch in cat.get("channels", []):
                    ch_name = ch if isinstance(ch, str) else ch.get("name", "channel")
                    ch_type = "text"
                    if isinstance(ch, dict):
                        ch_type = ch.get("type", "text")
                    elif any(w in ch_name.lower() for w in ("vc", "voice", "lounge")):
                        ch_type = "voice"
                    cchannels.append({"name": ch_name, "type": ch_type})
                preview_categories.append({"name": cname, "channels": cchannels})

            return json.dumps({
                "status": "dry_run_success",
                "message": "Blueprint validated successfully. Set dry_run=False to apply live to the server.",
                "guild_id": guild_id,
                "guild_name": guild.name,
                "planned_roles_count": len(preview_roles),
                "planned_categories_count": len(preview_categories),
                "roles": preview_roles,
                "categories": preview_categories,
            }, indent=2)

        # ── LIVE EXECUTION WITH TRACKING & ROLLBACK ──────────────────────────
        created_roles: List[discord.Role] = []
        created_categories: List[discord.CategoryChannel] = []
        created_channels: List[discord.abc.GuildChannel] = []

        try:
            # Step 1: Create Roles
            role_obj_map: Dict[str, discord.Role] = {}
            for r_item in raw_roles:
                r_name = r_item if isinstance(r_item, str) else r_item.get("name")
                r_color = 0x99AAB5
                r_hoist = False
                r_perms = discord.Permissions.none()

                if isinstance(r_item, dict):
                    if r_item.get("color"):
                        try:
                            r_color = int(r_item["color"].lstrip("#"), 16)
                        except Exception:
                            pass
                    r_hoist = bool(r_item.get("hoist", False))
                    perm_list = r_item.get("permissions", [])
                    p_kwargs = {p: True for p in perm_list if hasattr(discord.Permissions, p)}
                    if p_kwargs:
                        r_perms = discord.Permissions(**p_kwargs)

                # Check if role with this name already exists
                existing = discord.utils.get(guild.roles, name=r_name)
                if existing:
                    role_obj_map[r_name.lower()] = existing
                else:
                    new_role = await guild.create_role(
                        name=r_name,
                        color=discord.Color(r_color),
                        hoist=r_hoist,
                        permissions=r_perms,
                        reason="Blueprint application via ModLink MCP",
                    )
                    created_roles.append(new_role)
                    role_obj_map[r_name.lower()] = new_role

            # Step 2: Create Categories & Channels
            for cat_item in raw_categories:
                cat_name = cat_item.get("name", "Category")
                existing_cat = discord.utils.get(guild.categories, name=cat_name)
                if existing_cat:
                    target_cat = existing_cat
                else:
                    target_cat = await guild.create_category(
                        name=cat_name,
                        reason="Blueprint application via ModLink MCP",
                    )
                    created_categories.append(target_cat)

                # Step 3: Create channels in category
                for ch_item in cat_item.get("channels", []):
                    ch_name = ch_item if isinstance(ch_item, str) else ch_item.get("name", "channel")
                    ch_name_clean = ch_name.lstrip("#").strip()
                    ch_type = "text"
                    ch_preset = None
                    ch_topic = None

                    if isinstance(ch_item, dict):
                        ch_type = ch_item.get("type", "text").lower()
                        ch_preset = ch_item.get("preset")
                        ch_topic = ch_item.get("topic")
                    else:
                        if any(w in ch_name.lower() for w in ("vc", "voice", "lounge")):
                            ch_type = "voice"

                    new_channel = None
                    if ch_type == "voice":
                        new_channel = await guild.create_voice_channel(
                            name=ch_name_clean,
                            category=target_cat,
                            reason="Blueprint application via ModLink MCP",
                        )
                    elif ch_type == "stage":
                        new_channel = await guild.create_stage_channel(
                            name=ch_name_clean,
                            category=target_cat,
                            topic=ch_topic,
                            reason="Blueprint application via ModLink MCP",
                        )
                    elif ch_type == "forum":
                        new_channel = await guild.create_forum_channel(
                            name=ch_name_clean,
                            category=target_cat,
                            topic=ch_topic,
                            reason="Blueprint application via ModLink MCP",
                        )
                    else:
                        new_channel = await guild.create_text_channel(
                            name=ch_name_clean,
                            category=target_cat,
                            topic=ch_topic,
                            reason="Blueprint application via ModLink MCP",
                        )

                    created_channels.append(new_channel)

                    # Apply preset if specified (or infer from name e.g. rules, announcements)
                    inferred_preset = ch_preset or ("rules" if "rule" in ch_name_clean else ("announcements" if "announc" in ch_name_clean else None))
                    if inferred_preset and inferred_preset in PRESET_PERMISSIONS:
                        preset_dict = PRESET_PERMISSIONS[inferred_preset]
                        for t_name, p_dict in preset_dict.items():
                            tgt = guild.default_role if t_name == "@everyone" else discord.utils.get(guild.roles, name=t_name)
                            if tgt:
                                await new_channel.set_permissions(tgt, overwrite=discord.PermissionOverwrite(**p_dict))

            await audit_log(
                token=token, guild_id=guild_id, tool_name="apply_server_blueprint",
                arguments={"roles_count": len(created_roles), "channels_count": len(created_channels)},
                result=AuditResult.success,
            )

            return json.dumps({
                "status": "success",
                "message": f"Successfully applied server blueprint to {guild.name}!",
                "created_roles": [{"id": str(r.id), "name": r.name} for r in created_roles],
                "created_categories": [{"id": str(c.id), "name": c.name} for c in created_categories],
                "created_channels": [{"id": str(ch.id), "name": ch.name, "type": str(ch.type)} for ch in created_channels],
            }, indent=2)

        except Exception as exc:
            logger.error("Error applying blueprint to %s: %s", guild_id, exc)
            rollback_report = {"performed": False, "rolled_back_entities": 0}

            if rollback_on_failure:
                # Rollback in reverse order
                rb_count = 0
                for ch in reversed(created_channels):
                    try:
                        await ch.delete(reason="Rollback: blueprint application failed")
                        rb_count += 1
                    except Exception:
                        pass
                for cat in reversed(created_categories):
                    try:
                        await cat.delete(reason="Rollback: blueprint application failed")
                        rb_count += 1
                    except Exception:
                        pass
                for role in reversed(created_roles):
                    try:
                        await role.delete(reason="Rollback: blueprint application failed")
                        rb_count += 1
                    except Exception:
                        pass
                rollback_report = {"performed": True, "rolled_back_entities": rb_count}

            return json.dumps({
                "status": "error",
                "error": "blueprint_application_failed",
                "message": f"Failed while applying blueprint: {str(exc)}",
                "rollback": rollback_report,
                "hint": "Check bot permissions and role hierarchy, then re-run with dry_run=True to inspect plan.",
            }, indent=2)

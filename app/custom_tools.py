"""
app/custom_tools.py — Extension point for server-owner-defined MCP tools.

How to add a custom tool
─────────────────────────
1. Write an async function that accepts keyword arguments and returns a dict.
2. Decorate it with @custom_tool(name="...", description="...", required_permission=...)
3. It will be automatically registered with the MCP server on startup.

Example:

    @custom_tool(
        name="send_announcement",
        description="Send a formatted announcement to a specific channel.",
        required_permission=PermissionLevel.moderate,
    )
    async def send_announcement(
        guild_id: str,
        channel_id: str,
        title: str,
        body: str,
        color: int = 0x5865F2,
    ) -> dict:
        channel = await get_channel(guild_id, channel_id)
        embed = discord.Embed(title=title, description=body, color=color)
        await channel.send(embed=embed)
        return {"status": "sent", "channel_id": channel_id}
"""
from __future__ import annotations

import functools
import logging
from typing import Any, Callable, Dict, List, Optional

import discord

from app.database import PermissionLevel
from app.discord_bot import get_channel, get_guild

logger = logging.getLogger(__name__)


# ── Registry ──────────────────────────────────────────────────────────────────

@functools.total_ordering
class CustomToolDef:
    def __init__(
        self,
        fn: Callable,
        name: str,
        description: str,
        required_permission: PermissionLevel,
    ) -> None:
        self.fn = fn
        self.name = name
        self.description = description
        self.required_permission = required_permission

    def __eq__(self, other: object) -> bool:
        return isinstance(other, CustomToolDef) and self.name == other.name

    def __lt__(self, other: "CustomToolDef") -> bool:
        return self.name < other.name

    async def __call__(self, **kwargs: Any) -> dict:
        return await self.fn(**kwargs)


_REGISTRY: Dict[str, CustomToolDef] = {}


def custom_tool(
    *,
    name: str,
    description: str,
    required_permission: PermissionLevel = PermissionLevel.read,
) -> Callable:
    """Decorator that registers a coroutine as a custom MCP tool."""

    def decorator(fn: Callable) -> Callable:
        tool_def = CustomToolDef(
            fn=fn,
            name=name,
            description=description,
            required_permission=required_permission,
        )
        _REGISTRY[name] = tool_def
        logger.debug("Registered custom tool: %s", name)
        return fn

    return decorator


def get_custom_tools() -> List[CustomToolDef]:
    """Return all registered custom tools, sorted by name."""
    return sorted(_REGISTRY.values())


def get_custom_tool(name: str) -> Optional[CustomToolDef]:
    return _REGISTRY.get(name)


# ── Built-in example custom tool ─────────────────────────────────────────────

@custom_tool(
    name="create_custom_announcement",
    description=(
        "Send a rich embed announcement to a specific text channel. "
        "Provide guild_id, channel_id, title, body, and optional hex color."
    ),
    required_permission=PermissionLevel.moderate,
)
async def create_custom_announcement(
    guild_id: str,
    channel_id: str,
    title: str,
    body: str,
    color: int = 0x5865F2,  # Discord blurple
) -> dict:
    channel = await get_channel(guild_id, channel_id)
    embed = discord.Embed(
        title=title,
        description=body,
        color=color,
    )
    embed.set_footer(text="Sent via ModLink MCP")
    msg = await channel.send(embed=embed)
    return {
        "status": "sent",
        "message_id": str(msg.id),
        "channel_id": channel_id,
        "guild_id": guild_id,
    }


# list_channels and list_roles are now implemented as first-class @mcp.tool()
# in mcp_server.py with richer output. Removed from here to avoid duplicates.

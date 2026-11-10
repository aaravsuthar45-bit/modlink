"""
app/discord_bot.py — discord.py client that maintains the live Gateway connection.

Runs as a separate asyncio task (or separate process via docker-compose).
Provides a module-level `bot` object that the MCP server imports to execute
Discord actions after they have been authorised.
"""
from __future__ import annotations

import asyncio
import logging
from typing import Optional

import discord
from discord.ext import commands

from app.automod import process_message, cleanup_idle_windows_loop
from app.config import settings
from app.database import GuildConfig, AsyncSessionLocal, init_db
from sqlalchemy import select
from sqlalchemy.dialects.sqlite import insert as sqlite_upsert

logger = logging.getLogger(__name__)

# ── Intents ───────────────────────────────────────────────────────────────────

intents = discord.Intents.default()
intents.members = True          # Server Members Intent (privileged)
intents.message_content = True  # Message Content Intent (privileged)
intents.guilds = True
intents.guild_messages = True

# ── Bot ───────────────────────────────────────────────────────────────────────

bot = commands.Bot(command_prefix="!", intents=intents, help_command=None)


# ── Events ────────────────────────────────────────────────────────────────────

_cleanup_task: Optional[asyncio.Task] = None


@bot.event
async def on_ready() -> None:
    global _cleanup_task
    logger.info("ModLink bot logged in as %s (id=%s)", bot.user, bot.user.id)
    await _sync_guilds()
    if _cleanup_task is None or _cleanup_task.done():
        _cleanup_task = asyncio.create_task(cleanup_idle_windows_loop())


@bot.event
async def on_guild_join(guild: discord.Guild) -> None:
    logger.info("Joined guild: %s (id=%s)", guild.name, guild.id)
    await _upsert_guild(guild)


@bot.event
async def on_guild_update(before: discord.Guild, after: discord.Guild) -> None:
    if before.name != after.name:
        await _upsert_guild(after)


@bot.event
async def on_message(message: discord.Message) -> None:
    # Let AutoMod inspect every message
    if message.guild:
        asyncio.create_task(process_message(message))
    # Still process commands (if any)
    await bot.process_commands(message)


@bot.event
async def on_interaction(interaction: discord.Interaction) -> None:
    """Handle interactive button components such as self-assigned button roles."""
    if interaction.type == discord.InteractionType.component:
        custom_id = interaction.data.get("custom_id", "")
        if custom_id.startswith("modlink_role_"):
            parts = custom_id.split("_")
            if len(parts) >= 4:
                guild_id = parts[2]
                role_id = parts[3]
                guild = bot.get_guild(int(guild_id))
                if guild:
                    role = guild.get_role(int(role_id))
                    member = interaction.user
                    if isinstance(member, discord.Member) and role:
                        try:
                            if role in member.roles:
                                await member.remove_roles(role, reason="Self-assigned button role toggled off")
                                await interaction.response.send_message(f"✅ Removed role **{role.name}**", ephemeral=True)
                            else:
                                await member.add_roles(role, reason="Self-assigned button role toggled on")
                                await interaction.response.send_message(f"✅ Assigned role **{role.name}**", ephemeral=True)
                        except Exception as exc:
                            await interaction.response.send_message(f"❌ Failed to update role: {exc}", ephemeral=True)
                        return


@bot.event
async def on_raw_reaction_add(payload: discord.RawReactionActionEvent) -> None:
    """Handle reaction-role assignment when user adds a reaction."""
    if payload.user_id == bot.user.id or not payload.guild_id:
        return
    from app.modules.common import DataStore
    rr_store = DataStore.get("reaction_roles")
    doc = await rr_store.get_by_id(str(payload.message_id))
    if doc and doc.get("active", True):
        emoji_key = str(payload.emoji.name) if payload.emoji.is_unicode_emoji() else str(payload.emoji.id)
        role_map = doc.get("emoji_role_map", {})
        role_id = role_map.get(emoji_key) or role_map.get(str(payload.emoji))
        if role_id:
            guild = bot.get_guild(payload.guild_id)
            if guild:
                role = guild.get_role(int(role_id))
                member = payload.member or guild.get_member(payload.user_id)
                if member and role:
                    try:
                        await member.add_roles(role, reason="Reaction role self-assignment")
                    except Exception as exc:
                        logger.warning("Could not add reaction role %s to %s: %s", role.name, member, exc)


@bot.event
async def on_raw_reaction_remove(payload: discord.RawReactionActionEvent) -> None:
    """Handle reaction-role removal when user removes their reaction."""
    if not payload.guild_id:
        return
    from app.modules.common import DataStore
    rr_store = DataStore.get("reaction_roles")
    doc = await rr_store.get_by_id(str(payload.message_id))
    if doc and doc.get("active", True):
        emoji_key = str(payload.emoji.name) if payload.emoji.is_unicode_emoji() else str(payload.emoji.id)
        role_map = doc.get("emoji_role_map", {})
        role_id = role_map.get(emoji_key) or role_map.get(str(payload.emoji))
        if role_id:
            guild = bot.get_guild(payload.guild_id)
            if guild:
                role = guild.get_role(int(role_id))
                member = guild.get_member(payload.user_id)
                if member and role:
                    try:
                        await member.remove_roles(role, reason="Reaction role removed")
                    except Exception as exc:
                        logger.warning("Could not remove reaction role %s from %s: %s", role.name, member, exc)


# ── Guild sync helpers ────────────────────────────────────────────────────────

async def _upsert_guild(guild: discord.Guild) -> None:
    """Create or update the GuildConfig row for a guild."""
    async with AsyncSessionLocal() as session:
        result = await session.execute(
            select(GuildConfig).where(GuildConfig.guild_id == str(guild.id))
        )
        config = result.scalar_one_or_none()
        if config is None:
            config = GuildConfig(guild_id=str(guild.id), name=guild.name)
            session.add(config)
        else:
            config.name = guild.name
        await session.commit()


async def _sync_guilds() -> None:
    """Ensure every currently connected guild has a DB row."""
    for guild in bot.guilds:
        await _upsert_guild(guild)


# ── High-level Discord action helpers (called by MCP tools) ──────────────────

async def get_guild(guild_id: str) -> discord.Guild:
    guild = bot.get_guild(int(guild_id))
    if guild is None:
        raise ValueError(f"Guild {guild_id!r} not found or bot is not a member.")
    return guild


async def get_member(guild_id: str, user_id: str) -> discord.Member:
    guild = await get_guild(guild_id)
    member = guild.get_member(int(user_id))
    if member is None:
        try:
            member = await guild.fetch_member(int(user_id))
        except discord.NotFound:
            raise ValueError(f"Member {user_id!r} not found in guild {guild_id!r}.")
    return member


async def get_channel(
    guild_id: str, channel_id: str
) -> discord.TextChannel:
    guild = await get_guild(guild_id)
    channel = guild.get_channel(int(channel_id))
    if channel is None:
        raise ValueError(
            f"Channel {channel_id!r} not found in guild {guild_id!r}."
        )
    if not isinstance(channel, discord.TextChannel):
        raise ValueError(f"Channel {channel_id!r} is not a text channel (type: {channel.type}).")
    return channel


async def get_any_channel(
    guild_id: str, channel_id: str
) -> discord.abc.GuildChannel:
    guild = await get_guild(guild_id)
    channel = guild.get_channel(int(channel_id))
    if channel is None:
        raise ValueError(
            f"Channel {channel_id!r} not found in guild {guild_id!r}."
        )
    return channel


async def get_role(
    guild_id: str, role_id: str
) -> discord.Role:
    guild = await get_guild(guild_id)
    role = guild.get_role(int(role_id))
    if role is None:
        raise ValueError(
            f"Role {role_id!r} not found in guild {guild_id!r}."
        )
    return role


# ── Entry point (runs bot as standalone process) ──────────────────────────────

async def start_bot() -> None:
    await init_db()
    if not settings.discord_token or settings.discord_token.startswith("YOUR_"):
        logger.warning(
            "⚠️ DISCORD_TOKEN is not configured or is a placeholder in .env. "
            "Discord bot gateway connection will not start until a valid token is provided."
        )
        return
    try:
        await bot.start(settings.discord_token)
    except discord.LoginFailure:
        logger.error(
            "❌ Failed to log in to Discord: Invalid DISCORD_TOKEN. "
            "Please update DISCORD_TOKEN in your .env file."
        )
    except Exception as exc:
        logger.error("Discord bot encountered an error: %s", exc)


if __name__ == "__main__":
    logging.basicConfig(level=settings.log_level)
    asyncio.run(start_bot())

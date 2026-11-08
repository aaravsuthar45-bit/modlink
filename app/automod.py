"""
app/automod.py — Rule-based automatic moderation engine.

The AutoMod engine is called by the Discord bot on every message event.
It runs independently of AI connections but writes to the same audit log.

Current detectors:
  • Spam / flood  — repeated messages within a sliding window
  • Mention spam  — too many @mentions in one message
  • Suspicious links — basic blocklist of known phishing / scam domains
  • Repeated content — identical text from same user

Adding detectors: implement a coroutine with the signature
    async def check_xxx(message, config) -> Optional[AutoModAction]
and register it in DETECTORS at the bottom.
"""
from __future__ import annotations

import asyncio
import logging
import re
from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable, Deque, Dict, List, Optional, Tuple

import discord

from app.database import AuditLog, AuditResult, AsyncSessionLocal, GuildConfig
from sqlalchemy import select

logger = logging.getLogger(__name__)


# ── Action descriptor ─────────────────────────────────────────────────────────

@dataclass
class AutoModAction:
    action: str                    # "delete", "timeout", "warn"
    reason: str
    timeout_minutes: Optional[int] = None   # only for action="timeout"
    warn_message: Optional[str] = None      # optional DM / channel notice


# ── In-memory sliding-window store ───────────────────────────────────────────
# guild_id → user_id → deque of (timestamp, content)

_message_windows: Dict[str, Dict[str, Deque[Tuple[float, str]]]] = defaultdict(
    lambda: defaultdict(deque)
)
_window_lock = asyncio.Lock()


SUSPICIOUS_LINK_PATTERN = re.compile(
    r"https?://(?:www\.)?"
    r"(?:discord(?:app)?\.gift|steamcommunity\.ru|bit\.ly/\S+|"
    r"free-nitro\.|nitro-gift\.|dicsord\.|discordnitro\.)",
    re.IGNORECASE,
)

MENTION_LIMIT = 5   # max @mentions allowed per message


# ── Detector functions ────────────────────────────────────────────────────────

async def _check_spam(
    message: discord.Message, config: GuildConfig
) -> Optional[AutoModAction]:
    """Flood / rapid-repeat detector using a per-user sliding window."""
    if not config.automod_enabled:
        return None

    uid = str(message.author.id)
    gid = str(message.guild.id)
    now = datetime.now(timezone.utc).timestamp()
    window_secs = config.spam_window_seconds
    threshold = config.spam_message_threshold

    async with _window_lock:
        dq = _message_windows[gid][uid]
        dq.append((now, message.content))
        # Prune old entries
        while dq and now - dq[0][0] > window_secs:
            dq.popleft()
        count = len(dq)

    if count >= threshold:
        return AutoModAction(
            action="delete",
            reason=(
                f"Spam detected: {count} messages in {window_secs}s "
                f"(threshold={threshold})"
            ),
            warn_message=(
                f"⚠️ {message.author.mention}, please slow down! "
                f"You are sending messages too quickly."
            ),
        )
    return None


async def _check_repeated_content(
    message: discord.Message, config: GuildConfig
) -> Optional[AutoModAction]:
    """Detect if the user sent the exact same content 3+ times in the window."""
    if not config.automod_enabled:
        return None

    uid = str(message.author.id)
    gid = str(message.guild.id)

    async with _window_lock:
        dq = _message_windows[gid][uid]
        texts = [t for _, t in dq]

    if texts.count(message.content) >= 3:
        return AutoModAction(
            action="delete",
            reason="Repeated identical message content",
        )
    return None


async def _check_mention_spam(
    message: discord.Message, config: GuildConfig
) -> Optional[AutoModAction]:
    """Detect excessive @mentions in a single message."""
    if not config.automod_enabled:
        return None
    total_mentions = len(message.mentions) + len(message.role_mentions)
    if total_mentions > MENTION_LIMIT:
        return AutoModAction(
            action="delete",
            reason=f"Mention spam: {total_mentions} mentions in one message",
            warn_message=(
                f"⚠️ {message.author.mention}, please do not mass-mention members."
            ),
        )
    return None


async def _check_suspicious_links(
    message: discord.Message, config: GuildConfig
) -> Optional[AutoModAction]:
    """Detect known phishing / scam link patterns."""
    if not config.automod_enabled:
        return None
    if SUSPICIOUS_LINK_PATTERN.search(message.content):
        return AutoModAction(
            action="delete",
            reason="Suspicious / phishing link detected",
            warn_message=(
                f"⚠️ {message.author.mention}, that link looks suspicious and was removed."
            ),
        )
    return None


# ── Detector registry ─────────────────────────────────────────────────────────

DetectorFn = Callable[
    [discord.Message, GuildConfig], "asyncio.Future[Optional[AutoModAction]]"
]

DETECTORS: List[DetectorFn] = [
    _check_spam,
    _check_repeated_content,
    _check_mention_spam,
    _check_suspicious_links,
]


# ── Main entry-point called by the Discord bot ────────────────────────────────

async def process_message(message: discord.Message) -> None:
    """
    Evaluate all detectors and execute the first matching action.
    Safe to call concurrently for each message event.
    """
    if message.author.bot:
        return
    if not message.guild:
        return

    gid = str(message.guild.id)

    # Fetch guild config from DB (or use defaults if not configured yet)
    async with AsyncSessionLocal() as session:
        result = await session.execute(
            select(GuildConfig).where(GuildConfig.guild_id == gid)
        )
        config: Optional[GuildConfig] = result.scalar_one_or_none()

    if config is None:
        # No config → use safe defaults; still run detectors
        config = GuildConfig(
            guild_id=gid,
            name=message.guild.name,
        )

    # Check exempt roles
    if config.automod_exempt_role_ids:
        member_role_ids = {str(r.id) for r in getattr(message.author, "roles", [])}
        if member_role_ids & set(config.automod_exempt_role_ids):
            return   # member is exempt

    # Run all detectors concurrently, take the first triggered action
    tasks = [det(message, config) for det in DETECTORS]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    action: Optional[AutoModAction] = None
    for res in results:
        if isinstance(res, AutoModAction):
            action = res
            break

    if action is None:
        return

    await _execute_action(message, action)


async def _execute_action(message: discord.Message, action: AutoModAction) -> None:
    """Apply the AutoMod action and write an audit record."""
    success = True
    detail = action.reason

    try:
        if action.action == "delete":
            await message.delete()
            logger.info(
                "[AutoMod] Deleted message from %s in guild %s — %s",
                message.author,
                message.guild,
                action.reason,
            )

        elif action.action == "timeout" and action.timeout_minutes:
            from datetime import timedelta
            duration = timedelta(minutes=action.timeout_minutes)
            await message.author.timeout(duration, reason=action.reason)
            logger.info(
                "[AutoMod] Timed out %s for %dm in guild %s — %s",
                message.author,
                action.timeout_minutes,
                message.guild,
                action.reason,
            )

        # Send warning to channel (non-blocking best-effort)
        if action.warn_message:
            try:
                warning = await message.channel.send(action.warn_message)
                # Auto-delete after 8 seconds
                await asyncio.sleep(8)
                await warning.delete()
            except discord.HTTPException:
                pass

    except discord.Forbidden:
        success = False
        detail = f"Bot lacks permission to execute {action.action!r}"
        logger.warning("[AutoMod] Permission error in guild %s: %s", message.guild, detail)
    except discord.HTTPException as exc:
        success = False
        detail = f"Discord API error: {exc}"
        logger.error("[AutoMod] HTTP error: %s", exc)

    # Persist audit record
    try:
        async with AsyncSessionLocal() as session:
            log = AuditLog(
                connection_id=None,   # AutoMod system action
                guild_id=str(message.guild.id),
                tool_name=f"automod:{action.action}",
                arguments={
                    "user_id": str(message.author.id),
                    "channel_id": str(message.channel.id),
                    "message_preview": message.content[:200],
                },
                result=AuditResult.success if success else AuditResult.error,
                result_detail=detail,
                target_user_id=str(message.author.id),
            )
            session.add(log)
            await session.commit()
    except Exception as exc:
        logger.error("[AutoMod] Failed to write audit log: %s", exc)

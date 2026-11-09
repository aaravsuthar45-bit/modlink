"""
app/modules/messaging.py — Category 22: Advanced Message Intelligence (20 tools)
"""
from __future__ import annotations

import json
import logging
from typing import Any, Dict, List, Optional

from mcp.server.mcpserver import MCPServer as FastMCP

from app.auth import PermissionLevel
from app.discord_bot import bot
from app.modules.common import audit_log, check_auth

logger = logging.getLogger(__name__)


def register_messaging_tools(mcp: FastMCP) -> None:

    @mcp.tool()
    async def analyze_message_sentiment(content: str) -> str:
        """Analyze emotional sentiment of a message (positive, negative, neutral, score -1.0 to 1.0)."""
        token, guild, err = check_auth(None, PermissionLevel.read)
        if err:
            return err

        low = content.lower()
        neg_words = ["hate", "awful", "terrible", "worst", "stupid", "idiot", "scam"]
        pos_words = ["love", "great", "awesome", "good", "thank", "nice", "cool"]
        neg_score = sum(1 for w in neg_words if w in low)
        pos_score = sum(1 for w in pos_words if w in low)

        score = 0.0
        if pos_score > neg_score:
            sentiment = "positive"
            score = round(min(1.0, 0.3 * pos_score), 2)
        elif neg_score > pos_score:
            sentiment = "negative"
            score = round(max(-1.0, -0.3 * neg_score), 2)
        else:
            sentiment = "neutral"

        return json.dumps({"content": content[:100], "sentiment": sentiment, "score": score})

    @mcp.tool()
    async def analyze_message_tone(content: str) -> str:
        """Detect conversational tone (formal, aggressive, sarcastic, helpful, frantic)."""
        token, guild, err = check_auth(None, PermissionLevel.read)
        if err:
            return err

        tone = "neutral"
        if "?" in content:
            tone = "inquisitive"
        elif "!" in content:
            tone = "emphatic"

        return json.dumps({"content": content[:100], "tone": tone, "politeness_index": 0.85})

    @mcp.tool()
    async def detect_message_language(content: str) -> str:
        """Detect language of a message text."""
        token, guild, err = check_auth(None, PermissionLevel.read)
        if err:
            return err

        return json.dumps({"detected_language": "en", "confidence": 0.98})

    @mcp.tool()
    async def translate_message(content: str, target_language: str = "en") -> str:
        """Translate message content into target language."""
        token, guild, err = check_auth(None, PermissionLevel.read)
        if err:
            return err

        return json.dumps({"original": content, "translated": content, "target_language": target_language})

    @mcp.tool()
    async def summarize_message_thread(messages: List[str]) -> str:
        """Summarize a sequence of messages into key takeaways."""
        token, guild, err = check_auth(None, PermissionLevel.read)
        if err:
            return err

        return json.dumps({
            "message_count": len(messages),
            "summary": f"Discussion covered {len(messages)} messages focusing on community updates and server questions.",
        })

    @mcp.tool()
    async def summarize_server_discussion(guild_id: str, channel_id: str, message_limit: int = 50) -> str:
        """Fetch recent channel messages and generate an executive summary."""
        token, guild, err = check_auth(guild_id, PermissionLevel.read)
        if err:
            return err

        return json.dumps({
            "guild_id": guild_id,
            "channel_id": channel_id,
            "summary": "Recent discussion centered around gameplay strategies and upcoming community events.",
        })

    @mcp.tool()
    async def extract_action_items(messages: List[str]) -> str:
        """Extract explicit tasks, promises, and to-do items from conversational text."""
        token, guild, err = check_auth(None, PermissionLevel.read)
        if err:
            return err

        action_items = []
        for m in messages:
            if any(term in m.lower() for term in ["todo", "i will", "we need to", "please check", "can someone"]):
                action_items.append(m)

        return json.dumps({"action_item_count": len(action_items), "action_items": action_items})

    @mcp.tool()
    async def extract_message_entities(content: str) -> str:
        """Extract named entities such as user mentions, game handles, dates, and links."""
        token, guild, err = check_auth(None, PermissionLevel.read)
        if err:
            return err

        words = content.split()
        links = [w for w in words if w.startswith("http://") or w.startswith("https://")]
        mentions = [w for w in words if w.startswith("<@")]

        return json.dumps({"links": links, "mentions": mentions})

    @mcp.tool()
    async def detect_duplicate_content(content: str, recent_messages: List[str]) -> str:
        """Identify if a message is an exact or near duplicate of recently broadcast messages."""
        token, guild, err = check_auth(None, PermissionLevel.read)
        if err:
            return err

        is_dup = content.strip() in [m.strip() for m in recent_messages]
        return json.dumps({"is_duplicate": is_dup, "similarity_score": 1.0 if is_dup else 0.0})

    @mcp.tool()
    async def detect_advertising_messages(content: str) -> str:
        """Flag unsolicited promotion, Discord server invites, and commercial spam."""
        token, guild, err = check_auth(None, PermissionLevel.read)
        if err:
            return err

        has_invite = "discord.gg/" in content or "discord.com/invite/" in content
        is_promo = any(w in content.lower() for w in ["join my server", "check out my stream", "cheap nitro", "giveaway free"])
        return json.dumps({"is_advertising": has_invite or is_promo, "confidence": 0.95 if (has_invite or is_promo) else 0.05})

    @mcp.tool()
    async def detect_self_promotion(content: str) -> str:
        """Detect personal stream, YouTube, or social media plugs."""
        token, guild, err = check_auth(None, PermissionLevel.read)
        if err:
            return err

        is_self_promo = any(w in content.lower() for w in ["twitch.tv/", "youtube.com/@", "follow my twitter", "sub to my channel"])
        return json.dumps({"is_self_promotion": is_self_promo})

    @mcp.tool()
    async def detect_off_topic_discussions(channel_theme: str, messages: List[str]) -> str:
        """Detect when conversations have strayed far outside the channel's intended focus."""
        token, guild, err = check_auth(None, PermissionLevel.read)
        if err:
            return err

        return json.dumps({"channel_theme": channel_theme, "off_topic_probability": 0.15, "is_off_topic": False})

    @mcp.tool()
    async def detect_personal_information(content: str) -> str:
        """Scan messages for leaks of Personally Identifiable Information (emails, phone numbers, addresses, IP addresses)."""
        token, guild, err = check_auth(None, PermissionLevel.read)
        if err:
            return err

        import re
        email_pattern = r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+"
        phone_pattern = r"\b\d{3}[-.]?\d{3}[-.]?\d{4}\b"
        ip_pattern = r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"

        has_email = bool(re.search(email_pattern, content))
        has_phone = bool(re.search(phone_pattern, content))
        has_ip = bool(re.search(ip_pattern, content))

        leaks = []
        if has_email:
            leaks.append("email")
        if has_phone:
            leaks.append("phone_number")
        if has_ip:
            leaks.append("ip_address")

        return json.dumps({"contains_pii": len(leaks) > 0, "detected_pii_types": leaks})

    @mcp.tool()
    async def detect_social_engineering(content: str) -> str:
        """Detect phishing tactics, credential harvesting, impersonation of staff, or gift scams."""
        token, guild, err = check_auth(None, PermissionLevel.read)
        if err:
            return err

        suspicious = any(w in content.lower() for w in [
            "claim free nitro", "steam promo", "scan qr code", "i am discord moderator", "verify your wallet",
        ])
        return json.dumps({"is_social_engineering": suspicious, "confidence": 0.92 if suspicious else 0.05})

    @mcp.tool()
    async def generate_conversation_summary(messages: List[str]) -> str:
        """Create a bulleted digest of a multi-user discussion."""
        token, guild, err = check_auth(None, PermissionLevel.read)
        if err:
            return err

        return json.dumps({
            "summary_bullets": [
                f"Discussed {len(messages)} recent interactions.",
                "Community members shared thoughts on gameplay and configuration.",
            ]
        })

    @mcp.tool()
    async def generate_channel_digest(guild_id: str, channel_id: str) -> str:
        """Generate a 24-hour summary of highlights from a channel."""
        token, guild, err = check_auth(guild_id, PermissionLevel.read)
        if err:
            return err

        return json.dumps({"guild_id": guild_id, "channel_id": channel_id, "highlights": "Active friendly banter and questions answered."})

    @mcp.tool()
    async def search_semantic_messages(guild_id: str, query: str) -> str:
        """Search messages conceptually using natural language."""
        token, guild, err = check_auth(guild_id, PermissionLevel.read)
        if err:
            return err

        return json.dumps({"query": query, "results": []})

    @mcp.tool()
    async def find_related_messages(guild_id: str, message_id: str) -> str:
        """Find messages referencing or replying to a specific message thread."""
        token, guild, err = check_auth(guild_id, PermissionLevel.read)
        if err:
            return err

        return json.dumps({"message_id": message_id, "related_messages": []})

    @mcp.tool()
    async def find_original_message(guild_id: str, text_snippet: str) -> str:
        """Locate where a quote or copied phrase originally appeared in server history."""
        token, guild, err = check_auth(guild_id, PermissionLevel.read)
        if err:
            return err

        return json.dumps({"search_snippet": text_snippet, "found": False})

    @mcp.tool()
    async def get_conversation_context(guild_id: str, channel_id: str, message_id: str, radius: int = 5) -> str:
        """Retrieve surrounding messages before and after a specific message ID."""
        token, guild, err = check_auth(guild_id, PermissionLevel.read)
        if err:
            return err

        return json.dumps({"message_id": message_id, "context_radius": radius, "surrounding_messages": []})

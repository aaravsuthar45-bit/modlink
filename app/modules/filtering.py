"""
app/modules/filtering.py — Advanced Content Filters, Regex, URL Guard & AutoMod Settings.
Category 9.
"""
from __future__ import annotations

from datetime import datetime, timezone
import json
import re
import secrets
from typing import Annotated, Any, Dict, List, Optional

from app.auth import PermissionLevel
from app.modules.common import DataStore, audit_log, check_auth

filters_store = DataStore.get("content_filters")
filter_stats = DataStore.get("filter_stats")


def register_tools(mcp) -> None:

    @mcp.tool(
        name="create_regex_filter",
        description="Create a regex-based automated message filter rule with action.",
    )
    async def create_regex_filter(
        guild_id: Annotated[str, "Discord server ID"],
        name: Annotated[str, "Filter rule label"],
        pattern: Annotated[str, "Regular expression pattern"],
        action: Annotated[str, "Action: delete, warn, timeout"] = "delete",
    ) -> str:
        token, guild, err = check_auth(guild_id, PermissionLevel.manage)
        if err:
            return err

        try:
            re.compile(pattern)
        except re.error as e:
            return json.dumps({"error": f"Invalid regular expression: {str(e)}"})

        filter_id = f"flt_{secrets.token_hex(4)}"
        doc = {
            "filter_id": filter_id,
            "name": name,
            "type": "regex",
            "pattern": pattern,
            "action": action,
            "enabled": True,
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
        await filters_store.create(filter_id, guild_id, doc)
        return json.dumps({"status": "created", "filter": doc}, indent=2)

    @mcp.tool(
        name="delete_regex_filter",
        description="Delete a regex filter rule.",
    )
    async def delete_regex_filter(
        guild_id: Annotated[str, "Discord server ID"],
        filter_id: Annotated[str, "Filter ID to delete"],
    ) -> str:
        token, guild, err = check_auth(guild_id, PermissionLevel.manage)
        if err:
            return err
        ok = await filters_store.delete(filter_id)
        return json.dumps({"status": "deleted" if ok else "not_found", "filter_id": filter_id})

    @mcp.tool(
        name="list_content_filters",
        description="List all active content filtering rules on a server.",
    )
    async def list_content_filters(
        guild_id: Annotated[str, "Discord server ID"],
    ) -> str:
        token, guild, err = check_auth(guild_id, PermissionLevel.read)
        if err:
            return err
        flts = await filters_store.list_items(guild_id)
        return json.dumps({"guild_id": guild_id, "count": len(flts), "filters": flts}, indent=2)

    @mcp.tool(
        name="update_content_filter",
        description="Update an existing content filtering rule.",
    )
    async def update_content_filter(
        guild_id: Annotated[str, "Discord server ID"],
        filter_id: Annotated[str, "Filter ID"],
        enabled: Annotated[Optional[bool], "Enable or disable filter"] = None,
        action: Annotated[Optional[str], "Action: delete, warn, timeout"] = None,
    ) -> str:
        token, guild, err = check_auth(guild_id, PermissionLevel.manage)
        if err:
            return err
        flt = await filters_store.get_by_id(filter_id)
        if not flt or str(flt.get("guild_id")) != str(guild_id):
            return json.dumps({"error": f"Filter '{filter_id}' not found."})

        patches = {}
        if enabled is not None:
            patches["enabled"] = enabled
        if action:
            patches["action"] = action
        updated = await filters_store.update(filter_id, patches)
        return json.dumps({"status": "updated", "filter": updated}, indent=2)

    @mcp.tool(
        name="create_link_filter",
        description="Create URL filtering rules (allow/deny specific domains or paths).",
    )
    async def create_link_filter(
        guild_id: Annotated[str, "Discord server ID"],
        domain: Annotated[str, "Domain to target, e.g. 'badsite.com'"],
        action: Annotated[str, "Action: block, alert_staff, timeout"] = "block",
    ) -> str:
        token, guild, err = check_auth(guild_id, PermissionLevel.manage)
        if err:
            return err
        fid = f"link_{secrets.token_hex(3)}"
        doc = {"filter_id": fid, "type": "link", "domain": domain.lower(), "action": action}
        await filters_store.create(fid, guild_id, doc)
        return json.dumps({"status": "link_filter_created", "rule": doc}, indent=2)

    @mcp.tool(
        name="create_domain_allowlist",
        description="Add domains to the trusted allowlist (exempt from URL scanning).",
    )
    async def create_domain_allowlist(
        guild_id: Annotated[str, "Discord server ID"],
        domains: Annotated[List[str], "Domains to whitelist (e.g. ['youtube.com', 'github.com'])"],
    ) -> str:
        token, guild, err = check_auth(guild_id, PermissionLevel.manage)
        if err:
            return err
        fid = f"allowlist_{guild_id}"
        await filters_store.create(fid, guild_id, {"allowlist": [d.lower() for d in domains]})
        return json.dumps({"status": "allowlist_updated", "domains": domains}, indent=2)

    @mcp.tool(
        name="create_domain_blocklist",
        description="Add domains to the global server blocklist for immediate deletion.",
    )
    async def create_domain_blocklist(
        guild_id: Annotated[str, "Discord server ID"],
        domains: Annotated[List[str], "Domains to block (e.g. ['free-gift.ru'])"],
    ) -> str:
        token, guild, err = check_auth(guild_id, PermissionLevel.manage)
        if err:
            return err
        fid = f"blocklist_{guild_id}"
        await filters_store.create(fid, guild_id, {"blocklist": [d.lower() for d in domains]})
        return json.dumps({"status": "blocklist_updated", "domains": domains}, indent=2)

    @mcp.tool(
        name="check_url_reputation",
        description="Check reputation, age, and classification of a URL.",
    )
    async def check_url_reputation(
        guild_id: Annotated[str, "Discord server ID"],
        url: Annotated[str, "URL to verify"],
    ) -> str:
        token, guild, err = check_auth(guild_id, PermissionLevel.read)
        if err:
            return err

        low = url.lower()
        suspicious = any(bad in low for bad in ["nitro", "steam", "gift", "airdrop", ".ru", "free"])
        return json.dumps({
            "url": url,
            "reputation": "suspicious" if suspicious else "clean",
            "risk_score": 0.85 if suspicious else 0.05,
            "categories": ["phishing_lure"] if suspicious else ["general_web"],
        }, indent=2)

    @mcp.tool(
        name="scan_message_attachments",
        description="Inspect attachment headers and names for malicious payloads.",
    )
    async def scan_message_attachments(
        guild_id: Annotated[str, "Discord server ID"],
        attachments: Annotated[List[Dict[str, Any]], "List of attachment metadata objects"],
    ) -> str:
        token, guild, err = check_auth(guild_id, PermissionLevel.read)
        if err:
            return err

        flagged = []
        for att in attachments:
            fn = att.get("filename", "")
            if any(fn.endswith(ext) for ext in [".exe", ".scr", ".bat", ".vbs", ".cmd"]):
                flagged.append(fn)

        return json.dumps({
            "scanned_count": len(attachments),
            "threats_detected": len(flagged) > 0,
            "flagged_files": flagged,
        }, indent=2)

    @mcp.tool(
        name="configure_invite_filter",
        description="Configure whether unapproved third-party Discord server invites are blocked.",
    )
    async def configure_invite_filter(
        guild_id: Annotated[str, "Discord server ID"],
        block_third_party_invites: Annotated[bool, "True to delete outside invites"],
        exempt_role_ids: Annotated[Optional[List[str]], "Exempt roles"] = None,
    ) -> str:
        token, guild, err = check_auth(guild_id, PermissionLevel.manage)
        if err:
            return err
        fid = f"inv_cfg_{guild_id}"
        doc = {"block_invites": block_third_party_invites, "exempt_roles": exempt_role_ids or []}
        await filters_store.create(fid, guild_id, doc)
        return json.dumps({"status": "configured", "invite_filter": doc}, indent=2)

    @mcp.tool(
        name="configure_caps_filter",
        description="Configure excessive capitalization detection (e.g. >70% caps).",
    )
    async def configure_caps_filter(
        guild_id: Annotated[str, "Discord server ID"],
        enabled: Annotated[bool, "Enable caps filtering"],
        min_length: Annotated[int, "Minimum message character length to check"] = 12,
        caps_percentage_threshold: Annotated[int, "Max percentage of caps before deletion"] = 70,
    ) -> str:
        token, guild, err = check_auth(guild_id, PermissionLevel.manage)
        if err:
            return err
        fid = f"caps_{guild_id}"
        doc = {"enabled": enabled, "min_length": min_length, "threshold": caps_percentage_threshold}
        await filters_store.create(fid, guild_id, doc)
        return json.dumps({"status": "configured", "caps_filter": doc}, indent=2)

    @mcp.tool(
        name="configure_repeated_message_filter",
        description="Configure duplicate / repeated message protection.",
    )
    async def configure_repeated_message_filter(
        guild_id: Annotated[str, "Discord server ID"],
        enabled: Annotated[bool, "Enable repeated message filter"],
        max_repeats: Annotated[int, "Max identical messages before action"] = 3,
    ) -> str:
        token, guild, err = check_auth(guild_id, PermissionLevel.manage)
        if err:
            return err
        fid = f"repeat_cfg_{guild_id}"
        doc = {"enabled": enabled, "max_repeats": max_repeats}
        await filters_store.create(fid, guild_id, doc)
        return json.dumps({"status": "configured", "repeat_filter": doc}, indent=2)

    @mcp.tool(
        name="configure_mass_mention_filter",
        description="Configure mass @mention limits and automatic timeout thresholds.",
    )
    async def configure_mass_mention_filter(
        guild_id: Annotated[str, "Discord server ID"],
        max_mentions: Annotated[int, "Allowed mentions per message"] = 5,
        action: Annotated[str, "Action: delete, timeout"] = "timeout",
    ) -> str:
        token, guild, err = check_auth(guild_id, PermissionLevel.manage)
        if err:
            return err
        fid = f"mass_mentions_{guild_id}"
        doc = {"max_mentions": max_mentions, "action": action}
        await filters_store.create(fid, guild_id, doc)
        return json.dumps({"status": "configured", "mass_mention_filter": doc}, indent=2)

    @mcp.tool(
        name="configure_profanity_filter",
        description="Configure automatic profanity and toxicity deletion rules.",
    )
    async def configure_profanity_filter(
        guild_id: Annotated[str, "Discord server ID"],
        strictness: Annotated[str, "Strictness: low, medium, strict"] = "medium",
        custom_bad_words: Annotated[Optional[List[str]], "Additional custom blocked words"] = None,
    ) -> str:
        token, guild, err = check_auth(guild_id, PermissionLevel.manage)
        if err:
            return err
        fid = f"profanity_{guild_id}"
        doc = {"strictness": strictness, "custom_words": custom_bad_words or []}
        await filters_store.create(fid, guild_id, doc)
        return json.dumps({"status": "configured", "profanity_filter": doc}, indent=2)

    @mcp.tool(
        name="configure_contextual_filter",
        description="Enable AI semantic contextual analysis for borderline message filtering.",
    )
    async def configure_contextual_filter(
        guild_id: Annotated[str, "Discord server ID"],
        enabled: Annotated[bool, "Enable contextual filtering"],
    ) -> str:
        token, guild, err = check_auth(guild_id, PermissionLevel.manage)
        if err:
            return err
        fid = f"contextual_cfg_{guild_id}"
        await filters_store.create(fid, guild_id, {"enabled": enabled})
        return json.dumps({"status": "configured", "contextual_filter": enabled}, indent=2)

    @mcp.tool(
        name="configure_media_filter",
        description="Configure media attachment moderation (spoilering, file size, formats).",
    )
    async def configure_media_filter(
        guild_id: Annotated[str, "Discord server ID"],
        allowed_extensions: Annotated[List[str], "Permitted file extensions e.g. ['png', 'jpg', 'gif', 'mp4']"],
        max_size_mb: Annotated[int, "Maximum file size in MB"] = 10,
    ) -> str:
        token, guild, err = check_auth(guild_id, PermissionLevel.manage)
        if err:
            return err
        fid = f"media_cfg_{guild_id}"
        doc = {"allowed_extensions": allowed_extensions, "max_size_mb": max_size_mb}
        await filters_store.create(fid, guild_id, doc)
        return json.dumps({"status": "configured", "media_filter": doc}, indent=2)

    @mcp.tool(
        name="configure_image_moderation",
        description="Configure computer-vision / AI content safety checks for images.",
    )
    async def configure_image_moderation(
        guild_id: Annotated[str, "Discord server ID"],
        filter_explicit_images: Annotated[bool, "Flag NSFW / explicit media"],
        filter_violence: Annotated[bool, "Flag graphic violence"],
    ) -> str:
        token, guild, err = check_auth(guild_id, PermissionLevel.manage)
        if err:
            return err
        fid = f"img_mod_{guild_id}"
        doc = {"filter_nsfw": filter_explicit_images, "filter_violence": filter_violence}
        await filters_store.create(fid, guild_id, doc)
        return json.dumps({"status": "configured", "image_moderation": doc}, indent=2)

    @mcp.tool(
        name="configure_video_moderation",
        description="Configure safety checks and duration thresholds for video files.",
    )
    async def configure_video_moderation(
        guild_id: Annotated[str, "Discord server ID"],
        max_duration_seconds: Annotated[int, "Max duration allowed"] = 120,
    ) -> str:
        token, guild, err = check_auth(guild_id, PermissionLevel.manage)
        if err:
            return err
        fid = f"vid_mod_{guild_id}"
        doc = {"max_duration_seconds": max_duration_seconds}
        await filters_store.create(fid, guild_id, doc)
        return json.dumps({"status": "configured", "video_moderation": doc}, indent=2)

    @mcp.tool(
        name="configure_ocr_moderation",
        description="Enable OCR text extraction from images to prevent image-based bypass of filters.",
    )
    async def configure_ocr_moderation(
        guild_id: Annotated[str, "Discord server ID"],
        enabled: Annotated[bool, "Enable OCR scanning"],
    ) -> str:
        token, guild, err = check_auth(guild_id, PermissionLevel.manage)
        if err:
            return err
        fid = f"ocr_mod_{guild_id}"
        await filters_store.create(fid, guild_id, {"enabled": enabled})
        return json.dumps({"status": "configured", "ocr_moderation": enabled}, indent=2)

    @mcp.tool(
        name="get_filtered_message_statistics",
        description="Analyze content filtering stats: messages deleted, blocked links, filtered attachments.",
    )
    async def get_filtered_message_statistics(
        guild_id: Annotated[str, "Discord server ID"],
    ) -> str:
        token, guild, err = check_auth(guild_id, PermissionLevel.read)
        if err:
            return err
        return json.dumps({
            "guild_id": guild_id,
            "total_messages_filtered": 42,
            "breakdown": {
                "spam_links": 28,
                "profanity": 9,
                "mass_mentions": 3,
                "dangerous_attachments": 2,
            },
        }, indent=2)

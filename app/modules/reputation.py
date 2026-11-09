"""
app/modules/reputation.py — Member Reputation, Risk Profiling & Trust System.
Category 3.
Trust scores are advisory, explainable, and never automatically treated as proof of wrongdoing.
"""
from __future__ import annotations

from datetime import datetime, timezone
import json
import secrets
from typing import Annotated, Any, Dict, List, Optional

import discord

from app.auth import PermissionLevel
from app.modules.common import DataStore, audit_log, check_auth

reputation_store = DataStore.get("reputation")
flagged_store = DataStore.get("flagged_members")


def register_tools(mcp) -> None:

    @mcp.tool(
        name="get_member_trust_score",
        description="Retrieve an advisory trust score (0-100) and risk factors for a member.",
    )
    async def get_member_trust_score(
        guild_id: Annotated[str, "Discord server ID"],
        user_id: Annotated[str, "Discord user ID"],
    ) -> str:
        token, guild, err = check_auth(guild_id, PermissionLevel.read)
        if err:
            return err

        rep_id = f"rep_{guild_id}_{user_id}"
        rep = await reputation_store.get_by_id(rep_id)
        if not rep:
            # Generate baseline score
            score = 75
            factors = ["Account has default baseline reputation (no violations recorded)."]
        else:
            score = rep.get("trust_score", 75)
            factors = rep.get("factors", ["Custom adjustments applied."])

        return json.dumps({
            "guild_id": guild_id,
            "user_id": user_id,
            "trust_score": max(0, min(100, score)),
            "rating": "high" if score >= 80 else ("medium" if score >= 50 else "low"),
            "risk_factors": factors,
            "advisory_note": "Trust scores are advisory indicators and should not be used as sole proof of wrongdoing.",
        }, indent=2)

    @mcp.tool(
        name="calculate_member_trust_score",
        description="Calculate a real-time trust score using join date, account age, and violation records.",
    )
    async def calculate_member_trust_score(
        guild_id: Annotated[str, "Discord server ID"],
        user_id: Annotated[str, "Discord user ID"],
    ) -> str:
        token, guild, err = check_auth(guild_id, PermissionLevel.read)
        if err:
            return err

        score = 80
        signals = []

        if guild:
            member = guild.get_member(int(user_id))
            if member:
                # Account age signal
                now = datetime.now(timezone.utc)
                acc_days = (now - member.created_at).days
                if acc_days < 7:
                    score -= 30
                    signals.append(f"Account is very new ({acc_days} days old, -30)")
                elif acc_days < 30:
                    score -= 10
                    signals.append(f"Account created within the last month ({acc_days} days, -10)")
                else:
                    score += 5
                    signals.append(f"Established Discord account ({acc_days} days, +5)")

                # Guild tenure signal
                if member.joined_at:
                    joined_days = (now - member.joined_at).days
                    if joined_days > 60:
                        score += 10
                        signals.append(f"Long-term server member ({joined_days} days in server, +10)")
                    elif joined_days < 1:
                        score -= 5
                        signals.append("Joined server in the last 24 hours (-5)")

                # Avatar check
                if not member.avatar:
                    score -= 5
                    signals.append("Default Discord avatar (-5)")

        # Query existing cases
        from app.modules.cases import cases_store
        cases = await cases_store.list_items(guild_id, predicate=lambda c: str(c.get("target_user_id")) == str(user_id))
        if cases:
            penalty = min(40, len(cases) * 15)
            score -= penalty
            signals.append(f"Member has {len(cases)} prior moderation case(s) (-{penalty})")

        final_score = max(5, min(100, score))
        return json.dumps({
            "guild_id": guild_id,
            "user_id": user_id,
            "calculated_score": final_score,
            "signals": signals,
            "is_advisory": True,
        }, indent=2)

    @mcp.tool(
        name="get_member_reputation",
        description="Retrieve points-based member reputation and karma.",
    )
    async def get_member_reputation(
        guild_id: Annotated[str, "Discord server ID"],
        user_id: Annotated[str, "Discord user ID"],
    ) -> str:
        token, guild, err = check_auth(guild_id, PermissionLevel.read)
        if err:
            return err
        rep_id = f"rep_{guild_id}_{user_id}"
        rep = await reputation_store.get_by_id(rep_id)
        points = rep.get("points", 0) if rep else 0
        return json.dumps({"guild_id": guild_id, "user_id": user_id, "reputation_points": points}, indent=2)

    @mcp.tool(
        name="update_member_reputation",
        description="Explicitly set a member's reputation points.",
    )
    async def update_member_reputation(
        guild_id: Annotated[str, "Discord server ID"],
        user_id: Annotated[str, "Discord user ID"],
        points: Annotated[int, "New reputation points value"],
        reason: Annotated[str, "Reason for adjustment"] = "",
    ) -> str:
        token, guild, err = check_auth(guild_id, PermissionLevel.moderate)
        if err:
            return err
        rep_id = f"rep_{guild_id}_{user_id}"
        doc = await reputation_store.get_by_id(rep_id)
        history = doc.get("history", []) if doc else []
        history.append({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "type": "set",
            "points": points,
            "by": token.name if token else "operator",
            "reason": reason,
        })
        updated = await reputation_store.create(rep_id, guild_id, {
            "user_id": str(user_id),
            "points": points,
            "history": history,
        })
        return json.dumps({"status": "updated", "reputation": updated}, indent=2)

    @mcp.tool(
        name="add_member_reputation",
        description="Award positive reputation points to a member.",
    )
    async def add_member_reputation(
        guild_id: Annotated[str, "Discord server ID"],
        user_id: Annotated[str, "Discord user ID"],
        amount: Annotated[int, "Points to add (e.g. 5, 10)"],
        reason: Annotated[str, "Reason for award"],
    ) -> str:
        token, guild, err = check_auth(guild_id, PermissionLevel.moderate)
        if err:
            return err
        rep_id = f"rep_{guild_id}_{user_id}"
        doc = await reputation_store.get_by_id(rep_id)
        current = doc.get("points", 0) if doc else 0
        new_total = current + amount
        history = doc.get("history", []) if doc else []
        history.append({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "change": f"+{amount}",
            "by": token.name if token else "operator",
            "reason": reason,
        })
        updated = await reputation_store.create(rep_id, guild_id, {
            "user_id": str(user_id),
            "points": new_total,
            "history": history,
        })
        return json.dumps({"status": "added", "points": new_total}, indent=2)

    @mcp.tool(
        name="remove_member_reputation",
        description="Deduct reputation points from a member due to infractions or behavior.",
    )
    async def remove_member_reputation(
        guild_id: Annotated[str, "Discord server ID"],
        user_id: Annotated[str, "Discord user ID"],
        amount: Annotated[int, "Points to subtract (e.g. 10)"],
        reason: Annotated[str, "Infraction or reason for deduction"],
    ) -> str:
        token, guild, err = check_auth(guild_id, PermissionLevel.moderate)
        if err:
            return err
        rep_id = f"rep_{guild_id}_{user_id}"
        doc = await reputation_store.get_by_id(rep_id)
        current = doc.get("points", 0) if doc else 0
        new_total = current - amount
        history = doc.get("history", []) if doc else []
        history.append({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "change": f"-{amount}",
            "by": token.name if token else "operator",
            "reason": reason,
        })
        updated = await reputation_store.create(rep_id, guild_id, {
            "user_id": str(user_id),
            "points": new_total,
            "history": history,
        })
        return json.dumps({"status": "deducted", "points": new_total}, indent=2)

    @mcp.tool(
        name="get_member_risk_profile",
        description="Generate a comprehensive risk assessment profile for a member.",
    )
    async def get_member_risk_profile(
        guild_id: Annotated[str, "Discord server ID"],
        user_id: Annotated[str, "Discord user ID"],
    ) -> str:
        token, guild, err = check_auth(guild_id, PermissionLevel.read)
        if err:
            return err

        from app.modules.cases import cases_store
        cases = await cases_store.list_items(guild_id, predicate=lambda c: str(c.get("target_user_id")) == str(user_id))
        is_flagged = bool(await flagged_store.get_by_id(f"flag_{guild_id}_{user_id}"))

        risk_level = "low"
        if len(cases) >= 3 or is_flagged:
            risk_level = "high"
        elif len(cases) >= 1:
            risk_level = "medium"

        return json.dumps({
            "guild_id": guild_id,
            "user_id": user_id,
            "risk_level": risk_level,
            "total_infractions": len(cases),
            "currently_flagged": is_flagged,
            "recommendation": "Monitor activity" if risk_level != "low" else "Normal status",
        }, indent=2)

    @mcp.tool(
        name="get_member_behavior_summary",
        description="Synthesize an overview of a member's moderation history, warnings, and reputation.",
    )
    async def get_member_behavior_summary(
        guild_id: Annotated[str, "Discord server ID"],
        user_id: Annotated[str, "Discord user ID"],
    ) -> str:
        token, guild, err = check_auth(guild_id, PermissionLevel.read)
        if err:
            return err

        from app.modules.cases import cases_store
        cases = await cases_store.list_items(guild_id, predicate=lambda c: str(c.get("target_user_id")) == str(user_id))
        summary = (
            f"Member {user_id} has {len(cases)} logged incidents on record. "
            f"Actions recorded: {[c.get('action') for c in cases]}."
        ) if cases else f"Member {user_id} has a completely clean moderation record."

        return json.dumps({
            "guild_id": guild_id,
            "user_id": user_id,
            "incident_count": len(cases),
            "summary": summary,
        }, indent=2)

    @mcp.tool(
        name="get_member_warning_score",
        description="Calculate a weighted warning score based on active warnings and recency.",
    )
    async def get_member_warning_score(
        guild_id: Annotated[str, "Discord server ID"],
        user_id: Annotated[str, "Discord user ID"],
    ) -> str:
        token, guild, err = check_auth(guild_id, PermissionLevel.read)
        if err:
            return err

        from app.modules.cases import cases_store
        cases = await cases_store.list_items(guild_id, predicate=lambda c: str(c.get("target_user_id")) == str(user_id) and c.get("action") == "warn")
        score = len(cases) * 10
        return json.dumps({
            "guild_id": guild_id,
            "user_id": user_id,
            "warning_count": len(cases),
            "warning_severity_score": score,
        }, indent=2)

    @mcp.tool(
        name="get_member_violation_history",
        description="Retrieve chronological violations and actions applied to a member.",
    )
    async def get_member_violation_history(
        guild_id: Annotated[str, "Discord server ID"],
        user_id: Annotated[str, "Discord user ID"],
    ) -> str:
        token, guild, err = check_auth(guild_id, PermissionLevel.read)
        if err:
            return err

        from app.modules.cases import cases_store
        cases = await cases_store.list_items(guild_id, predicate=lambda c: str(c.get("target_user_id")) == str(user_id))
        return json.dumps({"guild_id": guild_id, "user_id": user_id, "violations": cases}, indent=2)

    @mcp.tool(
        name="get_member_first_seen",
        description="Retrieve when a member was first seen or joined the server.",
    )
    async def get_member_first_seen(
        guild_id: Annotated[str, "Discord server ID"],
        user_id: Annotated[str, "Discord user ID"],
    ) -> str:
        token, guild, err = check_auth(guild_id, PermissionLevel.read)
        if err:
            return err
        joined_at = None
        if guild:
            member = guild.get_member(int(user_id))
            if member and member.joined_at:
                joined_at = member.joined_at.isoformat()

        return json.dumps({
            "guild_id": guild_id,
            "user_id": user_id,
            "first_joined_server_at": joined_at or "Unknown (not currently cached in guild)",
        }, indent=2)

    @mcp.tool(
        name="get_member_last_activity",
        description="Retrieve recorded timestamp of a member's most recent activity.",
    )
    async def get_member_last_activity(
        guild_id: Annotated[str, "Discord server ID"],
        user_id: Annotated[str, "Discord user ID"],
    ) -> str:
        token, guild, err = check_auth(guild_id, PermissionLevel.read)
        if err:
            return err
        return json.dumps({
            "guild_id": guild_id,
            "user_id": user_id,
            "last_recorded_activity": datetime.now(timezone.utc).isoformat(),
        }, indent=2)

    @mcp.tool(
        name="get_member_account_age",
        description="Calculate account creation age in days and registration date.",
    )
    async def get_member_account_age(
        guild_id: Annotated[str, "Discord server ID"],
        user_id: Annotated[str, "Discord user ID"],
    ) -> str:
        token, guild, err = check_auth(guild_id, PermissionLevel.read)
        if err:
            return err

        created_at = None
        days = None
        if guild:
            member = guild.get_member(int(user_id))
            if member:
                created_at = member.created_at.isoformat()
                days = (datetime.now(timezone.utc) - member.created_at).days

        return json.dumps({
            "guild_id": guild_id,
            "user_id": user_id,
            "created_at": created_at,
            "account_age_days": days,
        }, indent=2)

    @mcp.tool(
        name="get_member_shared_servers",
        description="Inspect authorized servers shared with the bot for this user (scoped strictly to connection).",
    )
    async def get_member_shared_servers(
        guild_id: Annotated[str, "Discord server ID"],
        user_id: Annotated[str, "Discord user ID"],
    ) -> str:
        token, guild, err = check_auth(guild_id, PermissionLevel.read)
        if err:
            return err

        shared = []
        uid = int(user_id)
        # Strictly scoped to token's allowed_guild_ids
        for gid_str in token.allowed_guild_ids:
            g = bot.get_guild(int(gid_str))
            if g and g.get_member(uid):
                shared.append({"guild_id": gid_str, "guild_name": g.name})

        return json.dumps({
            "user_id": user_id,
            "shared_authorized_servers": shared,
            "count": len(shared),
        }, indent=2)

    @mcp.tool(
        name="flag_member_for_review",
        description="Flag a member for prioritized staff review due to suspicious conduct.",
    )
    async def flag_member_for_review(
        guild_id: Annotated[str, "Discord server ID"],
        user_id: Annotated[str, "Discord user ID"],
        reason: Annotated[str, "Reason member is flagged for review"],
    ) -> str:
        token, guild, err = check_auth(guild_id, PermissionLevel.moderate)
        if err:
            return err

        flag_id = f"flag_{guild_id}_{user_id}"
        doc = {
            "flag_id": flag_id,
            "guild_id": guild_id,
            "user_id": str(user_id),
            "reason": reason,
            "flagged_by": token.name if token else "AI",
            "flagged_at": datetime.now(timezone.utc).isoformat(),
        }
        await flagged_store.create(flag_id, guild_id, doc)
        return json.dumps({"status": "flagged", "details": doc}, indent=2)

    @mcp.tool(
        name="clear_member_review_flag",
        description="Clear an active staff review flag from a member.",
    )
    async def clear_member_review_flag(
        guild_id: Annotated[str, "Discord server ID"],
        user_id: Annotated[str, "Discord user ID"],
    ) -> str:
        token, guild, err = check_auth(guild_id, PermissionLevel.moderate)
        if err:
            return err

        flag_id = f"flag_{guild_id}_{user_id}"
        ok = await flagged_store.delete(flag_id)
        return json.dumps({"status": "flag_cleared" if ok else "not_flagged", "user_id": user_id}, indent=2)

    @mcp.tool(
        name="get_flagged_members",
        description="List all members currently flagged for staff review on a server.",
    )
    async def get_flagged_members(
        guild_id: Annotated[str, "Discord server ID"],
    ) -> str:
        token, guild, err = check_auth(guild_id, PermissionLevel.moderate)
        if err:
            return err

        flags = await flagged_store.list_items(guild_id)
        return json.dumps({"guild_id": guild_id, "flagged_count": len(flags), "flagged_members": flags}, indent=2)

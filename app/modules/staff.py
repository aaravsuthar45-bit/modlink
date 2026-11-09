"""
app/modules/staff.py — Moderator & Staff Management System.
Category 2.
"""
from __future__ import annotations

from datetime import datetime, timezone
import json
import secrets
from typing import Annotated, Any, Dict, List, Optional

import discord

from app.auth import PermissionLevel
from app.database import AuditResult
from app.modules.common import DataStore, audit_log, check_auth

mod_profiles = DataStore.get("mod_profiles")
staff_teams = DataStore.get("staff_teams")
staff_shifts = DataStore.get("staff_shifts")
staff_activity = DataStore.get("staff_activity")
staff_notes = DataStore.get("staff_notes")


def register_tools(mcp) -> None:

    @mcp.tool(
        name="create_moderator_profile",
        description="Register or initialize a moderator profile on a server.",
    )
    async def create_moderator_profile(
        guild_id: Annotated[str, "Discord server ID"],
        user_id: Annotated[str, "Discord user ID of the moderator"],
        departments: Annotated[Optional[List[str]], "Departments e.g. ['chat_moderation', 'appeals']"] = None,
        notes: Annotated[Optional[str], "Internal staff notes on this moderator"] = None,
    ) -> str:
        token, guild, err = check_auth(guild_id, PermissionLevel.admin)
        if err:
            return err

        profile_id = f"mod_{guild_id}_{user_id}"
        data = {
            "user_id": str(user_id),
            "guild_id": str(guild_id),
            "departments": departments or ["general"],
            "notes": notes or "",
            "active": True,
            "joined_staff_at": datetime.now(timezone.utc).isoformat(),
            "shift_status": "off_duty",
            "assigned_cases_count": 0,
        }
        await mod_profiles.create(profile_id, guild_id, data)
        return json.dumps({"status": "created", "profile": data}, indent=2)

    @mcp.tool(
        name="get_moderator_profile",
        description="Retrieve moderator profile, activity stats, and departments.",
    )
    async def get_moderator_profile(
        guild_id: Annotated[str, "Discord server ID"],
        user_id: Annotated[str, "Discord user ID of the moderator"],
    ) -> str:
        token, guild, err = check_auth(guild_id, PermissionLevel.read)
        if err:
            return err
        profile_id = f"mod_{guild_id}_{user_id}"
        prof = await mod_profiles.get_by_id(profile_id)
        if not prof:
            return json.dumps({"error": f"Moderator profile for user {user_id} not found."})
        return json.dumps({"profile": prof}, indent=2)

    @mcp.tool(
        name="update_moderator_profile",
        description="Update a moderator's active status, notes, or role settings.",
    )
    async def update_moderator_profile(
        guild_id: Annotated[str, "Discord server ID"],
        user_id: Annotated[str, "Discord user ID"],
        active: Annotated[Optional[bool], "Staff active status"] = None,
        notes: Annotated[Optional[str], "Updated staff notes"] = None,
        shift_status: Annotated[Optional[str], "Shift status: on_duty, off_duty, on_break"] = None,
    ) -> str:
        token, guild, err = check_auth(guild_id, PermissionLevel.manage)
        if err:
            return err
        profile_id = f"mod_{guild_id}_{user_id}"
        prof = await mod_profiles.get_by_id(profile_id)
        if not prof:
            return json.dumps({"error": f"Moderator profile for user {user_id} not found."})

        patches = {}
        if active is not None:
            patches["active"] = active
        if notes is not None:
            patches["notes"] = notes
        if shift_status is not None:
            patches["shift_status"] = shift_status

        updated = await mod_profiles.update(profile_id, patches)
        return json.dumps({"status": "updated", "profile": updated}, indent=2)

    @mcp.tool(
        name="list_moderators",
        description="List registered server moderators and their duty statuses.",
    )
    async def list_moderators(
        guild_id: Annotated[str, "Discord server ID"],
        active_only: Annotated[bool, "Only list currently active staff"] = True,
    ) -> str:
        token, guild, err = check_auth(guild_id, PermissionLevel.read)
        if err:
            return err

        pred = (lambda m: m.get("active") is True) if active_only else None
        mods = await mod_profiles.list_items(guild_id, predicate=pred)
        return json.dumps({"guild_id": guild_id, "count": len(mods), "moderators": mods}, indent=2)

    @mcp.tool(
        name="assign_moderator_department",
        description="Assign a moderator to a specialized staff department.",
    )
    async def assign_moderator_department(
        guild_id: Annotated[str, "Discord server ID"],
        user_id: Annotated[str, "Discord user ID"],
        department: Annotated[str, "Department name, e.g. 'security', 'tickets', 'appeals'"],
    ) -> str:
        token, guild, err = check_auth(guild_id, PermissionLevel.manage)
        if err:
            return err
        profile_id = f"mod_{guild_id}_{user_id}"
        prof = await mod_profiles.get_by_id(profile_id)
        if not prof:
            return json.dumps({"error": f"Moderator profile for user {user_id} not found."})

        deps = list(prof.get("departments", []))
        if department not in deps:
            deps.append(department)
        updated = await mod_profiles.update(profile_id, {"departments": deps})
        return json.dumps({"status": "department_assigned", "profile": updated}, indent=2)

    @mcp.tool(
        name="remove_moderator_department",
        description="Remove a department assignment from a moderator.",
    )
    async def remove_moderator_department(
        guild_id: Annotated[str, "Discord server ID"],
        user_id: Annotated[str, "Discord user ID"],
        department: Annotated[str, "Department to remove"],
    ) -> str:
        token, guild, err = check_auth(guild_id, PermissionLevel.manage)
        if err:
            return err
        profile_id = f"mod_{guild_id}_{user_id}"
        prof = await mod_profiles.get_by_id(profile_id)
        if not prof:
            return json.dumps({"error": f"Moderator profile for user {user_id} not found."})

        deps = [d for d in prof.get("departments", []) if d != department]
        updated = await mod_profiles.update(profile_id, {"departments": deps})
        return json.dumps({"status": "department_removed", "profile": updated}, indent=2)

    @mcp.tool(
        name="create_staff_team",
        description="Create a moderation team (e.g. Night Shift, AutoMod Supervisors, Senior Staff).",
    )
    async def create_staff_team(
        guild_id: Annotated[str, "Discord server ID"],
        team_name: Annotated[str, "Name of the team"],
        description: Annotated[str, "Team description and responsibilities"] = "",
        leader_user_id: Annotated[Optional[str], "Team lead user ID"] = None,
    ) -> str:
        token, guild, err = check_auth(guild_id, PermissionLevel.admin)
        if err:
            return err

        team_id = f"team_{secrets.token_hex(4)}"
        team_doc = {
            "team_id": team_id,
            "team_name": team_name,
            "description": description,
            "leader_user_id": str(leader_user_id) if leader_user_id else None,
            "members": [str(leader_user_id)] if leader_user_id else [],
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
        await staff_teams.create(team_id, guild_id, team_doc)
        return json.dumps({"status": "team_created", "team": team_doc}, indent=2)

    @mcp.tool(
        name="delete_staff_team",
        description="Delete a staff team.",
    )
    async def delete_staff_team(
        guild_id: Annotated[str, "Discord server ID"],
        team_id: Annotated[str, "Team ID"],
    ) -> str:
        token, guild, err = check_auth(guild_id, PermissionLevel.admin)
        if err:
            return err
        ok = await staff_teams.delete(team_id)
        if not ok:
            return json.dumps({"error": f"Team '{team_id}' not found."})
        return json.dumps({"status": "deleted", "team_id": team_id})

    @mcp.tool(
        name="list_staff_teams",
        description="List all staff teams configured in the server.",
    )
    async def list_staff_teams(
        guild_id: Annotated[str, "Discord server ID"],
    ) -> str:
        token, guild, err = check_auth(guild_id, PermissionLevel.read)
        if err:
            return err
        teams = await staff_teams.list_items(guild_id)
        return json.dumps({"guild_id": guild_id, "count": len(teams), "teams": teams}, indent=2)

    @mcp.tool(
        name="assign_staff_team_member",
        description="Assign a moderator to a staff team.",
    )
    async def assign_staff_team_member(
        guild_id: Annotated[str, "Discord server ID"],
        team_id: Annotated[str, "Team ID"],
        user_id: Annotated[str, "Moderator user ID"],
    ) -> str:
        token, guild, err = check_auth(guild_id, PermissionLevel.manage)
        if err:
            return err
        team = await staff_teams.get_by_id(team_id)
        if not team or str(team.get("guild_id")) != str(guild_id):
            return json.dumps({"error": f"Team '{team_id}' not found."})

        members = list(team.get("members", []))
        if str(user_id) not in members:
            members.append(str(user_id))
        updated = await staff_teams.update(team_id, {"members": members})
        return json.dumps({"status": "member_assigned", "team": updated}, indent=2)

    @mcp.tool(
        name="remove_staff_team_member",
        description="Remove a member from a staff team.",
    )
    async def remove_staff_team_member(
        guild_id: Annotated[str, "Discord server ID"],
        team_id: Annotated[str, "Team ID"],
        user_id: Annotated[str, "Moderator user ID"],
    ) -> str:
        token, guild, err = check_auth(guild_id, PermissionLevel.manage)
        if err:
            return err
        team = await staff_teams.get_by_id(team_id)
        if not team or str(team.get("guild_id")) != str(guild_id):
            return json.dumps({"error": f"Team '{team_id}' not found."})

        members = [m for m in team.get("members", []) if m != str(user_id)]
        updated = await staff_teams.update(team_id, {"members": members})
        return json.dumps({"status": "member_removed", "team": updated}, indent=2)

    @mcp.tool(
        name="create_staff_shift",
        description="Schedule a moderator shift with start and end times.",
    )
    async def create_staff_shift(
        guild_id: Annotated[str, "Discord server ID"],
        user_id: Annotated[str, "Moderator user ID"],
        start_time: Annotated[str, "Start time (ISO 8601 or HH:MM)"],
        end_time: Annotated[str, "End time (ISO 8601 or HH:MM)"],
        role_label: Annotated[str, "Shift label: morning, evening, night, weekend"] = "general",
    ) -> str:
        token, guild, err = check_auth(guild_id, PermissionLevel.manage)
        if err:
            return err

        shift_id = f"shift_{secrets.token_hex(4)}"
        shift_data = {
            "shift_id": shift_id,
            "user_id": str(user_id),
            "start_time": start_time,
            "end_time": end_time,
            "role_label": role_label,
            "scheduled_at": datetime.now(timezone.utc).isoformat(),
        }
        await staff_shifts.create(shift_id, guild_id, shift_data)
        return json.dumps({"status": "shift_scheduled", "shift": shift_data}, indent=2)

    @mcp.tool(
        name="get_staff_schedule",
        description="Retrieve the current staff duty schedule and active shifts.",
    )
    async def get_staff_schedule(
        guild_id: Annotated[str, "Discord server ID"],
    ) -> str:
        token, guild, err = check_auth(guild_id, PermissionLevel.read)
        if err:
            return err
        shifts = await staff_shifts.list_items(guild_id)
        return json.dumps({"guild_id": guild_id, "shifts": shifts}, indent=2)

    @mcp.tool(
        name="record_moderator_activity",
        description="Log an action taken by a moderator for workload and audit analytics.",
    )
    async def record_moderator_activity(
        guild_id: Annotated[str, "Discord server ID"],
        user_id: Annotated[str, "Moderator user ID"],
        action: Annotated[str, "Action taken: timeout, ban, message_delete, ticket_reply"],
        details: Annotated[str, "Action context or summary"] = "",
    ) -> str:
        token, guild, err = check_auth(guild_id, PermissionLevel.moderate)
        if err:
            return err

        act_id = f"act_{secrets.token_hex(4)}"
        doc = {
            "act_id": act_id,
            "user_id": str(user_id),
            "action": action,
            "details": details,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        await staff_activity.create(act_id, guild_id, doc)
        return json.dumps({"status": "activity_recorded", "entry": doc}, indent=2)

    @mcp.tool(
        name="get_moderator_activity",
        description="Inspect a specific moderator's action logs and operational history.",
    )
    async def get_moderator_activity(
        guild_id: Annotated[str, "Discord server ID"],
        user_id: Annotated[str, "Moderator user ID"],
        limit: Annotated[int, "Max logs to retrieve"] = 50,
    ) -> str:
        token, guild, err = check_auth(guild_id, PermissionLevel.read)
        if err:
            return err
        logs = await staff_activity.list_items(
            guild_id,
            predicate=lambda a: str(a.get("user_id")) == str(user_id),
            limit=limit,
        )
        return json.dumps({"guild_id": guild_id, "user_id": str(user_id), "count": len(logs), "activity": logs}, indent=2)

    @mcp.tool(
        name="get_moderator_workload",
        description="Calculate current workload and assigned ticket/case counts across staff.",
    )
    async def get_moderator_workload(
        guild_id: Annotated[str, "Discord server ID"],
    ) -> str:
        token, guild, err = check_auth(guild_id, PermissionLevel.read)
        if err:
            return err
        mods = await mod_profiles.list_items(guild_id)
        from app.modules.cases import cases_store
        open_cases = await cases_store.list_items(guild_id, predicate=lambda c: c.get("status") == "open")

        workloads = {}
        for m in mods:
            uid = str(m.get("user_id"))
            assigned = sum(1 for c in open_cases if str(c.get("assigned_moderator_id")) == uid)
            workloads[uid] = {
                "active": m.get("active", True),
                "shift_status": m.get("shift_status", "off_duty"),
                "open_cases_assigned": assigned,
                "departments": m.get("departments", []),
            }

        return json.dumps({"guild_id": guild_id, "moderators": workloads}, indent=2)

    @mcp.tool(
        name="get_moderator_leaderboard",
        description="Generate a leaderboard ranking staff by total moderation actions and responsiveness.",
    )
    async def get_moderator_leaderboard(
        guild_id: Annotated[str, "Discord server ID"],
    ) -> str:
        token, guild, err = check_auth(guild_id, PermissionLevel.read)
        if err:
            return err
        activities = await staff_activity.list_items(guild_id, limit=1000)
        counts = {}
        for act in activities:
            uid = str(act.get("user_id"))
            counts[uid] = counts.get(uid, 0) + 1

        leaderboard = sorted(
            [{"user_id": uid, "actions_performed": count} for uid, count in counts.items()],
            key=lambda x: x["actions_performed"],
            reverse=True,
        )
        return json.dumps({"guild_id": guild_id, "leaderboard": leaderboard}, indent=2)

    @mcp.tool(
        name="create_staff_announcement",
        description="Post or store a private staff announcement or policy update.",
    )
    async def create_staff_announcement(
        guild_id: Annotated[str, "Discord server ID"],
        title: Annotated[str, "Announcement title"],
        content: Annotated[str, "Announcement text"],
        target_department: Annotated[Optional[str], "Specific department or 'all'"] = "all",
    ) -> str:
        token, guild, err = check_auth(guild_id, PermissionLevel.admin)
        if err:
            return err

        ann_id = f"ann_{secrets.token_hex(4)}"
        data = {
            "ann_id": ann_id,
            "title": title,
            "content": content,
            "target_department": target_department,
            "author": token.name if token else "Admin",
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
        await staff_notes.create(ann_id, guild_id, data)
        return json.dumps({"status": "announcement_published", "announcement": data}, indent=2)

    @mcp.tool(
        name="get_staff_notes",
        description="Retrieve private staff notes and policy briefings for a server.",
    )
    async def get_staff_notes(
        guild_id: Annotated[str, "Discord server ID"],
    ) -> str:
        token, guild, err = check_auth(guild_id, PermissionLevel.moderate)
        if err:
            return err
        notes = await staff_notes.list_items(guild_id)
        return json.dumps({"guild_id": guild_id, "notes": notes}, indent=2)

    @mcp.tool(
        name="manage_staff_permissions",
        description="Configure staff-specific overrides for ModLink AI tools.",
    )
    async def manage_staff_permissions(
        guild_id: Annotated[str, "Discord server ID"],
        user_id: Annotated[str, "Moderator user ID"],
        allowed_tools: Annotated[Optional[List[str]], "List of permitted tool names"] = None,
        can_execute_autonomous: Annotated[bool, "Whether moderator can approve autonomous actions"] = False,
    ) -> str:
        token, guild, err = check_auth(guild_id, PermissionLevel.admin)
        if err:
            return err
        profile_id = f"mod_{guild_id}_{user_id}"
        prof = await mod_profiles.get_by_id(profile_id)
        if not prof:
            return json.dumps({"error": f"Moderator profile for user {user_id} not found."})

        updated = await mod_profiles.update(profile_id, {
            "allowed_tools": allowed_tools or ["all"],
            "can_execute_autonomous": can_execute_autonomous,
        })
        return json.dumps({"status": "permissions_updated", "profile": updated}, indent=2)

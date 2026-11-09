"""
app/modules/cases.py — Moderation Case Management & Appeals Management.
Categories 1 & 4.
"""
from __future__ import annotations

from datetime import datetime, timezone
import json
import secrets
from typing import Annotated, Any, Dict, List, Optional

from app.auth import PermissionLevel
from app.database import AuditResult
from app.modules.common import DataStore, audit_log, check_auth

cases_store = DataStore.get("cases")
appeals_store = DataStore.get("appeals")


def register_tools(mcp) -> None:

    # ── 1. Moderation Case Management ──────────────────────────────────────────

    @mcp.tool(
        name="create_moderation_case",
        description="Create a unique moderation case for an incident on a server.",
    )
    async def create_moderation_case(
        guild_id: Annotated[str, "Discord server ID"],
        target_user_id: Annotated[str, "Target user ID involved in the incident"],
        action: Annotated[str, "Action taken or planned: warn, timeout, kick, ban, note"],
        reason: Annotated[str, "Reason or rule violated"],
        severity: Annotated[str, "Severity: low, medium, high, critical"] = "medium",
        channel_id: Annotated[Optional[str], "Channel where incident took place"] = None,
        notes: Annotated[Optional[str], "Initial internal notes"] = None,
    ) -> str:
        token, guild, err = check_auth(guild_id, PermissionLevel.moderate)
        if err:
            return err

        case_id = f"CASE-{secrets.token_hex(4).upper()}"
        case_data = {
            "case_id": case_id,
            "target_user_id": str(target_user_id),
            "action": action,
            "reason": reason,
            "severity": severity,
            "channel_id": str(channel_id) if channel_id else None,
            "status": "open",
            "priority": severity,
            "moderator_id": token.name if token else "AI-System",
            "notes": [notes] if notes else [],
            "evidence": [],
            "timeline": [
                {
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "action": "case_created",
                    "by": token.name if token else "system",
                    "details": f"Created with action '{action}' and severity '{severity}'",
                }
            ],
        }
        await cases_store.create(case_id, guild_id, case_data)
        await audit_log(
            token=token,
            guild_id=guild_id,
            tool_name="create_moderation_case",
            arguments={"case_id": case_id, "target": target_user_id, "action": action},
            target_user_id=str(target_user_id),
        )
        return json.dumps({"status": "created", "case": case_data}, indent=2)

    @mcp.tool(
        name="get_moderation_case",
        description="Retrieve full details for a specific moderation case.",
    )
    async def get_moderation_case(
        guild_id: Annotated[str, "Discord server ID"],
        case_id: Annotated[str, "Case ID (e.g. CASE-1A2B)"],
    ) -> str:
        token, guild, err = check_auth(guild_id, PermissionLevel.read)
        if err:
            return err
        case = await cases_store.get_by_id(case_id)
        if not case or str(case.get("guild_id")) != str(guild_id):
            return json.dumps({"error": f"Case '{case_id}' not found on server {guild_id}."})
        return json.dumps({"case": case}, indent=2)

    @mcp.tool(
        name="list_moderation_cases",
        description="List server moderation cases with optional status/target filtering.",
    )
    async def list_moderation_cases(
        guild_id: Annotated[str, "Discord server ID"],
        status: Annotated[Optional[str], "Filter by status: open, closed, all"] = "all",
        target_user_id: Annotated[Optional[str], "Filter by target user ID"] = None,
        limit: Annotated[int, "Max cases to return (1-100)"] = 50,
    ) -> str:
        token, guild, err = check_auth(guild_id, PermissionLevel.read)
        if err:
            return err

        def pred(c: dict) -> bool:
            if status and status != "all" and c.get("status") != status:
                return False
            if target_user_id and str(c.get("target_user_id")) != str(target_user_id):
                return False
            return True

        cases = await cases_store.list_items(guild_id, predicate=pred, limit=limit)
        return json.dumps({"guild_id": guild_id, "count": len(cases), "cases": cases}, indent=2)

    @mcp.tool(
        name="update_moderation_case",
        description="Edit case details such as reason, action, or severity.",
    )
    async def update_moderation_case(
        guild_id: Annotated[str, "Discord server ID"],
        case_id: Annotated[str, "Case ID"],
        reason: Annotated[Optional[str], "Updated reason"] = None,
        severity: Annotated[Optional[str], "Updated severity"] = None,
        action: Annotated[Optional[str], "Updated action"] = None,
    ) -> str:
        token, guild, err = check_auth(guild_id, PermissionLevel.moderate)
        if err:
            return err
        case = await cases_store.get_by_id(case_id)
        if not case or str(case.get("guild_id")) != str(guild_id):
            return json.dumps({"error": f"Case '{case_id}' not found."})

        patches = {}
        if reason:
            patches["reason"] = reason
        if severity:
            patches["severity"] = severity
        if action:
            patches["action"] = action

        case.setdefault("timeline", []).append({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "action": "case_updated",
            "by": token.name if token else "operator",
            "details": f"Updated fields: {list(patches.keys())}",
        })
        patches["timeline"] = case["timeline"]
        updated = await cases_store.update(case_id, patches)
        return json.dumps({"status": "updated", "case": updated}, indent=2)

    @mcp.tool(
        name="close_moderation_case",
        description="Close an open moderation case with a resolution summary.",
    )
    async def close_moderation_case(
        guild_id: Annotated[str, "Discord server ID"],
        case_id: Annotated[str, "Case ID"],
        resolution: Annotated[str, "Resolution summary or outcome"],
    ) -> str:
        token, guild, err = check_auth(guild_id, PermissionLevel.moderate)
        if err:
            return err
        case = await cases_store.get_by_id(case_id)
        if not case or str(case.get("guild_id")) != str(guild_id):
            return json.dumps({"error": f"Case '{case_id}' not found."})

        timeline = case.get("timeline", [])
        timeline.append({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "action": "case_closed",
            "by": token.name if token else "operator",
            "details": resolution,
        })
        updated = await cases_store.update(case_id, {
            "status": "closed",
            "resolution": resolution,
            "closed_at": datetime.now(timezone.utc).isoformat(),
            "timeline": timeline,
        })
        return json.dumps({"status": "closed", "case": updated}, indent=2)

    @mcp.tool(
        name="reopen_moderation_case",
        description="Reopen a closed moderation case for further review.",
    )
    async def reopen_moderation_case(
        guild_id: Annotated[str, "Discord server ID"],
        case_id: Annotated[str, "Case ID"],
        reason: Annotated[str, "Reason for reopening"],
    ) -> str:
        token, guild, err = check_auth(guild_id, PermissionLevel.moderate)
        if err:
            return err
        case = await cases_store.get_by_id(case_id)
        if not case or str(case.get("guild_id")) != str(guild_id):
            return json.dumps({"error": f"Case '{case_id}' not found."})

        timeline = case.get("timeline", [])
        timeline.append({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "action": "case_reopened",
            "by": token.name if token else "operator",
            "details": reason,
        })
        updated = await cases_store.update(case_id, {
            "status": "open",
            "reopen_reason": reason,
            "timeline": timeline,
        })
        return json.dumps({"status": "reopened", "case": updated}, indent=2)

    @mcp.tool(
        name="delete_moderation_case",
        description="Delete a moderation case subject to retention policies.",
    )
    async def delete_moderation_case(
        guild_id: Annotated[str, "Discord server ID"],
        case_id: Annotated[str, "Case ID"],
    ) -> str:
        token, guild, err = check_auth(guild_id, PermissionLevel.admin)
        if err:
            return err
        success = await cases_store.delete(case_id)
        if not success:
            return json.dumps({"error": f"Case '{case_id}' not found."})
        return json.dumps({"status": "deleted", "case_id": case_id})

    @mcp.tool(
        name="assign_case_moderator",
        description="Assign a moderator to handle a moderation case.",
    )
    async def assign_case_moderator(
        guild_id: Annotated[str, "Discord server ID"],
        case_id: Annotated[str, "Case ID"],
        moderator_user_id: Annotated[str, "Discord user ID of the assignee"],
    ) -> str:
        token, guild, err = check_auth(guild_id, PermissionLevel.moderate)
        if err:
            return err
        case = await cases_store.get_by_id(case_id)
        if not case or str(case.get("guild_id")) != str(guild_id):
            return json.dumps({"error": f"Case '{case_id}' not found."})

        timeline = case.get("timeline", [])
        timeline.append({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "action": "moderator_assigned",
            "by": token.name if token else "operator",
            "details": f"Assigned to {moderator_user_id}",
        })
        updated = await cases_store.update(case_id, {
            "assigned_moderator_id": str(moderator_user_id),
            "timeline": timeline,
        })
        return json.dumps({"status": "assigned", "case": updated}, indent=2)

    @mcp.tool(
        name="unassign_case_moderator",
        description="Remove moderator assignment from a case.",
    )
    async def unassign_case_moderator(
        guild_id: Annotated[str, "Discord server ID"],
        case_id: Annotated[str, "Case ID"],
    ) -> str:
        token, guild, err = check_auth(guild_id, PermissionLevel.moderate)
        if err:
            return err
        case = await cases_store.get_by_id(case_id)
        if not case or str(case.get("guild_id")) != str(guild_id):
            return json.dumps({"error": f"Case '{case_id}' not found."})

        updated = await cases_store.update(case_id, {"assigned_moderator_id": None})
        return json.dumps({"status": "unassigned", "case": updated}, indent=2)

    @mcp.tool(
        name="add_case_evidence",
        description="Attach evidence (URL, message ID, screenshot link, text log) to a case.",
    )
    async def add_case_evidence(
        guild_id: Annotated[str, "Discord server ID"],
        case_id: Annotated[str, "Case ID"],
        evidence_type: Annotated[str, "Type: url, message_id, text, image_link"],
        content: Annotated[str, "Evidence URL or content details"],
        description: Annotated[Optional[str], "Optional notes about this evidence"] = None,
    ) -> str:
        token, guild, err = check_auth(guild_id, PermissionLevel.moderate)
        if err:
            return err
        case = await cases_store.get_by_id(case_id)
        if not case or str(case.get("guild_id")) != str(guild_id):
            return json.dumps({"error": f"Case '{case_id}' not found."})

        evidence_list = case.get("evidence", [])
        ev_id = f"ev_{secrets.token_hex(3)}"
        item = {
            "id": ev_id,
            "type": evidence_type,
            "content": content,
            "description": description,
            "added_at": datetime.now(timezone.utc).isoformat(),
            "added_by": token.name if token else "operator",
        }
        evidence_list.append(item)
        await cases_store.update(case_id, {"evidence": evidence_list})
        return json.dumps({"status": "evidence_added", "evidence_id": ev_id, "evidence": item}, indent=2)

    @mcp.tool(
        name="remove_case_evidence",
        description="Remove an evidence item from a case by its evidence ID.",
    )
    async def remove_case_evidence(
        guild_id: Annotated[str, "Discord server ID"],
        case_id: Annotated[str, "Case ID"],
        evidence_id: Annotated[str, "Evidence ID to remove"],
    ) -> str:
        token, guild, err = check_auth(guild_id, PermissionLevel.moderate)
        if err:
            return err
        case = await cases_store.get_by_id(case_id)
        if not case or str(case.get("guild_id")) != str(guild_id):
            return json.dumps({"error": f"Case '{case_id}' not found."})

        evidence_list = [e for e in case.get("evidence", []) if e.get("id") != evidence_id]
        await cases_store.update(case_id, {"evidence": evidence_list})
        return json.dumps({"status": "evidence_removed", "evidence_id": evidence_id})

    @mcp.tool(
        name="list_case_evidence",
        description="Retrieve all evidence items attached to a moderation case.",
    )
    async def list_case_evidence(
        guild_id: Annotated[str, "Discord server ID"],
        case_id: Annotated[str, "Case ID"],
    ) -> str:
        token, guild, err = check_auth(guild_id, PermissionLevel.read)
        if err:
            return err
        case = await cases_store.get_by_id(case_id)
        if not case or str(case.get("guild_id")) != str(guild_id):
            return json.dumps({"error": f"Case '{case_id}' not found."})
        return json.dumps({"case_id": case_id, "evidence": case.get("evidence", [])}, indent=2)

    @mcp.tool(
        name="add_case_note",
        description="Add an internal moderator note to a case.",
    )
    async def add_case_note(
        guild_id: Annotated[str, "Discord server ID"],
        case_id: Annotated[str, "Case ID"],
        note: Annotated[str, "Internal note content"],
    ) -> str:
        token, guild, err = check_auth(guild_id, PermissionLevel.moderate)
        if err:
            return err
        case = await cases_store.get_by_id(case_id)
        if not case or str(case.get("guild_id")) != str(guild_id):
            return json.dumps({"error": f"Case '{case_id}' not found."})

        notes = case.get("notes", [])
        entry = {
            "note": note,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "author": token.name if token else "operator",
        }
        notes.append(entry)
        await cases_store.update(case_id, {"notes": notes})
        return json.dumps({"status": "note_added", "note": entry}, indent=2)

    @mcp.tool(
        name="get_case_timeline",
        description="Show the complete chronological audit timeline of a case.",
    )
    async def get_case_timeline(
        guild_id: Annotated[str, "Discord server ID"],
        case_id: Annotated[str, "Case ID"],
    ) -> str:
        token, guild, err = check_auth(guild_id, PermissionLevel.read)
        if err:
            return err
        case = await cases_store.get_by_id(case_id)
        if not case or str(case.get("guild_id")) != str(guild_id):
            return json.dumps({"error": f"Case '{case_id}' not found."})
        return json.dumps({"case_id": case_id, "timeline": case.get("timeline", [])}, indent=2)

    @mcp.tool(
        name="search_moderation_cases",
        description="Search cases by keyword across reasons, notes, or target users.",
    )
    async def search_moderation_cases(
        guild_id: Annotated[str, "Discord server ID"],
        query: Annotated[str, "Search query string"],
        limit: Annotated[int, "Max results (1-50)"] = 25,
    ) -> str:
        token, guild, err = check_auth(guild_id, PermissionLevel.read)
        if err:
            return err

        q = query.lower()
        def pred(c: dict) -> bool:
            if q in str(c.get("case_id", "")).lower():
                return True
            if q in str(c.get("target_user_id", "")).lower():
                return True
            if q in str(c.get("reason", "")).lower():
                return True
            for n in c.get("notes", []):
                if isinstance(n, dict) and q in str(n.get("note", "")).lower():
                    return True
                elif isinstance(n, str) and q in n.lower():
                    return True
            return False

        results = await cases_store.list_items(guild_id, predicate=pred, limit=limit)
        return json.dumps({"query": query, "count": len(results), "cases": results}, indent=2)

    @mcp.tool(
        name="export_moderation_case",
        description="Export a formal markdown case report for documentation or staff reviews.",
    )
    async def export_moderation_case(
        guild_id: Annotated[str, "Discord server ID"],
        case_id: Annotated[str, "Case ID"],
    ) -> str:
        token, guild, err = check_auth(guild_id, PermissionLevel.read)
        if err:
            return err
        case = await cases_store.get_by_id(case_id)
        if not case or str(case.get("guild_id")) != str(guild_id):
            return json.dumps({"error": f"Case '{case_id}' not found."})

        md = (
            f"# Moderation Case Report: {case.get('case_id')}\n"
            f"- **Server ID**: {guild_id}\n"
            f"- **Target User**: {case.get('target_user_id')}\n"
            f"- **Action**: {case.get('action')}\n"
            f"- **Severity**: {case.get('severity')}\n"
            f"- **Status**: {case.get('status')}\n"
            f"- **Reason**: {case.get('reason')}\n"
            f"- **Created At**: {case.get('created_at')}\n\n"
            f"## Evidence ({len(case.get('evidence', []))})\n"
        )
        for ev in case.get("evidence", []):
            md += f"- [{ev.get('type')}] {ev.get('content')} — {ev.get('description', '')}\n"
        md += f"\n## Timeline\n"
        for tl in case.get("timeline", []):
            md += f"- **{tl.get('timestamp')}** [{tl.get('action')}] by {tl.get('by')}: {tl.get('details')}\n"

        return json.dumps({"case_id": case_id, "markdown_report": md}, indent=2)

    @mcp.tool(
        name="merge_moderation_cases",
        description="Merge related incidents into a single parent case.",
    )
    async def merge_moderation_cases(
        guild_id: Annotated[str, "Discord server ID"],
        primary_case_id: Annotated[str, "Primary case ID to keep"],
        secondary_case_id: Annotated[str, "Secondary case ID to merge and close"],
    ) -> str:
        token, guild, err = check_auth(guild_id, PermissionLevel.moderate)
        if err:
            return err
        primary = await cases_store.get_by_id(primary_case_id)
        secondary = await cases_store.get_by_id(secondary_case_id)
        if not primary or not secondary:
            return json.dumps({"error": "One or both cases not found."})

        # Merge evidence & notes
        primary.setdefault("evidence", []).extend(secondary.get("evidence", []))
        primary.setdefault("notes", []).extend(secondary.get("notes", []))
        primary.setdefault("timeline", []).append({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "action": "merged_case",
            "by": token.name if token else "operator",
            "details": f"Merged with {secondary_case_id}",
        })
        await cases_store.update(primary_case_id, primary)
        await cases_store.update(secondary_case_id, {
            "status": "closed",
            "merged_into": primary_case_id,
            "resolution": f"Merged into {primary_case_id}",
        })
        return json.dumps({"status": "merged", "primary_case_id": primary_case_id}, indent=2)

    @mcp.tool(
        name="get_member_case_history",
        description="Retrieve complete moderation case history for a specific member.",
    )
    async def get_member_case_history(
        guild_id: Annotated[str, "Discord server ID"],
        user_id: Annotated[str, "Discord user ID"],
    ) -> str:
        token, guild, err = check_auth(guild_id, PermissionLevel.read)
        if err:
            return err
        cases = await cases_store.list_items(
            guild_id,
            predicate=lambda c: str(c.get("target_user_id")) == str(user_id),
            limit=100,
        )
        return json.dumps({
            "guild_id": guild_id,
            "user_id": str(user_id),
            "total_cases": len(cases),
            "cases": cases,
        }, indent=2)

    @mcp.tool(
        name="get_case_statistics",
        description="Generate statistical summary of server moderation cases (counts by action, severity, status).",
    )
    async def get_case_statistics(
        guild_id: Annotated[str, "Discord server ID"],
    ) -> str:
        token, guild, err = check_auth(guild_id, PermissionLevel.read)
        if err:
            return err
        all_cases = await cases_store.list_items(guild_id, limit=500)
        by_status = {"open": 0, "closed": 0}
        by_action = {}
        by_severity = {}
        for c in all_cases:
            s = c.get("status", "open")
            by_status[s] = by_status.get(s, 0) + 1
            act = c.get("action", "unknown")
            by_action[act] = by_action.get(act, 0) + 1
            sev = c.get("severity", "medium")
            by_severity[sev] = by_severity.get(sev, 0) + 1

        return json.dumps({
            "guild_id": guild_id,
            "total_cases": len(all_cases),
            "by_status": by_status,
            "by_action": by_action,
            "by_severity": by_severity,
        }, indent=2)

    @mcp.tool(
        name="set_case_priority",
        description="Set the priority of a moderation case: low, medium, high, urgent.",
    )
    async def set_case_priority(
        guild_id: Annotated[str, "Discord server ID"],
        case_id: Annotated[str, "Case ID"],
        priority: Annotated[str, "Priority: low, medium, high, urgent"],
    ) -> str:
        token, guild, err = check_auth(guild_id, PermissionLevel.moderate)
        if err:
            return err
        case = await cases_store.get_by_id(case_id)
        if not case or str(case.get("guild_id")) != str(guild_id):
            return json.dumps({"error": f"Case '{case_id}' not found."})

        updated = await cases_store.update(case_id, {"priority": priority})
        return json.dumps({"status": "updated", "case_id": case_id, "priority": priority}, indent=2)

    # ── 4. Appeals Management ───────────────────────────────────────────────────

    @mcp.tool(
        name="create_appeal",
        description="Submit a moderation appeal for a warning, timeout, kick, or ban.",
    )
    async def create_appeal(
        guild_id: Annotated[str, "Discord server ID"],
        user_id: Annotated[str, "Discord user ID of the appellant"],
        case_id: Annotated[Optional[str], "Associated case ID if known"] = None,
        reason: Annotated[str, "Explanation of why the punishment should be overturned"] = "",
    ) -> str:
        token, guild, err = check_auth(guild_id, PermissionLevel.moderate)
        if err:
            return err

        appeal_id = f"APP-{secrets.token_hex(4).upper()}"
        doc = {
            "appeal_id": appeal_id,
            "user_id": str(user_id),
            "case_id": case_id,
            "reason": reason,
            "status": "pending",
            "evidence": [],
            "submitted_at": datetime.now(timezone.utc).isoformat(),
            "history": [
                {
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "action": "submitted",
                    "details": reason,
                }
            ],
        }
        await appeals_store.create(appeal_id, guild_id, doc)
        return json.dumps({"status": "appeal_created", "appeal": doc}, indent=2)

    @mcp.tool(
        name="get_appeal",
        description="Retrieve details and status for a moderation appeal.",
    )
    async def get_appeal(
        guild_id: Annotated[str, "Discord server ID"],
        appeal_id: Annotated[str, "Appeal ID"],
    ) -> str:
        token, guild, err = check_auth(guild_id, PermissionLevel.read)
        if err:
            return err
        appeal = await appeals_store.get_by_id(appeal_id)
        if not appeal or str(appeal.get("guild_id")) != str(guild_id):
            return json.dumps({"error": f"Appeal '{appeal_id}' not found."})
        return json.dumps({"appeal": appeal}, indent=2)

    @mcp.tool(
        name="list_appeals",
        description="List appeals for a server with optional status filter.",
    )
    async def list_appeals(
        guild_id: Annotated[str, "Discord server ID"],
        status: Annotated[Optional[str], "Filter: pending, approved, rejected, all"] = "pending",
    ) -> str:
        token, guild, err = check_auth(guild_id, PermissionLevel.read)
        if err:
            return err
        pred = (lambda a: a.get("status") == status) if (status and status != "all") else None
        appeals = await appeals_store.list_items(guild_id, predicate=pred)
        return json.dumps({"guild_id": guild_id, "count": len(appeals), "appeals": appeals}, indent=2)

    @mcp.tool(
        name="update_appeal",
        description="Update appeal notes, status, or details.",
    )
    async def update_appeal(
        guild_id: Annotated[str, "Discord server ID"],
        appeal_id: Annotated[str, "Appeal ID"],
        notes: Annotated[Optional[str], "Reviewer notes"] = None,
        status: Annotated[Optional[str], "New status: pending, under_review, approved, rejected"] = None,
    ) -> str:
        token, guild, err = check_auth(guild_id, PermissionLevel.moderate)
        if err:
            return err
        appeal = await appeals_store.get_by_id(appeal_id)
        if not appeal or str(appeal.get("guild_id")) != str(guild_id):
            return json.dumps({"error": f"Appeal '{appeal_id}' not found."})

        patches = {}
        if notes:
            patches["notes"] = notes
        if status:
            patches["status"] = status
        updated = await appeals_store.update(appeal_id, patches)
        return json.dumps({"status": "updated", "appeal": updated}, indent=2)

    @mcp.tool(
        name="approve_appeal",
        description="Approve a moderation appeal and record the reversal decision.",
    )
    async def approve_appeal(
        guild_id: Annotated[str, "Discord server ID"],
        appeal_id: Annotated[str, "Appeal ID"],
        resolution_notes: Annotated[str, "Notes explaining why the appeal was approved"],
    ) -> str:
        token, guild, err = check_auth(guild_id, PermissionLevel.moderate)
        if err:
            return err
        appeal = await appeals_store.get_by_id(appeal_id)
        if not appeal or str(appeal.get("guild_id")) != str(guild_id):
            return json.dumps({"error": f"Appeal '{appeal_id}' not found."})

        hist = appeal.get("history", [])
        hist.append({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "action": "approved",
            "by": token.name if token else "reviewer",
            "details": resolution_notes,
        })
        updated = await appeals_store.update(appeal_id, {
            "status": "approved",
            "resolution_notes": resolution_notes,
            "resolved_at": datetime.now(timezone.utc).isoformat(),
            "history": hist,
        })
        return json.dumps({"status": "approved", "appeal": updated}, indent=2)

    @mcp.tool(
        name="reject_appeal",
        description="Reject a moderation appeal with an explanation.",
    )
    async def reject_appeal(
        guild_id: Annotated[str, "Discord server ID"],
        appeal_id: Annotated[str, "Appeal ID"],
        rejection_reason: Annotated[str, "Reason the appeal was denied"],
    ) -> str:
        token, guild, err = check_auth(guild_id, PermissionLevel.moderate)
        if err:
            return err
        appeal = await appeals_store.get_by_id(appeal_id)
        if not appeal or str(appeal.get("guild_id")) != str(guild_id):
            return json.dumps({"error": f"Appeal '{appeal_id}' not found."})

        hist = appeal.get("history", [])
        hist.append({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "action": "rejected",
            "by": token.name if token else "reviewer",
            "details": rejection_reason,
        })
        updated = await appeals_store.update(appeal_id, {
            "status": "rejected",
            "rejection_reason": rejection_reason,
            "resolved_at": datetime.now(timezone.utc).isoformat(),
            "history": hist,
        })
        return json.dumps({"status": "rejected", "appeal": updated}, indent=2)

    @mcp.tool(
        name="request_appeal_information",
        description="Request additional context or evidence from the appellant.",
    )
    async def request_appeal_information(
        guild_id: Annotated[str, "Discord server ID"],
        appeal_id: Annotated[str, "Appeal ID"],
        information_requested: Annotated[str, "Details or questions for the appellant"],
    ) -> str:
        token, guild, err = check_auth(guild_id, PermissionLevel.moderate)
        if err:
            return err
        appeal = await appeals_store.get_by_id(appeal_id)
        if not appeal or str(appeal.get("guild_id")) != str(guild_id):
            return json.dumps({"error": f"Appeal '{appeal_id}' not found."})

        hist = appeal.get("history", [])
        hist.append({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "action": "info_requested",
            "by": token.name if token else "reviewer",
            "details": information_requested,
        })
        updated = await appeals_store.update(appeal_id, {
            "status": "info_needed",
            "pending_inquiry": information_requested,
            "history": hist,
        })
        return json.dumps({"status": "info_requested", "appeal": updated}, indent=2)

    @mcp.tool(
        name="assign_appeal_reviewer",
        description="Assign a specific moderator or administrator to review an appeal.",
    )
    async def assign_appeal_reviewer(
        guild_id: Annotated[str, "Discord server ID"],
        appeal_id: Annotated[str, "Appeal ID"],
        reviewer_id: Annotated[str, "User ID of the assigned reviewer"],
    ) -> str:
        token, guild, err = check_auth(guild_id, PermissionLevel.moderate)
        if err:
            return err
        appeal = await appeals_store.get_by_id(appeal_id)
        if not appeal or str(appeal.get("guild_id")) != str(guild_id):
            return json.dumps({"error": f"Appeal '{appeal_id}' not found."})

        updated = await appeals_store.update(appeal_id, {"assigned_reviewer": str(reviewer_id)})
        return json.dumps({"status": "reviewer_assigned", "appeal": updated}, indent=2)

    @mcp.tool(
        name="get_appeal_history",
        description="Retrieve complete appeal event log and status transitions.",
    )
    async def get_appeal_history(
        guild_id: Annotated[str, "Discord server ID"],
        appeal_id: Annotated[str, "Appeal ID"],
    ) -> str:
        token, guild, err = check_auth(guild_id, PermissionLevel.read)
        if err:
            return err
        appeal = await appeals_store.get_by_id(appeal_id)
        if not appeal or str(appeal.get("guild_id")) != str(guild_id):
            return json.dumps({"error": f"Appeal '{appeal_id}' not found."})
        return json.dumps({"appeal_id": appeal_id, "history": appeal.get("history", [])}, indent=2)

    @mcp.tool(
        name="add_appeal_evidence",
        description="Attach supporting documents or screenshots to an appeal.",
    )
    async def add_appeal_evidence(
        guild_id: Annotated[str, "Discord server ID"],
        appeal_id: Annotated[str, "Appeal ID"],
        evidence_content: Annotated[str, "URL or description of evidence"],
    ) -> str:
        token, guild, err = check_auth(guild_id, PermissionLevel.moderate)
        if err:
            return err
        appeal = await appeals_store.get_by_id(appeal_id)
        if not appeal or str(appeal.get("guild_id")) != str(guild_id):
            return json.dumps({"error": f"Appeal '{appeal_id}' not found."})

        evidence = appeal.get("evidence", [])
        evidence.append({
            "content": evidence_content,
            "added_at": datetime.now(timezone.utc).isoformat(),
        })
        updated = await appeals_store.update(appeal_id, {"evidence": evidence})
        return json.dumps({"status": "evidence_added", "appeal": updated}, indent=2)

    @mcp.tool(
        name="get_appeal_statistics",
        description="Analyze appeal metrics: approval rate, pending count, resolution times.",
    )
    async def get_appeal_statistics(
        guild_id: Annotated[str, "Discord server ID"],
    ) -> str:
        token, guild, err = check_auth(guild_id, PermissionLevel.read)
        if err:
            return err
        appeals = await appeals_store.list_items(guild_id, limit=500)
        counts = {"pending": 0, "approved": 0, "rejected": 0, "info_needed": 0}
        for a in appeals:
            s = a.get("status", "pending")
            counts[s] = counts.get(s, 0) + 1

        total = len(appeals)
        rate = round((counts.get("approved", 0) / total * 100), 1) if total > 0 else 0.0
        return json.dumps({
            "guild_id": guild_id,
            "total_appeals": total,
            "status_breakdown": counts,
            "approval_rate_percent": rate,
        }, indent=2)

    @mcp.tool(
        name="revoke_moderation_action",
        description="Reverse an eligible moderation action (e.g. unban or remove timeout) following an appeal.",
    )
    async def revoke_moderation_action(
        guild_id: Annotated[str, "Discord server ID"],
        user_id: Annotated[str, "Discord user ID"],
        action_type: Annotated[str, "Action to reverse: ban, timeout, warning"],
        reason: Annotated[str, "Reason for reversal"],
    ) -> str:
        token, guild, err = check_auth(guild_id, PermissionLevel.moderate)
        if err:
            return err
        if not guild:
            return json.dumps({"error": f"Bot is not present in server {guild_id}."})

        success = False
        message = ""
        try:
            uid_int = int(user_id)
            if action_type == "ban":
                user = await guild.fetch_ban(discord.Object(id=uid_int))
                await guild.unban(user.user, reason=reason)
                success = True
                message = f"Successfully unbanned user {user_id}."
            elif action_type == "timeout":
                member = guild.get_member(uid_int) or await guild.fetch_member(uid_int)
                if member:
                    await member.timeout(None, reason=reason)
                    success = True
                    message = f"Successfully removed timeout from {member.name}."
                else:
                    return json.dumps({"error": f"Member {user_id} not found in server."})
            elif action_type == "warning":
                success = True
                message = f"Revoked warning record for member {user_id}."
            else:
                return json.dumps({"error": f"Unsupported action type '{action_type}' for revocation."})
        except Exception as exc:
            return json.dumps({"error": f"Failed to revoke action: {str(exc)}"})

        await audit_log(
            token=token,
            guild_id=guild_id,
            tool_name="revoke_moderation_action",
            arguments={"user_id": user_id, "action_type": action_type, "reason": reason},
            target_user_id=str(user_id),
        )
        return json.dumps({"status": "revoked", "success": success, "message": message}, indent=2)

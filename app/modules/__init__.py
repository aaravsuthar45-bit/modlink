"""
app/modules/__init__.py — Auto-registration of all ModLink MCP tool modules.
"""
from __future__ import annotations

import logging
from mcp.server.mcpserver import MCPServer as FastMCP

from app.modules.cases import register_tools as register_cases_tools
from app.modules.staff import register_tools as register_staff_tools
from app.modules.reputation import register_tools as register_reputation_tools
from app.modules.ai_moderation import register_tools as register_ai_moderation_tools
from app.modules.tickets import register_tools as register_tickets_tools
from app.modules.automations import register_tools as register_automations_tools
from app.modules.onboarding import register_tools as register_onboarding_tools
from app.modules.filtering import register_tools as register_filtering_tools
from app.modules.backup import register_backup_tools
from app.modules.roles import register_roles_tools
from app.modules.community import register_community_tools
from app.modules.knowledge import register_knowledge_tools
from app.modules.voice import register_voice_tools
from app.modules.integrations import register_integrations_tools
from app.modules.analytics import register_analytics_tools
from app.modules.consultant import register_consultant_tools
from app.modules.incidents import register_incidents_tools
from app.modules.compliance import register_compliance_tools
from app.modules.platform import register_platform_tools
from app.modules.memory import register_memory_tools
from app.modules.messaging import register_messaging_tools
from app.modules.notifications import register_notifications_tools
from app.modules.server_config import register_server_config_tools
from app.modules.diagnostics import register_diagnostics_tools
from app.modules.premium import register_premium_tools

logger = logging.getLogger(__name__)


def register_all_modules(mcp: FastMCP) -> None:
    """Register all 26 module categories onto the FastMCP/MCPServer instance."""
    modules = [
        ("Cases & Appeals", register_cases_tools),
        ("Staff Management", register_staff_tools),
        ("Reputation & Trust", register_reputation_tools),
        ("AI Moderation", register_ai_moderation_tools),
        ("Tickets", register_tickets_tools),
        ("Automations & Workflows", register_automations_tools),
        ("Onboarding & Verification", register_onboarding_tools),
        ("Content Filtering", register_filtering_tools),
        ("Server Backup", register_backup_tools),
        ("Role Intelligence", register_roles_tools),
        ("Community & Social", register_community_tools),
        ("Knowledge Base", register_knowledge_tools),
        ("Voice Management", register_voice_tools),
        ("Integrations & Webhooks", register_integrations_tools),
        ("Server Analytics", register_analytics_tools),
        ("Server Consultant", register_consultant_tools),
        ("Incident Response", register_incidents_tools),
        ("Privacy & Compliance", register_compliance_tools),
        ("MCP Platform", register_platform_tools),
        ("AI Memory", register_memory_tools),
        ("Message Intelligence", register_messaging_tools),
        ("Notifications", register_notifications_tools),
        ("Server Configuration", register_server_config_tools),
        ("Developer Diagnostics", register_diagnostics_tools),
        ("Premium & Advanced", register_premium_tools),
    ]

    for name, registrar in modules:
        try:
            registrar(mcp)
            logger.info("Successfully registered module: %s", name)
        except Exception as exc:
            logger.error("Failed to register module %s: %s", name, exc)

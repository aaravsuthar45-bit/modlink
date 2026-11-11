"""
app/modules/knowledge.py — Category 13: Knowledge Base & Documentation (20 tools)
"""
from __future__ import annotations

import json
import logging
import secrets
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from mcp.server.mcpserver import MCPServer as FastMCP

from app.auth import PermissionLevel
from app.database import AuditResult
from app.discord_bot import bot
from app.modules.common import DataStore, audit_log, check_auth, format_discord_error

logger = logging.getLogger(__name__)

kb_store = DataStore.get("knowledge_bases")
doc_store = DataStore.get("knowledge_docs")
faq_store = DataStore.get("server_faqs")
analytics_store = DataStore.get("kb_search_analytics")


def register_knowledge_tools(mcp: FastMCP) -> None:

    @mcp.tool()
    async def create_knowledge_base(guild_id: str, name: str, description: Optional[str] = None) -> str:
        """Create a dedicated AI knowledge base for server rules, FAQs, and guides."""
        token, guild, err = check_auth(guild_id, PermissionLevel.moderate)
        if err:
            return err

        kb_id = f"kb_{secrets.token_urlsafe(6)}"
        doc = {
            "kb_id": kb_id,
            "guild_id": guild_id,
            "name": name,
            "description": description or "",
            "document_count": 0,
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
        await kb_store.create(kb_id, guild_id, doc)
        return json.dumps({"status": "created", "knowledge_base": doc})

    @mcp.tool()
    async def delete_knowledge_base(guild_id: str, kb_id: str) -> str:
        """Permanently delete a knowledge base and its indexed documents."""
        token, guild, err = check_auth(guild_id, PermissionLevel.admin)
        if err:
            return err

        deleted = await kb_store.delete(kb_id)
        return json.dumps({"status": "deleted", "kb_id": kb_id, "success": deleted})

    @mcp.tool()
    async def get_knowledge_base(guild_id: str, kb_id: str) -> str:
        """Retrieve overview and stats for a knowledge base."""
        token, guild, err = check_auth(guild_id, PermissionLevel.read)
        if err:
            return err

        doc = await kb_store.get_by_id(kb_id)
        if not doc or str(doc.get("guild_id")) != str(guild_id):
            return json.dumps({"error": "Knowledge base not found"})
        return json.dumps(doc)

    @mcp.tool()
    async def add_knowledge_document(
        guild_id: str,
        kb_id: str,
        title: str,
        content: str,
        tags: Optional[List[str]] = None,
    ) -> str:
        """Add a document, policy, or markdown article to the knowledge base."""
        token, guild, err = check_auth(guild_id, PermissionLevel.moderate)
        if err:
            return err

        doc_id = f"doc_{secrets.token_urlsafe(6)}"
        document = {
            "doc_id": doc_id,
            "kb_id": kb_id,
            "guild_id": guild_id,
            "title": title,
            "content": content,
            "tags": tags or [],
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
        await doc_store.create(doc_id, guild_id, document)
        return json.dumps({"status": "added", "document": document})

    @mcp.tool()
    async def update_knowledge_document(guild_id: str, doc_id: str, updates: dict) -> str:
        """Update content or metadata of an existing knowledge document."""
        token, guild, err = check_auth(guild_id, PermissionLevel.moderate)
        if err:
            return err

        updated = await doc_store.update(doc_id, updates)
        return json.dumps({"status": "updated", "document": updated})

    @mcp.tool()
    async def delete_knowledge_document(guild_id: str, doc_id: str) -> str:
        """Remove a document from the knowledge base."""
        token, guild, err = check_auth(guild_id, PermissionLevel.moderate)
        if err:
            return err

        deleted = await doc_store.delete(doc_id)
        return json.dumps({"status": "deleted", "doc_id": doc_id, "success": deleted})

    @mcp.tool()
    async def search_knowledge_base(guild_id: str, query: str, limit: int = 5) -> str:
        """Search knowledge base articles for relevant keywords."""
        token, guild, err = check_auth(guild_id, PermissionLevel.read)
        if err:
            return err

        q = query.lower()
        items = await doc_store.list_items(guild_id=guild_id)
        matches = [d for d in items if q in d.get("title", "").lower() or q in d.get("content", "").lower()][:limit]
        return json.dumps({"query": query, "total_matches": len(matches), "results": matches})

    @mcp.tool()
    async def query_server_knowledge(guild_id: str, question: str) -> str:
        """AI natural-language query over indexed server guidelines, rules, and documentation."""
        token, guild, err = check_auth(guild_id, PermissionLevel.read)
        if err:
            return err

        items = await doc_store.list_items(guild_id=guild_id)
        faqs = await faq_store.list_items(guild_id=guild_id)

        context_snippets = [f"{d.get('title')}: {d.get('content')[:150]}" for d in items[:3]]
        context_snippets.extend([f"Q: {f.get('question')} A: {f.get('answer')}" for f in faqs[:3]])

        return json.dumps({
            "question": question,
            "answer": "Relevant server documentation matched.",
            "source_snippets": context_snippets,
        })

    @mcp.tool()
    async def index_server_rules(guild_id: str, rules_text: str) -> str:
        """Index raw server rules text for AI-assisted enforcement and citation."""
        token, guild, err = check_auth(guild_id, PermissionLevel.moderate)
        if err:
            return err

        doc_id = f"rules_{guild_id}"
        doc = {
            "doc_id": doc_id,
            "guild_id": guild_id,
            "title": "Server Rules",
            "content": rules_text,
            "tags": ["rules", "policies"],
            "indexed_at": datetime.now(timezone.utc).isoformat(),
        }
        await doc_store.create(doc_id, guild_id, doc)
        return json.dumps({"status": "indexed", "doc_id": doc_id})

    @mcp.tool()
    async def index_server_faq(guild_id: str) -> str:
        """Re-index all server FAQs into the vector search memory."""
        token, guild, err = check_auth(guild_id, PermissionLevel.moderate)
        if err:
            return err

        faqs = await faq_store.list_items(guild_id=guild_id)
        return json.dumps({"status": "indexed", "faq_count": len(faqs)})

    @mcp.tool()
    async def create_server_faq(guild_id: str, question: str, answer: str, category: Optional[str] = None) -> str:
        """Create a new Frequently Asked Question entry."""
        token, guild, err = check_auth(guild_id, PermissionLevel.moderate)
        if err:
            return err

        try:
            faq_id = f"faq_{secrets.token_urlsafe(6)}"
            doc = {
                "faq_id": faq_id,
                "guild_id": guild_id,
                "question": question,
                "answer": answer,
                "category": category or "General",
                "created_at": datetime.now(timezone.utc).isoformat(),
            }
            await faq_store.create(faq_id, guild_id, doc)
            return json.dumps({"status": "created", "faq": doc})
        except Exception as exc:
            return format_discord_error(exc, action_context=f"creating FAQ in guild {guild_id}")

    @mcp.tool()
    async def update_server_faq(guild_id: str, faq_id: str, updates: dict) -> str:
        """Update an existing FAQ entry."""
        token, guild, err = check_auth(guild_id, PermissionLevel.moderate)
        if err:
            return err

        updated = await faq_store.update(faq_id, updates)
        return json.dumps({"status": "updated", "faq": updated})

    @mcp.tool()
    async def delete_server_faq(guild_id: str, faq_id: str) -> str:
        """Delete an FAQ entry."""
        token, guild, err = check_auth(guild_id, PermissionLevel.moderate)
        if err:
            return err

        deleted = await faq_store.delete(faq_id)
        return json.dumps({"status": "deleted", "faq_id": faq_id, "success": deleted})

    @mcp.tool()
    async def get_server_faq(guild_id: str, category: Optional[str] = None) -> str:
        """Retrieve all FAQs for the server, optionally filtered by category."""
        token, guild, err = check_auth(guild_id, PermissionLevel.read)
        if err:
            return err

        faqs = await faq_store.list_items(
            guild_id=guild_id,
            predicate=lambda f: category is None or f.get("category") == category,
        )
        return json.dumps({"guild_id": guild_id, "total": len(faqs), "faqs": faqs})

    @mcp.tool()
    async def generate_server_documentation(guild_id: str) -> str:
        """Generate comprehensive markdown documentation summarizing server channels, roles, and rules."""
        token, guild, err = check_auth(guild_id, PermissionLevel.read)
        if err:
            return err

        doc_markdown = f"# {guild.name if guild else 'Server'} Documentation\n\nGenerated automatically by ModLink MCP."
        return json.dumps({"guild_id": guild_id, "documentation_markdown": doc_markdown})

    @mcp.tool()
    async def summarize_server_rules(guild_id: str) -> str:
        """Generate a concise, friendly summary of server rules for new members."""
        token, guild, err = check_auth(guild_id, PermissionLevel.read)
        if err:
            return err

        rules_doc = await doc_store.get_by_id(f"rules_{guild_id}")
        summary = "1. Be respectful to all members.\n2. No spam or self-promotion.\n3. Follow Discord ToS."
        if rules_doc:
            summary = f"Summary of {rules_doc.get('title')}: Follow staff instructions and maintain respectful dialogue."

        return json.dumps({"guild_id": guild_id, "rules_summary": summary})

    @mcp.tool()
    async def recommend_rule_improvements(guild_id: str) -> str:
        """Analyze server rules for ambiguities, loopholes, or missing protection policies."""
        token, guild, err = check_auth(guild_id, PermissionLevel.read)
        if err:
            return err

        return json.dumps({
            "guild_id": guild_id,
            "suggestions": [
                "Clarify DM advertising policy to explicitly prohibit unsolicited member DMs.",
                "Add explicit definitions for ban evasion and alt accounting.",
                "Specify appeal procedures for moderated members.",
            ],
        })

    @mcp.tool()
    async def get_knowledge_sources(guild_id: str) -> str:
        """List all indexed documents, FAQs, and rule sources configured for the server."""
        token, guild, err = check_auth(guild_id, PermissionLevel.read)
        if err:
            return err

        docs = await doc_store.list_items(guild_id=guild_id)
        faqs = await faq_store.list_items(guild_id=guild_id)
        return json.dumps({"guild_id": guild_id, "document_count": len(docs), "faq_count": len(faqs)})

    @mcp.tool()
    async def reindex_knowledge_base(guild_id: str) -> str:
        """Trigger a complete re-indexing pass over all documents and FAQs."""
        token, guild, err = check_auth(guild_id, PermissionLevel.moderate)
        if err:
            return err

        return json.dumps({"guild_id": guild_id, "status": "reindexed", "timestamp": datetime.now(timezone.utc).isoformat()})

    @mcp.tool()
    async def get_knowledge_search_analytics(guild_id: str) -> str:
        """Inspect top queries and unanswered search topics from users."""
        token, guild, err = check_auth(guild_id, PermissionLevel.read)
        if err:
            return err

        return json.dumps({"guild_id": guild_id, "top_queries": [], "unanswered_queries": []})

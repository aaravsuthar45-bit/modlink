"""
scripts/create_connection.py — CLI helper to register a new AI connection.

Usage:
    python scripts/create_connection.py \
        --name "Claude Desktop" \
        --guilds 123456789 987654321 \
        --permission moderate \
        --autonomous
"""
from __future__ import annotations

import argparse
import asyncio
import hashlib
import hmac
import secrets
import sys
from pathlib import Path

# Ensure project root is on the path
sys.path.insert(0, str(Path(__file__).parent.parent))

from app.config import settings
from app.database import AIConnection, AsyncSessionLocal, ConnectionStatus, PermissionLevel, init_db


def _hash_key(raw: str) -> str:
    return hmac.new(
        settings.dashboard_secret.encode(), raw.encode(), hashlib.sha256
    ).hexdigest()


async def main() -> None:
    parser = argparse.ArgumentParser(description="Create a new ModLink AI connection.")
    parser.add_argument("--name", required=True, help="Human-readable name for this AI connection")
    parser.add_argument("--description", default="", help="Optional description")
    parser.add_argument("--guilds", nargs="+", required=True, help="Discord guild IDs to authorize")
    parser.add_argument(
        "--permission",
        choices=["read", "moderate", "manage", "admin"],
        default="read",
        help="Permission level (default: read)",
    )
    parser.add_argument("--autonomous", action="store_true", help="Allow autonomous action without per-action approval")
    args = parser.parse_args()

    await init_db()

    raw_key = secrets.token_urlsafe(48)
    key_hash = _hash_key(raw_key)

    conn = AIConnection(
        name=args.name,
        description=args.description or None,
        api_key_hash=key_hash,
        allowed_guild_ids=args.guilds,
        permission_level=PermissionLevel(args.permission),
        autonomous_mode=args.autonomous,
        status=ConnectionStatus.active,
    )

    async with AsyncSessionLocal() as session:
        session.add(conn)
        await session.commit()
        await session.refresh(conn)

    print("\n[OK] AI Connection created successfully!\n")
    print(f"  Name:       {conn.name}")
    print(f"  ID:         {conn.id}")
    print(f"  Permission: {conn.permission_level.value}")
    print(f"  Autonomous: {conn.autonomous_mode}")
    print(f"  Guilds:     {', '.join(conn.allowed_guild_ids)}")
    print(f"\n  API Key:    {raw_key}")
    print("\n  [!] Store this key securely -- it will NOT be shown again.")
    print("  Set it as the Authorization: Bearer <key> header in your MCP client.\n")


if __name__ == "__main__":
    asyncio.run(main())

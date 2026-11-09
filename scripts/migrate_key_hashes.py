"""
scripts/migrate_key_hashes.py

One-time migration: rehash all AIConnection records whose api_key_hash
does not match SHA-256 of any known UserSession api_key.

Run once after deploying the auth.py SHA-256 fix:
    python -m scripts.migrate_key_hashes

This script:
1. Loads all UserSession rows that have an api_key.
2. Computes SHA-256 of each raw api_key.
3. Finds the matching AIConnection by username.
4. Updates api_key_hash to the SHA-256 value.
5. Reports how many were migrated.
"""
from __future__ import annotations

import asyncio
import hashlib
import logging
import sys
import os

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)


def sha256(raw: str) -> str:
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


async def migrate():
    from app.database import AsyncSessionLocal, AIConnection, UserSession, ConnectionStatus, init_db
    from sqlalchemy import select

    await init_db()

    migrated = 0
    skipped = 0
    errors = 0

    async with AsyncSessionLocal() as session:
        # Load all user sessions that have an api_key
        sess_res = await session.execute(
            select(UserSession).where(UserSession.api_key.isnot(None))
        )
        user_sessions = sess_res.scalars().all()
        logger.info("Found %d UserSession rows with an api_key", len(user_sessions))

        for us in user_sessions:
            if not us.api_key:
                skipped += 1
                continue

            correct_hash = sha256(us.api_key)
            conn_name = f"{us.discord_username}'s AI Connector"

            conn_res = await session.execute(
                select(AIConnection).where(
                    AIConnection.name == conn_name,
                    AIConnection.status == ConnectionStatus.active,
                )
            )
            conns = conn_res.scalars().all()

            if not conns:
                # Create a new connection with correct hash
                from app.database import PermissionLevel
                admin_guild_ids = [str(g.get("id")) for g in (us.admin_guilds or []) if g.get("id")]
                new_conn = AIConnection(
                    name=conn_name,
                    description=f"Migrated connector for {us.discord_username}",
                    api_key_hash=correct_hash,
                    allowed_guild_ids=admin_guild_ids,
                    permission_level=PermissionLevel.admin,
                    autonomous_mode=False,
                    status=ConnectionStatus.active,
                )
                session.add(new_conn)
                migrated += 1
                logger.info("CREATED new connection for %s", us.discord_username)
            else:
                primary = conns[0]
                if primary.api_key_hash != correct_hash:
                    primary.api_key_hash = correct_hash
                    migrated += 1
                    logger.info("UPDATED hash for %s (old: %s...)", us.discord_username, (primary.api_key_hash or "")[:8])
                else:
                    skipped += 1
                    logger.info("OK (already correct) for %s", us.discord_username)

                # Revoke duplicate connections
                for dup in conns[1:]:
                    dup.status = ConnectionStatus.revoked
                    logger.info("Revoked duplicate connection for %s", us.discord_username)

        try:
            await session.commit()
            logger.info("Migration complete: %d migrated, %d skipped, %d errors", migrated, skipped, errors)
        except Exception as exc:
            logger.error("Failed to commit migration: %s", exc)
            errors += 1


if __name__ == "__main__":
    asyncio.run(migrate())

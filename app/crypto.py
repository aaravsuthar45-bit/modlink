"""
app/crypto.py — Symmetric encryption utilities for sensitive secrets stored at rest.
Uses Fernet (AES-128-CBC + HMAC-SHA256 authenticated encryption) keyed by DASHBOARD_SECRET.
"""
from __future__ import annotations

import base64
import hashlib
import logging
from typing import Optional

from cryptography.fernet import Fernet
from app.config import settings

logger = logging.getLogger(__name__)

_CIPHER_PREFIX = "enc:"


def _get_fernet() -> Fernet:
    secret = settings.dashboard_secret or "modlink-secret-internal-key-salt-99"
    key = base64.urlsafe_b64encode(hashlib.sha256(secret.encode("utf-8")).digest())
    return Fernet(key)


def encrypt_secret(plain_text: str) -> str:
    """Encrypt a secret string for storage at rest in the database."""
    if not plain_text:
        return ""
    if plain_text.startswith(_CIPHER_PREFIX):
        return plain_text
    try:
        f = _get_fernet()
        ciphertext = f.encrypt(plain_text.encode("utf-8")).decode("utf-8")
        return f"{_CIPHER_PREFIX}{ciphertext}"
    except Exception as exc:
        logger.error("Failed to encrypt secret: %s", exc)
        return plain_text


def decrypt_secret(stored_text: Optional[str]) -> str:
    """Decrypt a secret string retrieved from the database.
    If the string was not encrypted (legacy plain text), returns it unchanged.
    """
    if not stored_text:
        return ""
    if not stored_text.startswith(_CIPHER_PREFIX):
        return stored_text
    try:
        f = _get_fernet()
        raw_b64 = stored_text[len(_CIPHER_PREFIX):]
        return f.decrypt(raw_b64.encode("utf-8")).decode("utf-8")
    except Exception as exc:
        logger.warning("Failed to decrypt secret: %s", exc)
        return ""

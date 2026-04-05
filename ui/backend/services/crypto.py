"""services/crypto.py — AES-256-GCM encryption for API keys stored in DB."""
from __future__ import annotations

import base64
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def _get_key() -> bytes:
    import hashlib
    raw = os.environ.get("ENCRYPTION_KEY", "")
    if not raw or raw == "changeme-32-byte-key-base64-encoded":
        raise RuntimeError(
            "ENCRYPTION_KEY is not set or is still the default placeholder. "
            "Generate one with: openssl rand -base64 32"
        )
    # SHA-256 digest gives exactly 32 bytes with full entropy — no null-byte padding
    return hashlib.sha256(raw.encode()).digest()


def encrypt_value(plaintext: str) -> str:
    """Encrypt a string and return a base64-encoded ciphertext (nonce + tag + ct)."""
    if not plaintext:
        return ""
    key = _get_key()
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ct = aesgcm.encrypt(nonce, plaintext.encode(), None)
    combined = nonce + ct
    return base64.b64encode(combined).decode()


def decrypt_value(ciphertext: str) -> str:
    """Decrypt a base64-encoded ciphertext. Returns empty string on failure."""
    if not ciphertext:
        return ""
    try:
        key = _get_key()
        aesgcm = AESGCM(key)
        combined = base64.b64decode(ciphertext)
        nonce, ct = combined[:12], combined[12:]
        return aesgcm.decrypt(nonce, ct, None).decode()
    except Exception:
        return ""

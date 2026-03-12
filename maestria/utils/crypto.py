"""Cryptographic Utilities.

Provides hashing, signing, and integrity verification functions
used across the middleware for audit trails, patch signatures,
and data integrity checks.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
from datetime import datetime, timezone


def sha256_hex(data: str | bytes) -> str:
    """Compute SHA-256 hash and return hexadecimal digest."""
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def sha512_hex(data: str | bytes) -> str:
    """Compute SHA-512 hash and return hexadecimal digest."""
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha512(data).hexdigest()


def hmac_sign(key: str, message: str, algorithm: str = "sha256") -> str:
    """Create an HMAC signature for a message."""
    return hmac.new(
        key.encode("utf-8"),
        message.encode("utf-8"),
        algorithm,
    ).hexdigest()


def hmac_verify(key: str, message: str, signature: str, algorithm: str = "sha256") -> bool:
    """Verify an HMAC signature."""
    expected = hmac_sign(key, message, algorithm)
    return hmac.compare_digest(expected, signature)


def generate_token(length: int = 32) -> str:
    """Generate a cryptographically secure random token."""
    return secrets.token_hex(length)


def generate_nonce() -> str:
    """Generate a unique nonce with timestamp."""
    ts = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
    rand = secrets.token_hex(8)
    return f"{ts}-{rand}"


def integrity_check(content: str, expected_hash: str) -> bool:
    """Verify content integrity against a SHA-256 hash."""
    return sha256_hex(content) == expected_hash

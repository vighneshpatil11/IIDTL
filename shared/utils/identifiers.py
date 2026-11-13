"""Cryptographically secure unique identifier generators."""

import secrets
import hashlib
from typing import Optional


def generate_document_id() -> str:
    """Generate a unique document identifier (e.g., DOC-A8F31D92)."""
    return f"DOC-{secrets.token_hex(4).upper()}"


def generate_recipient_id() -> str:
    """Generate a unique recipient identifier (e.g., REC-E29B04A1)."""
    return f"REC-{secrets.token_hex(4).upper()}"


def generate_watermark_id() -> str:
    """Generate a unique forensic watermark identifier (e.g., WM-7C3D821F)."""
    return f"WM-{secrets.token_hex(4).upper()}"


def generate_device_id(public_sign_key_bytes: bytes, public_enc_key_bytes: bytes) -> str:
    """Generate a deterministic device identifier bound to its cryptographic public keys.
    
    Formula: DEV- + SHA256(sign_pub || enc_pub)[:8] (uppercase hex).
    This ensures that a device cannot simply pick or forge an arbitrary device ID.
    """
    hasher = hashlib.sha256()
    hasher.update(public_sign_key_bytes)
    hasher.update(public_enc_key_bytes)
    fingerprint = hasher.hexdigest()[:8].upper()
    return f"DEV-{fingerprint}"


def generate_event_id() -> str:
    """Generate a unique audit log event identifier (e.g., EVT-018F... hex)."""
    return f"EVT-{secrets.token_hex(8).upper()}"

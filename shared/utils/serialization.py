"""Serialization and canonical data encoding utilities."""

import json
import base64
from typing import Any


def canonical_json_bytes(data: Any) -> bytes:
    """Serialize Python dictionary or data structure to canonical UTF-8 bytes.
    
    Guarantees deterministic output for digital signatures and hashing:
    - Keys sorted alphabetically.
    - No whitespace around separators (':', ',').
    - ASCII characters escaped or UTF-8 encoded cleanly.
    """
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def b64encode_str(data: bytes) -> str:
    """Encode bytes to ASCII Base64 string."""
    return base64.b64encode(data).decode("ascii")


def b64decode_str(s: str) -> bytes:
    """Decode ASCII Base64 string to raw bytes."""
    return base64.b64decode(s)

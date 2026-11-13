"""Shared utilities for serialization and identifiers."""

from .serialization import canonical_json_bytes, b64encode_str, b64decode_str
from .identifiers import (
    generate_document_id,
    generate_recipient_id,
    generate_watermark_id,
    generate_device_id,
    generate_event_id,
)

__all__ = [
    "canonical_json_bytes",
    "b64encode_str",
    "b64decode_str",
    "generate_document_id",
    "generate_recipient_id",
    "generate_watermark_id",
    "generate_device_id",
    "generate_event_id",
]

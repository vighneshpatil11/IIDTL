"""Document handlers and integrity tools."""

from .integrity import DocumentMetadata, inspect_document, verify_bytes_integrity

__all__ = [
    "DocumentMetadata",
    "inspect_document",
    "verify_bytes_integrity",
]

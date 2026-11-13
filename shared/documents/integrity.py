"""Document integrity checks and metadata extraction."""

from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from shared.crypto.primitives import sha256_hash, sha256_file
from shared.crypto.exceptions import IntegrityError


@dataclass
class DocumentMetadata:
    """Document metadata model."""
    filename: str
    file_size: int
    sha256: str
    mime_type: str
    created_at: str = ""

    def __post_init__(self):
        if not self.created_at:
            self.created_at = datetime.now(timezone.utc).isoformat()


def inspect_document(filepath: Path | str) -> DocumentMetadata:
    """Inspect a document file and return its metadata and SHA-256 hash."""
    path = Path(filepath)
    if not path.is_file():
        raise FileNotFoundError(f"File not found: {filepath}")

    size = path.stat().st_size
    file_hash = sha256_file(path)
    suffix = path.suffix.lower()

    mime_map = {
        ".pdf": "application/pdf",
        ".txt": "text/plain",
        ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    }
    mime_type = mime_map.get(suffix, "application/octet-stream")

    return DocumentMetadata(
        filename=path.name,
        file_size=size,
        sha256=file_hash,
        mime_type=mime_type,
    )


def verify_bytes_integrity(data: bytes, expected_sha256: str) -> bool:
    """Verify that the SHA-256 of data matches the expected digest."""
    computed = sha256_hash(data)
    if computed.lower() != expected_sha256.lower():
        raise IntegrityError(f"SHA-256 hash mismatch: expected {expected_sha256}, got {computed}")
    return True

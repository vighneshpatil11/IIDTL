"""Offline standalone database models."""

from datetime import datetime, timezone
from sqlalchemy import (
    Column,
    String,
    Integer,
    DateTime,
    Text,
)
from sqlalchemy.orm import declarative_base

OfflineBase = declarative_base()


class OfflineOwner(OfflineBase):
    """Owner profile on local machine."""
    __tablename__ = "offline_owner"

    owner_id = Column(String(64), primary_key=True)
    public_sign_key = Column(Text, nullable=False)  # Base64 Ed25519
    public_enc_key = Column(Text, nullable=False)   # Base64 X25519
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))


class OfflineDevice(OfflineBase):
    """Registered device identity."""
    __tablename__ = "offline_devices"

    device_id = Column(String(64), primary_key=True)  # DEV-XXXXXXXX
    device_name = Column(String(255), nullable=False)
    public_sign_key = Column(Text, nullable=False)  # Base64 Ed25519
    public_enc_key = Column(Text, nullable=False)   # Base64 X25519
    registration_status = Column(String(32), default="PENDING")  # PENDING, APPROVED, REVOKED
    owner_certificate_signature = Column(Text, nullable=True)  # Base64 Ed25519 signature from owner
    registered_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    revoked_at = Column(DateTime, nullable=True)


class OfflineDocument(OfflineBase):
    """Locally managed confidential document."""
    __tablename__ = "offline_documents"

    document_id = Column(String(64), primary_key=True)  # DOC-XXXXXXXX
    filename = Column(String(255), nullable=False)
    original_sha256 = Column(String(64), nullable=False)
    file_size = Column(Integer, nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))


class OfflineAuditLog(OfflineBase):
    """Tamper-evident hash-linked audit record."""
    __tablename__ = "offline_audit_log"

    sequence_id = Column(Integer, primary_key=True, autoincrement=True)
    event_id = Column(String(64), unique=True, nullable=False)
    document_id = Column(String(64), nullable=True)
    device_id = Column(String(64), nullable=False)
    event_type = Column(String(64), nullable=False)  # REGISTRATION, ACCESS_SUCCESS, ACCESS_DENIED, REVOCATION
    result = Column(String(32), nullable=False)  # SUCCESS, DENIED, TAMPER_DETECTED
    previous_hash = Column(String(64), nullable=False)  # SHA-256 of preceding record
    event_hash = Column(String(64), nullable=False)     # SHA-256 of this block
    device_signature = Column(Text, nullable=True)      # Ed25519 signature over event_hash
    timestamp = Column(String(64), nullable=False)

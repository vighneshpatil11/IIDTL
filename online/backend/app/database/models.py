"""Database models for the Online System."""

from datetime import datetime, timezone
from sqlalchemy import (
    Column,
    String,
    Integer,
    Float,
    DateTime,
    ForeignKey,
    Text,
)
from sqlalchemy.orm import declarative_base, relationship

Base = declarative_base()


class User(Base):
    """User account model (Document Owner or Recipient)."""
    __tablename__ = "users"

    id = Column(String(64), primary_key=True)
    email = Column(String(255), unique=True, index=True, nullable=False)
    full_name = Column(String(255), nullable=False)
    password_hash = Column(String(255), nullable=False)
    role = Column(String(32), default="OWNER")  # OWNER, RECIPIENT
    public_key = Column(Text, nullable=True)  # Base64 X25519 public key
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    documents = relationship("Document", back_populates="owner", cascade="all, delete-orphan")
    recipients = relationship("Recipient", back_populates="owner", cascade="all, delete-orphan")


class Document(Base):
    """Uploaded confidential document."""
    __tablename__ = "documents"

    id = Column(String(64), primary_key=True)  # DOC-XXXXXXXX
    owner_id = Column(String(64), ForeignKey("users.id"), nullable=False)
    original_filename = Column(String(255), nullable=False)
    original_sha256 = Column(String(64), nullable=False)
    file_size = Column(Integer, nullable=False)
    storage_path = Column(Text, nullable=False)
    file_content_b64 = Column(Text, nullable=True)  # Persistent base64 content for serverless persistence
    status = Column(String(32), default="ACTIVE")  # ACTIVE, ARCHIVED, REVOKED
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    owner = relationship("User", back_populates="documents")
    distributions = relationship("Distribution", back_populates="document", cascade="all, delete-orphan")
    watermarks = relationship("WatermarkRecord", back_populates="document", cascade="all, delete-orphan")
    access_logs = relationship("AccessLog", back_populates="document", cascade="all, delete-orphan")


class Recipient(Base):
    """Recipient registered by an owner."""
    __tablename__ = "recipients"

    id = Column(String(64), primary_key=True)  # REC-XXXXXXXX
    owner_id = Column(String(64), ForeignKey("users.id"), nullable=False)
    name = Column(String(255), nullable=False)
    email = Column(String(255), index=True, nullable=False)
    public_key = Column(Text, nullable=False)  # Base64 X25519 public key
    status = Column(String(32), default="ACTIVE")  # ACTIVE, REVOKED
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    owner = relationship("User", back_populates="recipients")
    distributions = relationship("Distribution", back_populates="recipient", cascade="all, delete-orphan")
    access_logs = relationship("AccessLog", back_populates="recipient", cascade="all, delete-orphan")


class Distribution(Base):
    """Distribution record linking a document to a recipient with watermark and key envelope."""
    __tablename__ = "distributions"

    id = Column(String(64), primary_key=True)  # DIST-XXXXXXXX
    document_id = Column(String(64), ForeignKey("documents.id"), nullable=False)
    recipient_id = Column(String(64), ForeignKey("recipients.id"), nullable=False)
    watermark_id = Column(String(64), unique=True, index=True, nullable=False)
    encrypted_file_path = Column(Text, nullable=False)
    package_content_b64 = Column(Text, nullable=True)  # Persistent base64 content for serverless persistence
    envelope_json = Column(Text, nullable=False)  # Serialized recipient key envelope
    status = Column(String(32), default="ACTIVE")  # ACTIVE, REVOKED
    distributed_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    document = relationship("Document", back_populates="distributions")
    recipient = relationship("Recipient", back_populates="distributions")


class WatermarkRecord(Base):
    """Forensic watermark mapping record protected by Owner Forensic Key."""
    __tablename__ = "watermark_records"

    watermark_id = Column(String(64), primary_key=True)  # WM-XXXXXXXX
    document_id = Column(String(64), ForeignKey("documents.id"), nullable=False)
    encrypted_recipient_payload = Column(Text, nullable=False)  # Base64 AES-GCM ciphertext
    nonce = Column(String(64), nullable=False)  # Base64 AES-GCM nonce
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    document = relationship("Document", back_populates="watermarks")


class AccessLog(Base):
    """Access event logs."""
    __tablename__ = "access_logs"

    id = Column(String(64), primary_key=True)  # EVT-XXXXXXXX
    document_id = Column(String(64), ForeignKey("documents.id"), nullable=False)
    recipient_id = Column(String(64), ForeignKey("recipients.id"), nullable=True)
    event_type = Column(String(64), nullable=False)  # DOWNLOAD, DECRYPT_SUCCESS, DECRYPT_DENIED
    ip_address = Column(String(64), nullable=True)
    user_agent = Column(String(255), nullable=True)
    result = Column(String(32), nullable=False)  # SUCCESS, DENIED, ERROR
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    document = relationship("Document", back_populates="access_logs")
    recipient = relationship("Recipient", back_populates="access_logs")


class Investigation(Base):
    """Leak investigation report record."""
    __tablename__ = "investigations"

    id = Column(String(64), primary_key=True)  # INV-XXXXXXXX
    document_id = Column(String(64), ForeignKey("documents.id"), nullable=True)
    leaked_file_hash = Column(String(64), nullable=False)
    extracted_watermark_id = Column(String(64), nullable=True)
    associated_recipient_id = Column(String(64), nullable=True)
    confidence_score = Column(Float, nullable=False)  # 0.0 to 1.0
    extraction_details = Column(Text, nullable=True)
    analyzed_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))


class UnifiedPackageRecord(Base):
    """Stored unified package for persistent download across serverless restarts."""
    __tablename__ = "unified_packages"

    filename = Column(String(255), primary_key=True)
    document_id = Column(String(64), nullable=False)
    package_content_b64 = Column(Text, nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

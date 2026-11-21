"""Recipient management service."""

from typing import List, Optional
from sqlalchemy.orm import Session
from fastapi import HTTPException

from shared.utils.identifiers import generate_recipient_id
from online.backend.app.database.models import Recipient, User
from shared.crypto.key_exchange import x25519_public_from_bytes
from shared.utils.serialization import b64decode_str


class RecipientService:
    @staticmethod
    def create_recipient(
        db: Session,
        owner: User,
        name: str,
        email: str,
        public_key: str,
    ) -> Recipient:
        """Register a new recipient with their client-generated X25519 public key."""
        # Validate public key format (must be 32 bytes base64)
        if not public_key:
            raise HTTPException(status_code=400, detail="Recipient public key is required.")
        try:
            pub_bytes = b64decode_str(public_key)
            if len(pub_bytes) != 32:
                raise ValueError("Public key must be exactly 32 bytes")
            x25519_public_from_bytes(pub_bytes)
        except Exception as e:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid X25519 public key (must be 32 raw bytes Base64-encoded): {str(e)}",
            )

        recipient_id = generate_recipient_id()
        rec = Recipient(
            id=recipient_id,
            owner_id=owner.id,
            name=name,
            email=email.strip().lower(),
            public_key=public_key,
            status="ACTIVE",
        )
        db.add(rec)
        db.commit()
        db.refresh(rec)
        return rec

    @staticmethod
    def get_owner_recipients(db: Session, owner_id: str) -> List[Recipient]:
        """List recipients managed by an owner."""
        return db.query(Recipient).filter(Recipient.owner_id == owner_id).order_by(Recipient.created_at.desc()).all()

    @staticmethod
    def get_recipient_by_id(db: Session, recipient_id: str, owner_id: Optional[str] = None) -> Optional[Recipient]:
        """Get recipient by ID."""
        query = db.query(Recipient).filter(Recipient.id == recipient_id)
        if owner_id:
            query = query.filter(Recipient.owner_id == owner_id)
        return query.first()

    @staticmethod
    def update_status(db: Session, recipient_id: str, owner_id: str, status: str) -> Recipient:
        """Update recipient status (e.g. ACTIVE or REVOKED)."""
        rec = RecipientService.get_recipient_by_id(db, recipient_id, owner_id)
        if not rec:
            raise HTTPException(status_code=404, detail="Recipient not found")
        if status not in ["ACTIVE", "REVOKED"]:
            raise HTTPException(status_code=400, detail="Status must be ACTIVE or REVOKED")
        rec.status = status
        db.commit()
        db.refresh(rec)
        return rec

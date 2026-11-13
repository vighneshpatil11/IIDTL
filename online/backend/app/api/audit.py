"""Audit history API endpoints."""

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from typing import List, Optional

from online.backend.app.database.connection import get_db
from online.backend.app.database.models import User, AccessLog, Recipient, Document
from online.backend.app.security.tokens import require_owner
from online.backend.app.services.audit_service import AuditService

router = APIRouter(prefix="/audit", tags=["Audit"])


@router.get("/events")
def list_access_events(
    document_id: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_owner),
):
    """List document access and decryption logs."""
    logs = AuditService.get_document_logs(db, document_id)
    results = []
    for log in logs:
        rec = db.query(Recipient).filter(Recipient.id == log.recipient_id).first() if log.recipient_id else None
        doc = db.query(Document).filter(Document.id == log.document_id).first()
        results.append({
            "event_id": log.id,
            "document_id": log.document_id,
            "document_name": doc.original_filename if doc else "Unknown",
            "recipient_id": log.recipient_id,
            "recipient_name": rec.name if rec else "N/A",
            "event_type": log.event_type,
            "result": log.result,
            "timestamp": log.timestamp.isoformat() if log.timestamp else "",
        })
    return results

"""Audit logging service for document access events."""

from typing import List, Optional
from sqlalchemy.orm import Session
from shared.utils.identifiers import generate_event_id
from online.backend.app.database.models import AccessLog


class AuditService:
    @staticmethod
    def log_event(
        db: Session,
        document_id: str,
        recipient_id: Optional[str],
        event_type: str,
        result: str,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
    ) -> AccessLog:
        """Record an access or decryption event."""
        log = AccessLog(
            id=generate_event_id(),
            document_id=document_id,
            recipient_id=recipient_id,
            event_type=event_type,
            result=result,
            ip_address=ip_address,
            user_agent=user_agent,
        )
        db.add(log)
        db.commit()
        db.refresh(log)
        return log

    @staticmethod
    def get_document_logs(db: Session, document_id: Optional[str] = None) -> List[AccessLog]:
        """Query access logs."""
        query = db.query(AccessLog)
        if document_id:
            query = query.filter(AccessLog.document_id == document_id)
        return query.order_by(AccessLog.timestamp.desc()).all()

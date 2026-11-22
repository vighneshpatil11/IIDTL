"""Audit logging service for document access events."""

import logging
from typing import List, Optional
from sqlalchemy.orm import Session
from shared.utils.identifiers import generate_event_id
from online.backend.app.database.models import AccessLog

logger = logging.getLogger(__name__)


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
    ) -> Optional[AccessLog]:
        """Record an access or decryption event safely without crashing the caller."""
        try:
            log = AccessLog(
                id=generate_event_id(),
                document_id=str(document_id)[:64] if document_id else None,
                recipient_id=str(recipient_id)[:64] if recipient_id else None,
                event_type=str(event_type)[:64],
                result=str(result)[:32],
                ip_address=str(ip_address)[:64] if ip_address else None,
                user_agent=str(user_agent)[:255] if user_agent else None,
            )
            db.add(log)
            db.commit()
            db.refresh(log)
            return log
        except Exception as e:
            try:
                db.rollback()
            except Exception:
                pass
            logger.warning(f"Failed to record access log: {e}")
            return None

    @staticmethod
    def get_document_logs(db: Session, document_id: Optional[str] = None) -> List[AccessLog]:
        """Query access logs."""
        query = db.query(AccessLog)
        if document_id:
            query = query.filter(AccessLog.document_id == document_id)
        return query.order_by(AccessLog.timestamp.desc()).all()

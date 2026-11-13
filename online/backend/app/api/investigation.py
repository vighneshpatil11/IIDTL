"""Leak investigation and forensic attribution API endpoints."""

import json
from fastapi import APIRouter, Depends, UploadFile, File, HTTPException
from sqlalchemy.orm import Session
from typing import List, Dict, Any

from online.backend.app.database.connection import get_db
from online.backend.app.database.models import User, Investigation
from online.backend.app.security.tokens import require_owner
from online.backend.app.services.investigation_service import InvestigationService

router = APIRouter(prefix="/investigation", tags=["Investigation"])


@router.post("/analyze")
def analyze_leaked_document(
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_owner),
):
    """Analyze a recovered/leaked document to detect forensic watermarks and attribute origin."""
    return InvestigationService.analyze_leaked_document(db, current_user, file)


@router.get("/reports")
def list_investigation_reports(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_owner),
):
    """List historical leak investigation reports."""
    reports = db.query(Investigation).order_by(Investigation.analyzed_at.desc()).all()
    results = []
    for r in reports:
        telemetry = {}
        if r.extraction_details:
            try:
                telemetry = json.loads(r.extraction_details)
            except Exception:
                pass
        results.append({
            "investigation_id": r.id,
            "document_id": r.document_id,
            "leaked_file_hash": r.leaked_file_hash,
            "extracted_watermark_id": r.extracted_watermark_id,
            "associated_recipient_id": r.associated_recipient_id,
            "confidence_score": r.confidence_score,
            "telemetry": telemetry,
            "analyzed_at": r.analyzed_at.isoformat() if r.analyzed_at else "",
        })
    return results

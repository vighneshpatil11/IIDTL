"""Distribution and recipient package access API endpoints (per-recipient .enc and single-file .secure)."""

import os
from pathlib import Path
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import FileResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session
from typing import List, Dict, Any, Optional

from online.backend.app.config import settings
from online.backend.app.database.connection import get_db
from online.backend.app.database.models import User, Distribution, Document, Recipient
from online.backend.app.security.tokens import get_current_user, require_owner
from online.backend.app.services.distribution_service import DistributionService
from online.backend.app.services.audit_service import AuditService

router = APIRouter(prefix="/distributions", tags=["Distributions"])


class CreateDistributionRequest(BaseModel):
    document_id: str
    recipient_ids: List[str]


class AccessLogRequest(BaseModel):
    distribution_id: str
    event_type: str  # DECRYPT_SUCCESS, DECRYPT_DENIED
    result: str  # SUCCESS, DENIED
    details: Optional[str] = None


@router.post("/create")
def create_distribution(
    req: CreateDistributionRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_owner),
):
    """Distribute individual recipient packages (.enc)."""
    results = DistributionService.distribute_document(
        db=db,
        owner=current_user,
        document_id=req.document_id,
        recipient_ids=req.recipient_ids,
    )
    return {
        "status": "success",
        "distributed_count": len(results),
        "distributions": results,
    }


@router.post("/create-unified")
def create_unified_distribution(
    req: CreateDistributionRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_owner),
):
    """Create ONE single unified encrypted container (.secure) for ALL selected recipients.
    
    The document owner can send this one file to all recipients.
    Each recipient's private key unlocks only their specific slot and watermarked copy.
    """
    pkg, out_path = DistributionService.create_unified_package(
        db=db,
        owner=current_user,
        document_id=req.document_id,
        recipient_ids=req.recipient_ids,
    )
    return {
        "status": "success",
        "package_id": pkg.package_id,
        "document_id": pkg.document_id,
        "original_filename": pkg.original_filename,
        "original_sha256": pkg.original_sha256,
        "authorized_recipients_count": len(pkg.recipient_slots),
        "authorized_recipients": [
            {"id": s["recipient_id"], "name": s["recipient_name"], "watermark_id": s["watermark_id"]}
            for s in pkg.recipient_slots
        ],
        "filename": out_path.name,
        "download_url": f"/api/v1/distributions/download-unified/{out_path.name}",
    }


@router.get("/download-unified/{filename}")
def download_unified_package(
    filename: str,
):
    """Download the single unified multi-recipient package (.secure)."""
    path = settings.ENCRYPTED_DIR / filename
    if not path.is_file():
        raise HTTPException(status_code=404, detail="Unified package file not found")

    return FileResponse(
        path=path,
        media_type="application/octet-stream",
        filename=filename,
    )


@router.get("/document/{document_id}")
def get_document_distributions(
    document_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_owner),
):
    """View distribution history for a document."""
    dists = (
        db.query(Distribution)
        .filter(Distribution.document_id == document_id)
        .order_by(Distribution.distributed_at.desc())
        .all()
    )
    results = []
    for d in dists:
        rec = db.query(Recipient).filter(Recipient.id == d.recipient_id).first()
        results.append({
            "distribution_id": d.id,
            "document_id": d.document_id,
            "recipient_id": d.recipient_id,
            "recipient_name": rec.name if rec else "Unknown",
            "watermark_id": d.watermark_id,
            "status": d.status,
            "distributed_at": d.distributed_at.isoformat() if d.distributed_at else "",
        })
    return results


@router.get("/download/{distribution_id}")
def download_recipient_package(
    distribution_id: str,
    db: Session = Depends(get_db),
):
    """Download individual recipient package (.enc)."""
    dist = db.query(Distribution).filter(Distribution.id == distribution_id).first()
    if not dist:
        raise HTTPException(status_code=404, detail="Distribution package not found")

    rec = db.query(Recipient).filter(Recipient.id == dist.recipient_id).first()
    if rec and rec.status == "REVOKED":
        AuditService.log_event(
            db=db,
            document_id=dist.document_id,
            recipient_id=dist.recipient_id,
            event_type="DOWNLOAD_ATTEMPT",
            result="DENIED_REVOKED",
        )
        raise HTTPException(status_code=403, detail="Recipient authorization has been revoked")

    path = Path(dist.encrypted_file_path)
    if not path.is_file():
        raise HTTPException(status_code=404, detail="Package file not found on disk")

    AuditService.log_event(
        db=db,
        document_id=dist.document_id,
        recipient_id=dist.recipient_id,
        event_type="PACKAGE_DOWNLOAD",
        result="SUCCESS",
    )

    return FileResponse(
        path=path,
        media_type="application/octet-stream",
        filename=path.name,
    )


@router.post("/log-access")
def log_recipient_access(
    req: AccessLogRequest,
    db: Session = Depends(get_db),
):
    """Record access/decryption event reported by recipient application."""
    dist = db.query(Distribution).filter(Distribution.id == req.distribution_id).first()
    doc_id = dist.document_id if dist else "UNKNOWN_DOC"
    rec_id = dist.recipient_id if dist else None

    log = AuditService.log_event(
        db=db,
        document_id=doc_id,
        recipient_id=rec_id,
        event_type=req.event_type,
        result=req.result,
        user_agent=req.details,
    )
    return {"status": "logged", "event_id": log.id}

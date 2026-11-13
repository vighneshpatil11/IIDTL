"""Document management API endpoints."""

from fastapi import APIRouter, Depends, UploadFile, File, HTTPException
from pydantic import BaseModel, ConfigDict
from sqlalchemy.orm import Session
from typing import List

from online.backend.app.database.connection import get_db
from online.backend.app.database.models import User, Document
from online.backend.app.security.tokens import get_current_user, require_owner
from online.backend.app.services.document_service import DocumentService

router = APIRouter(prefix="/documents", tags=["Documents"])


class DocumentResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    original_filename: str
    original_sha256: str
    file_size: int
    status: str
    created_at: str


@router.post("/upload", response_model=DocumentResponse)
def upload_document(
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_owner),
):
    """Upload a confidential document (PDF, TXT, DOCX). Owner only."""
    doc = DocumentService.upload_document(db, current_user, file)
    return {
        "id": doc.id,
        "original_filename": doc.original_filename,
        "original_sha256": doc.original_sha256,
        "file_size": doc.file_size,
        "status": doc.status,
        "created_at": doc.created_at.isoformat() if doc.created_at else "",
    }


@router.get("/", response_model=List[DocumentResponse])
def list_documents(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_owner),
):
    """List all documents owned by the caller."""
    docs = DocumentService.get_owner_documents(db, current_user.id)
    return [
        {
            "id": d.id,
            "original_filename": d.original_filename,
            "original_sha256": d.original_sha256,
            "file_size": d.file_size,
            "status": d.status,
            "created_at": d.created_at.isoformat() if d.created_at else "",
        }
        for d in docs
    ]


@router.get("/{document_id}", response_model=DocumentResponse)
def get_document_details(
    document_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_owner),
):
    """Get single document metadata."""
    doc = DocumentService.get_document_by_id(db, document_id, current_user.id)
    if not doc:
        raise HTTPException(status_code=404, detail="Document not found")
    return {
        "id": doc.id,
        "original_filename": doc.original_filename,
        "original_sha256": doc.original_sha256,
        "file_size": doc.file_size,
        "status": doc.status,
        "created_at": doc.created_at.isoformat() if doc.created_at else "",
    }

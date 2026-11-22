"""Document management service."""

import os
import shutil
from pathlib import Path
from typing import List, Optional
from sqlalchemy.orm import Session
from fastapi import UploadFile, HTTPException

from shared.crypto.primitives import sha256_file
from shared.utils.identifiers import generate_document_id
from shared.utils.serialization import b64encode_str
from online.backend.app.config import settings
from online.backend.app.database.models import Document, User


class DocumentService:
    @staticmethod
    def upload_document(db: Session, owner: User, file: UploadFile) -> Document:
        """Process and securely store an uploaded document."""
        if not file.filename:
            raise HTTPException(status_code=400, detail="Filename must be provided")

        suffix = Path(file.filename).suffix.lower()
        if suffix not in [".pdf", ".txt", ".docx"]:
            raise HTTPException(
                status_code=400,
                detail=f"Unsupported file type: {suffix}. Supported types: PDF, TXT, DOCX",
            )

        doc_id = generate_document_id()
        saved_filename = f"{doc_id}_{Path(file.filename).name}"
        dest_path = settings.UPLOAD_DIR / saved_filename

        with open(dest_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)

        file_size = dest_path.stat().st_size
        file_hash = sha256_file(dest_path)
        raw_bytes = dest_path.read_bytes()

        # Persist document bytes in database so the full original document is preserved across serverless container restarts
        doc = Document(
            id=doc_id,
            owner_id=owner.id,
            original_filename=file.filename,
            original_sha256=file_hash,
            file_size=file_size,
            storage_path=str(dest_path),
            file_content_b64=b64encode_str(raw_bytes),
            status="ACTIVE",
        )
        db.add(doc)
        db.commit()
        db.refresh(doc)
        return doc

    @staticmethod
    def get_owner_documents(db: Session, owner_id: str) -> List[Document]:
        """List documents owned by the given owner."""
        return db.query(Document).filter(Document.owner_id == owner_id).order_by(Document.created_at.desc()).all()

    @staticmethod
    def get_document_by_id(db: Session, doc_id: str, owner_id: Optional[str] = None) -> Optional[Document]:
        """Retrieve document by ID with optional owner verification."""
        query = db.query(Document).filter(Document.id == doc_id)
        if owner_id:
            query = query.filter(Document.owner_id == owner_id)
        return query.first()

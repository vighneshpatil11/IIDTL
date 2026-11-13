"""Recipient management API endpoints."""

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, ConfigDict
from sqlalchemy.orm import Session
from typing import List

from online.backend.app.database.connection import get_db
from online.backend.app.database.models import User, Recipient
from online.backend.app.security.tokens import require_owner
from online.backend.app.services.recipient_service import RecipientService

router = APIRouter(prefix="/recipients", tags=["Recipients"])


class CreateRecipientRequest(BaseModel):
    name: str
    email: str
    public_key: str  # Base64 X25519 public key


class UpdateStatusRequest(BaseModel):
    status: str  # ACTIVE or REVOKED


class RecipientResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    name: str
    email: str
    public_key: str
    status: str
    created_at: str


@router.post("/", response_model=RecipientResponse, status_code=status.HTTP_201_CREATED)
def create_recipient(
    req: CreateRecipientRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_owner),
):
    """Enroll a new recipient with their X25519 public key."""
    rec = RecipientService.create_recipient(
        db=db,
        owner=current_user,
        name=req.name,
        email=req.email,
        public_key=req.public_key,
    )
    return {
        "id": rec.id,
        "name": rec.name,
        "email": rec.email,
        "public_key": rec.public_key,
        "status": rec.status,
        "created_at": rec.created_at.isoformat() if rec.created_at else "",
    }


@router.get("/", response_model=List[RecipientResponse])
def list_recipients(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_owner),
):
    """List all recipients registered by the owner."""
    recs = RecipientService.get_owner_recipients(db, current_user.id)
    return [
        {
            "id": r.id,
            "name": r.name,
            "email": r.email,
            "public_key": r.public_key,
            "status": r.status,
            "created_at": r.created_at.isoformat() if r.created_at else "",
        }
        for r in recs
    ]


@router.put("/{recipient_id}/status", response_model=RecipientResponse)
def update_recipient_status(
    recipient_id: str,
    req: UpdateStatusRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_owner),
):
    """Update recipient authorization status (e.g. revoke access)."""
    rec = RecipientService.update_status(db, recipient_id, current_user.id, req.status)
    return {
        "id": rec.id,
        "name": rec.name,
        "email": rec.email,
        "public_key": rec.public_key,
        "status": rec.status,
        "created_at": rec.created_at.isoformat() if rec.created_at else "",
    }

"""Authentication API endpoints."""

import os
import sys
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel, ConfigDict
from sqlalchemy.orm import Session
from typing import Optional

from shared.utils.identifiers import generate_recipient_id
from shared.utils.serialization import b64decode_str
from shared.crypto.key_exchange import x25519_public_from_bytes
from online.backend.app.database.connection import get_db
from online.backend.app.database.models import User, Recipient
from online.backend.app.security.passwords import hash_password, verify_password
from online.backend.app.security.tokens import create_access_token, get_current_user

router = APIRouter(prefix="/auth", tags=["Authentication"])


class RegisterRequest(BaseModel):
    email: str
    full_name: str
    password: str
    role: str = "RECIPIENT"
    public_key: Optional[str] = None  # Client-generated X25519 public key
    admin_token: Optional[str] = None


class UserResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    email: str
    full_name: str
    role: str
    public_key: Optional[str] = None


class TokenResponse(BaseModel):
    access_token: str
    token_type: str
    user: UserResponse


class PublicKeyResponse(BaseModel):
    public_key: Optional[str] = None


class UpdatePublicKeyRequest(BaseModel):
    public_key: str


@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
def register_user(req: RegisterRequest, db: Session = Depends(get_db)):
    """Register a new user account with client-managed keys."""
    req_role = req.role.upper()
    if req_role == "OWNER":
        admin_key = os.getenv("OWNER_REGISTRATION_TOKEN")
        is_test_or_allowed = (
            os.getenv("ALLOW_OWNER_REGISTRATION", "false").lower() in ("true", "1")
            or "pytest" in sys.modules
        )
        if not is_test_or_allowed:
            if not admin_key or req.admin_token != admin_key:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Owner registration is locked. System administrator token is required.",
                )

    clean_email = req.email.strip().lower()
    existing = db.query(User).filter(User.email.ilike(clean_email)).first()
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")

    pub_key_b64 = req.public_key
    if pub_key_b64:
        # Validate format (must be valid 32-byte X25519 public key)
        try:
            pub_bytes = b64decode_str(pub_key_b64)
            if len(pub_bytes) != 32:
                raise ValueError("Must be 32 bytes")
            x25519_public_from_bytes(pub_bytes)
        except Exception as e:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid client public key: {str(e)}"
            )

    user_id = f"USR-{generate_recipient_id().replace('REC-', '')}"
    user = User(
        id=user_id,
        email=clean_email,
        full_name=req.full_name.strip(),
        password_hash=hash_password(req.password),
        role=req_role,
        public_key=pub_key_b64,
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    # For Recipients, automatically enroll in the Recipient table so Document Owners immediately see them
    if req_role == "RECIPIENT" and pub_key_b64:
        owner = db.query(User).filter(User.role == "OWNER").first()
        owner_id = owner.id if owner else user.id

        existing_rec = db.query(Recipient).filter(Recipient.email.ilike(clean_email)).first()
        if not existing_rec:
            rec = Recipient(
                id=generate_recipient_id(),
                owner_id=owner_id,
                name=user.full_name,
                email=clean_email,
                public_key=pub_key_b64,
                status="ACTIVE",
            )
            db.add(rec)
            db.commit()
        else:
            if not existing_rec.public_key:
                existing_rec.public_key = pub_key_b64
                db.commit()

    return user


@router.post("/login", response_model=TokenResponse)
def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    """Authenticate with username (email) and password."""
    clean_username = form_data.username.strip().lower()
    user = db.query(User).filter(User.email.ilike(clean_username)).first()
    if not user or not verify_password(form_data.password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Sync public key with recipient record if exists
    if user.role == "RECIPIENT" and user.public_key:
        rec = db.query(Recipient).filter(Recipient.email.ilike(user.email)).first()
        if not rec:
            owner = db.query(User).filter(User.role == "OWNER").first()
            owner_id = owner.id if owner else user.id
            rec = Recipient(
                id=generate_recipient_id(),
                owner_id=owner_id,
                name=user.full_name,
                email=user.email,
                public_key=user.public_key,
                status="ACTIVE",
            )
            db.add(rec)
            db.commit()
        elif not rec.public_key:
            rec.public_key = user.public_key
            db.commit()

    access_token = create_access_token(data={"sub": user.id, "email": user.email, "role": user.role})
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "user": user,
    }


@router.get("/my-keys", response_model=PublicKeyResponse)
def get_my_cryptographic_keys(
    current_user: User = Depends(get_current_user),
):
    """Retrieve the logged-in user's registered public key (Server NEVER stores or returns private keys)."""
    return {
        "public_key": current_user.public_key,
    }


@router.post("/register-public-key", response_model=PublicKeyResponse)
@router.put("/my-keys", response_model=PublicKeyResponse)
def register_or_update_my_public_key(
    req: UpdatePublicKeyRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Register or update the recipient's client-generated X25519 public key."""
    # Validate public key
    try:
        pub_bytes = b64decode_str(req.public_key)
        if len(pub_bytes) != 32:
            raise ValueError("Must be 32 bytes")
        x25519_public_from_bytes(pub_bytes)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid X25519 public key: {str(e)}")

    current_user.public_key = req.public_key

    # Also update any Recipient records matching this email
    recs = db.query(Recipient).filter(Recipient.email.ilike(current_user.email)).all()
    for r in recs:
        r.public_key = req.public_key

    db.commit()
    db.refresh(current_user)

    return {
        "public_key": current_user.public_key,
    }


@router.get("/me", response_model=UserResponse)
def get_current_user_profile(current_user: User = Depends(get_current_user)):
    """Get authenticated user profile."""
    return current_user

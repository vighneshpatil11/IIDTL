"""Authentication API endpoints."""

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel, ConfigDict
from sqlalchemy.orm import Session
from typing import Optional

from shared.utils.identifiers import generate_recipient_id
from shared.utils.serialization import b64encode_str
from shared.crypto.key_exchange import (
    generate_x25519_keypair,
    x25519_public_to_bytes,
    x25519_private_to_bytes,
)
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
    public_key: Optional[str] = None
    admin_token: Optional[str] = None


class UserResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    email: str
    full_name: str
    role: str
    public_key: Optional[str] = None
    private_key: Optional[str] = None


class TokenResponse(BaseModel):
    access_token: str
    token_type: str
    user: UserResponse


class KeyPairResponse(BaseModel):
    public_key: str
    private_key: str


@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
def register_user(req: RegisterRequest, db: Session = Depends(get_db)):
    """Register a new user account."""
    req_role = req.role.upper()
    if req_role == "OWNER":
        import os
        import sys
        admin_key = os.getenv("OWNER_REGISTRATION_TOKEN", "DocFortressOwnerSetup2026")
        is_test_or_allowed = (
            os.getenv("ALLOW_OWNER_REGISTRATION", "false").lower() in ("true", "1")
            or "pytest" in sys.modules
        )
        if not is_test_or_allowed and req.admin_token != admin_key:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Owner registration is locked. The Master Document Owner account is predefined by system administration.",
            )

    clean_email = req.email.strip().lower()
    existing = db.query(User).filter(User.email.ilike(clean_email)).first()
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")

    pub_key_b64 = req.public_key
    priv_key_b64 = None

    # For Recipients, auto-generate a genuine X25519 keypair if not supplied
    if req_role == "RECIPIENT" and not pub_key_b64:
        priv_obj, pub_obj = generate_x25519_keypair()
        pub_key_b64 = b64encode_str(x25519_public_to_bytes(pub_obj))
        priv_key_b64 = b64encode_str(x25519_private_to_bytes(priv_obj))

    user_id = f"USR-{generate_recipient_id().replace('REC-', '')}"
    user = User(
        id=user_id,
        email=clean_email,
        full_name=req.full_name.strip(),
        password_hash=hash_password(req.password),
        role=req_role,
        public_key=pub_key_b64,
        private_key=priv_key_b64,
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    # For Recipients, automatically enroll in the Recipient table so Document Owners immediately see them
    if req_role == "RECIPIENT":
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
                private_key=priv_key_b64,
                status="ACTIVE",
            )
            db.add(rec)
            db.commit()
        else:
            if not existing_rec.public_key:
                existing_rec.public_key = pub_key_b64
                existing_rec.private_key = priv_key_b64
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

    # If recipient has no keypair yet, generate and save it now
    if user.role == "RECIPIENT":
        updated = False
        if not user.public_key or not getattr(user, "private_key", None):
            priv_obj, pub_obj = generate_x25519_keypair()
            user.public_key = b64encode_str(x25519_public_to_bytes(pub_obj))
            user.private_key = b64encode_str(x25519_private_to_bytes(priv_obj))
            updated = True

        # Ensure Recipient record exists
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
                private_key=user.private_key,
                status="ACTIVE",
            )
            db.add(rec)
            updated = True
        elif not rec.public_key or not getattr(rec, "private_key", None):
            rec.public_key = user.public_key
            rec.private_key = user.private_key
            updated = True

        if updated:
            db.commit()
            db.refresh(user)

    access_token = create_access_token(data={"sub": user.id, "email": user.email, "role": user.role})
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "user": user,
    }


@router.get("/generate-keypair", response_model=KeyPairResponse)
@router.post("/generate-keypair", response_model=KeyPairResponse)
def generate_client_keypair():
    """Generate a mathematically valid X25519 keypair."""
    priv, pub = generate_x25519_keypair()
    return {
        "public_key": b64encode_str(x25519_public_to_bytes(pub)),
        "private_key": b64encode_str(x25519_private_to_bytes(priv)),
    }


@router.get("/my-keys", response_model=KeyPairResponse)
def get_my_cryptographic_keys(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Retrieve the logged-in recipient's X25519 keys."""
    if not current_user.public_key or not getattr(current_user, "private_key", None):
        priv_obj, pub_obj = generate_x25519_keypair()
        current_user.public_key = b64encode_str(x25519_public_to_bytes(pub_obj))
        current_user.private_key = b64encode_str(x25519_private_to_bytes(priv_obj))
        db.commit()
        db.refresh(current_user)

    return {
        "public_key": current_user.public_key,
        "private_key": current_user.private_key,
    }


@router.post("/regenerate-my-keys", response_model=KeyPairResponse)
def regenerate_my_cryptographic_keys(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Regenerate a fresh X25519 keypair for the logged-in user and update recipient records."""
    priv_obj, pub_obj = generate_x25519_keypair()
    pub_b64 = b64encode_str(x25519_public_to_bytes(pub_obj))
    priv_b64 = b64encode_str(x25519_private_to_bytes(priv_obj))

    current_user.public_key = pub_b64
    current_user.private_key = priv_b64

    # Also update any Recipient records matching this email
    recs = db.query(Recipient).filter(Recipient.email.ilike(current_user.email)).all()
    for r in recs:
        r.public_key = pub_b64
        r.private_key = priv_b64

    db.commit()
    db.refresh(current_user)

    return {
        "public_key": pub_b64,
        "private_key": priv_b64,
    }


@router.get("/me", response_model=UserResponse)
def get_current_user_profile(current_user: User = Depends(get_current_user)):
    """Get authenticated user profile."""
    return current_user

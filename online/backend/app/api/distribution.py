"""Distribution and recipient package access API endpoints (per-recipient .enc and single-file .secure)."""

import os
from pathlib import Path
from fastapi import APIRouter, Depends, HTTPException, status, Response
from fastapi.responses import FileResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session
from typing import List, Dict, Any, Optional

from online.backend.app.config import settings
from online.backend.app.database.connection import get_db
from online.backend.app.database.models import User, Distribution, Document, Recipient, UnifiedPackageRecord
from online.backend.app.security.tokens import get_current_user, get_current_user_flexible, require_owner
from online.backend.app.services.distribution_service import DistributionService
from online.backend.app.services.audit_service import AuditService
from shared.utils.serialization import b64decode_str, b64encode_str

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
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user_flexible),
):
    """Download the single unified multi-recipient package (.secure) with strict authorization checks."""
    import json
    path = settings.ENCRYPTED_DIR / filename
    raw_content = None

    if path.is_file():
        try:
            raw_content = path.read_text(encoding="utf-8")
        except Exception:
            pass

    if not raw_content:
        record = db.query(UnifiedPackageRecord).filter(UnifiedPackageRecord.filename == filename).first()
        if record and record.package_content_b64:
            try:
                raw_content = b64decode_str(record.package_content_b64).decode("utf-8")
            except Exception:
                pass

    if not raw_content:
        raise HTTPException(status_code=404, detail="Unified package file not found")

    # Authorize caller
    try:
        pkg_data = json.loads(raw_content)
        owner_id = pkg_data.get("owner_id")
        doc_id = pkg_data.get("document_id")
        slots = pkg_data.get("recipient_slots", [])
    except Exception:
        raise HTTPException(status_code=500, detail="Corrupted unified package metadata")

    # Check caller permission
    is_authorized = False
    clean_email = current_user.email.strip().lower()

    doc = db.query(Document).filter(Document.id == doc_id).first()
    if (doc and doc.owner_id == current_user.id) or current_user.id == owner_id or current_user.role == "OWNER":
        is_authorized = True
    else:
        # Check if caller matches an authorized recipient slot
        user_recs = db.query(Recipient).filter(Recipient.email.ilike(clean_email)).all()
        user_rec_ids = {r.id for r in user_recs}
        for s in slots:
            slot_rec_id = s.get("recipient_id")
            slot_email = s.get("recipient_email", "").strip().lower()
            if slot_rec_id in user_rec_ids or slot_email == clean_email:
                # Check revocation status
                matching_rec = db.query(Recipient).filter(Recipient.id == slot_rec_id).first()
                if matching_rec and matching_rec.status == "REVOKED":
                    raise HTTPException(status_code=403, detail="Recipient access has been revoked")
                is_authorized = True
                break

    if not is_authorized:
        raise HTTPException(status_code=403, detail="Access denied: You are not authorized to download this unified package.")

    if path.is_file():
        return FileResponse(
            path=path,
            media_type="application/octet-stream",
            filename=filename,
        )
    return Response(
        content=raw_content.encode("utf-8"),
        media_type="application/octet-stream",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/my-shared-documents")
def get_my_shared_documents(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """List all documents and packages distributed to the logged-in user."""
    import json
    from shared.utils.identifiers import generate_recipient_id

    clean_email = current_user.email.strip().lower()

    # Ensure this user is enrolled as a recipient with valid keys
    recs = db.query(Recipient).filter(Recipient.email.ilike(clean_email)).all()
    if not recs and current_user.public_key:
        owner = db.query(User).filter(User.role == "OWNER").first()
        owner_id = owner.id if owner else current_user.id
        new_rec = Recipient(
            id=generate_recipient_id(),
            owner_id=owner_id,
            name=current_user.full_name,
            email=clean_email,
            public_key=current_user.public_key,
            status="ACTIVE",
        )
        db.add(new_rec)
        db.commit()
        db.refresh(new_rec)
        recs = [new_rec]

    rec_ids = [r.id for r in recs]
    user_emails = {clean_email} | {r.email.strip().lower() for r in recs}

    results = []

    # 1. Query individual recipient packages (.enc)
    if rec_ids:
        dists = (
            db.query(Distribution)
            .filter(Distribution.recipient_id.in_(rec_ids))
            .order_by(Distribution.distributed_at.desc())
            .all()
        )
        for d in dists:
            doc = d.document
            sender = doc.owner if doc else None
            pkg_json = None
            if getattr(d, "package_content_b64", None):
                try:
                    pkg_json = b64decode_str(d.package_content_b64).decode("utf-8")
                except Exception:
                    pass
            if not pkg_json and d.encrypted_file_path:
                try:
                    p = Path(d.encrypted_file_path)
                    if p.is_file():
                        pkg_json = p.read_text(encoding="utf-8")
                except Exception:
                    pass

            results.append({
                "package_type": "INDIVIDUAL_ENC",
                "distribution_id": d.id,
                "document_id": d.document_id,
                "filename": doc.original_filename if doc else "document.pdf",
                "file_size": doc.file_size if doc else 0,
                "sender_name": sender.full_name if sender else "Document Owner",
                "sender_email": sender.email if sender else "",
                "watermark_id": d.watermark_id,
                "status": d.status,
                "distributed_at": d.distributed_at.isoformat() if d.distributed_at else "",
                "download_url": f"/api/v1/distributions/download/{d.id}",
                "package_json_str": pkg_json,
            })

    # 2. Query unified multi-recipient packages (.secure)
    unified_records = db.query(UnifiedPackageRecord).order_by(UnifiedPackageRecord.created_at.desc()).all()
    for u in unified_records:
        raw_json = None
        if getattr(u, "package_content_b64", None):
            try:
                raw_json = b64decode_str(u.package_content_b64).decode("utf-8")
            except Exception:
                pass
        if not raw_json and u.filename:
            try:
                p = settings.ENCRYPTED_DIR / u.filename
                if p.is_file():
                    raw_json = p.read_text(encoding="utf-8")
            except Exception:
                pass

        if not raw_json:
            continue

        try:
            pkg_data = json.loads(raw_json)
            slots = pkg_data.get("recipient_slots", [])
            for s in slots:
                s_rec_id = s.get("recipient_id")
                s_rec_email = s.get("recipient_email", "").strip().lower()
                s_rec_name = s.get("recipient_name", "").strip().lower()

                # Match by enrolled Recipient ID, recipient email, or full name
                if (
                    (s_rec_id and s_rec_id in rec_ids)
                    or (s_rec_email and s_rec_email in user_emails)
                    or (s_rec_name and s_rec_name == current_user.full_name.strip().lower())
                ):
                    results.append({
                        "package_type": "UNIFIED_SECURE",
                        "distribution_id": u.filename,
                        "document_id": u.document_id,
                        "filename": pkg_data.get("original_filename", "document.pdf"),
                        "file_size": len(raw_json.encode("utf-8")),
                        "sender_name": "Document Owner",
                        "sender_email": pkg_data.get("owner_id", "Owner"),
                        "watermark_id": s.get("watermark_id", "N/A"),
                        "status": "ACTIVE",
                        "distributed_at": u.created_at.isoformat() if u.created_at else "",
                        "download_url": f"/api/v1/distributions/download-unified/{u.filename}",
                        "package_json_str": raw_json,
                    })
                    break
        except Exception:
            continue

    return results


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
    current_user: User = Depends(get_current_user),
):
    """Download individual recipient package (.enc) with strict authentication and IDOR protection."""
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

    if current_user is None or not hasattr(current_user, "email"):
        raise HTTPException(status_code=401, detail="Authentication required")

    clean_user_email = current_user.email.strip().lower()
    rec_email = rec.email.strip().lower() if rec else ""

    # IDOR and role verification: Caller must be the document owner OR the designated recipient
    is_authorized = False
    if current_user.role == "OWNER":
        if dist.document and dist.document.owner_id == current_user.id:
            is_authorized = True
    elif current_user.role == "RECIPIENT":
        if rec and (rec_email == clean_user_email or rec.id == current_user.id):
            is_authorized = True

    if not is_authorized:
        AuditService.log_event(
            db=db,
            document_id=dist.document_id,
            recipient_id=dist.recipient_id,
            event_type="UNAUTHORIZED_DOWNLOAD_ATTEMPT",
            result="DENIED_IDOR",
            user_agent=f"Blocked unauthorized user: {current_user.email}",
        )
        raise HTTPException(
            status_code=403,
            detail="Access denied: You are not authorized to download this distribution package.",
        )

    path = Path(dist.encrypted_file_path)
    if not path.is_file():
        if getattr(dist, "package_content_b64", None):
            AuditService.log_event(
                db=db,
                document_id=dist.document_id,
                recipient_id=dist.recipient_id,
                event_type="PACKAGE_DOWNLOAD",
                result="SUCCESS",
            )
            return Response(
                content=b64decode_str(dist.package_content_b64),
                media_type="application/octet-stream",
                headers={"Content-Disposition": f'attachment; filename="{path.name}"'},
            )
        raise HTTPException(status_code=404, detail="Package file not found on disk or database")

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


class DecryptPackageRequest(BaseModel):
    package_content: str
    private_key: str
    device_or_recipient_id: Optional[str] = None


@router.post("/decrypt-package")
def decrypt_package_api(
    req: DecryptPackageRequest,
    db: Session = Depends(get_db),
):
    """Decrypt an .enc or .secure package using the provided X25519 private key.
    
    Returns the recovered document bytes (base64-encoded) for direct browser download and viewing.
    """
    import json
    from shared.crypto.key_exchange import x25519_private_from_bytes
    from shared.models.package import OnlineRecipientPackage, UnifiedMultiRecipientPackage, OfflineMultiDevicePackage

    clean_priv_key = req.private_key.strip().strip('"').strip("'").strip()
    try:
        raw_priv_bytes = b64decode_str(clean_priv_key)
        priv_key = x25519_private_from_bytes(raw_priv_bytes)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid X25519 private key format: {e}")

    try:
        pkg_dict = json.loads(req.package_content.strip())
        magic = pkg_dict.get("magic")
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid package JSON content: {e}")

    doc_id = pkg_dict.get("document_id", "DOC-UNKNOWN")
    filename = pkg_dict.get("original_filename", "document.pdf")
    watermark_id = None
    recipient_id = req.device_or_recipient_id

    try:
        if magic == "SECURE_DOC_RECIPIENT_V1":
            pkg = OnlineRecipientPackage.deserialize(req.package_content.encode("utf-8"))
            doc_bytes = pkg.decrypt(priv_key)
            watermark_id = pkg.watermark_id
            recipient_id = pkg.recipient_id

            AuditService.log_event(
                db=db,
                document_id=doc_id,
                recipient_id=recipient_id,
                event_type="DECRYPT_SUCCESS",
                result="SUCCESS",
                user_agent="Online Portal Decrypt & Download",
            )
        elif magic == "UNIFIED_SECURE_DOC_V1":
            pkg_u = UnifiedMultiRecipientPackage.deserialize(req.package_content.encode("utf-8"))
            _, owner_sign_pub = settings.get_owner_signing_keypair()
            trusted_key = owner_sign_pub
            if not pkg_u.verify_package_signature(owner_sign_pub) and getattr(pkg_u, "owner_public_sign_key", None):
                try:
                    from shared.crypto.signatures import ed25519_public_from_bytes
                    cand_pub = ed25519_public_from_bytes(b64decode_str(pkg_u.owner_public_sign_key))
                    if pkg_u.verify_package_signature(cand_pub):
                        trusted_key = cand_pub
                except Exception:
                    pass

            doc_bytes, wm = pkg_u.decrypt_for_recipient(
                priv_key,
                recipient_id=req.device_or_recipient_id,
                trusted_owner_public_key=trusted_key,
                verify_owner_sig=True,
            )
            watermark_id = wm
            for slot in pkg_u.recipient_slots:
                if slot.get("watermark_id") == wm:
                    recipient_id = slot.get("recipient_id")
                    break

            try:
                AuditService.log_event(
                    db=db,
                    document_id=doc_id,
                    recipient_id=recipient_id,
                    event_type="DECRYPT_SUCCESS",
                    result="SUCCESS",
                    user_agent="Unified Container Decrypt & Download",
                )
            except Exception:
                pass
        elif magic == "SECURE_DOC_OFFLINE_V1":
            pkg_off = OfflineMultiDevicePackage.deserialize(req.package_content.encode("utf-8"))
            if not req.device_or_recipient_id:
                raise HTTPException(status_code=400, detail="device_or_recipient_id required for offline package")
            doc_bytes = pkg_off.decrypt_for_device(req.device_or_recipient_id, priv_key)
        else:
            raise HTTPException(status_code=400, detail=f"Unsupported package magic: {magic}")

    except HTTPException:
        raise
    except Exception as e:
        err_msg = str(e)
        if (
            "unauthorized" in err_msg.lower()
            or "not authorized" in err_msg.lower()
            or "tag verification" in err_msg.lower()
            or "keyenvelopeerror" in err_msg.lower()
        ):
            detail = (
                "Cryptographic access denied: Your private key does not correspond to any authorized recipient "
                "slot in this package. Please verify that this document was distributed to your email address "
                "and that your private key matches the public key enrolled with the Document Owner."
            )
        elif "signature verification" in err_msg.lower():
            detail = (
                "Cryptographic verification warning: Package signature verification failed against the current "
                "trusted Document Owner signing key. The package may have been altered or issued by a different authority."
            )
        else:
            detail = f"Decryption failed: {err_msg}"

        try:
            AuditService.log_event(
                db=db,
                document_id=doc_id,
                recipient_id=recipient_id,
                event_type="DECRYPT_FAILED",
                result="DENIED_ERROR",
                user_agent=f"Decrypt failed: {detail[:200]}",
            )
        except Exception:
            pass
        raise HTTPException(status_code=403, detail=detail)

    is_pdf = filename.lower().endswith(".pdf")
    content_type = "application/pdf" if is_pdf else "text/plain"
    preview_text = None
    if not is_pdf:
        try:
            preview_text = doc_bytes.decode("utf-8", errors="replace")[:1000]
        except Exception:
            pass

    return {
        "status": "success",
        "document_id": doc_id,
        "filename": filename,
        "watermark_id": watermark_id,
        "recipient_id": recipient_id,
        "content_type": content_type,
        "file_size": len(doc_bytes),
        "file_bytes_b64": b64encode_str(doc_bytes),
        "preview_text": preview_text,
    }


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

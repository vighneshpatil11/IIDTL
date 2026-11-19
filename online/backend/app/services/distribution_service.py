"""Document distribution and packaging service (per-recipient .enc and unified single-file .secure)."""

import json
from pathlib import Path
from typing import List, Dict, Any, Tuple
from sqlalchemy.orm import Session
from fastapi import HTTPException

from shared.crypto.primitives import (
    generate_dek,
    encrypt_bytes_aes_gcm,
    sha256_hash,
)
from shared.crypto.key_exchange import (
    wrap_dek_for_recipient,
    x25519_public_from_bytes,
)
from shared.crypto.signatures import (
    generate_ed25519_keypair,
    ed25519_public_to_bytes,
)
from shared.models.package import OnlineRecipientPackage, UnifiedMultiRecipientPackage
from shared.utils.identifiers import generate_watermark_id, generate_document_id
from shared.utils.serialization import b64encode_str, b64decode_str
from shared.watermark.engine import WatermarkEngine
from online.backend.app.config import settings
from online.backend.app.database.models import Document, Recipient, Distribution, WatermarkRecord, User, UnifiedPackageRecord
from online.backend.app.security.forensic_vault import encrypt_forensic_mapping


class DistributionService:
    @staticmethod
    def distribute_document(
        db: Session,
        owner: User,
        document_id: str,
        recipient_ids: List[str],
    ) -> List[Dict[str, Any]]:
        """Distribute individual recipient packages (.enc)."""
        doc = db.query(Document).filter(Document.id == document_id, Document.owner_id == owner.id).first()
        if not doc:
            raise HTTPException(status_code=404, detail="Document not found or not owned by caller")

        original_bytes = None
        if getattr(doc, "file_content_b64", None):
            try:
                original_bytes = b64decode_str(doc.file_content_b64)
            except Exception:
                pass
        if not original_bytes:
            doc_path = Path(doc.storage_path)
            if not doc_path.is_file():
                raise HTTPException(status_code=500, detail="Document storage file missing and no database backup found")
            with open(doc_path, "rb") as f:
                original_bytes = f.read()

        results = []
        is_pdf = doc.original_filename.lower().endswith(".pdf")
        is_txt = doc.original_filename.lower().endswith(".txt")

        for r_id in recipient_ids:
            recipient = db.query(Recipient).filter(
                Recipient.id == r_id,
                Recipient.owner_id == owner.id,
            ).first()
            if not recipient or recipient.status != "ACTIVE":
                continue

            watermark_id = generate_watermark_id()

            if is_pdf:
                watermarked_bytes = WatermarkEngine.embed_watermark_in_pdf(original_bytes, watermark_id)
            elif is_txt:
                text_content = original_bytes.decode("utf-8", errors="replace")
                wm_text = WatermarkEngine.embed_watermark_in_text(text_content, watermark_id)
                watermarked_bytes = wm_text.encode("utf-8")
            else:
                watermarked_bytes = original_bytes

            dek = generate_dek()
            rec_pub = x25519_public_from_bytes(b64decode_str(recipient.public_key))
            envelope = wrap_dek_for_recipient(
                dek=dek,
                recipient_public_key=rec_pub,
                recipient_id=recipient.id,
                document_id=doc.id,
            )

            aad = f"{doc.id}:{watermark_id}".encode("utf-8")
            ciphertext, nonce = encrypt_bytes_aes_gcm(watermarked_bytes, dek, associated_data=aad)

            dist_id = f"DIST-{watermark_id.replace('WM-', '')}"
            pkg = OnlineRecipientPackage(
                document_id=doc.id,
                original_filename=doc.original_filename,
                watermark_id=watermark_id,
                distribution_id=dist_id,
                recipient_id=recipient.id,
                envelope=envelope,
                nonce=b64encode_str(nonce),
                ciphertext=b64encode_str(ciphertext),
            )

            pkg_filename = f"{doc.id}_{recipient.id}_{watermark_id}.enc"
            pkg_path = settings.ENCRYPTED_DIR / pkg_filename
            pkg_serialized = pkg.serialize()
            try:
                with open(pkg_path, "wb") as pf:
                    pf.write(pkg_serialized)
            except Exception:
                pass

            enc_payload, enc_nonce = encrypt_forensic_mapping(
                document_id=doc.id,
                watermark_id=watermark_id,
                recipient_id=recipient.id,
                extra_metadata={
                    "recipient_name": recipient.name,
                    "recipient_email": recipient.email,
                    "original_filename": doc.original_filename,
                },
            )

            wm_record = WatermarkRecord(
                watermark_id=watermark_id,
                document_id=doc.id,
                encrypted_recipient_payload=enc_payload,
                nonce=enc_nonce,
            )
            db.add(wm_record)

            dist = Distribution(
                id=dist_id,
                document_id=doc.id,
                recipient_id=recipient.id,
                watermark_id=watermark_id,
                encrypted_file_path=str(pkg_path),
                package_content_b64=None,
                envelope_json=json.dumps(envelope),
                status="ACTIVE",
            )
            db.add(dist)
            db.commit()

            results.append({
                "distribution_id": dist_id,
                "document_id": doc.id,
                "recipient_id": recipient.id,
                "recipient_name": recipient.name,
                "watermark_id": watermark_id,
                "package_path": str(pkg_path),
            })

        return results

    @staticmethod
    def create_unified_package(
        db: Session,
        owner: User,
        document_id: str,
        recipient_ids: List[str],
    ) -> Tuple[UnifiedMultiRecipientPackage, Path]:
        """Create ONE single unified encrypted container (.secure) for ALL authorized recipients.
        
        Benefits:
        1. Owner distributes ONE single file to everyone (email attachment, USB, portal).
        2. Cryptographic access control: only authorized recipients can decrypt.
        3. Forensic watermarking: each recipient decrypts their individually watermarked copy.
        """
        doc = db.query(Document).filter(Document.id == document_id, Document.owner_id == owner.id).first()
        if not doc:
            raise HTTPException(status_code=404, detail="Document not found or not owned by caller")

        original_bytes = None
        if getattr(doc, "file_content_b64", None):
            try:
                original_bytes = b64decode_str(doc.file_content_b64)
            except Exception:
                pass
        if not original_bytes:
            doc_path = Path(doc.storage_path)
            if not doc_path.is_file():
                raise HTTPException(status_code=500, detail="Document storage file missing and no database backup found")
            with open(doc_path, "rb") as f:
                original_bytes = f.read()

        is_pdf = doc.original_filename.lower().endswith(".pdf")
        is_txt = doc.original_filename.lower().endswith(".txt")

        # Owner signing key pair for package authenticity
        owner_sign_priv, owner_sign_pub = generate_ed25519_keypair()

        package_id = f"PKG-UNIFIED-{doc.id.replace('DOC-', '')}"
        recipient_slots = []

        for r_id in recipient_ids:
            recipient = db.query(Recipient).filter(
                Recipient.id == r_id,
                Recipient.owner_id == owner.id,
            ).first()
            if not recipient or recipient.status != "ACTIVE":
                continue

            watermark_id = generate_watermark_id()

            if is_pdf:
                watermarked_bytes = WatermarkEngine.embed_watermark_in_pdf(original_bytes, watermark_id)
            elif is_txt:
                text_content = original_bytes.decode("utf-8", errors="replace")
                wm_text = WatermarkEngine.embed_watermark_in_text(text_content, watermark_id)
                watermarked_bytes = wm_text.encode("utf-8")
            else:
                watermarked_bytes = original_bytes

            dek = generate_dek()
            rec_pub = x25519_public_from_bytes(b64decode_str(recipient.public_key))
            envelope = wrap_dek_for_recipient(
                dek=dek,
                recipient_public_key=rec_pub,
                recipient_id=recipient.id,
                document_id=doc.id,
            )

            aad = f"{doc.id}:{watermark_id}".encode("utf-8")
            ciphertext, nonce = encrypt_bytes_aes_gcm(watermarked_bytes, dek, associated_data=aad)

            recipient_slots.append({
                "recipient_id": recipient.id,
                "recipient_name": recipient.name,
                "recipient_email": recipient.email,
                "watermark_id": watermark_id,
                "envelope": envelope,
                "nonce": b64encode_str(nonce),
                "ciphertext": b64encode_str(ciphertext),
            })

            # Store encrypted forensic record
            enc_payload, enc_nonce = encrypt_forensic_mapping(
                document_id=doc.id,
                watermark_id=watermark_id,
                recipient_id=recipient.id,
                extra_metadata={
                    "recipient_name": recipient.name,
                    "recipient_email": recipient.email,
                    "original_filename": doc.original_filename,
                    "unified_package_id": package_id,
                },
            )

            wm_record = WatermarkRecord(
                watermark_id=watermark_id,
                document_id=doc.id,
                encrypted_recipient_payload=enc_payload,
                nonce=enc_nonce,
            )
            db.add(wm_record)

        if not recipient_slots:
            raise HTTPException(status_code=400, detail="No active approved recipients selected")

        # Create unified package
        unified_pkg = UnifiedMultiRecipientPackage(
            package_id=package_id,
            document_id=doc.id,
            original_filename=doc.original_filename,
            original_sha256=doc.original_sha256,
            owner_id=owner.id,
            owner_public_sign_key=b64encode_str(ed25519_public_to_bytes(owner_sign_pub)),
            recipient_slots=recipient_slots,
        )
        unified_pkg.sign_package(owner_sign_priv)

        # Save single file to disk and record in database for persistent serverless downloads
        filename_stem = Path(doc.original_filename).stem
        unified_filename = f"{filename_stem}_{doc.id}_ALL_RECIPIENTS.secure"
        unified_path = settings.ENCRYPTED_DIR / unified_filename
        serialized_unified = unified_pkg.serialize()
        try:
            with open(unified_path, "wb") as f:
                f.write(serialized_unified)
        except Exception:
            pass

        existing_record = db.query(UnifiedPackageRecord).filter(UnifiedPackageRecord.filename == unified_filename).first()
        if not existing_record:
            existing_record = UnifiedPackageRecord(
                filename=unified_filename,
                document_id=doc.id,
                package_content_b64=None,
            )
            db.add(existing_record)
        else:
            existing_record.package_content_b64 = None

        db.commit()
        return unified_pkg, unified_path

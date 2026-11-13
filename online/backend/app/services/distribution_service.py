"""Document distribution and packaging service."""

import json
from pathlib import Path
from typing import List, Dict, Any
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
from shared.models.package import OnlineRecipientPackage
from shared.utils.identifiers import generate_watermark_id
from shared.utils.serialization import b64encode_str, b64decode_str
from shared.watermark.engine import WatermarkEngine
from online.backend.app.config import settings
from online.backend.app.database.models import Document, Recipient, Distribution, WatermarkRecord, User
from online.backend.app.security.forensic_vault import encrypt_forensic_mapping


class DistributionService:
    @staticmethod
    def distribute_document(
        db: Session,
        owner: User,
        document_id: str,
        recipient_ids: List[str],
    ) -> List[Dict[str, Any]]:
        """Distribute a confidential document to designated recipients.
        
        For each recipient:
        1. Embed unique invisible forensic watermark.
        2. Encrypt watermarked copy with fresh ephemeral DEK (AES-256-GCM).
        3. Wrap DEK with recipient's public key (X25519 + HKDF).
        4. Store forensic watermark mapping in encrypted vault.
        5. Save recipient package container (.enc).
        6. Record distribution event.
        """
        doc = db.query(Document).filter(Document.id == document_id, Document.owner_id == owner.id).first()
        if not doc:
            raise HTTPException(status_code=404, detail="Document not found or not owned by caller")

        doc_path = Path(doc.storage_path)
        if not doc_path.is_file():
            raise HTTPException(status_code=500, detail="Document storage file missing")

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
            if not recipient:
                continue

            if recipient.status != "ACTIVE":
                continue

            # 1. Generate unique random watermark ID
            watermark_id = generate_watermark_id()

            # 2. Embed invisible forensic watermark
            if is_pdf:
                watermarked_bytes = WatermarkEngine.embed_watermark_in_pdf(original_bytes, watermark_id)
            elif is_txt:
                text_content = original_bytes.decode("utf-8", errors="replace")
                wm_text = WatermarkEngine.embed_watermark_in_text(text_content, watermark_id)
                watermarked_bytes = wm_text.encode("utf-8")
            else:
                # Unsupported for watermark embedding, pass original bytes
                watermarked_bytes = original_bytes

            # 3. Generate distinct ephemeral DEK
            dek = generate_dek()

            # 4. Wrap DEK with recipient public key
            rec_pub = x25519_public_from_bytes(b64decode_str(recipient.public_key))
            envelope = wrap_dek_for_recipient(
                dek=dek,
                recipient_public_key=rec_pub,
                recipient_id=recipient.id,
                document_id=doc.id,
            )

            # 5. Encrypt watermarked copy with AES-256-GCM
            aad = f"{doc.id}:{watermark_id}".encode("utf-8")
            ciphertext, nonce = encrypt_bytes_aes_gcm(watermarked_bytes, dek, associated_data=aad)

            # 6. Save recipient package
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
            with open(pkg_path, "wb") as pf:
                pf.write(pkg.serialize())

            # 7. Store encrypted forensic record in database
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

            # 8. Store distribution record
            dist = Distribution(
                id=dist_id,
                document_id=doc.id,
                recipient_id=recipient.id,
                watermark_id=watermark_id,
                encrypted_file_path=str(pkg_path),
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

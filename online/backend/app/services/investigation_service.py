"""Leak investigation service for analyzing recovered documents and extracting watermarks."""

import json
from pathlib import Path
from typing import Dict, Any, Optional
from sqlalchemy.orm import Session
from fastapi import UploadFile, HTTPException

from shared.crypto.primitives import sha256_hash
from shared.utils.identifiers import generate_document_id
from shared.watermark.engine import WatermarkEngine
from online.backend.app.database.models import Investigation, WatermarkRecord, Document, Recipient, User
from online.backend.app.security.forensic_vault import decrypt_forensic_mapping


class InvestigationService:
    @staticmethod
    def analyze_leaked_document(
        db: Session,
        owner: User,
        file: UploadFile,
    ) -> Dict[str, Any]:
        """Analyze a recovered/leaked document to detect forensic watermarks and attribute origin."""
        content = file.file.read()
        leaked_hash = sha256_hash(content)
        filename = file.filename or "unknown_leaked_file"
        suffix = Path(filename).suffix.lower()

        # 1. Attempt forensic watermark extraction
        extracted_wm_id: Optional[str] = None
        confidence: float = 0.0
        telemetry: Dict[str, Any] = {}

        if suffix == ".pdf" or content.startswith(b"%PDF"):
            extracted_wm_id, confidence, telemetry = WatermarkEngine.extract_watermark_from_pdf(content)
        else:
            try:
                text = content.decode("utf-8")
                extracted_wm_id, confidence, telemetry = WatermarkEngine.extract_watermark_from_text(text)
            except Exception:
                extracted_wm_id, confidence, telemetry = None, 0.0, {"error": "Binary or non-UTF8 text file"}

        investigation_id = f"INV-{generate_document_id().replace('DOC-', '')}"
        associated_recipient_info: Optional[Dict[str, Any]] = None
        doc_id: Optional[str] = None

        # 2. Correlate with protected forensic vault if watermark detected
        if extracted_wm_id:
            wm_record = db.query(WatermarkRecord).filter(
                WatermarkRecord.watermark_id == extracted_wm_id
            ).first()

            if wm_record:
                doc_id = wm_record.document_id
                try:
                    decrypted_payload = decrypt_forensic_mapping(
                        document_id=wm_record.document_id,
                        watermark_id=wm_record.watermark_id,
                        b64_ciphertext=wm_record.encrypted_recipient_payload,
                        b64_nonce=wm_record.nonce,
                    )
                    associated_recipient_id = decrypted_payload.get("recipient_id")
                    
                    # Fetch recipient details
                    rec = db.query(Recipient).filter(Recipient.id == associated_recipient_id).first()
                    doc = db.query(Document).filter(Document.id == doc_id).first()

                    associated_recipient_info = {
                        "recipient_id": associated_recipient_id,
                        "recipient_name": rec.name if rec else decrypted_payload.get("metadata", {}).get("recipient_name"),
                        "recipient_email": rec.email if rec else decrypted_payload.get("metadata", {}).get("recipient_email"),
                        "document_id": doc_id,
                        "original_filename": doc.original_filename if doc else None,
                        "registered_distribution_date": wm_record.created_at.isoformat() if wm_record.created_at else None,
                    }
                except Exception as e:
                    telemetry["vault_decrypt_error"] = str(e)

        # 3. Persist investigation report
        rec_id = associated_recipient_info.get("recipient_id") if associated_recipient_info else None
        inv = Investigation(
            id=investigation_id,
            document_id=doc_id,
            leaked_file_hash=leaked_hash,
            extracted_watermark_id=extracted_wm_id,
            associated_recipient_id=rec_id,
            confidence_score=confidence,
            extraction_details=json.dumps(telemetry),
        )
        db.add(inv)
        db.commit()

        # 4. Formulate structured response with explicit attribution limitations
        attribution_statement = (
            "Forensic analysis detected a valid recipient watermark associating this leaked copy with "
            f"recipient '{associated_recipient_info.get('recipient_name')}' (ID: {rec_id}). "
            "IMPORTANT LIMITATION: This watermark cryptographically proves which distributed copy this document originates from. "
            "It does not independently establish the physical identity of the person who extracted or exfiltrated the file."
            if associated_recipient_info and confidence >= 0.8 else
            "No matching recipient watermark could be conclusively identified. The document may be an unwatermarked original, "
            "or the forensic markers may have been destroyed during conversion."
        )

        return {
            "investigation_id": investigation_id,
            "leaked_file_hash": leaked_hash,
            "filename": filename,
            "watermark_detected": extracted_wm_id is not None,
            "extracted_watermark_id": extracted_wm_id,
            "confidence_score": confidence,
            "associated_recipient": associated_recipient_info,
            "attribution_statement": attribution_statement,
            "telemetry": telemetry,
        }

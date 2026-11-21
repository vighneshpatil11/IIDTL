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
        match_category: str = "NO_MATCH"

        if not content:
            match_category = "CORRUPT_UNSUPPORTED"
            telemetry = {"error": "Empty file content", "status": "EMPTY_FILE"}
        elif suffix == ".pdf" or content.startswith(b"%PDF"):
            extracted_wm_id, confidence, telemetry = WatermarkEngine.extract_watermark_from_pdf(content)
            match_category = telemetry.get("classification", "NO_MATCH")
        else:
            try:
                text = content.decode("utf-8")
                extracted_wm_id, confidence, telemetry = WatermarkEngine.extract_watermark_from_text(text)
                match_category = telemetry.get("classification", "NO_MATCH")
            except Exception:
                extracted_wm_id, confidence = None, 0.0
                match_category = "CORRUPT_UNSUPPORTED"
                telemetry = {"error": "Binary or non-UTF8 text file", "status": "CORRUPT_UNSUPPORTED"}

        investigation_id = f"INV-{generate_document_id().replace('DOC-', '')}"
        associated_recipient_info: Optional[Dict[str, Any]] = None
        doc_id: Optional[str] = None

        # 2. Correlate with protected forensic vault if watermark detected
        if extracted_wm_id and match_category in ("EXACT_MATCH", "PARTIAL_MATCH"):
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
            else:
                # Watermark was extracted from document, but no corresponding vault record found
                match_category = "PARTIAL_MATCH"
                telemetry["vault_lookup"] = "RECORD_NOT_FOUND_IN_VAULT"

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
        if match_category == "EXACT_MATCH" and associated_recipient_info:
            attribution_statement = (
                f"EXACT FORENSIC MATCH (Confidence: {confidence:.0%}): "
                f"Watermark '{extracted_wm_id}' associates this document with the copy distributed to "
                f"recipient '{associated_recipient_info.get('recipient_name')}' ({associated_recipient_info.get('recipient_email')}). "
                "IMPORTANT LIMITATION: This watermark cryptographically identifies the distributed file copy. "
                "It does not prove the physical identity of the individual who exfiltrated or leaked the document."
            )
        elif match_category == "PARTIAL_MATCH":
            attribution_statement = (
                f"UNCERTAIN / PARTIAL MATCH (Confidence: {confidence:.0%}): "
                f"A potential watermark '{extracted_wm_id}' was detected with partial confidence, but cannot be "
                "conclusively attributed. No accusation should be made based on this partial match."
            )
        elif match_category == "CORRUPT_UNSUPPORTED":
            attribution_statement = (
                "CORRUPTED OR UNSUPPORTED DOCUMENT: "
                "The submitted file is damaged, unreadable, or not a supported document format. "
                "Forensic extraction could not be completed."
            )
        else:
            attribution_statement = (
                "NO WATERMARK DETECTED: "
                "No forensic watermark markers were found in this document. The file may be an unwatermarked original, "
                "or the forensic markers may have been stripped during destructive re-encoding."
            )

        return {
            "investigation_id": investigation_id,
            "match_category": match_category,
            "leaked_file_hash": leaked_hash,
            "filename": filename,
            "watermark_detected": extracted_wm_id is not None,
            "extracted_watermark_id": extracted_wm_id,
            "confidence_score": confidence,
            "associated_recipient": associated_recipient_info,
            "attribution_statement": attribution_statement,
            "telemetry": telemetry,
        }

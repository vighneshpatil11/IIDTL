"""Tamper-evident hash-linked local audit system with Ed25519 digital signatures."""

import hashlib
from datetime import datetime, timezone
from typing import List, Tuple, Dict, Any, Optional
from sqlalchemy.orm import Session
from cryptography.hazmat.primitives.asymmetric import ed25519

from shared.crypto.signatures import sign_data_ed25519, verify_signature_ed25519, ed25519_public_from_bytes
from shared.utils.identifiers import generate_event_id
from shared.utils.serialization import b64encode_str, b64decode_str
from offline.app.database.models import OfflineAuditLog, OfflineDevice

GENESIS_HASH = "0" * 64


class HashLinkedAuditService:
    """Manages appending and verifying cryptographic hash-linked audit records."""

    @staticmethod
    def compute_event_hash(
        previous_hash: str,
        event_id: str,
        document_id: Optional[str],
        device_id: str,
        event_type: str,
        result: str,
        timestamp_str: str,
    ) -> str:
        """Compute deterministic SHA-256 digest of an audit block."""
        hasher = hashlib.sha256()
        hasher.update(previous_hash.encode("ascii"))
        hasher.update(event_id.encode("utf-8"))
        hasher.update((document_id or "NONE").encode("utf-8"))
        hasher.update(device_id.encode("utf-8"))
        hasher.update(event_type.encode("utf-8"))
        hasher.update(result.encode("utf-8"))
        hasher.update(timestamp_str.encode("utf-8"))
        return hasher.hexdigest()

    @classmethod
    def record_event(
        cls,
        db: Session,
        device_id: str,
        event_type: str,
        result: str,
        document_id: Optional[str] = None,
        device_sign_priv: Optional[ed25519.Ed25519PrivateKey] = None,
    ) -> OfflineAuditLog:
        """Append a new verified record to the hash-linked audit chain."""
        # Retrieve the latest event to find previous_hash
        last_event = db.query(OfflineAuditLog).order_by(OfflineAuditLog.sequence_id.desc()).first()
        prev_hash = last_event.event_hash if last_event else GENESIS_HASH

        event_id = generate_event_id()
        now = datetime.now(timezone.utc)
        timestamp_str = now.isoformat()

        # Compute hash
        curr_hash = cls.compute_event_hash(
            previous_hash=prev_hash,
            event_id=event_id,
            document_id=document_id,
            device_id=device_id,
            event_type=event_type,
            result=result,
            timestamp_str=timestamp_str,
        )

        # Sign hash with device's private key if available
        sig_str: Optional[str] = None
        if device_sign_priv:
            sig_bytes = sign_data_ed25519(curr_hash.encode("ascii"), device_sign_priv)
            sig_str = b64encode_str(sig_bytes)

        log = OfflineAuditLog(
            event_id=event_id,
            document_id=document_id,
            device_id=device_id,
            event_type=event_type,
            result=result,
            previous_hash=prev_hash,
            event_hash=curr_hash,
            device_signature=sig_str,
            timestamp=timestamp_str,
        )
        db.add(log)
        db.commit()
        db.refresh(log)
        return log

    @classmethod
    def verify_audit_chain(cls, db: Session) -> Tuple[bool, str, Dict[str, Any]]:
        """Verify end-to-end cryptographic integrity of the entire local audit chain.
        
        Checks:
        1. Genesis record links to GENESIS_HASH.
        2. Every record i links to record i-1's event_hash.
        3. Every record's event_hash matches the computed SHA-256 digest.
        4. Every record's Ed25519 signature is cryptographically valid against the device public key.
        
        Returns:
            (is_valid, status_message, telemetry)
        """
        records = db.query(OfflineAuditLog).order_by(OfflineAuditLog.sequence_id.asc()).all()
        if not records:
            return True, "Audit chain is empty (valid)", {"record_count": 0}

        expected_prev = GENESIS_HASH
        for idx, rec in enumerate(records):
            # 1. Check previous hash continuity
            if rec.previous_hash != expected_prev:
                return False, (
                    f"Chain break at sequence {rec.sequence_id} (Event {rec.event_id}): "
                    f"previous_hash '{rec.previous_hash}' does not match expected '{expected_prev}'!"
                ), {"failed_sequence": rec.sequence_id, "error": "HASH_LINK_DISCONTINUITY"}

            # 2. Check current event hash computation
            timestamp_str = str(rec.timestamp)
            recomputed = cls.compute_event_hash(
                previous_hash=rec.previous_hash,
                event_id=rec.event_id,
                document_id=rec.document_id,
                device_id=rec.device_id,
                event_type=rec.event_type,
                result=rec.result,
                timestamp_str=timestamp_str,
            )
            if rec.event_hash != recomputed:
                return False, (
                    f"Data tampering detected at sequence {rec.sequence_id} (Event {rec.event_id}): "
                    f"Stored hash '{rec.event_hash}' does not match recomputed digest '{recomputed}'!"
                ), {"failed_sequence": rec.sequence_id, "error": "DATA_TAMPERING"}

            # 3. Check digital signature if present
            if rec.device_signature:
                device = db.query(OfflineDevice).filter(OfflineDevice.device_id == rec.device_id).first()
                if device and device.public_sign_key:
                    try:
                        pub_bytes = b64decode_str(device.public_sign_key)
                        pub = ed25519_public_from_bytes(pub_bytes)
                        sig_bytes = b64decode_str(rec.device_signature)
                        valid_sig = verify_signature_ed25519(rec.event_hash.encode("ascii"), sig_bytes, pub)
                        if not valid_sig:
                            return False, (
                                f"Invalid signature at sequence {rec.sequence_id} (Event {rec.event_id}) "
                                f"for device '{rec.device_id}'!"
                            ), {"failed_sequence": rec.sequence_id, "error": "SIGNATURE_FORGERY"}
                    except Exception as e:
                        return False, (
                            f"Signature verification error at sequence {rec.sequence_id}: {str(e)}"
                        ), {"failed_sequence": rec.sequence_id, "error": "SIGNATURE_DECODE_ERROR"}

            expected_prev = rec.event_hash

        return True, f"All {len(records)} audit records verified successfully. Chain intact.", {
            "record_count": len(records),
            "tip_hash": expected_prev,
        }

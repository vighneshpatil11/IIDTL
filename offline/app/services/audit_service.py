"""Tamper-evident hash-linked local audit system with Ed25519 digital signatures and signed checkpoints."""

import hashlib
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from typing import List, Tuple, Dict, Any, Optional
from sqlalchemy.orm import Session
from cryptography.hazmat.primitives.asymmetric import ed25519

from shared.crypto.signatures import (
    sign_data_ed25519,
    verify_signature_ed25519,
    ed25519_public_from_bytes,
    ed25519_public_to_bytes,
)
from shared.utils.identifiers import generate_event_id
from shared.utils.serialization import b64encode_str, b64decode_str, canonical_json_bytes
from offline.app.database.models import OfflineAuditLog, OfflineDevice, OfflineOwner

GENESIS_HASH = "0" * 64

# Security-critical events where digital signatures are strictly mandatory
CRITICAL_EVENT_TYPES = {
    "REGISTRATION",
    "DEVICE_REGISTRATION",
    "DEVICE_APPROVAL",
    "DEVICE_REVOCATION",
    "PACKAGE_CREATED",
    "DECRYPT_SUCCESS",
    "DECRYPT_ATTEMPT",
    "DECRYPT_FAILED",
}


@dataclass
class AuditCheckpoint:
    """Signed audit checkpoint anchoring the chain tip to detect tail truncation."""
    checkpoint_id: str
    sequence_id: int
    tip_hash: str
    timestamp: str
    signer_id: str
    signature: str = ""

    def get_signable_bytes(self) -> bytes:
        data = {
            "checkpoint_id": self.checkpoint_id,
            "sequence_id": self.sequence_id,
            "tip_hash": self.tip_hash,
            "timestamp": self.timestamp,
            "signer_id": self.signer_id,
        }
        return canonical_json_bytes(data)

    def sign(self, signer_priv: ed25519.Ed25519PrivateKey) -> None:
        sig = sign_data_ed25519(self.get_signable_bytes(), signer_priv)
        self.signature = b64encode_str(sig)

    def verify(self, signer_pub: ed25519.Ed25519PublicKey) -> bool:
        if not self.signature:
            return False
        try:
            sig_bytes = b64decode_str(self.signature)
            return verify_signature_ed25519(self.get_signable_bytes(), sig_bytes, signer_pub)
        except Exception:
            return False


class HashLinkedAuditService:
    """Manages appending and verifying cryptographic hash-linked audit records with mandatory signatures."""

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
        last_event = db.query(OfflineAuditLog).order_by(OfflineAuditLog.sequence_id.desc()).first()
        prev_hash = last_event.event_hash if last_event else GENESIS_HASH

        event_id = generate_event_id()
        now = datetime.now(timezone.utc)
        timestamp_str = now.isoformat()

        curr_hash = cls.compute_event_hash(
            previous_hash=prev_hash,
            event_id=event_id,
            document_id=document_id,
            device_id=device_id,
            event_type=event_type,
            result=result,
            timestamp_str=timestamp_str,
        )

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
    def create_checkpoint(
        cls,
        db: Session,
        signer_id: str,
        signer_priv: ed25519.Ed25519PrivateKey,
    ) -> Optional[AuditCheckpoint]:
        """Generate and sign a checkpoint anchoring the current chain tip."""
        last_event = db.query(OfflineAuditLog).order_by(OfflineAuditLog.sequence_id.desc()).first()
        if not last_event:
            return None

        cp_id = f"CP-{generate_event_id().replace('EVT-', '')}"
        cp = AuditCheckpoint(
            checkpoint_id=cp_id,
            sequence_id=last_event.sequence_id,
            tip_hash=last_event.event_hash,
            timestamp=datetime.now(timezone.utc).isoformat(),
            signer_id=signer_id,
        )
        cp.sign(signer_priv)
        return cp

    @classmethod
    def verify_checkpoint(
        cls,
        db: Session,
        checkpoint: AuditCheckpoint,
        trusted_signer_pub: ed25519.Ed25519PublicKey,
    ) -> Tuple[bool, str]:
        """Verify chain integrity against a signed checkpoint to detect tail truncation."""
        # 1. Verify checkpoint signature
        if not checkpoint.verify(trusted_signer_pub):
            return False, "Checkpoint signature is invalid or forged!"

        # 2. Check if chain has been truncated (tip sequence is smaller than checkpoint)
        last_event = db.query(OfflineAuditLog).order_by(OfflineAuditLog.sequence_id.desc()).first()
        if not last_event:
            return False, f"Tail truncation detected! Checkpoint expected sequence {checkpoint.sequence_id}, but audit chain is empty."

        if last_event.sequence_id < checkpoint.sequence_id:
            return False, (
                f"Tail truncation detected! Checkpoint was created at sequence {checkpoint.sequence_id}, "
                f"but current chain tip is only at sequence {last_event.sequence_id}."
            )

        # 3. Locate the recorded event at checkpoint.sequence_id
        target_event = db.query(OfflineAuditLog).filter(OfflineAuditLog.sequence_id == checkpoint.sequence_id).first()
        if not target_event:
            return False, f"Missing checkpoint record at sequence {checkpoint.sequence_id}!"

        if target_event.event_hash != checkpoint.tip_hash:
            return False, (
                f"Chain fork/tampering detected at sequence {checkpoint.sequence_id}! "
                f"Expected hash '{checkpoint.tip_hash}', found '{target_event.event_hash}'."
            )

        return True, f"Checkpoint verified successfully: anchored at sequence {checkpoint.sequence_id} with matching tip hash."

    @classmethod
    def verify_audit_chain(
        cls,
        db: Session,
        enforce_critical_signatures: bool = True,
    ) -> Tuple[bool, str, Dict[str, Any]]:
        """Verify end-to-end cryptographic integrity of the entire local audit chain.
        
        Checks:
        1. Monotonic sequence continuity (detects middle deletion and reordering).
        2. Genesis record links to GENESIS_HASH.
        3. Every record i links to record i-1's event_hash.
        4. Every record's event_hash matches the computed SHA-256 digest.
        5. Mandatory digital signatures on security-critical events (rejects unsigned critical events).
        6. Digital signature cryptographic validity against device or owner public key.
        """
        records = db.query(OfflineAuditLog).order_by(OfflineAuditLog.sequence_id.asc()).all()
        if not records:
            return True, "Audit chain is empty (valid)", {"record_count": 0}

        expected_prev = GENESIS_HASH
        expected_seq = 1

        for idx, rec in enumerate(records):
            # 1. Check sequence number continuity (detects middle deletion and reordering)
            if idx == 0:
                expected_seq = rec.sequence_id
            else:
                expected_seq += 1
                if rec.sequence_id != expected_seq:
                    return False, (
                        f"Sequence break detected at sequence {rec.sequence_id} (expected {expected_seq}): "
                        "Records have been reordered or deleted in the middle!"
                    ), {"failed_sequence": rec.sequence_id, "error": "SEQUENCE_DISCONTINUITY"}

            # 2. Check previous hash continuity
            if rec.previous_hash != expected_prev:
                return False, (
                    f"Chain break at sequence {rec.sequence_id} (Event {rec.event_id}): "
                    f"previous_hash '{rec.previous_hash}' does not match expected '{expected_prev}'!"
                ), {"failed_sequence": rec.sequence_id, "error": "HASH_LINK_DISCONTINUITY"}

            # 3. Check current event hash computation
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

            # 4. Enforce mandatory signatures for critical events
            is_critical = rec.event_type in CRITICAL_EVENT_TYPES
            if enforce_critical_signatures and is_critical and not rec.device_signature:
                return False, (
                    f"Security policy violation at sequence {rec.sequence_id} (Event {rec.event_id}): "
                    f"Critical security event '{rec.event_type}' lacks required digital signature!"
                ), {"failed_sequence": rec.sequence_id, "error": "MISSING_MANDATORY_SIGNATURE"}

            # 5. Check digital signature if present
            if rec.device_signature:
                # Find device public key or owner public key
                pub_key_b64 = None
                device = db.query(OfflineDevice).filter(OfflineDevice.device_id == rec.device_id).first()
                if device and device.public_sign_key:
                    pub_key_b64 = device.public_sign_key
                else:
                    owner = db.query(OfflineOwner).filter(OfflineOwner.owner_id == rec.device_id).first()
                    if owner and owner.public_sign_key:
                        pub_key_b64 = owner.public_sign_key

                if not pub_key_b64:
                    return False, (
                        f"Unknown signing identity at sequence {rec.sequence_id}: "
                        f"No public key found for '{rec.device_id}'!"
                    ), {"failed_sequence": rec.sequence_id, "error": "UNKNOWN_SIGNER"}

                try:
                    pub_bytes = b64decode_str(pub_key_b64)
                    pub = ed25519_public_from_bytes(pub_bytes)
                    sig_bytes = b64decode_str(rec.device_signature)
                    valid_sig = verify_signature_ed25519(rec.event_hash.encode("ascii"), sig_bytes, pub)
                    if not valid_sig:
                        return False, (
                            f"Invalid digital signature at sequence {rec.sequence_id} (Event {rec.event_id}) "
                            f"for entity '{rec.device_id}'!"
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

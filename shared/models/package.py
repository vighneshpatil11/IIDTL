"""Package serialization and models for Online (.enc), Offline (.secure), and Unified Multi-Recipient (.secure) formats."""

import json
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional, Tuple

from shared.utils.serialization import canonical_json_bytes, b64encode_str, b64decode_str
from shared.crypto.primitives import (
    encrypt_bytes_aes_gcm,
    decrypt_bytes_aes_gcm,
    sha256_hash,
)
from shared.crypto.key_exchange import (
    wrap_dek_for_recipient,
    unwrap_dek_for_recipient,
    x25519_public_from_bytes,
)
from shared.crypto.signatures import (
    sign_data_ed25519,
    verify_signature_ed25519,
    ed25519_public_from_bytes,
)
from shared.crypto.exceptions import (
    DecryptionError,
    IntegrityError,
    KeyEnvelopeError,
    SignatureVerificationError,
    AuthorizationError,
)
from cryptography.hazmat.primitives.asymmetric import x25519, ed25519


@dataclass
class OnlineRecipientPackage:
    """Recipient-specific encrypted document package (.enc)."""
    magic: str = "SECURE_DOC_RECIPIENT_V1"
    document_id: str = ""
    original_filename: str = ""
    watermark_id: str = ""
    distribution_id: str = ""
    recipient_id: str = ""
    envelope: Dict[str, str] = field(default_factory=dict)
    nonce: str = ""  # Base64 AES-GCM nonce for ciphertext
    ciphertext: str = ""  # Base64 AES-GCM ciphertext + tag
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def serialize(self) -> bytes:
        """Serialize package to UTF-8 JSON bytes."""
        return canonical_json_bytes(asdict(self))

    @classmethod
    def deserialize(cls, data: bytes | str) -> "OnlineRecipientPackage":
        """Deserialize package from UTF-8 JSON bytes or string."""
        if isinstance(data, bytes):
            data = data.decode("utf-8")
        payload = json.loads(data)
        if payload.get("magic") != "SECURE_DOC_RECIPIENT_V1":
            raise ValueError(f"Invalid magic identifier: {payload.get('magic')}")
        return cls(**payload)

    def decrypt(self, recipient_private_key: x25519.X25519PrivateKey) -> bytes:
        """Decrypt the recipient's package using their X25519 private key."""
        dek = unwrap_dek_for_recipient(
            envelope=self.envelope,
            recipient_private_key=recipient_private_key,
            document_id=self.document_id,
        )

        nonce_bytes = b64decode_str(self.nonce)
        ciphertext_bytes = b64decode_str(self.ciphertext)
        aad = f"{self.document_id}:{self.watermark_id}".encode("utf-8")

        return decrypt_bytes_aes_gcm(
            ciphertext=ciphertext_bytes,
            key=dek,
            nonce=nonce_bytes,
            associated_data=aad,
        )


@dataclass
class UnifiedMultiRecipientPackage:
    """One single encrypted distribution container (.secure) for ALL authorized recipients.
    
    Contains:
    - Package metadata signed with Document Owner's Ed25519 Administrative Key.
    - An array of recipient slots, each containing:
      * recipient_id: Unique recipient identifier
      * watermark_id: Unique forensic watermark identifier
      * envelope: Recipient-specific key envelope wrapping their DEK (X25519 + HKDF-SHA256 + AES-256-GCM)
      * nonce & ciphertext: Recipient's watermarked document encrypted with their DEK.
    
    Any recipient can open the exact same file. The application detects the recipient's private key,
    unlocks their specific envelope, and decrypts their watermarked document copy.
    """
    magic: str = "UNIFIED_SECURE_DOC_V1"
    package_id: str = ""
    document_id: str = ""
    original_filename: str = ""
    original_sha256: str = ""
    owner_id: str = ""
    owner_public_sign_key: str = ""  # Base64 Ed25519 pubkey of owner
    owner_signature: str = ""        # Base64 Ed25519 signature
    recipient_slots: List[Dict[str, Any]] = field(default_factory=list)
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def get_signable_content(self) -> bytes:
        """Compute canonical signable payload for owner signature."""
        data_to_sign = {
            "magic": self.magic,
            "package_id": self.package_id,
            "document_id": self.document_id,
            "original_filename": self.original_filename,
            "original_sha256": self.original_sha256,
            "owner_id": self.owner_id,
            "recipient_slots": [
                {
                    "recipient_id": s.get("recipient_id"),
                    "watermark_id": s.get("watermark_id"),
                    "envelope": s.get("envelope"),
                    "nonce": s.get("nonce"),
                }
                for s in self.recipient_slots
            ],
            "created_at": self.created_at,
        }
        return canonical_json_bytes(data_to_sign)

    def sign_package(self, owner_private_key: ed25519.Ed25519PrivateKey) -> None:
        """Sign package metadata and recipient slots with owner's Ed25519 private key."""
        signable_bytes = self.get_signable_content()
        sig = sign_data_ed25519(signable_bytes, owner_private_key)
        self.owner_signature = b64encode_str(sig)

    def verify_package_signature(self) -> bool:
        """Verify the owner's digital signature on this unified package."""
        if not self.owner_signature or not self.owner_public_sign_key:
            return False
        try:
            pub_bytes = b64decode_str(self.owner_public_sign_key)
            owner_pub = ed25519_public_from_bytes(pub_bytes)
            sig_bytes = b64decode_str(self.owner_signature)
            return verify_signature_ed25519(self.get_signable_content(), sig_bytes, owner_pub)
        except Exception:
            return False

    def serialize(self) -> bytes:
        """Serialize unified package to UTF-8 JSON bytes."""
        return canonical_json_bytes(asdict(self))

    @classmethod
    def deserialize(cls, data: bytes | str) -> "UnifiedMultiRecipientPackage":
        """Deserialize package from UTF-8 JSON bytes or string."""
        if isinstance(data, bytes):
            data = data.decode("utf-8")
        payload = json.loads(data)
        if payload.get("magic") != "UNIFIED_SECURE_DOC_V1":
            raise ValueError(f"Invalid magic identifier: {payload.get('magic')}")
        return cls(**payload)

    def decrypt_for_recipient(
        self,
        recipient_private_key: x25519.X25519PrivateKey,
        recipient_id: Optional[str] = None,
        verify_owner_sig: bool = True,
    ) -> Tuple[bytes, str]:
        """Decrypt the unified package using the recipient's private key.
        
        If recipient_id is provided, checks that specific slot.
        If recipient_id is None, automatically iterates through authorized slots to find
        the slot that can be unwrapped by the provided private key.
        
        Returns:
            (decrypted_document_bytes, watermark_id)
            
        Raises:
            SignatureVerificationError: If owner signature verification fails.
            AuthorizationError: If the recipient is not authorized in this package.
        """
        if verify_owner_sig and not self.verify_package_signature():
            raise SignatureVerificationError("Package metadata failed owner signature verification!")

        # Find matching slot
        candidate_slots = self.recipient_slots
        if recipient_id:
            candidate_slots = [s for s in self.recipient_slots if s.get("recipient_id") == recipient_id]
            if not candidate_slots:
                raise AuthorizationError(f"Recipient '{recipient_id}' is not authorized in this package.")

        for slot in candidate_slots:
            slot_rec_id = slot.get("recipient_id")
            wm_id = slot.get("watermark_id")
            envelope = slot.get("envelope", {})
            try:
                # Attempt to unwrap DEK
                dek = unwrap_dek_for_recipient(
                    envelope=envelope,
                    recipient_private_key=recipient_private_key,
                    document_id=self.document_id,
                )
                # Unwrap succeeded! Decrypt ciphertext
                nonce_bytes = b64decode_str(slot["nonce"])
                ciphertext_bytes = b64decode_str(slot["ciphertext"])
                aad = f"{self.document_id}:{wm_id}".encode("utf-8")

                plaintext = decrypt_bytes_aes_gcm(
                    ciphertext=ciphertext_bytes,
                    key=dek,
                    nonce=nonce_bytes,
                    associated_data=aad,
                )
                return plaintext, wm_id
            except (KeyEnvelopeError, DecryptionError):
                continue

        raise AuthorizationError("Access Denied: Your private key is not authorized to decrypt this package.")


@dataclass
class OfflineMultiDevicePackage:
    """Offline standalone package container (.secure) authorized for multiple devices."""
    magic: str = "SECURE_DOC_OFFLINE_V1"
    package_id: str = ""
    document_id: str = ""
    original_filename: str = ""
    original_sha256: str = ""
    owner_id: str = ""
    owner_public_sign_key: str = ""
    owner_signature: str = ""
    nonce: str = ""
    key_envelopes: List[Dict[str, str]] = field(default_factory=list)
    ciphertext: str = ""
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def get_signable_content(self) -> bytes:
        data_to_sign = {
            "magic": self.magic,
            "package_id": self.package_id,
            "document_id": self.document_id,
            "original_filename": self.original_filename,
            "original_sha256": self.original_sha256,
            "owner_id": self.owner_id,
            "nonce": self.nonce,
            "key_envelopes": self.key_envelopes,
            "created_at": self.created_at,
        }
        return canonical_json_bytes(data_to_sign)

    def sign_package(self, owner_private_key: ed25519.Ed25519PrivateKey) -> None:
        signable_bytes = self.get_signable_content()
        sig = sign_data_ed25519(signable_bytes, owner_private_key)
        self.owner_signature = b64encode_str(sig)

    def verify_package_signature(self) -> bool:
        if not self.owner_signature or not self.owner_public_sign_key:
            return False
        try:
            pub_bytes = b64decode_str(self.owner_public_sign_key)
            owner_pub = ed25519_public_from_bytes(pub_bytes)
            sig_bytes = b64decode_str(self.owner_signature)
            return verify_signature_ed25519(self.get_signable_content(), sig_bytes, owner_pub)
        except Exception:
            return False

    def serialize(self) -> bytes:
        return canonical_json_bytes(asdict(self))

    @classmethod
    def deserialize(cls, data: bytes | str) -> "OfflineMultiDevicePackage":
        if isinstance(data, bytes):
            data = data.decode("utf-8")
        payload = json.loads(data)
        if payload.get("magic") != "SECURE_DOC_OFFLINE_V1":
            raise ValueError(f"Invalid magic identifier: {payload.get('magic')}")
        return cls(**payload)

    def decrypt_for_device(
        self,
        device_id: str,
        device_private_enc_key: x25519.X25519PrivateKey,
        verify_owner_sig: bool = True,
    ) -> bytes:
        if verify_owner_sig and not self.verify_package_signature():
            raise SignatureVerificationError("Package metadata failed owner signature verification!")

        target_envelope = None
        for env in self.key_envelopes:
            if env.get("recipient_id") == device_id:
                target_envelope = env
                break

        if not target_envelope:
            raise AuthorizationError(f"Device {device_id} is not authorized to decrypt this package.")

        dek = unwrap_dek_for_recipient(
            envelope=target_envelope,
            recipient_private_key=device_private_enc_key,
            document_id=self.document_id,
        )

        nonce_bytes = b64decode_str(self.nonce)
        ciphertext_bytes = b64decode_str(self.ciphertext)
        aad = f"{self.document_id}:{self.original_sha256}".encode("utf-8")

        plaintext = decrypt_bytes_aes_gcm(
            ciphertext=ciphertext_bytes,
            key=dek,
            nonce=nonce_bytes,
            associated_data=aad,
        )

        actual_sha256 = sha256_hash(plaintext)
        if actual_sha256 != self.original_sha256:
            raise IntegrityError(
                f"Integrity check failed: expected {self.original_sha256}, got {actual_sha256}"
            )

        return plaintext

"""Package serialization and models for Online (.enc) and Offline (.secure) formats."""

import json
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional

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
        """Decrypt the recipient's package using their X25519 private key.
        
        Recovers the recipient-specific DEK from the envelope, then decrypts the ciphertext.
        """
        # 1. Recover DEK
        dek = unwrap_dek_for_recipient(
            envelope=self.envelope,
            recipient_private_key=recipient_private_key,
            document_id=self.document_id,
        )

        # 2. Decrypt payload
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
class OfflineMultiDevicePackage:
    """Offline standalone package container (.secure) authorized for multiple devices."""
    magic: str = "SECURE_DOC_OFFLINE_V1"
    package_id: str = ""
    document_id: str = ""
    original_filename: str = ""
    original_sha256: str = ""
    owner_id: str = ""
    owner_public_sign_key: str = ""  # Base64 Ed25519 pubkey of owner
    owner_signature: str = ""  # Base64 Ed25519 signature over package metadata + envelopes
    nonce: str = ""  # Base64 AES-GCM nonce for ciphertext
    key_envelopes: List[Dict[str, str]] = field(default_factory=list)
    ciphertext: str = ""  # Base64 AES-GCM ciphertext + tag
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
            "nonce": self.nonce,
            "key_envelopes": self.key_envelopes,
            "created_at": self.created_at,
        }
        return canonical_json_bytes(data_to_sign)

    def sign_package(self, owner_private_key: ed25519.Ed25519PrivateKey) -> None:
        """Sign package metadata and envelopes using owner's Ed25519 private key."""
        signable_bytes = self.get_signable_content()
        sig = sign_data_ed25519(signable_bytes, owner_private_key)
        self.owner_signature = b64encode_str(sig)

    def verify_package_signature(self) -> bool:
        """Verify the owner signature on the package metadata."""
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
        """Serialize package to UTF-8 JSON bytes."""
        return canonical_json_bytes(asdict(self))

    @classmethod
    def deserialize(cls, data: bytes | str) -> "OfflineMultiDevicePackage":
        """Deserialize package from UTF-8 JSON bytes or string."""
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
        """Decrypt package content for an authorized device.
        
        Args:
            device_id: Target device ID.
            device_private_enc_key: Target device's X25519 private encryption key.
            verify_owner_sig: Whether to enforce owner digital signature check.
            
        Returns:
            Decrypted plaintext bytes.
            
        Raises:
            AuthorizationError: If device is not in key_envelopes.
            SignatureVerificationError: If owner signature verification fails.
            IntegrityError: If decrypted content SHA-256 does not match original_sha256.
            DecryptionError: If ciphertext decryption fails.
        """
        # 1. Verify owner signature
        if verify_owner_sig and not self.verify_package_signature():
            raise SignatureVerificationError("Package metadata failed owner signature verification!")

        # 2. Locate device key envelope
        target_envelope = None
        for env in self.key_envelopes:
            if env.get("recipient_id") == device_id:
                target_envelope = env
                break

        if not target_envelope:
            raise AuthorizationError(f"Device {device_id} is not authorized to decrypt this package.")

        # 3. Unwrap DEK
        dek = unwrap_dek_for_recipient(
            envelope=target_envelope,
            recipient_private_key=device_private_enc_key,
            document_id=self.document_id,
        )

        # 4. Decrypt ciphertext
        nonce_bytes = b64decode_str(self.nonce)
        ciphertext_bytes = b64decode_str(self.ciphertext)
        aad = f"{self.document_id}:{self.original_sha256}".encode("utf-8")

        plaintext = decrypt_bytes_aes_gcm(
            ciphertext=ciphertext_bytes,
            key=dek,
            nonce=nonce_bytes,
            associated_data=aad,
        )

        # 5. Verify document integrity against original SHA-256
        actual_sha256 = sha256_hash(plaintext)
        if actual_sha256 != self.original_sha256:
            raise IntegrityError(
                f"Integrity check failed: expected {self.original_sha256}, got {actual_sha256}"
            )

        return plaintext

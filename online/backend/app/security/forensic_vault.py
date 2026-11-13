"""Forensic Key Vault for protected Watermark-to-Recipient mapping encryption."""

import json
from typing import Dict, Any, Tuple
from shared.crypto.primitives import (
    encrypt_bytes_aes_gcm,
    decrypt_bytes_aes_gcm,
    derive_hkdf_key,
)
from shared.utils.serialization import canonical_json_bytes, b64encode_str, b64decode_str
from online.backend.app.config import settings


def get_forensic_key() -> bytes:
    """Derive 32-byte Owner Forensic Key (OFK) from configuration."""
    raw_key = bytes.fromhex(settings.FORENSIC_MASTER_KEY_HEX)
    return derive_hkdf_key(
        ikm=raw_key,
        salt=b"secure-document-system:forensic-vault:salt",
        info=b"forensic-mapping-encryption-v1",
        length=32,
    )


def encrypt_forensic_mapping(
    document_id: str,
    watermark_id: str,
    recipient_id: str,
    extra_metadata: Dict[str, Any] | None = None,
) -> Tuple[str, str]:
    """Encrypt the watermark-to-recipient association using the Owner Forensic Key.
    
    Returns:
        (b64_ciphertext, b64_nonce)
    """
    payload = {
        "document_id": document_id,
        "watermark_id": watermark_id,
        "recipient_id": recipient_id,
        "metadata": extra_metadata or {},
    }
    canonical_bytes = canonical_json_bytes(payload)
    key = get_forensic_key()
    aad = f"{document_id}:{watermark_id}".encode("utf-8")
    ciphertext, nonce = encrypt_bytes_aes_gcm(canonical_bytes, key, associated_data=aad)
    return b64encode_str(ciphertext), b64encode_str(nonce)


def decrypt_forensic_mapping(
    document_id: str,
    watermark_id: str,
    b64_ciphertext: str,
    b64_nonce: str,
) -> Dict[str, Any]:
    """Decrypt the watermark-to-recipient association using the Owner Forensic Key."""
    ciphertext = b64decode_str(b64_ciphertext)
    nonce = b64decode_str(b64_nonce)
    key = get_forensic_key()
    aad = f"{document_id}:{watermark_id}".encode("utf-8")
    decrypted_bytes = decrypt_bytes_aes_gcm(ciphertext, key, nonce, associated_data=aad)
    return json.loads(decrypted_bytes.decode("utf-8"))

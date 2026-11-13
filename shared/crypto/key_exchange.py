"""Asymmetric key agreement and recipient key wrapping via X25519 and HKDF."""

import base64
from typing import Dict, Tuple

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519

from .primitives import (
    derive_hkdf_key,
    encrypt_bytes_aes_gcm,
    decrypt_bytes_aes_gcm,
    DEK_SIZE_BYTES,
)
from .exceptions import KeyEnvelopeError, DecryptionError


HKDF_INFO_KEK = b"secure-document-system:v1:kek-wrapping"


def generate_x25519_keypair() -> Tuple[x25519.X25519PrivateKey, x25519.X25519PublicKey]:
    """Generate a new Curve25519 (X25519) private and public key pair."""
    priv = x25519.X25519PrivateKey.generate()
    pub = priv.public_key()
    return priv, pub


def x25519_public_to_bytes(pub: x25519.X25519PublicKey) -> bytes:
    """Export X25519 public key as raw 32 bytes."""
    return pub.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def x25519_public_from_bytes(data: bytes) -> x25519.X25519PublicKey:
    """Load X25519 public key from raw 32 bytes."""
    if len(data) != 32:
        raise ValueError(f"X25519 public key must be 32 bytes, got {len(data)}")
    return x25519.X25519PublicKey.from_public_bytes(data)


def x25519_private_to_bytes(priv: x25519.X25519PrivateKey) -> bytes:
    """Export X25519 private key as raw 32 bytes."""
    return priv.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )


def x25519_private_from_bytes(data: bytes) -> x25519.X25519PrivateKey:
    """Load X25519 private key from raw 32 bytes."""
    if len(data) != 32:
        raise ValueError(f"X25519 private key must be 32 bytes, got {len(data)}")
    return x25519.X25519PrivateKey.from_private_bytes(data)


def wrap_dek_for_recipient(
    dek: bytes,
    recipient_public_key: x25519.X25519PublicKey,
    recipient_id: str,
    document_id: str,
) -> Dict[str, str]:
    """Wrap a Document Encryption Key (DEK) for a specific recipient using ECIES-style X25519+HKDF+AES-GCM.
    
    Args:
        dek: 32-byte Document Encryption Key.
        recipient_public_key: Recipient's X25519 public key.
        recipient_id: Unique identifier for the recipient.
        document_id: Unique identifier for the document.
        
    Returns:
        Dictionary containing the base64-encoded envelope fields.
    """
    if len(dek) != DEK_SIZE_BYTES:
        raise ValueError(f"DEK must be {DEK_SIZE_BYTES} bytes, got {len(dek)}")

    # 1. Generate ephemeral sender key pair
    ephemeral_priv = x25519.X25519PrivateKey.generate()
    ephemeral_pub = ephemeral_priv.public_key()
    ephemeral_pub_bytes = x25519_public_to_bytes(ephemeral_pub)
    recipient_pub_bytes = x25519_public_to_bytes(recipient_public_key)

    # 2. Compute shared secret: ECDH(ephemeral_priv, recipient_pub)
    shared_secret = ephemeral_priv.exchange(recipient_public_key)

    # 3. Derive Key-Encryption-Key (KEK) using HKDF-SHA256 bound to both public keys
    salt = ephemeral_pub_bytes + recipient_pub_bytes
    kek = derive_hkdf_key(ikm=shared_secret, salt=salt, info=HKDF_INFO_KEK, length=32)

    # 4. Bind document_id and recipient_id as Associated Authenticated Data (AAD)
    aad = f"{document_id}:{recipient_id}".encode("utf-8")

    # 5. Encrypt DEK with KEK using AES-256-GCM
    wrapped_dek, nonce = encrypt_bytes_aes_gcm(plaintext=dek, key=kek, associated_data=aad)

    return {
        "recipient_id": recipient_id,
        "ephemeral_public_key": base64.b64encode(ephemeral_pub_bytes).decode("ascii"),
        "wrapped_dek": base64.b64encode(wrapped_dek).decode("ascii"),
        "nonce": base64.b64encode(nonce).decode("ascii"),
    }


def unwrap_dek_for_recipient(
    envelope: Dict[str, str],
    recipient_private_key: x25519.X25519PrivateKey,
    document_id: str,
) -> bytes:
    """Unwrap a recipient key envelope to recover the Document Encryption Key (DEK).
    
    Args:
        envelope: Key envelope dictionary produced by wrap_dek_for_recipient.
        recipient_private_key: Recipient's X25519 private key.
        document_id: Unique identifier for the document (must match encryption AAD).
        
    Returns:
        Recovered 32-byte DEK.
        
    Raises:
        KeyEnvelopeError: If unwrap fails due to invalid key, altered AAD, or corrupted payload.
    """
    required_keys = {"recipient_id", "ephemeral_public_key", "wrapped_dek", "nonce"}
    if not required_keys.issubset(envelope.keys()):
        missing = required_keys - envelope.keys()
        raise KeyEnvelopeError(f"Missing required envelope fields: {missing}")

    try:
        ephemeral_pub_bytes = base64.b64decode(envelope["ephemeral_public_key"])
        wrapped_dek = base64.b64decode(envelope["wrapped_dek"])
        nonce = base64.b64decode(envelope["nonce"])
        recipient_id = envelope["recipient_id"]

        ephemeral_pub = x25519_public_from_bytes(ephemeral_pub_bytes)
        recipient_pub_bytes = x25519_public_to_bytes(recipient_private_key.public_key())

        # 1. Compute shared secret: ECDH(recipient_priv, ephemeral_pub)
        shared_secret = recipient_private_key.exchange(ephemeral_pub)

        # 2. Derive KEK matching encryption parameters
        salt = ephemeral_pub_bytes + recipient_pub_bytes
        kek = derive_hkdf_key(ikm=shared_secret, salt=salt, info=HKDF_INFO_KEK, length=32)

        # 3. Reconstruct AAD
        aad = f"{document_id}:{recipient_id}".encode("utf-8")

        # 4. Decrypt wrapped DEK
        return decrypt_bytes_aes_gcm(ciphertext=wrapped_dek, key=kek, nonce=nonce, associated_data=aad)
    except (DecryptionError, ValueError) as e:
        raise KeyEnvelopeError(f"Failed to unwrap DEK: unauthorized key or corrupted envelope.") from e
    except Exception as e:
        raise KeyEnvelopeError(f"Unexpected error during DEK unwrapping: {str(e)}") from e

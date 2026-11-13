"""Cryptographic primitives: AES-256-GCM, SHA-256, CSPRNG, and HKDF."""

import os
import hashlib
from pathlib import Path
from typing import Optional, Tuple

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

from .exceptions import DecryptionError, IntegrityError


DEK_SIZE_BYTES = 32  # 256 bits
AES_GCM_NONCE_SIZE = 12  # 96 bits (standard for AES-GCM)
AES_GCM_TAG_SIZE = 16  # 128-bit authentication tag


def generate_dek() -> bytes:
    """Generate a cryptographically secure random 256-bit Document Encryption Key (DEK)."""
    return os.urandom(DEK_SIZE_BYTES)


def generate_nonce() -> bytes:
    """Generate a cryptographically secure random 96-bit nonce for AES-GCM."""
    return os.urandom(AES_GCM_NONCE_SIZE)


def sha256_hash(data: bytes) -> str:
    """Compute hex-encoded SHA-256 digest of bytes."""
    return hashlib.sha256(data).hexdigest()


def sha256_bytes(data: bytes) -> bytes:
    """Compute raw 32-byte SHA-256 digest."""
    return hashlib.sha256(data).digest()


def sha256_file(filepath: Path | str, chunk_size: int = 65536) -> str:
    """Compute hex-encoded SHA-256 digest of a file in chunks."""
    hasher = hashlib.sha256()
    path = Path(filepath)
    if not path.is_file():
        raise FileNotFoundError(f"File not found for hashing: {filepath}")
    with open(path, "rb") as f:
        while chunk := f.read(chunk_size):
            hasher.update(chunk)
    return hasher.hexdigest()


def encrypt_bytes_aes_gcm(
    plaintext: bytes,
    key: bytes,
    associated_data: Optional[bytes] = None,
    nonce: Optional[bytes] = None,
) -> Tuple[bytes, bytes]:
    """Encrypt plaintext using AES-256-GCM.
    
    Args:
        plaintext: Raw data to encrypt.
        key: 32-byte AES key.
        associated_data: Optional authenticated data (AAD) bound to the ciphertext.
        nonce: Optional 12-byte nonce. If None, a fresh random nonce is generated.
        
    Returns:
        Tuple of (ciphertext_with_tag, nonce)
        where ciphertext_with_tag includes the 16-byte authentication tag at the end.
    """
    if len(key) != DEK_SIZE_BYTES:
        raise ValueError(f"AES key must be {DEK_SIZE_BYTES} bytes, got {len(key)}")
    
    if nonce is None:
        nonce = generate_nonce()
    elif len(nonce) != AES_GCM_NONCE_SIZE:
        raise ValueError(f"AES-GCM nonce must be {AES_GCM_NONCE_SIZE} bytes, got {len(nonce)}")

    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data)
    return ciphertext, nonce


def decrypt_bytes_aes_gcm(
    ciphertext: bytes,
    key: bytes,
    nonce: bytes,
    associated_data: Optional[bytes] = None,
) -> bytes:
    """Decrypt ciphertext using AES-256-GCM with authentication verification.
    
    Args:
        ciphertext: Ciphertext bytes ending with the 16-byte authentication tag.
        key: 32-byte AES key.
        nonce: 12-byte nonce used during encryption.
        associated_data: Optional authenticated data (AAD) that must match encryption.
        
    Returns:
        Decrypted plaintext bytes.
        
    Raises:
        DecryptionError: If the authentication tag verification fails or key is invalid.
    """
    if len(key) != DEK_SIZE_BYTES:
        raise ValueError(f"AES key must be {DEK_SIZE_BYTES} bytes, got {len(key)}")
    if len(nonce) != AES_GCM_NONCE_SIZE:
        raise ValueError(f"AES-GCM nonce must be {AES_GCM_NONCE_SIZE} bytes, got {len(nonce)}")
    if len(ciphertext) < AES_GCM_TAG_SIZE:
        raise DecryptionError("Ciphertext is too short to contain a valid authentication tag.")

    aesgcm = AESGCM(key)
    try:
        return aesgcm.decrypt(nonce, ciphertext, associated_data)
    except InvalidTag as e:
        raise DecryptionError("Authentication tag verification failed: corrupted data or wrong key.") from e


def derive_hkdf_key(
    ikm: bytes,
    salt: Optional[bytes],
    info: bytes,
    length: int = 32,
) -> bytes:
    """Derive key material using HKDF with SHA-256 (RFC 5869).
    
    Args:
        ikm: Input Keying Material.
        salt: Optional salt. If None, HKDF uses a zero-filled byte array.
        info: Context and application specific information.
        length: Length of output key material in bytes (default 32).
        
    Returns:
        Derived key bytes.
    """
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        info=info,
    )
    return hkdf.derive(ikm)

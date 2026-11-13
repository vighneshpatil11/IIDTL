"""Cryptographic primitives, key exchange, and digital signatures."""

from .primitives import (
    generate_dek,
    generate_nonce,
    sha256_hash,
    sha256_file,
    encrypt_bytes_aes_gcm,
    decrypt_bytes_aes_gcm,
    derive_hkdf_key,
)
from .key_exchange import (
    generate_x25519_keypair,
    x25519_public_from_bytes,
    x25519_private_from_bytes,
    wrap_dek_for_recipient,
    unwrap_dek_for_recipient,
)
from .signatures import (
    generate_ed25519_keypair,
    ed25519_public_from_bytes,
    ed25519_private_from_bytes,
    sign_data_ed25519,
    verify_signature_ed25519,
)
from .exceptions import (
    CryptoError,
    DecryptionError,
    IntegrityError,
    KeyEnvelopeError,
    SignatureVerificationError,
    AuthorizationError,
)

__all__ = [
    "generate_dek",
    "generate_nonce",
    "sha256_hash",
    "sha256_file",
    "encrypt_bytes_aes_gcm",
    "decrypt_bytes_aes_gcm",
    "derive_hkdf_key",
    "generate_x25519_keypair",
    "x25519_public_from_bytes",
    "x25519_private_from_bytes",
    "wrap_dek_for_recipient",
    "unwrap_dek_for_recipient",
    "generate_ed25519_keypair",
    "ed25519_public_from_bytes",
    "ed25519_private_from_bytes",
    "sign_data_ed25519",
    "verify_signature_ed25519",
    "CryptoError",
    "DecryptionError",
    "IntegrityError",
    "KeyEnvelopeError",
    "SignatureVerificationError",
    "AuthorizationError",
]

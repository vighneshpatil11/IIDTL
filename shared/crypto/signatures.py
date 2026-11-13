"""Digital signatures and verification using Ed25519."""

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from .exceptions import SignatureVerificationError


def generate_ed25519_keypair() -> tuple[ed25519.Ed25519PrivateKey, ed25519.Ed25519PublicKey]:
    """Generate a new Ed25519 signing key pair."""
    priv = ed25519.Ed25519PrivateKey.generate()
    pub = priv.public_key()
    return priv, pub


def ed25519_public_to_bytes(pub: ed25519.Ed25519PublicKey) -> bytes:
    """Export Ed25519 public key as raw 32 bytes."""
    return pub.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def ed25519_public_from_bytes(data: bytes) -> ed25519.Ed25519PublicKey:
    """Load Ed25519 public key from raw 32 bytes."""
    if len(data) != 32:
        raise ValueError(f"Ed25519 public key must be 32 bytes, got {len(data)}")
    return ed25519.Ed25519PublicKey.from_public_bytes(data)


def ed25519_private_to_bytes(priv: ed25519.Ed25519PrivateKey) -> bytes:
    """Export Ed25519 private key as raw 32 bytes."""
    return priv.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )


def ed25519_private_from_bytes(data: bytes) -> ed25519.Ed25519PrivateKey:
    """Load Ed25519 private key from raw 32 bytes."""
    if len(data) != 32:
        raise ValueError(f"Ed25519 private key must be 32 bytes, got {len(data)}")
    return ed25519.Ed25519PrivateKey.from_private_bytes(data)


def sign_data_ed25519(data: bytes, private_key: ed25519.Ed25519PrivateKey) -> bytes:
    """Sign arbitrary data using Ed25519 private key.
    
    Args:
        data: Raw payload to sign.
        private_key: Ed25519 private key.
        
    Returns:
        64-byte Ed25519 signature.
    """
    return private_key.sign(data)


def verify_signature_ed25519(
    data: bytes,
    signature: bytes,
    public_key: ed25519.Ed25519PublicKey,
    raise_exception: bool = False,
) -> bool:
    """Verify an Ed25519 signature against data and public key.
    
    Args:
        data: Raw payload that was signed.
        signature: 64-byte Ed25519 signature.
        public_key: Ed25519 public key.
        raise_exception: If True, raises SignatureVerificationError on failure;
                         If False, returns False.
                         
    Returns:
        True if signature is valid.
        
    Raises:
        SignatureVerificationError: If raise_exception=True and signature is invalid.
    """
    if len(signature) != 64:
        if raise_exception:
            raise SignatureVerificationError(f"Invalid signature length: expected 64, got {len(signature)}")
        return False

    try:
        public_key.verify(signature, data)
        return True
    except InvalidSignature as e:
        if raise_exception:
            raise SignatureVerificationError("Signature verification failed: data or signature invalid.") from e
        return False

"""Cryptographic exceptions for the secure document platform."""


class CryptoError(Exception):
    """Base exception for all cryptographic errors."""
    pass


class DecryptionError(CryptoError):
    """Raised when decryption fails (invalid key, tag mismatch, corrupted ciphertext)."""
    pass


class IntegrityError(CryptoError):
    """Raised when hash verification or authentication tag check fails."""
    pass


class KeyEnvelopeError(CryptoError):
    """Raised when recipient key envelope unwrapping or agreement fails."""
    pass


class SignatureVerificationError(CryptoError):
    """Raised when digital signature verification fails."""
    pass


class AuthorizationError(CryptoError):
    """Raised when device or recipient is not authorized."""
    pass


class WatermarkingError(CryptoError):
    """Base exception for watermarking failures."""
    pass


class WatermarkEmbeddingError(WatermarkingError):
    """Raised when embedding a forensic watermark in a document fails."""
    pass


class WatermarkVerificationError(WatermarkingError):
    """Raised when embedded forensic watermark cannot be verified immediately after embedding."""
    pass

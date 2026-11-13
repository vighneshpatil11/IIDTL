"""Comprehensive automated tests for Phase 1: Shared Cryptographic Core."""

import pytest
import os
import base64
from pathlib import Path

from shared.crypto.primitives import (
    generate_dek,
    generate_nonce,
    sha256_hash,
    encrypt_bytes_aes_gcm,
    decrypt_bytes_aes_gcm,
    derive_hkdf_key,
)
from shared.crypto.key_exchange import (
    generate_x25519_keypair,
    x25519_public_to_bytes,
    x25519_public_from_bytes,
    x25519_private_to_bytes,
    x25519_private_from_bytes,
    wrap_dek_for_recipient,
    unwrap_dek_for_recipient,
)
from shared.crypto.signatures import (
    generate_ed25519_keypair,
    sign_data_ed25519,
    verify_signature_ed25519,
    ed25519_public_to_bytes,
    ed25519_private_to_bytes,
)
from shared.crypto.exceptions import (
    DecryptionError,
    IntegrityError,
    KeyEnvelopeError,
    SignatureVerificationError,
    AuthorizationError,
)
from shared.models.package import (
    OnlineRecipientPackage,
    OfflineMultiDevicePackage,
)
from shared.utils.identifiers import (
    generate_document_id,
    generate_recipient_id,
    generate_device_id,
    generate_watermark_id,
)
from shared.utils.serialization import b64encode_str


class TestAESGCMPrimitives:
    """Tests for AES-256-GCM symmetric encryption."""

    def test_encryption_and_decryption_success(self):
        key = generate_dek()
        plaintext = b"Highly confidential internal report content."
        aad = b"DOC-1234:USER-5678"

        ciphertext, nonce = encrypt_bytes_aes_gcm(plaintext, key, associated_data=aad)
        decrypted = decrypt_bytes_aes_gcm(ciphertext, key, nonce, associated_data=aad)

        assert decrypted == plaintext

    def test_wrong_key_fails(self):
        key1 = generate_dek()
        key2 = generate_dek()
        plaintext = b"Secret payload"

        ciphertext, nonce = encrypt_bytes_aes_gcm(plaintext, key1)
        with pytest.raises(DecryptionError):
            decrypt_bytes_aes_gcm(ciphertext, key2, nonce)

    def test_modified_ciphertext_fails_tag(self):
        key = generate_dek()
        plaintext = b"Secret payload"

        ciphertext, nonce = encrypt_bytes_aes_gcm(plaintext, key)
        # Flip a bit in the ciphertext
        corrupted = bytearray(ciphertext)
        corrupted[5] ^= 0xFF

        with pytest.raises(DecryptionError):
            decrypt_bytes_aes_gcm(bytes(corrupted), key, nonce)

    def test_modified_aad_fails(self):
        key = generate_dek()
        plaintext = b"Secret payload"
        aad_correct = b"DOC-1234:USER-A"
        aad_tampered = b"DOC-1234:USER-B"

        ciphertext, nonce = encrypt_bytes_aes_gcm(plaintext, key, associated_data=aad_correct)
        with pytest.raises(DecryptionError):
            decrypt_bytes_aes_gcm(ciphertext, key, nonce, associated_data=aad_tampered)

    def test_fresh_nonce_per_call(self):
        key = generate_dek()
        plaintext = b"Same plaintext"

        _, nonce1 = encrypt_bytes_aes_gcm(plaintext, key)
        _, nonce2 = encrypt_bytes_aes_gcm(plaintext, key)

        assert nonce1 != nonce2


class TestKeyWrappingAndExchange:
    """Tests for X25519 key exchange and ECIES key wrapping."""

    def test_key_wrapping_and_unwrapping_success(self):
        dek = generate_dek()
        rec_priv, rec_pub = generate_x25519_keypair()
        doc_id = "DOC-TEST01"
        rec_id = "REC-USER01"

        envelope = wrap_dek_for_recipient(dek, rec_pub, rec_id, doc_id)
        recovered_dek = unwrap_dek_for_recipient(envelope, rec_priv, doc_id)

        assert recovered_dek == dek

    def test_unauthorized_recipient_cannot_unwrap(self):
        dek = generate_dek()
        rec_priv1, rec_pub1 = generate_x25519_keypair()
        rec_priv2, _ = generate_x25519_keypair()
        doc_id = "DOC-TEST01"
        rec_id = "REC-USER01"

        envelope = wrap_dek_for_recipient(dek, rec_pub1, rec_id, doc_id)

        # Recipient 2 tries to unwrap Recipient 1's envelope
        with pytest.raises(KeyEnvelopeError):
            unwrap_dek_for_recipient(envelope, rec_priv2, doc_id)

    def test_tampered_document_id_fails_unwrap(self):
        dek = generate_dek()
        rec_priv, rec_pub = generate_x25519_keypair()
        doc_id = "DOC-TEST01"
        rec_id = "REC-USER01"

        envelope = wrap_dek_for_recipient(dek, rec_pub, rec_id, doc_id)

        # Attacker tries to apply envelope to another document
        with pytest.raises(KeyEnvelopeError):
            unwrap_dek_for_recipient(envelope, rec_priv, "DOC-ANOTHER99")


class TestDigitalSignatures:
    """Tests for Ed25519 digital signatures."""

    def test_sign_and_verify_success(self):
        priv, pub = generate_ed25519_keypair()
        data = b"Audit record: Device DEV-001 opened document DOC-001"

        sig = sign_data_ed25519(data, priv)
        assert verify_signature_ed25519(data, sig, pub) is True

    def test_tampered_data_fails_verification(self):
        priv, pub = generate_ed25519_keypair()
        data = b"Original data"
        sig = sign_data_ed25519(data, priv)

        assert verify_signature_ed25519(b"Tampered data", sig, pub) is False


class TestPackages:
    """Tests for Online (.enc) and Offline (.secure) packages."""

    def test_online_recipient_package_e2e(self):
        doc_id = generate_document_id()
        rec_id = generate_recipient_id()
        wm_id = generate_watermark_id()
        plaintext = b"Watermarked PDF bytes for Recipient A"

        # 1. Recipient generates key pair
        rec_priv, rec_pub = generate_x25519_keypair()

        # 2. Server generates DEK and encrypts document
        dek = generate_dek()
        envelope = wrap_dek_for_recipient(dek, rec_pub, rec_id, doc_id)
        aad = f"{doc_id}:{wm_id}".encode("utf-8")
        ciphertext, nonce = encrypt_bytes_aes_gcm(plaintext, dek, associated_data=aad)

        # 3. Create package
        pkg = OnlineRecipientPackage(
            document_id=doc_id,
            original_filename="confidential.pdf",
            watermark_id=wm_id,
            distribution_id="DIST-001",
            recipient_id=rec_id,
            envelope=envelope,
            nonce=b64encode_str(nonce),
            ciphertext=b64encode_str(ciphertext),
        )

        serialized = pkg.serialize()
        restored_pkg = OnlineRecipientPackage.deserialize(serialized)

        # 4. Recipient decrypts
        decrypted = restored_pkg.decrypt(rec_priv)
        assert decrypted == plaintext

        # 5. Wrong recipient fails
        wrong_priv, _ = generate_x25519_keypair()
        with pytest.raises(KeyEnvelopeError):
            restored_pkg.decrypt(wrong_priv)

    def test_offline_multi_device_package_e2e(self):
        doc_id = generate_document_id()
        plaintext = b"Classified offline intelligence briefing"
        original_sha256 = sha256_hash(plaintext)

        # Owner keys
        owner_sign_priv, owner_sign_pub = generate_ed25519_keypair()

        # Devices: DEV-1 (authorized), DEV-2 (authorized), DEV-3 (unauthorized)
        dev1_enc_priv, dev1_enc_pub = generate_x25519_keypair()
        dev1_id = "DEV-001"

        dev2_enc_priv, dev2_enc_pub = generate_x25519_keypair()
        dev2_id = "DEV-002"

        dev3_enc_priv, _ = generate_x25519_keypair()
        dev3_id = "DEV-003"

        # Encrypt document once with ephemeral DEK
        dek = generate_dek()
        aad = f"{doc_id}:{original_sha256}".encode("utf-8")
        ciphertext, nonce = encrypt_bytes_aes_gcm(plaintext, dek, associated_data=aad)

        # Wrap DEK for DEV-1 and DEV-2
        env1 = wrap_dek_for_recipient(dek, dev1_enc_pub, dev1_id, doc_id)
        env2 = wrap_dek_for_recipient(dek, dev2_enc_pub, dev2_id, doc_id)

        pkg = OfflineMultiDevicePackage(
            package_id="PKG-001",
            document_id=doc_id,
            original_filename="classified.pdf",
            original_sha256=original_sha256,
            owner_id="OWNER-ROOT",
            owner_public_sign_key=b64encode_str(ed25519_public_to_bytes(owner_sign_pub)),
            nonce=b64encode_str(nonce),
            key_envelopes=[env1, env2],
            ciphertext=b64encode_str(ciphertext),
        )
        pkg.sign_package(owner_sign_priv)

        serialized = pkg.serialize()
        restored = OfflineMultiDevicePackage.deserialize(serialized)

        # DEV-1 decrypts successfully
        dec1 = restored.decrypt_for_device(dev1_id, dev1_enc_priv)
        assert dec1 == plaintext

        # DEV-2 decrypts successfully
        dec2 = restored.decrypt_for_device(dev2_id, dev2_enc_priv)
        assert dec2 == plaintext

        # DEV-3 is unauthorized and fails
        with pytest.raises(AuthorizationError):
            restored.decrypt_for_device(dev3_id, dev3_enc_priv)

    def test_offline_package_tampered_signature_fails(self):
        plaintext = b"Test doc"
        doc_id = "DOC-T1"
        sha = sha256_hash(plaintext)

        owner_sign_priv, owner_sign_pub = generate_ed25519_keypair()
        dev1_enc_priv, dev1_enc_pub = generate_x25519_keypair()
        dev1_id = "DEV-001"

        dek = generate_dek()
        aad = f"{doc_id}:{sha}".encode("utf-8")
        ciphertext, nonce = encrypt_bytes_aes_gcm(plaintext, dek, associated_data=aad)
        env = wrap_dek_for_recipient(dek, dev1_enc_pub, dev1_id, doc_id)

        pkg = OfflineMultiDevicePackage(
            package_id="PKG-TAMPER",
            document_id=doc_id,
            original_filename="t.pdf",
            original_sha256=sha,
            owner_id="OWNER-ROOT",
            owner_public_sign_key=b64encode_str(ed25519_public_to_bytes(owner_sign_pub)),
            nonce=b64encode_str(nonce),
            key_envelopes=[env],
            ciphertext=b64encode_str(ciphertext),
        )
        pkg.sign_package(owner_sign_priv)

        # Tamper with filename
        pkg.original_filename = "hacked.pdf"

        with pytest.raises(SignatureVerificationError):
            pkg.decrypt_for_device(dev1_id, dev1_enc_priv, verify_owner_sig=True)

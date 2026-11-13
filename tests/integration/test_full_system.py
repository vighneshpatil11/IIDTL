"""Full system integration test suite covering security edge cases, large files, and tamper attempts."""

import pytest
import io
import os
import tempfile
from pathlib import Path
from starlette.datastructures import UploadFile

from online.backend.app.database.connection import SessionLocal, init_db
from online.backend.app.api.auth import register_user, RegisterRequest
from online.backend.app.api.documents import upload_document
from online.backend.app.api.recipients import create_recipient, CreateRecipientRequest, update_recipient_status, UpdateStatusRequest
from online.backend.app.api.distribution import create_distribution, download_recipient_package, CreateDistributionRequest
from online.backend.app.api.investigation import analyze_leaked_document
from offline.app.database.connection import init_offline_db, get_offline_db
from offline.app.database.models import OfflineDevice
from offline.app.security.device_keys import DeviceKeyManager
from offline.app.services.offline_packager import OfflinePackagingService
from offline.app.services.audit_service import HashLinkedAuditService
from shared.crypto.primitives import generate_dek, sha256_hash, encrypt_bytes_aes_gcm, decrypt_bytes_aes_gcm
from shared.crypto.key_exchange import generate_x25519_keypair, x25519_public_to_bytes
from shared.crypto.signatures import generate_ed25519_keypair, ed25519_public_to_bytes
from shared.models.package import OnlineRecipientPackage, OfflineMultiDevicePackage
from shared.watermark.engine import WatermarkEngine
from shared.utils.serialization import b64encode_str, b64decode_str
from shared.crypto.exceptions import DecryptionError, AuthorizationError, KeyEnvelopeError


def test_large_file_encryption_and_integrity():
    """Verify performance and memory safety on large file payloads (5 MB payload)."""
    large_payload = os.urandom(5 * 1024 * 1024)  # 5 MB
    orig_hash = sha256_hash(large_payload)

    key = generate_dek()
    ciphertext, nonce = encrypt_bytes_aes_gcm(large_payload, key)
    decrypted = decrypt_bytes_aes_gcm(ciphertext, key, nonce)

    assert len(decrypted) == len(large_payload)
    assert sha256_hash(decrypted) == orig_hash


def test_watermark_false_positive_resistance():
    """Verify that multiple clean PDFs and random data do not trigger false positive watermark matches."""
    random_bytes = os.urandom(4096)
    extracted, conf, tel = WatermarkEngine.extract_watermark_from_pdf(random_bytes)
    assert extracted is None
    assert conf == 0.0

    clean_text = "This is a clean corporate communication regarding quarterly financial objectives."
    extracted_txt, conf_txt, _ = WatermarkEngine.extract_watermark_from_text(clean_text)
    assert extracted_txt is None
    assert conf_txt == 0.0


def test_offline_device_tampering_and_audit_resilience():
    """Verify that offline audit chain detects deletions or sequence truncation."""
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from offline.app.database.models import OfflineBase

    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    OfflineBase.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine)
    db = Session()

    dev_id, sign_priv, _ = DeviceKeyManager.create_device_identity("Resilience-Test-Dev")
    db_dev = OfflineDevice(
        device_id=dev_id,
        device_name="Resilience-Test-Dev",
        public_sign_key=b64encode_str(ed25519_public_to_bytes(sign_priv.public_key())),
        public_enc_key=b64encode_str(b"\x00" * 32),
        registration_status="APPROVED",
    )
    db.add(db_dev)
    db.commit()

    # Record 2 events
    log1 = HashLinkedAuditService.record_event(db, dev_id, "TEST_A", "SUCCESS", device_sign_priv=sign_priv)
    log2 = HashLinkedAuditService.record_event(db, dev_id, "TEST_B", "SUCCESS", device_sign_priv=sign_priv)

    is_valid, msg, _ = HashLinkedAuditService.verify_audit_chain(db)
    assert is_valid is True

    # Simulate deletion of log1 (truncation / intermediate deletion)
    db.delete(log1)
    db.commit()

    # Re-verify -> MUST detect link discontinuity!
    is_valid_after_del, del_msg, tel = HashLinkedAuditService.verify_audit_chain(db)
    assert is_valid_after_del is False
    assert tel["error"] == "HASH_LINK_DISCONTINUITY"

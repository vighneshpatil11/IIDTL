"""Comprehensive automated test suite for the Offline Prototype (Phases 5, 6, 7)."""

import pytest
import tempfile
from pathlib import Path
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from offline.app.database.models import OfflineBase, OfflineDevice, OfflineAuditLog
from offline.app.security.device_keys import (
    DeviceKeyManager,
    DeviceRegistrationRequest,
    DeviceCertificate,
)
from offline.app.services.offline_packager import OfflinePackagingService
from offline.app.services.audit_service import HashLinkedAuditService
from shared.crypto.signatures import generate_ed25519_keypair, ed25519_public_to_bytes
from shared.crypto.key_exchange import generate_x25519_keypair, x25519_public_to_bytes
from shared.crypto.exceptions import (
    AuthorizationError,
    SignatureVerificationError,
    IntegrityError,
)
from shared.utils.serialization import b64encode_str


@pytest.fixture
def test_db():
    """In-memory SQLite database for isolated offline testing."""
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    OfflineBase.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine)
    session = Session()
    try:
        yield session
    finally:
        session.close()


class TestDeviceRegistrationAndCertificates:
    """Tests for Phase 5: Device Registration & Unique Cryptographic Identity."""

    def test_device_identity_and_request_signing(self):
        dev_id, sign_priv, enc_priv = DeviceKeyManager.create_device_identity("Field-Laptop-01")
        assert dev_id.startswith("DEV-")

        # Export registration request
        req = DeviceKeyManager.export_registration_request(
            device_id=dev_id,
            device_name="Field-Laptop-01",
            sign_priv=sign_priv,
            enc_pub=enc_priv.public_key(),
        )
        assert req.verify() is True

    def test_tampered_registration_request_fails_verification(self):
        dev_id, sign_priv, enc_priv = DeviceKeyManager.create_device_identity("Field-Laptop-01")
        req = DeviceKeyManager.export_registration_request(
            device_id=dev_id,
            device_name="Field-Laptop-01",
            sign_priv=sign_priv,
            enc_pub=enc_priv.public_key(),
        )
        # Attacker tampers with device name
        req.device_name = "Rogue-Terminal"
        assert req.verify() is False

    def test_owner_approval_and_signed_certificate(self):
        owner_sign_priv, owner_sign_pub = generate_ed25519_keypair()
        dev_id, sign_priv, enc_priv = DeviceKeyManager.create_device_identity("Field-Laptop-01")
        req = DeviceKeyManager.export_registration_request(
            device_id=dev_id,
            device_name="Field-Laptop-01",
            sign_priv=sign_priv,
            enc_pub=enc_priv.public_key(),
        )

        cert = DeviceKeyManager.approve_device_registration(
            request=req,
            owner_id="OWNER-ADMIN",
            owner_sign_priv=owner_sign_priv,
        )
        assert cert.verify_owner(owner_sign_pub) is True
        assert cert.status == "APPROVED"


class TestOfflinePackagingAndDecryption:
    """Tests for Phase 6: Offline Document Encryption, Multi-Device Envelopes & Decryption."""

    def test_offline_multi_device_distribution_workflow(self, test_db):
        owner_sign_priv, _ = generate_ed25519_keypair()
        owner_id = "OWNER-ADMIN"

        # Register Device 1
        dev1_id, dev1_sign_priv, dev1_enc_priv = DeviceKeyManager.create_device_identity("Field-01")
        db_dev1 = OfflineDevice(
            device_id=dev1_id,
            device_name="Field-01",
            public_sign_key=b64encode_str(ed25519_public_to_bytes(dev1_sign_priv.public_key())),
            public_enc_key=b64encode_str(x25519_public_to_bytes(dev1_enc_priv.public_key())),
            registration_status="APPROVED",
        )
        test_db.add(db_dev1)

        # Register Device 2
        dev2_id, dev2_sign_priv, dev2_enc_priv = DeviceKeyManager.create_device_identity("HQ-02")
        db_dev2 = OfflineDevice(
            device_id=dev2_id,
            device_name="HQ-02",
            public_sign_key=b64encode_str(ed25519_public_to_bytes(dev2_sign_priv.public_key())),
            public_enc_key=b64encode_str(x25519_public_to_bytes(dev2_enc_priv.public_key())),
            registration_status="APPROVED",
        )
        test_db.add(db_dev2)
        test_db.commit()

        # Unregistered Device 3
        dev3_id, dev3_sign_priv, dev3_enc_priv = DeviceKeyManager.create_device_identity("Rogue-03")

        # Create package for DEV-1 and DEV-2
        secret_content = b"TOP SECRET AIR-GAPPED INTEL REPORT"
        with tempfile.TemporaryDirectory() as tmpdir:
            pkg, pkg_path = OfflinePackagingService.create_package(
                db=test_db,
                document_bytes=secret_content,
                filename="tactical_intel.pdf",
                owner_id=owner_id,
                owner_sign_priv=owner_sign_priv,
                authorized_device_ids=[dev1_id, dev2_id],
                output_dir=tmpdir,
            )

            package_bytes = pkg_path.read_bytes()

            # DEV-1 Decrypts successfully
            dec1 = OfflinePackagingService.decrypt_package_on_device(
                db=test_db,
                package_bytes=package_bytes,
                device_id=dev1_id,
                device_enc_priv=dev1_enc_priv,
                device_sign_priv=dev1_sign_priv,
            )
            assert dec1 == secret_content

            # DEV-2 Decrypts successfully
            dec2 = OfflinePackagingService.decrypt_package_on_device(
                db=test_db,
                package_bytes=package_bytes,
                device_id=dev2_id,
                device_enc_priv=dev2_enc_priv,
                device_sign_priv=dev2_sign_priv,
            )
            assert dec2 == secret_content

            # DEV-3 is unauthorized -> REJECTED
            with pytest.raises(AuthorizationError):
                OfflinePackagingService.decrypt_package_on_device(
                    db=test_db,
                    package_bytes=package_bytes,
                    device_id=dev3_id,
                    device_enc_priv=dev3_enc_priv,
                    device_sign_priv=dev3_sign_priv,
                )

            # Owner Revokes DEV-2
            db_dev2.registration_status = "REVOKED"
            test_db.commit()

            # DEV-2 Decryption attempt -> REJECTED (Revoked)
            with pytest.raises(AuthorizationError):
                OfflinePackagingService.decrypt_package_on_device(
                    db=test_db,
                    package_bytes=package_bytes,
                    device_id=dev2_id,
                    device_enc_priv=dev2_enc_priv,
                    device_sign_priv=dev2_sign_priv,
                )


class TestTamperEvidentAuditSystem:
    """Tests for Phase 7: Hash-Linked Audit Records & Verification."""

    def test_audit_chain_verification_and_tamper_detection(self, test_db):
        dev_id, sign_priv, _ = DeviceKeyManager.create_device_identity("Device-Audit-01")
        dev = OfflineDevice(
            device_id=dev_id,
            device_name="Audit-Test-Device",
            public_sign_key=b64encode_str(ed25519_public_to_bytes(sign_priv.public_key())),
            public_enc_key=b64encode_str(b"\x00" * 32),
            registration_status="APPROVED",
        )
        test_db.add(dev)
        test_db.commit()

        # Add 3 legitimate events
        HashLinkedAuditService.record_event(test_db, dev_id, "LOGIN", "SUCCESS", device_sign_priv=sign_priv)
        HashLinkedAuditService.record_event(test_db, dev_id, "OPEN_DOC", "SUCCESS", document_id="DOC-001", device_sign_priv=sign_priv)
        HashLinkedAuditService.record_event(test_db, dev_id, "EXPORT_REPORT", "SUCCESS", document_id="DOC-001", device_sign_priv=sign_priv)

        # 1. Verify pristine chain
        is_valid, msg, telemetry = HashLinkedAuditService.verify_audit_chain(test_db)
        assert is_valid is True
        assert telemetry["record_count"] == 3

        # 2. Tamper Test: Modify record #2 content in the database
        rec2 = test_db.query(OfflineAuditLog).filter(OfflineAuditLog.sequence_id == 2).first()
        rec2.result = "FAILED"  # Attacker alters event result
        test_db.commit()

        # Verification must catch data tampering
        is_valid_after_tamper, tamper_msg, tel = HashLinkedAuditService.verify_audit_chain(test_db)
        assert is_valid_after_tamper is False
        assert tel["error"] == "DATA_TAMPERING"
        assert tel["failed_sequence"] == 2

    def test_keystore_encryption_and_recovery(self):
        dev_id, sign_priv, enc_priv = DeviceKeyManager.create_device_identity("Keystore-Device")
        passphrase = "UltraSecureOfflinePassphrase123!"

        with tempfile.TemporaryDirectory() as tmpdir:
            keystore_path = Path(tmpdir) / "device.keystore"
            # Save keystore
            DeviceKeyManager.save_keystore(keystore_path, passphrase, sign_priv, enc_priv, dev_id)

            # Load keystore
            rec_id, rec_sign_priv, rec_enc_priv = DeviceKeyManager.load_keystore(keystore_path, passphrase)

            assert rec_id == dev_id
            assert ed25519_public_to_bytes(rec_sign_priv.public_key()) == ed25519_public_to_bytes(sign_priv.public_key())
            assert x25519_public_to_bytes(rec_enc_priv.public_key()) == x25519_public_to_bytes(enc_priv.public_key())

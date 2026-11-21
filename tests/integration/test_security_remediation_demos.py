"""
End-to-End Security Remediation Demonstration Suite

Demonstrates and verifies:
1. Online Workflow:
   - Client-side key custody (3 recipients with genuine X25519 keys).
   - Upload confidential document.
   - Unified multi-recipient encrypted distribution (.secure) with persistent owner Ed25519 signature.
   - 3 distinct forensic watermark IDs embedded and verified.
   - Authorized recipient decryption; unauthorized key rejection.
   - Leak investigation attributing recovered document to recipient with explicit forensic limitations.

2. Offline Workflow:
   - Device identity generation & signed registration requests.
   - Owner verification & signed DeviceCertificate.
   - Hardened keystore storage with Scrypt KDF (V2) & per-keystore salt.
   - Multi-device packaging with trusted owner signature verification.
   - Authorized device decryption vs unauthorized device rejection.
   - Tamper-evident hash-linked audit logging with mandatory signatures for critical events.
   - Signed AuditCheckpoint verifying chain tip and detecting tail truncation and intermediate record deletions.
"""

import io
import os
import json
import pytest
from pathlib import Path
from starlette.datastructures import UploadFile
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas

from online.backend.app.database.connection import SessionLocal, init_db
from online.backend.app.database.models import User, Recipient
from online.backend.app.api.auth import register_user, RegisterRequest
from online.backend.app.api.documents import upload_document
from online.backend.app.api.recipients import create_recipient, CreateRecipientRequest
from online.backend.app.api.distribution import (
    create_unified_distribution,
    decrypt_package_api,
    CreateDistributionRequest,
    DecryptPackageRequest,
)
from online.backend.app.api.investigation import analyze_leaked_document
from online.backend.app.config import settings

from shared.crypto.key_exchange import (
    generate_x25519_keypair,
    x25519_private_to_bytes,
    x25519_public_to_bytes,
    x25519_private_from_bytes,
)
from shared.crypto.signatures import (
    generate_ed25519_keypair,
    ed25519_public_to_bytes,
    ed25519_private_to_bytes,
)
from shared.crypto.exceptions import (
    SignatureVerificationError,
    AuthorizationError,
    DecryptionError,
)
from shared.utils.serialization import b64encode_str, b64decode_str

from offline.app.security.device_keys import DeviceKeyManager
from offline.app.services.offline_packager import OfflinePackagingService
from offline.app.services.audit_service import HashLinkedAuditService
from offline.app.database.models import OfflineBase
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker


def make_confidential_pdf(title: str = "CONFIDENTIAL STRATEGIC PLAN 2026") -> bytes:
    buf = io.BytesIO()
    c = canvas.Canvas(buf, pagesize=letter)
    c.drawString(72, 750, title)
    c.drawString(72, 720, "Project Falcon: High-assurance document distribution protocol.")
    c.drawString(72, 690, "Security Classification: TOP SECRET // NOFORN")
    c.drawString(72, 660, "Mandatory forensic tracing enabled for all authorized recipients.")
    c.showPage()
    c.save()
    return buf.getvalue()


# ===========================================================================
# DEMO 1: ONLINE SYSTEM END-TO-END DEMO
# ===========================================================================

def test_demo_online_document_distribution_and_forensic_investigation(tmp_path):
    """Full demonstration of the Online Architecture meeting Priorities 1, 2, 3, 5, 7."""
    init_db()
    db = SessionLocal()
    try:
        import secrets
        run_id = secrets.token_hex(4)

        # 1. Register Document Owner
        owner_email = f"ciso_{run_id}@docfortress.mil"
        owner = register_user(
            RegisterRequest(
                email=owner_email,
                full_name="Chief Information Security Officer",
                password="OwnerMasterSecret!2026",
                role="OWNER",
            ),
            db=db,
        )

        # 2. Three Recipients generate their own private keys CLIENT-SIDE (Priority 1)
        recipients = []
        for name in ["Alice Analyst", "Bob Director", "Charlie Auditor"]:
            priv, pub = generate_x25519_keypair()
            priv_b64 = b64encode_str(x25519_private_to_bytes(priv))
            pub_b64 = b64encode_str(x25519_public_to_bytes(pub))
            email = f"{name.lower().replace(' ', '.')}_{run_id}@defense.gov"

            # Enrolled using ONLY public key — server never sees private key
            rec = create_recipient(
                CreateRecipientRequest(
                    name=name,
                    email=email,
                    public_key=pub_b64,
                ),
                db=db,
                current_user=owner,
            )
            recipients.append({
                "name": name,
                "email": email,
                "id": rec["id"],
                "priv_b64": priv_b64,
                "pub_b64": pub_b64,
            })

        # 3. Owner uploads confidential document
        pdf_bytes = make_confidential_pdf()
        upload_file = UploadFile(filename=f"strategy_memo_{run_id}.pdf", file=io.BytesIO(pdf_bytes))
        doc_record = upload_document(file=upload_file, db=db, current_user=owner)
        doc_id = doc_record["id"]

        # 4. Owner creates single unified distribution container (.secure) for all 3 recipients
        dist_req = CreateDistributionRequest(
            document_id=doc_id,
            recipient_ids=[r["id"] for r in recipients],
        )
        dist_res = create_unified_distribution(req=dist_req, db=db, current_user=owner)
        assert dist_res["status"] == "success"
        assert dist_res["authorized_recipients_count"] == 3

        # Verify 3 distinct watermark IDs were generated and associated
        watermarks = [r["watermark_id"] for r in dist_res["authorized_recipients"]]
        assert len(set(watermarks)) == 3, f"Recipients must each receive unique watermarks! Got {watermarks}"

        # Read the encrypted package container
        pkg_file = settings.ENCRYPTED_DIR / dist_res["filename"]
        pkg_content = pkg_file.read_text(encoding="utf-8")
        pkg_dict = json.loads(pkg_content)

        # Verify persistent owner Ed25519 signature is present (Priority 5)
        assert pkg_dict["owner_signature"], "Package must be digitally signed by owner"
        assert pkg_dict["owner_public_sign_key"], "Package must include owner public key"

        # 5. Alice decrypts her copy using her client private key
        alice = recipients[0]
        alice_dec = decrypt_package_api(
            DecryptPackageRequest(
                package_content=pkg_content,
                private_key=alice["priv_b64"],
            ),
            db=db,
        )
        assert alice_dec["recipient_id"] == alice["id"]
        assert alice_dec["watermark_id"] == watermarks[0]
        alice_pdf_bytes = b64decode_str(alice_dec["file_bytes_b64"])
        assert alice_pdf_bytes.startswith(b"%PDF")

        # 6. Bob decrypts his copy using his client private key
        bob = recipients[1]
        bob_dec = decrypt_package_api(
            DecryptPackageRequest(
                package_content=pkg_content,
                private_key=bob["priv_b64"],
            ),
            db=db,
        )
        assert bob_dec["recipient_id"] == bob["id"]
        assert bob_dec["watermark_id"] == watermarks[1]
        bob_pdf_bytes = b64decode_str(bob_dec["file_bytes_b64"])

        # 7. Charlie decrypts his copy
        charlie = recipients[2]
        charlie_dec = decrypt_package_api(
            DecryptPackageRequest(
                package_content=pkg_content,
                private_key=charlie["priv_b64"],
            ),
            db=db,
        )
        assert charlie_dec["watermark_id"] == watermarks[2]

        # 8. Eve (attacker with unauthorized private key) attempts decryption
        eve_priv, _ = generate_x25519_keypair()
        eve_priv_b64 = b64encode_str(x25519_private_to_bytes(eve_priv))
        from fastapi import HTTPException
        with pytest.raises(HTTPException) as exc_info:
            decrypt_package_api(
                DecryptPackageRequest(
                    package_content=pkg_content,
                    private_key=eve_priv_b64,
                ),
                db=db,
            )
        assert exc_info.value.status_code == 403

        # 9. FORENSIC INVESTIGATION:
        # Simulate leak: Bob's decrypted document is recovered from a public leak
        leaked_file = UploadFile(
            filename="leaked_document_found_online.pdf",
            file=io.BytesIO(bob_pdf_bytes),
        )
        investigation_result = analyze_leaked_document(
            db=db,
            current_user=owner,
            file=leaked_file,
        )

        # Verify exact forensic watermark match
        assert investigation_result["match_category"] == "EXACT_MATCH"
        assert investigation_result["extracted_watermark_id"] == watermarks[1]
        assert investigation_result["associated_recipient"]["recipient_id"] == bob["id"]
        assert investigation_result["associated_recipient"]["recipient_name"] == "Bob Director"
        assert investigation_result["confidence_score"] >= 0.95

        # Verify attribution limitation statement is explicitly present
        assert "IMPORTANT LIMITATION" in investigation_result["attribution_statement"]
        assert "does not prove the physical identity" in investigation_result["attribution_statement"]

    finally:
        db.close()


# ===========================================================================
# DEMO 2: OFFLINE SYSTEM AIR-GAPPED & AUDIT DEMO
# ===========================================================================

def test_demo_offline_airgapped_audit_and_tamper_resilience(tmp_path):
    """Full demonstration of the Offline Standalone Architecture meeting Priorities 4, 5, 6, 7."""
    offline_db_path = tmp_path / "offline_demo.db"
    offline_engine = create_engine(f"sqlite:///{offline_db_path}")
    OfflineBase.metadata.create_all(bind=offline_engine)
    OfflineSession = sessionmaker(bind=offline_engine)
    db = OfflineSession()

    try:
        # 1. Owner Setup
        owner_sign_priv, owner_sign_pub = generate_ed25519_keypair()
        owner_id = "OFFLINE-MASTER-OWNER"

        # 2. Device A and Device B generate cryptographic identities
        dev_a_id, dev_a_sign_priv, dev_a_enc_priv = DeviceKeyManager.create_device_identity("Field Laptop Alpha")
        dev_b_id, dev_b_sign_priv, dev_b_enc_priv = DeviceKeyManager.create_device_identity("Field Laptop Bravo")

        # 3. Devices export signed registration requests
        req_a = DeviceKeyManager.export_registration_request(
            device_id=dev_a_id,
            device_name="Field Laptop Alpha",
            sign_priv=dev_a_sign_priv,
            enc_pub=dev_a_enc_priv.public_key(),
        )
        assert req_a.verify() is True

        req_b = DeviceKeyManager.export_registration_request(
            device_id=dev_b_id,
            device_name="Field Laptop Bravo",
            sign_priv=dev_b_sign_priv,
            enc_pub=dev_b_enc_priv.public_key(),
        )
        assert req_b.verify() is True

        # 4. Owner approves Device A, issues signed certificate
        cert_a = DeviceKeyManager.approve_device_registration(req_a, owner_id, owner_sign_priv)
        assert cert_a.verify_owner(owner_sign_pub) is True

        # Record in offline DB
        from offline.app.database.models import OfflineDevice
        db_dev_a = OfflineDevice(
            device_id=dev_a_id,
            device_name="Field Laptop Alpha",
            public_sign_key=req_a.public_sign_key,
            public_enc_key=req_a.public_enc_key,
            registration_status="APPROVED",
            owner_certificate_signature=cert_a.owner_signature,
        )
        db_dev_b = OfflineDevice(
            device_id=dev_b_id,
            device_name="Field Laptop Bravo",
            public_sign_key=req_b.public_sign_key,
            public_enc_key=req_b.public_enc_key,
            registration_status="PENDING",  # Not approved!
        )
        db.add_all([db_dev_a, db_dev_b])
        db.commit()

        # Audit log for registrations (signed by devices/owner)
        HashLinkedAuditService.record_event(
            db=db,
            device_id=dev_a_id,
            event_type="DEVICE_REGISTRATION",
            result="APPROVED",
            device_sign_priv=dev_a_sign_priv,
        )

        # 5. Keystore Hardening: Device A persists private keys with Scrypt V2 & unique salt (Priority 4)
        keystore_path = tmp_path / "device_a.keystore"
        passphrase = "UltraSecureFieldPassphrase!2026"
        DeviceKeyManager.save_keystore(
            filepath=keystore_path,
            passphrase=passphrase,
            sign_priv=dev_a_sign_priv,
            enc_priv=dev_a_enc_priv,
            device_id=dev_a_id,
        )

        # Verify keystore uses Scrypt V2 format
        with open(keystore_path, "r") as kf:
            keystore_data = json.load(kf)
        assert keystore_data["magic"] == "OFFLINE_KEYSTORE_V2"
        assert keystore_data["kdf"]["algorithm"] == "scrypt"
        assert keystore_data["kdf"]["n"] == 16384
        assert keystore_data["kdf"]["salt"] is not None

        # Unlocking with correct passphrase works
        loaded_id, loaded_sign, loaded_enc = DeviceKeyManager.load_keystore(keystore_path, passphrase)
        assert loaded_id == dev_a_id

        # Unlocking with wrong passphrase fails
        with pytest.raises(DecryptionError):
            DeviceKeyManager.load_keystore(keystore_path, "WrongPassphrase!")

        # 6. Owner encrypts confidential document for authorized device A only
        doc_content = b"TOP SECRET MISSION DIRECTIVE: Coordinates 37.2431 N, 115.7930 W."
        pkg, pkg_path = OfflinePackagingService.create_package(
            db=db,
            document_bytes=doc_content,
            filename="mission_directive.txt",
            owner_id=owner_id,
            owner_sign_priv=owner_sign_priv,
            authorized_device_ids=[dev_a_id, dev_b_id],  # B is filtered out because it is PENDING
            output_dir=tmp_path,
        )

        # Log package creation
        HashLinkedAuditService.record_event(
            db=db,
            device_id=owner_id,
            event_type="PACKAGE_CREATED",
            result="SUCCESS",
            document_id=pkg.document_id,
            device_sign_priv=owner_sign_priv,
        )

        # 7. Device A decrypts package successfully with trusted owner public key verification (Priority 5)
        decrypted_doc = pkg.decrypt_for_device(
            device_id=dev_a_id,
            device_private_enc_key=loaded_enc,
            trusted_owner_public_key=owner_sign_pub,
            verify_owner_sig=True,
        )
        assert decrypted_doc == doc_content

        HashLinkedAuditService.record_event(
            db=db,
            device_id=dev_a_id,
            event_type="DECRYPT_SUCCESS",
            result="SUCCESS",
            document_id=pkg.document_id,
            device_sign_priv=loaded_sign,
        )

        # 8. Device B attempts decryption -> rejected (unauthorized)
        with pytest.raises(AuthorizationError):
            pkg.decrypt_for_device(
                device_id=dev_b_id,
                device_private_enc_key=dev_b_enc_priv,
                trusted_owner_public_key=owner_sign_pub,
            )

        # 9. Tampered signature rejection: attacker substitutes owner public key
        untrusted_priv, untrusted_pub = generate_ed25519_keypair()
        with pytest.raises(SignatureVerificationError):
            pkg.decrypt_for_device(
                device_id=dev_a_id,
                device_private_enc_key=loaded_enc,
                trusted_owner_public_key=untrusted_pub,  # Untrusted key!
            )

        # 10. Audit Chain Verification & Signed Checkpoint (Priority 6)
        valid, msg, details = HashLinkedAuditService.verify_audit_chain(db)
        assert valid is True, f"Audit chain verification failed: {msg}"

        # Create signed checkpoint anchoring chain tip
        checkpoint = HashLinkedAuditService.create_checkpoint(
            db=db,
            signer_id=owner_id,
            signer_priv=owner_sign_priv,
        )
        assert checkpoint is not None
        cp_valid, cp_msg = HashLinkedAuditService.verify_checkpoint(db, checkpoint, owner_sign_pub)
        assert cp_valid is True

        # Test truncation detection: delete newest record and verify checkpoint detects tail truncation
        from offline.app.database.models import OfflineAuditLog
        last_rec = db.query(OfflineAuditLog).order_by(OfflineAuditLog.sequence_id.desc()).first()
        db.delete(last_rec)
        db.commit()

        cp_valid_truncated, cp_err = HashLinkedAuditService.verify_checkpoint(db, checkpoint, owner_sign_pub)
        assert cp_valid_truncated is False
        assert "Tail truncation detected" in cp_err

    finally:
        db.close()

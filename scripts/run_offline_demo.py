"""End-to-End interactive demonstration runner for Offline Scenarios:
- DEMO C: Offline Device Registration & Approval
- DEMO D: Offline Restricted Multi-Device Distribution (.secure)
- DEMO E: Tamper-Evident Access Audit & Integrity Verification
"""

import sys
import tempfile
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from offline.app.database.models import OfflineBase, OfflineDevice, OfflineAuditLog
from offline.app.security.device_keys import DeviceKeyManager
from offline.app.services.offline_packager import OfflinePackagingService
from offline.app.services.audit_service import HashLinkedAuditService
from shared.crypto.signatures import generate_ed25519_keypair, ed25519_public_to_bytes
from shared.crypto.key_exchange import x25519_public_to_bytes
from shared.crypto.exceptions import AuthorizationError
from shared.utils.serialization import b64encode_str


def run():
    print("=" * 80)
    print("OFFLINE PROTOTYPE DEMONSTRATION: SCENARIOS C, D, & E")
    print("=" * 80)

    # Initialize in-memory clean database for demonstration
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    OfflineBase.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine)
    db = Session()

    # --------------------------------------------------------------------------
    # DEMO C: Offline Device Registration
    # --------------------------------------------------------------------------
    print("\n" + "-" * 80)
    print("DEMO C: OFFLINE DEVICE REGISTRATION & OWNER APPROVAL")
    print("-" * 80)

    owner_sign_priv, owner_sign_pub = generate_ed25519_keypair()
    owner_id = "OFFLINE-OWNER-ROOT"
    print(f"[+] Initialized Owner Administrative Identity: {owner_id}")

    # Register Device 1 (Field Laptop)
    dev1_id, dev1_sign_priv, dev1_enc_priv = DeviceKeyManager.create_device_identity("Field-Tactical-Laptop")
    dev1_req = DeviceKeyManager.export_registration_request(dev1_id, "Field-Tactical-Laptop", dev1_sign_priv, dev1_enc_priv.public_key())
    print(f"\n[+] DEV-1 Generated Identity: {dev1_id}")
    print(f"    - Device Name: {dev1_req.device_name}")
    print(f"    - Request Signature Valid: {dev1_req.verify()}")

    dev1_cert = DeviceKeyManager.approve_device_registration(dev1_req, owner_id, owner_sign_priv)
    print(f"    - Owner Approved & Signed Certificate: Valid={dev1_cert.verify_owner(owner_sign_pub)}")

    db_dev1 = OfflineDevice(
        device_id=dev1_id,
        device_name=dev1_req.device_name,
        public_sign_key=dev1_req.public_sign_key,
        public_enc_key=dev1_req.public_enc_key,
        registration_status="APPROVED",
        owner_certificate_signature=dev1_cert.owner_signature,
    )
    db.add(db_dev1)

    # Register Device 2 (Base Station Terminal)
    dev2_id, dev2_sign_priv, dev2_enc_priv = DeviceKeyManager.create_device_identity("Base-Station-Terminal")
    dev2_req = DeviceKeyManager.export_registration_request(dev2_id, "Base-Station-Terminal", dev2_sign_priv, dev2_enc_priv.public_key())
    dev2_cert = DeviceKeyManager.approve_device_registration(dev2_req, owner_id, owner_sign_priv)
    db_dev2 = OfflineDevice(
        device_id=dev2_id,
        device_name=dev2_req.device_name,
        public_sign_key=dev2_req.public_sign_key,
        public_enc_key=dev2_req.public_enc_key,
        registration_status="APPROVED",
        owner_certificate_signature=dev2_cert.owner_signature,
    )
    db.add(db_dev2)
    db.commit()

    print(f"\n[+] DEV-2 Generated Identity: {dev2_id}")
    print(f"    - Device Name: {dev2_req.device_name}")
    print(f"    - Owner Approved & Signed Certificate: Valid={dev2_cert.verify_owner(owner_sign_pub)}")
    print("[+] Both devices successfully registered in local registry.")

    # --------------------------------------------------------------------------
    # DEMO D: Offline Restricted Distribution
    # --------------------------------------------------------------------------
    print("\n" + "-" * 80)
    print("DEMO D: OFFLINE RESTRICTED DISTRIBUTION (.secure container)")
    print("-" * 80)

    document_content = (
        b"CONFIDENTIAL TACTICAL DEPLOYMENT ORDERS - AIR-GAPPED ENVIRONMENT\n"
        b"Grid Coordinates: Sector 7G.\n"
        b"Access strictly restricted to Field Tactical Unit (DEV-1)."
    )

    with tempfile.TemporaryDirectory() as tmpdir:
        # Owner selects document and authorizes ONLY DEV-1
        print(f"[*] Owner encrypts document with AES-256-GCM authorizing ONLY {dev1_id}...")
        pkg, pkg_path = OfflinePackagingService.create_package(
            db=db,
            document_bytes=document_content,
            filename="Tactical_Deployment_Orders.pdf",
            owner_id=owner_id,
            owner_sign_priv=owner_sign_priv,
            authorized_device_ids=[dev1_id],  # ONLY DEV-1, NOT DEV-2!
            output_dir=tmpdir,
        )

        package_bytes = pkg_path.read_bytes()
        print(f"[+] Package Generated: {pkg_path.name}")
        print(f"    - Package Size: {len(package_bytes)} bytes")
        print(f"    - Owner Signature Verified: {pkg.verify_package_signature()}")
        print(f"    - Key Envelopes Embedded: {[env['recipient_id'] for env in pkg.key_envelopes]}")

        # Transfer package to DEV-1 -> Decrypts
        print(f"\n[*] Transferring package to DEV-1 ({dev1_id})...")
        decrypted_dev1 = OfflinePackagingService.decrypt_package_on_device(
            db=db,
            package_bytes=package_bytes,
            device_id=dev1_id,
            device_enc_priv=dev1_enc_priv,
            device_sign_priv=dev1_sign_priv,
        )
        print(f"[+] DEV-1 Decryption: SUCCESS!")
        print(f"    Recovered text: \"{decrypted_dev1.decode('utf-8')[:64]}...\"")

        # Transfer package to DEV-2 -> Attempts Decrypt
        print(f"\n[*] Transferring package to DEV-2 ({dev2_id})...")
        try:
            OfflinePackagingService.decrypt_package_on_device(
                db=db,
                package_bytes=package_bytes,
                device_id=dev2_id,
                device_enc_priv=dev2_enc_priv,
                device_sign_priv=dev2_sign_priv,
            )
            print("[-] CRITICAL FAILURE: Unauthorized DEV-2 decrypted package!")
        except AuthorizationError as e:
            print(f"[+] DEV-2 Decryption: CORRECTLY REJECTED ({str(e)})")

    # --------------------------------------------------------------------------
    # DEMO E: Offline Access Audit & Hash-Linked Verification
    # --------------------------------------------------------------------------
    print("\n" + "-" * 80)
    print("DEMO E: TAMPER-EVIDENT ACCESS AUDIT")
    print("-" * 80)

    print("[*] Inspecting recorded local audit events:")
    logs = db.query(OfflineAuditLog).order_by(OfflineAuditLog.sequence_id.asc()).all()
    for l in logs:
        print(f"    [Seq {l.sequence_id}] Event: {l.event_type:<18} Device: {l.device_id:<14} Result: {l.result:<12} Hash: {l.event_hash[:16]}...")

    print("\n[*] Performing cryptographic audit chain verification...")
    is_valid, msg, telemetry = HashLinkedAuditService.verify_audit_chain(db)
    print(f"    - Verification Result: {is_valid}")
    print(f"    - Status Message:      {msg}")
    print(f"    - Verified Records:    {telemetry['record_count']}")
    assert is_valid is True

    # Tamper simulation test
    print("\n[*] Simulating an attacker modifying an audit record in the database...")
    target_record = db.query(OfflineAuditLog).filter(OfflineAuditLog.sequence_id == 2).first()
    original_result = target_record.result
    target_record.result = "UNAUTHORIZED_ALTERATION"
    db.commit()

    is_valid_after_tamper, tamper_msg, tel = HashLinkedAuditService.verify_audit_chain(db)
    print(f"    - Tamper Detected:     {not is_valid_after_tamper}")
    print(f"    - Detection Details:   {tamper_msg}")
    assert is_valid_after_tamper is False
    assert tel["error"] == "DATA_TAMPERING"

    db.close()
    print("\n" + "=" * 80)
    print("OFFLINE DEMO C, D & E COMPLETED SUCCESSFULLY")
    print("=" * 80)


if __name__ == "__main__":
    run()

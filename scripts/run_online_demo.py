"""End-to-End interactive demonstration runner for Online Scenarios:
- DEMO A: Multi-Recipient Distribution
- DEMO B: Leak Investigation & Attribution
"""

import sys
import io
import time
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from starlette.datastructures import UploadFile

from online.backend.app.database.connection import SessionLocal, init_db
from online.backend.app.api.auth import register_user, login_for_access_token, RegisterRequest
from online.backend.app.api.documents import upload_document
from online.backend.app.api.recipients import create_recipient, CreateRecipientRequest
from online.backend.app.api.distribution import (
    create_distribution,
    download_recipient_package,
    create_unified_distribution,
    download_unified_package,
    CreateDistributionRequest,
)
from online.backend.app.api.investigation import analyze_leaked_document
from shared.crypto.key_exchange import generate_x25519_keypair, x25519_public_to_bytes
from shared.models.package import OnlineRecipientPackage, UnifiedMultiRecipientPackage
from shared.crypto.exceptions import AuthorizationError
from shared.utils.serialization import b64encode_str


def create_sample_pdf(title: str = "CONFIDENTIAL STRATEGIC ACQUISITION") -> bytes:
    buf = io.BytesIO()
    c = canvas.Canvas(buf, pagesize=letter)
    c.drawString(100, 750, title)
    c.drawString(100, 700, "Project Falcon: Proposed $45M Acquisition Target.")
    c.drawString(100, 650, "Classification: RESTRICTED DISTRIBUTION - DO NOT EXFILTRATE.")
    c.showPage()
    c.save()
    return buf.getvalue()


def run():
    print("=" * 80)
    print("DEMO SCENARIOS A & B: ONLINE DISTRIBUTION AND LEAK INVESTIGATION")
    print("=" * 80)

    init_db()
    db = SessionLocal()

    # Step 1: Owner Setup
    print("\n[STEP 1] Document Owner Registration & Authentication")
    owner_email = f"cso_demo_{int(time.time())}@securecorp.test"
    owner_pw = "MasterCSOPass2026!"
    owner = register_user(
        RegisterRequest(email=owner_email, full_name="Chief Information Security Officer", password=owner_pw, role="OWNER"),
        db,
    )
    print(f"  [+] Owner Created: {owner.full_name} ({owner.email}) [ID: {owner.id}]")

    # Step 2: Upload Document
    print("\n[STEP 2] Document Owner Uploads Confidential PDF")
    pdf_bytes = create_sample_pdf()
    up_file = UploadFile(filename="Project_Falcon_Acquisition.pdf", file=io.BytesIO(pdf_bytes))
    doc = upload_document(up_file, db, owner)
    print(f"  [+] Document Uploaded: {doc['original_filename']}")
    print(f"      - Document ID:   {doc['id']}")
    print(f"      - SHA-256 Hash:  {doc['original_sha256']}")
    print(f"      - File Size:     {doc['file_size']} bytes")

    # Step 3: Register 3 Authorized Recipients
    print("\n[STEP 3] Owner Registers Three Authorized Recipients (Generating X25519 Keypairs)")
    recipients_data = [
        ("Alice Vance (Legal Counsel)", "alice@legal.test"),
        ("Bob Miller (VP Finance)", "bob@finance.test"),
        ("Charlie Stone (Chief Architect)", "charlie@tech.test"),
    ]
    rec_objects = []
    rec_keys = {}

    for name, email in recipients_data:
        priv, pub = generate_x25519_keypair()
        pub_b64 = b64encode_str(x25519_public_to_bytes(pub))
        rec = create_recipient(CreateRecipientRequest(name=name, email=email, public_key=pub_b64), db, owner)
        rec_objects.append(rec)
        rec_keys[rec["id"]] = (priv, pub)
        print(f"  [+] Enrolled: {name} -> {rec['id']} (Public Key: {pub_b64[:16]}...)")

    # Step 4: Distribute Document
    print("\n[STEP 4] Executing Batch Distribution (Watermarking + Ephemeral DEK Encryption)")
    dist_req = CreateDistributionRequest(
        document_id=doc["id"],
        recipient_ids=[r["id"] for r in rec_objects],
    )
    dist_res = create_distribution(dist_req, db, owner)
    print(f"  [+] Generated {dist_res['distributed_count']} distinct recipient packages:")
    for d in dist_res["distributions"]:
        print(f"      - Recipient: {d['recipient_name']} ({d['recipient_id']})")
        print(f"        Watermark ID: {d['watermark_id']}")
        print(f"        Package File: {Path(d['package_path']).name}")

    # Step 5: Recipient Access Demo
    print("\n[STEP 5] DEMO A: Authorized Recipient Decryption vs Unauthorized Access")
    alice_dist = dist_res["distributions"][0]
    bob_dist = dist_res["distributions"][1]

    # Alice downloads her package
    pkg_resp = download_recipient_package(alice_dist["distribution_id"], db)
    with open(pkg_resp.path, "rb") as f:
        alice_pkg_bytes = f.read()

    alice_pkg = OnlineRecipientPackage.deserialize(alice_pkg_bytes)
    alice_priv = rec_keys[alice_dist["recipient_id"]][0]
    bob_priv = rec_keys[bob_dist["recipient_id"]][0]

    # Alice decrypts
    alice_decrypted = alice_pkg.decrypt(alice_priv)
    print(f"  [+] Alice decrypts her package: SUCCESS ({len(alice_decrypted)} bytes plaintext recovered)")

    # Bob attempts to decrypt Alice's package
    try:
        alice_pkg.decrypt(bob_priv)
        print("  [-] FAILURE: Bob decrypted Alice's file!")
    except Exception:
        print("  [+] Bob attempts to decrypt Alice's package: REJECTED (Unauthorized Key)")

    # Step 6: Leak Investigation Demo
    print("\n" + "=" * 80)
    print("[STEP 6] DEMO B: FORENSIC LEAK INVESTIGATION")
    print("=" * 80)
    print("  [*] Scenario: A confidential copy of the PDF surfaces on an external channel.")
    print("  [*] Simulating leak by taking Alice's decrypted PDF and uploading to the Investigation Engine...")

    leak_upload = UploadFile(filename="suspicious_leaked_file.pdf", file=io.BytesIO(alice_decrypted))
    inv_result = analyze_leaked_document(leak_upload, db, owner)

    print("\n  [INVESTIGATION REPORT]")
    print(f"  - Investigation ID:       {inv_result['investigation_id']}")
    print(f"  - Leaked Document Hash:   {inv_result['leaked_file_hash']}")
    print(f"  - Watermark Detected:     {inv_result['watermark_detected']}")
    print(f"  - Extracted Watermark ID: {inv_result['extracted_watermark_id']}")
    print(f"  - Detection Confidence:   {inv_result['confidence_score'] * 100:.1f}%")
    print(f"  - Attributed Recipient:   {inv_result['associated_recipient']['recipient_name']} ({inv_result['associated_recipient']['recipient_id']})")
    print(f"  - Distribution Date:      {inv_result['associated_recipient']['registered_distribution_date']}")
    print(f"\n  [ATTRIBUTION STATEMENT]:\n  \"{inv_result['attribution_statement']}\"")

    # Step 7: Unified Single-File Distribution Demo (User Request: ONE file for all recipients)
    print("\n" + "=" * 80)
    print("[STEP 7] DEMO C: UNIFIED SINGLE-FILE DISTRIBUTION (ONE Encrypted File For All)")
    print("=" * 80)
    print("  [*] Scenario: Owner wants to distribute ONE single file to ALL recipients (email/USB).")
    print("  [*] System builds a UnifiedMultiRecipientPackage (.secure) containing individual slots.")

    unified_res = create_unified_distribution(dist_req, db, owner)
    print(f"  [+] Created single file: {unified_res['filename']}")
    print(f"      - Authorized recipients: {unified_res['authorized_recipients_count']}")
    for r in unified_res["authorized_recipients"]:
        print(f"        * Slot: {r['name']} ({r['id']}) -> Watermark: {r['watermark_id']}")

    uni_file_resp = download_unified_package(unified_res["filename"])
    with open(uni_file_resp.path, "rb") as f:
        unified_file_bytes = f.read()
    print(f"  [+] Single container file size: {len(unified_file_bytes)} bytes")

    # Alice opens the single file
    uni_container_a = UnifiedMultiRecipientPackage.deserialize(unified_file_bytes)
    alice_doc_c, alice_wm_c = uni_container_a.decrypt_for_recipient(alice_priv)
    print(f"  [+] Alice opens the single file: SUCCESS (Watermark: {alice_wm_c})")

    # Bob opens the EXACT SAME single file
    uni_container_b = UnifiedMultiRecipientPackage.deserialize(unified_file_bytes)
    bob_doc_c, bob_wm_c = uni_container_b.decrypt_for_recipient(bob_priv)
    print(f"  [+] Bob opens the EXACT SAME single file: SUCCESS (Watermark: {bob_wm_c})")
    assert alice_wm_c != bob_wm_c, "Watermarks must be distinct!"

    # Unauthorized party (David) tries to open the file
    david_priv, _ = generate_x25519_keypair()
    try:
        uni_container_b.decrypt_for_recipient(david_priv)
        print("  [-] FAILURE: David accessed the file!")
    except AuthorizationError:
        print("  [+] Unauthorized party (David) opens single file: REJECTED (No matching key slot)")

    # Simulate Bob leaking his copy recovered from the single file
    print("\n  [*] Leak Simulation: Bob's copy from the single file surfaces publicly...")
    bob_leak_file = UploadFile(filename="bob_leaked_copy.pdf", file=io.BytesIO(bob_doc_c))
    bob_inv = analyze_leaked_document(bob_leak_file, db, owner)
    print(f"  [+] Forensic scan detects watermark: {bob_inv['extracted_watermark_id']}")
    print(f"  [+] Associated recipient: {bob_inv['associated_recipient']['recipient_name']} ({bob_inv['associated_recipient']['recipient_id']})")
    print(f"  [+] Confidence: {bob_inv['confidence_score'] * 100:.1f}%")

    db.close()
    print("\n" + "=" * 80)
    print("ALL ONLINE DEMO SCENARIOS A, B & C COMPLETED SUCCESSFULLY")
    print("=" * 80)


if __name__ == "__main__":
    run()

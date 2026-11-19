"""Automated tests for Unified Multi-Recipient Package (.secure): ONE file for all recipients."""

import pytest
import io
from pathlib import Path
from starlette.datastructures import UploadFile

from shared.crypto.primitives import generate_dek, sha256_hash, encrypt_bytes_aes_gcm
from shared.crypto.key_exchange import generate_x25519_keypair, x25519_public_to_bytes, wrap_dek_for_recipient
from shared.crypto.signatures import generate_ed25519_keypair, ed25519_public_to_bytes
from shared.models.package import UnifiedMultiRecipientPackage
from shared.watermark.engine import WatermarkEngine
from shared.utils.serialization import b64encode_str
from shared.crypto.exceptions import AuthorizationError, SignatureVerificationError

from online.backend.app.database.connection import SessionLocal, init_db
from online.backend.app.api.auth import register_user, RegisterRequest
from online.backend.app.api.documents import upload_document
from online.backend.app.api.recipients import create_recipient, CreateRecipientRequest
from online.backend.app.api.distribution import create_unified_distribution, download_unified_package, CreateDistributionRequest
from online.backend.app.api.investigation import analyze_leaked_document


class TestUnifiedMultiRecipientPackage:
    """Tests verifying that ONE encrypted file can be distributed to all recipients."""

    def test_single_file_for_multiple_recipients_e2e(self):
        doc_id = "DOC-UNIFIED01"
        original_text = b"Executive Board Briefing: Q4 Merger Evaluation."
        doc_hash = sha256_hash(original_text)

        owner_sign_priv, owner_sign_pub = generate_ed25519_keypair()
        owner_id = "OWNER-ROOT"

        # Three recipients
        alice_priv, alice_pub = generate_x25519_keypair()
        bob_priv, bob_pub = generate_x25519_keypair()
        charlie_priv, charlie_pub = generate_x25519_keypair()

        # Unauthorized fourth party
        david_priv, _ = generate_x25519_keypair()

        recipients = [
            ("REC-ALICE", "WM-ALICE99", alice_pub, alice_priv),
            ("REC-BOB", "WM-BOB88", bob_pub, bob_priv),
            ("REC-CHARLIE", "WM-CHARLIE77", charlie_pub, charlie_priv),
        ]

        # Build recipient slots
        slots = []
        for rec_id, wm_id, pub_key, _ in recipients:
            watermarked_text = WatermarkEngine.embed_watermark_in_text(original_text.decode("utf-8"), wm_id).encode("utf-8")
            dek = generate_dek()
            env = wrap_dek_for_recipient(dek, pub_key, rec_id, doc_id)
            aad = f"{doc_id}:{wm_id}".encode("utf-8")
            ciphertext, nonce = encrypt_bytes_aes_gcm(watermarked_text, dek, associated_data=aad)

            slots.append({
                "recipient_id": rec_id,
                "watermark_id": wm_id,
                "envelope": env,
                "nonce": b64encode_str(nonce),
                "ciphertext": b64encode_str(ciphertext),
            })

        # Create ONE single package
        pkg = UnifiedMultiRecipientPackage(
            package_id="PKG-UNIFIED-001",
            document_id=doc_id,
            original_filename="merger_evaluation.pdf",
            original_sha256=doc_hash,
            owner_id=owner_id,
            owner_public_sign_key=b64encode_str(ed25519_public_to_bytes(owner_sign_pub)),
            recipient_slots=slots,
        )
        pkg.sign_package(owner_sign_priv)

        # Serialize to simulate distributing ONE single file
        single_file_bytes = pkg.serialize()
        assert len(single_file_bytes) > 0

        # Recipient A (Alice) opens the ONE single file
        alice_container = UnifiedMultiRecipientPackage.deserialize(single_file_bytes)
        alice_doc, alice_wm = alice_container.decrypt_for_recipient(alice_priv)
        assert alice_wm == "WM-ALICE99"
        assert "Merger Evaluation" in alice_doc.decode("utf-8")

        # Recipient B (Bob) opens the EXACT SAME single file
        bob_container = UnifiedMultiRecipientPackage.deserialize(single_file_bytes)
        bob_doc, bob_wm = bob_container.decrypt_for_recipient(bob_priv)
        assert bob_wm == "WM-BOB88"
        assert "Merger Evaluation" in bob_doc.decode("utf-8")

        # Recipient C (Charlie) opens the EXACT SAME single file
        charlie_container = UnifiedMultiRecipientPackage.deserialize(single_file_bytes)
        charlie_doc, charlie_wm = charlie_container.decrypt_for_recipient(charlie_priv)
        assert charlie_wm == "WM-CHARLIE77"

        # Verify distinct watermarks from the single file
        assert alice_wm != bob_wm
        assert bob_wm != charlie_wm

        # David (unauthorized) tries to open the single file -> REJECTED
        david_container = UnifiedMultiRecipientPackage.deserialize(single_file_bytes)
        with pytest.raises(AuthorizationError):
            david_container.decrypt_for_recipient(david_priv)

    def test_unified_package_tampering_breaks_signature(self):
        owner_sign_priv, owner_sign_pub = generate_ed25519_keypair()
        pkg = UnifiedMultiRecipientPackage(
            package_id="PKG-TAMPER-TEST",
            document_id="DOC-TAMPER",
            original_filename="audit.pdf",
            original_sha256="abc123",
            owner_id="OWNER",
            owner_public_sign_key=b64encode_str(ed25519_public_to_bytes(owner_sign_pub)),
            recipient_slots=[],
        )
        pkg.sign_package(owner_sign_priv)
        assert pkg.verify_package_signature() is True

        # Attacker tampers with filename
        pkg.original_filename = "tampered_filename.pdf"
        assert pkg.verify_package_signature() is False

    def test_online_unified_api_workflow(self):
        """Test creating ONE unified file via API, downloading it, and tracing leaks."""
        init_db()
        db = SessionLocal()
        import secrets
        sfx = secrets.token_hex(4)

        owner = register_user(
            RegisterRequest(email=f"cso_{sfx}@unified.test", full_name="CSO Unified", password="Password123!"),
            db,
        )

        import io
        from reportlab.lib.pagesizes import letter
        from reportlab.pdfgen import canvas

        buf = io.BytesIO()
        c = canvas.Canvas(buf, pagesize=letter)
        c.drawString(100, 750, "Classified Single-File Distribution Document")
        c.drawString(100, 700, "One container file distributed to all authorized parties.")
        c.showPage()
        c.save()
        doc_bytes = buf.getvalue()
        upload = UploadFile(filename="Strategic_Plan.pdf", file=io.BytesIO(doc_bytes))
        doc_resp = upload_document(upload, db, owner)
        doc_id = doc_resp["id"]

        # Register Alice and Bob
        a_priv, a_pub = generate_x25519_keypair()
        b_priv, b_pub = generate_x25519_keypair()

        rec_a = create_recipient(
            CreateRecipientRequest(name="Alice", email=f"alice_{sfx}@u.test", public_key=b64encode_str(x25519_public_to_bytes(a_pub))),
            db, owner,
        )
        rec_b = create_recipient(
            CreateRecipientRequest(name="Bob", email=f"bob_{sfx}@u.test", public_key=b64encode_str(x25519_public_to_bytes(b_pub))),
            db, owner,
        )

        # Call API to generate ONE single encrypted file for both Alice and Bob
        unified_res = create_unified_distribution(
            CreateDistributionRequest(document_id=doc_id, recipient_ids=[rec_a["id"], rec_b["id"]]),
            db, owner,
        )
        assert unified_res["authorized_recipients_count"] == 2
        filename = unified_res["filename"]
        assert filename.endswith("_ALL_RECIPIENTS.secure")

        # Download the single file
        file_resp = download_unified_package(filename)
        with open(file_resp.path, "rb") as f:
            downloaded_bytes = f.read()

        # Test the decrypt-and-download API endpoint
        from online.backend.app.api.distribution import decrypt_package_api, DecryptPackageRequest
        from shared.crypto.key_exchange import x25519_private_to_bytes
        dec_api_res = decrypt_package_api(
            DecryptPackageRequest(
                package_content=downloaded_bytes.decode("utf-8"),
                private_key=b64encode_str(x25519_private_to_bytes(a_priv)),
            ),
            db=db,
        )
        assert dec_api_res["status"] == "success"
        assert len(dec_api_res["file_bytes_b64"]) > 0

        # Alice decrypts the single file
        pkg_alice = UnifiedMultiRecipientPackage.deserialize(downloaded_bytes)
        alice_pdf, alice_wm = pkg_alice.decrypt_for_recipient(a_priv)
        assert alice_wm == unified_res["authorized_recipients"][0]["watermark_id"]

        # Bob decrypts the EXACT SAME single file
        pkg_bob = UnifiedMultiRecipientPackage.deserialize(downloaded_bytes)
        bob_pdf, bob_wm = pkg_bob.decrypt_for_recipient(b_priv)
        assert bob_wm == unified_res["authorized_recipients"][1]["watermark_id"]

        # Leak simulation: Alice's copy surfaces
        leak_file = UploadFile(filename="leaked_from_single_file.pdf", file=io.BytesIO(alice_pdf))
        inv = analyze_leaked_document(leak_file, db, owner)
        assert inv["watermark_detected"] is True
        assert inv["extracted_watermark_id"] == alice_wm
        assert inv["associated_recipient"]["recipient_id"] == rec_a["id"]

        db.close()

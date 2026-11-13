"""End-to-End automated test suite for Online Backend, Watermarking, and Leak Investigation.

Invokes route handler functions directly to ensure 100% test coverage without AnyIO BlockingPortal deadlocks.
"""

import io
import pytest
from starlette.datastructures import UploadFile
from fastapi.security import OAuth2PasswordRequestForm
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas

from online.backend.app.database.connection import SessionLocal, init_db
from online.backend.app.api.auth import register_user, login_for_access_token, RegisterRequest
from online.backend.app.api.documents import upload_document, list_documents, get_document_details
from online.backend.app.api.recipients import create_recipient, list_recipients, update_recipient_status, CreateRecipientRequest, UpdateStatusRequest
from online.backend.app.api.distribution import create_distribution, download_recipient_package, log_recipient_access, CreateDistributionRequest, AccessLogRequest
from online.backend.app.api.investigation import analyze_leaked_document, list_investigation_reports
from online.backend.app.api.audit import list_access_events
from shared.crypto.key_exchange import (
    generate_x25519_keypair,
    x25519_public_to_bytes,
)
from shared.models.package import OnlineRecipientPackage
from shared.utils.serialization import b64encode_str


def make_test_pdf_bytes(title: str = "Confidential Q4 Earnings Report") -> bytes:
    """Generate in-memory test PDF bytes."""
    buf = io.BytesIO()
    c = canvas.Canvas(buf, pagesize=letter)
    c.drawString(100, 750, title)
    c.drawString(100, 700, "Secret internal figures: Net revenue $48.2M.")
    c.drawString(100, 650, "Authorized eyes only. Do not duplicate.")
    c.showPage()
    c.save()
    return buf.getvalue()


@pytest.fixture(scope="module")
def db_session():
    """Transactional DB session for test lifecycle."""
    init_db()
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()


def test_online_complete_lifecycle(db_session):
    import secrets
    run_suffix = secrets.token_hex(4)

    # 1. Owner Registration
    owner_email = f"cso_{run_suffix}@defense-org.test"
    owner_pw = "MasterSecretPass123!"
    reg_req = RegisterRequest(
        email=owner_email,
        full_name="Chief Security Officer",
        password=owner_pw,
        role="OWNER",
    )
    owner_user = register_user(reg_req, db_session)
    assert owner_user.id.startswith("USR-")
    assert owner_user.email == owner_email

    # 2. Owner Login
    form_data = OAuth2PasswordRequestForm(
        grant_type="password",
        username=owner_email,
        password=owner_pw,
        scope="",
        client_id=None,
        client_secret=None,
    )
    token_resp = login_for_access_token(form_data, db_session)
    assert "access_token" in token_resp
    assert token_resp["user"].id == owner_user.id

    # 3. Upload Document
    pdf_bytes = make_test_pdf_bytes("Classified Operations Briefing")
    upload_file = UploadFile(
        filename="Classified_Briefing.pdf",
        file=io.BytesIO(pdf_bytes),
    )
    doc_resp = upload_document(file=upload_file, db=db_session, current_user=owner_user)
    doc_id = doc_resp["id"]
    assert doc_id.startswith("DOC-")
    assert doc_resp["original_filename"] == "Classified_Briefing.pdf"

    # Verify document in list
    docs = list_documents(db=db_session, current_user=owner_user)
    assert any(d["id"] == doc_id for d in docs)

    # 4. Register Recipients (Alice and Bob) with X25519 Keys
    alice_priv, alice_pub = generate_x25519_keypair()
    alice_pub_b64 = b64encode_str(x25519_public_to_bytes(alice_pub))
    rec_alice = create_recipient(
        req=CreateRecipientRequest(
            name="Alice Smith",
            email=f"alice_{run_suffix}@partner.test",
            public_key=alice_pub_b64,
        ),
        db=db_session,
        current_user=owner_user,
    )
    alice_id = rec_alice["id"]

    bob_priv, bob_pub = generate_x25519_keypair()
    bob_pub_b64 = b64encode_str(x25519_public_to_bytes(bob_pub))
    rec_bob = create_recipient(
        req=CreateRecipientRequest(
            name="Bob Jones",
            email=f"bob_{run_suffix}@contractor.test",
            public_key=bob_pub_b64,
        ),
        db=db_session,
        current_user=owner_user,
    )
    bob_id = rec_bob["id"]

    recs = list_recipients(db=db_session, current_user=owner_user)
    assert len(recs) >= 2

    # 5. Distribute Document to Alice and Bob
    dist_req = CreateDistributionRequest(
        document_id=doc_id,
        recipient_ids=[alice_id, bob_id],
    )
    dist_resp = create_distribution(req=dist_req, db=db_session, current_user=owner_user)
    assert dist_resp["distributed_count"] == 2
    distributions = dist_resp["distributions"]
    alice_dist = next(d for d in distributions if d["recipient_id"] == alice_id)
    bob_dist = next(d for d in distributions if d["recipient_id"] == bob_id)

    # Assert distinct watermarks
    assert alice_dist["watermark_id"] != bob_dist["watermark_id"]

    # 6. Download Alice's Encrypted Package (.enc)
    file_resp = download_recipient_package(distribution_id=alice_dist["distribution_id"], db=db_session)
    # Read the downloaded package from the file response path
    with open(file_resp.path, "rb") as f:
        alice_pkg_bytes = f.read()

    # 7. Alice Decrypts Her Package with Her Private Key
    alice_pkg = OnlineRecipientPackage.deserialize(alice_pkg_bytes)
    decrypted_alice_pdf = alice_pkg.decrypt(alice_priv)
    assert len(decrypted_alice_pdf) > 0
    assert b"%PDF" in decrypted_alice_pdf[:10]

    # Log successful recipient access
    log_recipient_access(
        req=AccessLogRequest(
            distribution_id=alice_dist["distribution_id"],
            event_type="DECRYPT_SUCCESS",
            result="SUCCESS",
            details="Decrypted in Recipient Secure Viewer v1.0",
        ),
        db=db_session,
    )

    # 8. Bob Attempts to Decrypt Alice's Package -> MUST FAIL
    with pytest.raises(Exception):
        alice_pkg.decrypt(bob_priv)

    # Log failed recipient access
    log_recipient_access(
        req=AccessLogRequest(
            distribution_id=alice_dist["distribution_id"],
            event_type="DECRYPT_DENIED",
            result="DENIED",
            details="Unauthorized private key",
        ),
        db=db_session,
    )

    # 9. Leak Investigation: Simulate Alice's decrypted PDF leaking
    leak_upload = UploadFile(
        filename="recovered_leak_from_darkweb.pdf",
        file=io.BytesIO(decrypted_alice_pdf),
    )
    inv_data = analyze_leaked_document(file=leak_upload, db=db_session, current_user=owner_user)

    assert inv_data["watermark_detected"] is True
    assert inv_data["extracted_watermark_id"] == alice_dist["watermark_id"]
    assert inv_data["confidence_score"] >= 0.9
    assert inv_data["associated_recipient"]["recipient_id"] == alice_id
    assert inv_data["associated_recipient"]["recipient_name"] == "Alice Smith"
    assert "IMPORTANT LIMITATION" in inv_data["attribution_statement"]

    # Verify investigation appears in history reports
    inv_reports = list_investigation_reports(db=db_session, current_user=owner_user)
    assert len(inv_reports) >= 1
    assert inv_reports[0]["extracted_watermark_id"] == alice_dist["watermark_id"]

    # 10. Investigation with Unwatermarked File -> Reports No Match
    clean_upload = UploadFile(
        filename="public_press_release.pdf",
        file=io.BytesIO(make_test_pdf_bytes("Public Press Release")),
    )
    inv_clean = analyze_leaked_document(file=clean_upload, db=db_session, current_user=owner_user)
    assert inv_clean["watermark_detected"] is False

    # 11. Revocation: Owner Revokes Alice
    revoked_rec = update_recipient_status(
        recipient_id=alice_id,
        req=UpdateStatusRequest(status="REVOKED"),
        db=db_session,
        current_user=owner_user,
    )
    assert revoked_rec["status"] == "REVOKED"

    # Subsequent download for revoked recipient is rejected
    with pytest.raises(Exception) as exc_info:
        download_recipient_package(distribution_id=alice_dist["distribution_id"], db=db_session)
    assert "revoked" in str(exc_info.value).lower()

    # 12. Audit Logs Check
    events = list_access_events(document_id=doc_id, db=db_session, current_user=owner_user)
    assert len(events) >= 3
    event_types = [e["event_type"] for e in events]
    assert "PACKAGE_DOWNLOAD" in event_types
    assert "DECRYPT_SUCCESS" in event_types
    assert "DOWNLOAD_ATTEMPT" in event_types

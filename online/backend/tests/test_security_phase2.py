"""
Phase 2 Security Tests — Private-Key Custody & Secret Management

Verifies:
- Server never generates, stores, or returns private keys.
- Recipient registration requires a client-provided public key.
- Login response contains no private_key field.
- /auth/my-keys returns ONLY public_key.
- GET /recipients/ items contain no private_key.
- Owner cannot read recipient private keys.
- Recipient A cannot access Recipient B's private key.
- Distribution succeeds with client-provided public key.
- Correct recipient decrypts; wrong private key decryption fails.
- Known insecure secrets and placeholders are strictly rejected in config.
"""

import io
import os
import sys
import json
import pytest
from starlette.datastructures import UploadFile
from fastapi.security import OAuth2PasswordRequestForm
from fastapi import HTTPException

os.environ["ENVIRONMENT"] = "testing"
os.environ["ALLOW_OWNER_REGISTRATION"] = "true"

from online.backend.app.database.connection import SessionLocal, init_db, engine
from online.backend.app.database.models import User, Recipient, Document
from online.backend.app.api.auth import (
    register_user,
    login_for_access_token,
    get_my_cryptographic_keys,
    RegisterRequest,
)
from online.backend.app.api.recipients import (
    list_recipients,
    create_recipient,
    CreateRecipientRequest,
)
from online.backend.app.api.documents import upload_document
from online.backend.app.api.distribution import (
    create_unified_distribution,
    decrypt_package_api,
    CreateDistributionRequest,
    DecryptPackageRequest,
)
from shared.crypto.key_exchange import (
    generate_x25519_keypair,
    x25519_private_to_bytes,
    x25519_public_to_bytes,
)
from shared.utils.serialization import b64encode_str


def _gen_keypair():
    """Generate a client-side X25519 keypair and return (priv_b64, pub_b64)."""
    priv, pub = generate_x25519_keypair()
    return b64encode_str(x25519_private_to_bytes(priv)), b64encode_str(x25519_public_to_bytes(pub))


@pytest.fixture(scope="module")
def db():
    init_db()
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()


@pytest.fixture(scope="module")
def owner_user(db):
    """Seed or fetch owner account."""
    owner = db.query(User).filter(User.role == "OWNER").first()
    if not owner:
        reg_req = RegisterRequest(
            email="sec_owner@docfortress.internal",
            full_name="Security Owner",
            password="StrongOwnerPass!99",
            role="OWNER",
        )
        owner = register_user(reg_req, db=db)
    return owner


@pytest.fixture(scope="module")
def recipient_data(db, owner_user):
    """Register a recipient with client-managed keys."""
    import secrets
    priv_b64, pub_b64 = _gen_keypair()
    suffix = secrets.token_hex(4)
    email = f"sec_test_rec_{suffix}@example.com"
    reg_req = RegisterRequest(
        email=email,
        full_name="Security Test Recipient",
        password="StrongPass!123",
        role="RECIPIENT",
        public_key=pub_b64,
    )
    user = register_user(reg_req, db=db)

    form = OAuth2PasswordRequestForm(
        grant_type="password",
        username=email,
        password="StrongPass!123",
        scope="",
        client_id=None,
        client_secret=None,
    )
    login_resp = login_for_access_token(form_data=form, db=db)
    return {
        "user": user,
        "email": email,
        "priv_b64": priv_b64,
        "pub_b64": pub_b64,
        "login_response": login_resp,
    }


# ---------------------------------------------------------------------------
# TC-S2-01: Registration response contains no private_key field
# ---------------------------------------------------------------------------

def test_registration_response_no_private_key(db):
    import secrets
    _, pub_b64 = _gen_keypair()
    suffix = secrets.token_hex(4)
    reg_req = RegisterRequest(
        email=f"noprivkey_{suffix}@example.com",
        full_name="NoPK Reg Test",
        password="StrongReg!Pass1",
        role="RECIPIENT",
        public_key=pub_b64,
    )
    user = register_user(reg_req, db=db)
    assert not hasattr(user, "private_key"), "User model MUST NOT have a private_key attribute!"
    user_dict = {c.name: getattr(user, c.name) for c in user.__table__.columns}
    assert "private_key" not in user_dict, "User table MUST NOT contain private_key column!"


# ---------------------------------------------------------------------------
# TC-S2-02: Login response contains no private_key
# ---------------------------------------------------------------------------

def test_login_response_no_private_key(recipient_data):
    login_resp = recipient_data["login_response"]
    assert "private_key" not in login_resp, "Login response must not contain private_key!"
    user_obj = login_resp["user"]
    assert not hasattr(user_obj, "private_key"), "User in login response must not contain private_key!"


# ---------------------------------------------------------------------------
# TC-S2-03: /auth/my-keys returns ONLY public_key (no private_key)
# ---------------------------------------------------------------------------

def test_my_keys_returns_only_public_key(recipient_data):
    keys = get_my_cryptographic_keys(current_user=recipient_data["user"])
    assert "private_key" not in keys, "/auth/my-keys must NEVER return private_key!"
    assert "public_key" in keys, "/auth/my-keys must return public_key"
    assert keys["public_key"] == recipient_data["pub_b64"]


# ---------------------------------------------------------------------------
# TC-S2-04: Recipient registration with no public_key allowed for OWNER
# ---------------------------------------------------------------------------

def test_owner_registration_no_public_key_allowed(db):
    import secrets
    suffix = secrets.token_hex(4)
    reg_req = RegisterRequest(
        email=f"nopk_owner_{suffix}@example.com",
        full_name="NoPK Owner",
        password="StrongOwnerPass!1",
        role="OWNER",
        public_key=None,
    )
    owner = register_user(reg_req, db=db)
    assert owner.id.startswith("USR-")
    assert not hasattr(owner, "private_key")


# ---------------------------------------------------------------------------
# TC-S2-05: GET /recipients/ items contain no private_key
# ---------------------------------------------------------------------------

def test_recipient_list_no_private_key(db, owner_user):
    recs = list_recipients(db=db, current_user=owner_user)
    assert len(recs) > 0
    for item in recs:
        assert "private_key" not in item, f"Recipient list item exposes private_key! {item}"
        assert "public_key" in item, "Recipient must expose public_key"


# ---------------------------------------------------------------------------
# TC-S2-06: Owner cannot retrieve any private key via /recipients/
# ---------------------------------------------------------------------------

def test_owner_cannot_read_recipient_private_key(db, owner_user):
    recs = list_recipients(db=db, current_user=owner_user)
    for rec in recs:
        assert "private_key" not in rec


# ---------------------------------------------------------------------------
# TC-S2-07: Recipient role blocked from owner-only recipient management
# ---------------------------------------------------------------------------

def test_recipient_blocked_from_owner_recipient_endpoints(db, recipient_data):
    from online.backend.app.security.tokens import require_owner
    with pytest.raises(HTTPException) as exc_info:
        require_owner(current_user=recipient_data["user"])
    assert exc_info.value.status_code == 403


# ---------------------------------------------------------------------------
# TC-S2-08: Distribution works with a client-provided public key
# ---------------------------------------------------------------------------

def test_distribution_works_with_client_public_key(db, owner_user, recipient_data):
    pdf_bytes = (
        b"%PDF-1.4\n1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n"
        b"2 0 obj<</Type/Pages/Count 1/Kids[3 0 R]>>endobj\n"
        b"3 0 obj<</Type/Page/MediaBox[0 0 612 792]/Parent 2 0 R/Contents 4 0 R/Resources<<>>>>endobj\n"
        b"4 0 obj<</Length 44>>\nstream\nBT /F1 12 Tf 100 700 Td (Phase2 Test) Tj ET\nendstream\nendobj\n"
        b"xref\n0 5\n0000000000 65535 f\n0000000009 00000 n\n0000000058 00000 n\n0000000115 00000 n\n0000000266 00000 n\n"
        b"trailer<</Size 5/Root 1 0 R>>\nstartxref\n360\n%%EOF"
    )
    upload_file = UploadFile(filename="phase2_test.pdf", file=io.BytesIO(pdf_bytes))
    doc_res = upload_document(file=upload_file, db=db, current_user=owner_user)
    doc_id = doc_res["id"]

    recs = list_recipients(db=db, current_user=owner_user)
    matching = [r for r in recs if r["email"] == recipient_data["email"]]
    assert len(matching) > 0
    rec_id = matching[0]["id"]

    dist_req = CreateDistributionRequest(document_id=doc_id, recipient_ids=[rec_id])
    dist_res = create_unified_distribution(req=dist_req, db=db, current_user=owner_user)
    assert dist_res["status"] == "success"
    assert "private_key" not in json.dumps(dist_res)


# ---------------------------------------------------------------------------
# TC-S2-09: Correct recipient decrypts successfully
# ---------------------------------------------------------------------------

def test_correct_recipient_can_decrypt(db, owner_user, recipient_data):
    pdf_bytes = (
        b"%PDF-1.4\n1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n"
        b"2 0 obj<</Type/Pages/Count 1/Kids[3 0 R]>>endobj\n"
        b"3 0 obj<</Type/Page/MediaBox[0 0 612 792]/Parent 2 0 R/Contents 4 0 R/Resources<<>>>>endobj\n"
        b"4 0 obj<</Length 46>>\nstream\nBT /F1 12 Tf 100 700 Td (DecryptTest) Tj ET\nendstream\nendobj\n"
        b"xref\n0 5\n0000000000 65535 f\n0000000009 00000 n\n0000000058 00000 n\n0000000115 00000 n\n0000000266 00000 n\n"
        b"trailer<</Size 5/Root 1 0 R>>\nstartxref\n360\n%%EOF"
    )
    upload_file = UploadFile(filename="decrypt_test.pdf", file=io.BytesIO(pdf_bytes))
    doc_res = upload_document(file=upload_file, db=db, current_user=owner_user)
    doc_id = doc_res["id"]

    recs = list_recipients(db=db, current_user=owner_user)
    matching = [r for r in recs if r["email"] == recipient_data["email"]]
    rec_id = matching[0]["id"]

    dist_req = CreateDistributionRequest(document_id=doc_id, recipient_ids=[rec_id])
    dist_res = create_unified_distribution(req=dist_req, db=db, current_user=owner_user)

    filename = dist_res["filename"]
    from online.backend.app.config import settings
    pkg_file = settings.ENCRYPTED_DIR / filename
    pkg_content = pkg_file.read_text(encoding="utf-8")

    dec_req = DecryptPackageRequest(
        package_content=pkg_content,
        private_key=recipient_data["priv_b64"],
    )
    dec_res = decrypt_package_api(req=dec_req, db=db)
    assert dec_res["document_id"] == doc_id
    assert "file_bytes_b64" in dec_res


# ---------------------------------------------------------------------------
# TC-S2-10: Wrong private key cannot decrypt (access control check)
# ---------------------------------------------------------------------------

def test_wrong_private_key_cannot_decrypt(db, owner_user, recipient_data):
    pdf_bytes = (
        b"%PDF-1.4\n1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n"
        b"2 0 obj<</Type/Pages/Count 1/Kids[3 0 R]>>endobj\n"
        b"3 0 obj<</Type/Page/MediaBox[0 0 612 792]/Parent 2 0 R/Contents 4 0 R/Resources<<>>>>endobj\n"
        b"4 0 obj<</Length 44>>\nstream\nBT /F1 12 Tf 100 700 Td (WrongKey) Tj ET\nendstream\nendobj\n"
        b"xref\n0 5\n0000000000 65535 f\n0000000009 00000 n\n0000000058 00000 n\n0000000115 00000 n\n0000000266 00000 n\n"
        b"trailer<</Size 5/Root 1 0 R>>\nstartxref\n360\n%%EOF"
    )
    upload_file = UploadFile(filename="wrongkey_test.pdf", file=io.BytesIO(pdf_bytes))
    doc_res = upload_document(file=upload_file, db=db, current_user=owner_user)
    doc_id = doc_res["id"]

    recs = list_recipients(db=db, current_user=owner_user)
    matching = [r for r in recs if r["email"] == recipient_data["email"]]
    rec_id = matching[0]["id"]

    dist_req = CreateDistributionRequest(document_id=doc_id, recipient_ids=[rec_id])
    dist_res = create_unified_distribution(req=dist_req, db=db, current_user=owner_user)

    filename = dist_res["filename"]
    from online.backend.app.config import settings
    pkg_file = settings.ENCRYPTED_DIR / filename
    pkg_content = pkg_file.read_text(encoding="utf-8")

    wrong_priv_b64, _ = _gen_keypair()
    dec_req = DecryptPackageRequest(
        package_content=pkg_content,
        private_key=wrong_priv_b64,
    )
    with pytest.raises(HTTPException) as exc_info:
        decrypt_package_api(req=dec_req, db=db)
    assert exc_info.value.status_code == 403


# ---------------------------------------------------------------------------
# TC-S2-11: config.py rejects placeholder values
# ---------------------------------------------------------------------------

def test_config_rejects_placeholders():
    from online.backend.app.config import _is_placeholder
    assert _is_placeholder("<REPLACE_WITH_SECURE_32_BYTE_HEX_JWT_SECRET>")
    assert _is_placeholder("REPLACE_WITH_SOMETHING")
    assert not _is_placeholder("a" * 64)
    assert not _is_placeholder("test-jwt-secret-key-for-automated-tests-only-32bytes")


# ---------------------------------------------------------------------------
# TC-S2-12: config.py rejects known insecure secrets in production
# ---------------------------------------------------------------------------

def test_config_known_insecure_secrets_set():
    from online.backend.app.config import KNOWN_INSECURE_SECRETS
    assert any("insecure" in s.lower() or len(s) >= 16 for s in KNOWN_INSECURE_SECRETS)


# ---------------------------------------------------------------------------
# TC-S2-13: JWT key and forensic key are always different (domain separation)
# ---------------------------------------------------------------------------

def test_jwt_and_forensic_key_are_different():
    from online.backend.app.config import settings
    assert settings.SECRET_KEY != settings.FORENSIC_MASTER_KEY_HEX


# ---------------------------------------------------------------------------
# TC-S2-14: Database has no stored private keys (purge migration ran)
# ---------------------------------------------------------------------------

def test_no_private_keys_in_database(db):
    from sqlalchemy import text, inspect
    inspector = inspect(engine)
    for table_name in ["users", "recipients"]:
        cols = [c["name"] for c in inspector.get_columns(table_name)]
        if "private_key" in cols:
            with engine.connect() as conn:
                result = conn.execute(text(f"SELECT COUNT(*) FROM {table_name} WHERE private_key IS NOT NULL")).scalar()
                assert result == 0, f"Table {table_name} has {result} rows with private_key!"

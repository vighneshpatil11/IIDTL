"""Command-line demonstration of Phase 1 Cryptographic Core capabilities."""

import sys
from pathlib import Path

# Ensure root directory is in sys.path
ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from shared.crypto.primitives import (
    generate_dek,
    sha256_hash,
    encrypt_bytes_aes_gcm,
    decrypt_bytes_aes_gcm,
)
from shared.crypto.key_exchange import (
    generate_x25519_keypair,
    wrap_dek_for_recipient,
    unwrap_dek_for_recipient,
)
from shared.crypto.signatures import (
    generate_ed25519_keypair,
    ed25519_public_to_bytes,
)
from shared.models.package import (
    OnlineRecipientPackage,
    OfflineMultiDevicePackage,
)
from shared.crypto.exceptions import (
    DecryptionError,
    KeyEnvelopeError,
    AuthorizationError,
)
from shared.utils.identifiers import (
    generate_document_id,
    generate_recipient_id,
    generate_watermark_id,
    generate_device_id,
)
from shared.utils.serialization import b64encode_str, b64decode_str


def run_demonstration():
    print("=" * 75)
    print("SECURE DOCUMENT DISTRIBUTION - CRYPTOGRAPHIC CORE DEMONSTRATION")
    print("=" * 75)

    doc_id = generate_document_id()
    sample_text = (
        b"CONFIDENTIAL BOARD MEETING MINUTES - Q4 FINANCIAL REPORT\n"
        b"Project Alpha budget allocation: $12,500,000.\n"
        b"Authorized for designated recipients only."
    )
    doc_hash = sha256_hash(sample_text)
    print(f"\n[+] Original Document ID: {doc_id}")
    print(f"[+] Document SHA-256:    {doc_hash}")
    print(f"[+] Plaintext Preview:   {sample_text.decode('utf-8')[:60]}...")

    # 1. Online Multi-Recipient Packaging Simulation
    print("\n" + "-" * 75)
    print("1. ONLINE RECIPIENT-SPECIFIC ENCRYPTION & KEY ENVELOPE")
    print("-" * 75)

    rec_a_id = generate_recipient_id()
    rec_b_id = generate_recipient_id()
    rec_a_priv, rec_a_pub = generate_x25519_keypair()
    rec_b_priv, rec_b_pub = generate_x25519_keypair()

    print(f"[+] Recipient A registered: {rec_a_id}")
    print(f"[+] Recipient B registered: {rec_b_id}")

    # Generate distinct ephemeral DEK for Recipient A
    dek_a = generate_dek()
    wm_a_id = generate_watermark_id()
    env_a = wrap_dek_for_recipient(dek_a, rec_a_pub, rec_a_id, doc_id)
    aad_a = f"{doc_id}:{wm_a_id}".encode("utf-8")
    ciphertext_a, nonce_a = encrypt_bytes_aes_gcm(sample_text, dek_a, associated_data=aad_a)

    pkg_a = OnlineRecipientPackage(
        document_id=doc_id,
        original_filename="Board_Minutes.pdf",
        watermark_id=wm_a_id,
        distribution_id="DIST-001A",
        recipient_id=rec_a_id,
        envelope=env_a,
        nonce=b64encode_str(nonce_a),
        ciphertext=b64encode_str(ciphertext_a),
    )

    print(f"[+] Package created for Recipient A with Watermark {wm_a_id}")
    print(f"    - Serialized package size: {len(pkg_a.serialize())} bytes")

    # Recipient A decrypts
    decrypted_a = pkg_a.decrypt(rec_a_priv)
    print(f"[+] Recipient A decryption with private key: SUCCESS")
    assert decrypted_a == sample_text

    # Recipient B attempts to decrypt Recipient A's package
    try:
        pkg_a.decrypt(rec_b_priv)
        print("[-] SECURITY BREACH: Recipient B decrypted Recipient A's package!")
    except KeyEnvelopeError:
        print("[+] Recipient B decryption attempt of Package A: CORRECTLY REJECTED (Unauthorized Key)")

    # 2. Offline Standalone Multi-Device Container Simulation
    print("\n" + "-" * 75)
    print("2. OFFLINE STANDALONE MULTI-DEVICE ENCRYPTED CONTAINER (.secure)")
    print("-" * 75)

    owner_priv, owner_pub = generate_ed25519_keypair()
    dev1_enc_priv, dev1_enc_pub = generate_x25519_keypair()
    dev2_enc_priv, dev2_enc_pub = generate_x25519_keypair()
    dev_unauth_priv, _ = generate_x25519_keypair()

    dev1_id = "DEV-FIELD-01"
    dev2_id = "DEV-HQ-02"
    dev_unauth_id = "DEV-ROGUE-99"

    print(f"[+] Owner Ed25519 key generated.")
    print(f"[+] Authorized devices: {dev1_id}, {dev2_id}")
    print(f"[+] Unauthorized device: {dev_unauth_id}")

    # Offline encryption: 1 file ciphertext + N device envelopes
    dek_offline = generate_dek()
    aad_offline = f"{doc_id}:{doc_hash}".encode("utf-8")
    cipher_off, nonce_off = encrypt_bytes_aes_gcm(sample_text, dek_offline, associated_data=aad_offline)

    env_dev1 = wrap_dek_for_recipient(dek_offline, dev1_enc_pub, dev1_id, doc_id)
    env_dev2 = wrap_dek_for_recipient(dek_offline, dev2_enc_pub, dev2_id, doc_id)

    pkg_offline = OfflineMultiDevicePackage(
        package_id="PKG-OFFLINE-001",
        document_id=doc_id,
        original_filename="Board_Minutes.pdf",
        original_sha256=doc_hash,
        owner_id="OWNER-ADMIN-01",
        owner_public_sign_key=b64encode_str(ed25519_public_to_bytes(owner_pub)),
        nonce=b64encode_str(nonce_off),
        key_envelopes=[env_dev1, env_dev2],
        ciphertext=b64encode_str(cipher_off),
    )
    pkg_offline.sign_package(owner_priv)
    print(f"[+] Package signed with Owner Ed25519 Key. Signature verification: {pkg_offline.verify_package_signature()}")

    # DEV-1 opens package
    dec_dev1 = pkg_offline.decrypt_for_device(dev1_id, dev1_enc_priv)
    print(f"[+] {dev1_id} decryption: SUCCESS (Integrity verified against SHA-256)")
    assert dec_dev1 == sample_text

    # Unauthorized device opens package
    try:
        pkg_offline.decrypt_for_device(dev_unauth_id, dev_unauth_priv)
        print(f"[-] SECURITY BREACH: {dev_unauth_id} decrypted package!")
    except AuthorizationError:
        print(f"[+] {dev_unauth_id} decryption: CORRECTLY REJECTED (Device not in authorized envelopes)")

    # Tamper test on offline package
    print("\n" + "-" * 75)
    print("3. TAMPER DETECTION TEST")
    print("-" * 75)
    tampered_bytes = bytearray(b64decode_str(pkg_offline.ciphertext))
    tampered_bytes[10] ^= 0xAA
    pkg_offline.ciphertext = b64encode_str(bytes(tampered_bytes))

    try:
        pkg_offline.decrypt_for_device(dev1_id, dev1_enc_priv)
        print("[-] SECURITY BREACH: Tampered ciphertext was accepted!")
    except DecryptionError:
        print("[+] Tampered ciphertext detected via AES-256-GCM authentication tag: REJECTED")

    print("\n" + "=" * 75)
    print("ALL PHASE 1 CRYPTOGRAPHIC CHECKS & DEMONSTRATION PASSED")
    print("=" * 75)


if __name__ == "__main__":
    run_demonstration()

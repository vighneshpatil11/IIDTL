"""Offline multi-device document packaging, encryption, and secure decryption."""

from pathlib import Path
from typing import List, Dict, Any, Tuple
from sqlalchemy.orm import Session
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519

from shared.crypto.primitives import (
    generate_dek,
    encrypt_bytes_aes_gcm,
    sha256_hash,
)
from shared.crypto.key_exchange import (
    wrap_dek_for_recipient,
    x25519_public_from_bytes,
)
from shared.crypto.signatures import ed25519_public_to_bytes
from shared.models.package import (
    OfflineMultiDevicePackage,
    OnlineRecipientPackage,
    UnifiedMultiRecipientPackage,
)
from shared.utils.identifiers import generate_document_id
from shared.utils.serialization import b64encode_str, b64decode_str
from shared.crypto.exceptions import AuthorizationError, IntegrityError
from offline.app.database.models import OfflineDevice, OfflineDocument, OfflineOwner
from offline.app.services.audit_service import HashLinkedAuditService


class OfflinePackagingService:
    @staticmethod
    def create_package(
        db: Session,
        document_bytes: bytes,
        filename: str,
        owner_id: str,
        owner_sign_priv: ed25519.Ed25519PrivateKey,
        authorized_device_ids: List[str],
        output_dir: Path | str,
    ) -> Tuple[OfflineMultiDevicePackage, Path]:
        """Encrypt document for selected offline devices and wrap in signed .secure container."""
        doc_id = generate_document_id()
        doc_hash = sha256_hash(document_bytes)
        pkg_id = f"PKG-{doc_id.replace('DOC-', '')}"

        # Record document metadata locally
        offline_doc = OfflineDocument(
            document_id=doc_id,
            filename=filename,
            original_sha256=doc_hash,
            file_size=len(document_bytes),
        )
        db.add(offline_doc)
        db.commit()

        # 1. Encrypt document once with ephemeral DEK
        dek = generate_dek()
        aad = f"{doc_id}:{doc_hash}".encode("utf-8")
        ciphertext, nonce = encrypt_bytes_aes_gcm(document_bytes, dek, associated_data=aad)

        # 2. Wrap DEK for each authorized device
        key_envelopes = []
        for dev_id in authorized_device_ids:
            device = db.query(OfflineDevice).filter(OfflineDevice.device_id == dev_id).first()
            if not device or device.registration_status != "APPROVED":
                continue

            enc_pub = x25519_public_from_bytes(b64decode_str(device.public_enc_key))
            env = wrap_dek_for_recipient(
                dek=dek,
                recipient_public_key=enc_pub,
                recipient_id=device.device_id,
                document_id=doc_id,
            )
            key_envelopes.append(env)

        if not key_envelopes:
            raise ValueError("No valid approved devices selected for packaging!")

        owner_sign_pub = owner_sign_priv.public_key()
        owner_pub_bytes = ed25519_public_to_bytes(owner_sign_pub)

        # Register owner identity as trusted in the offline store if not present
        existing_owner = db.query(OfflineOwner).filter(OfflineOwner.owner_id == owner_id).first()
        if not existing_owner:
            owner_rec = OfflineOwner(
                owner_id=owner_id,
                public_sign_key=b64encode_str(owner_pub_bytes),
                public_enc_key=b64encode_str(b"\x00" * 32),
            )
            db.add(owner_rec)
            db.commit()

        # 3. Create and sign package container
        pkg = OfflineMultiDevicePackage(
            package_id=pkg_id,
            document_id=doc_id,
            original_filename=filename,
            original_sha256=doc_hash,
            owner_id=owner_id,
            owner_public_sign_key=b64encode_str(owner_pub_bytes),
            nonce=b64encode_str(nonce),
            key_envelopes=key_envelopes,
            ciphertext=b64encode_str(ciphertext),
        )
        pkg.sign_package(owner_sign_priv)

        # 4. Save to disk
        out_path = Path(output_dir) / f"{Path(filename).stem}_{doc_id}.secure"
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with open(out_path, "wb") as f:
            f.write(pkg.serialize())

        # 5. Log audit event
        HashLinkedAuditService.record_event(
            db=db,
            device_id=owner_id,
            event_type="PACKAGE_CREATED",
            result="SUCCESS",
            document_id=doc_id,
            device_sign_priv=owner_sign_priv,
        )

        return pkg, out_path

    @staticmethod
    def decrypt_package_on_device(
        db: Session,
        package_bytes: bytes,
        device_id: str,
        device_enc_priv: x25519.X25519PrivateKey,
        device_sign_priv: Optional[ed25519.Ed25519PrivateKey] = None,
        trusted_owner_public_key: Optional[ed25519.Ed25519PublicKey] = None,
    ) -> bytes:
        """Decrypt offline (.secure), online (.enc), or unified (.secure) package for the calling device/recipient."""
        import json
        from offline.app.database.models import OfflineOwner
        from shared.crypto.signatures import ed25519_public_from_bytes

        payload = json.loads(package_bytes.decode("utf-8"))
        magic = payload.get("magic")
        doc_id = payload.get("document_id", "UNKNOWN_DOC")

        # Resolve trusted owner public key from local device database if not passed explicitly
        if trusted_owner_public_key is None:
            owner_rec = db.query(OfflineOwner).first()
            if owner_rec and owner_rec.public_sign_key:
                try:
                    pub_bytes = b64decode_str(owner_rec.public_sign_key)
                    trusted_owner_public_key = ed25519_public_from_bytes(pub_bytes)
                except Exception:
                    pass

        # Check local device revocation registry
        device = db.query(OfflineDevice).filter(OfflineDevice.device_id == device_id).first()
        if device and device.registration_status == "REVOKED":
            HashLinkedAuditService.record_event(
                db=db,
                device_id=device_id,
                event_type="DECRYPT_ATTEMPT",
                result="DENIED_REVOKED",
                document_id=doc_id,
                device_sign_priv=device_sign_priv,
            )
            raise AuthorizationError(f"Device '{device_id}' has been REVOKED by the owner.")

        try:
            if magic == "SECURE_DOC_OFFLINE_V1":
                pkg = OfflineMultiDevicePackage.deserialize(package_bytes)
                plaintext = pkg.decrypt_for_device(
                    device_id=device_id,
                    device_private_enc_key=device_enc_priv,
                    trusted_owner_public_key=trusted_owner_public_key,
                    verify_owner_sig=True,
                )
            elif magic == "SECURE_DOC_RECIPIENT_V1":
                pkg_online = OnlineRecipientPackage.deserialize(package_bytes)
                plaintext = pkg_online.decrypt(recipient_private_key=device_enc_priv)
            elif magic == "UNIFIED_SECURE_DOC_V1":
                pkg_unified = UnifiedMultiRecipientPackage.deserialize(package_bytes)
                plaintext, _ = pkg_unified.decrypt_for_recipient(
                    recipient_private_key=device_enc_priv,
                    recipient_id=device_id,
                    trusted_owner_public_key=trusted_owner_public_key,
                    verify_owner_sig=True,
                )
            else:
                raise ValueError(f"Unrecognized package magic: {magic}")

            # Record success in hash-linked audit chain
            HashLinkedAuditService.record_event(
                db=db,
                device_id=device_id,
                event_type="DECRYPT_SUCCESS",
                result="SUCCESS",
                document_id=doc_id,
                device_sign_priv=device_sign_priv,
            )
            return plaintext

        except Exception as e:
            # Record failure in hash-linked audit chain
            HashLinkedAuditService.record_event(
                db=db,
                device_id=device_id,
                event_type="DECRYPT_FAILED",
                result="DENIED_ERROR",
                document_id=doc_id,
                device_sign_priv=device_sign_priv,
            )
            raise

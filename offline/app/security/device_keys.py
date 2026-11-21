"""Cryptographic device identity, registration certificates, and keystore management."""

import json
import logging
import os
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Tuple, Dict, Any, Optional

from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from shared.crypto.signatures import (
    generate_ed25519_keypair,
    sign_data_ed25519,
    verify_signature_ed25519,
    ed25519_public_to_bytes,
    ed25519_public_from_bytes,
    ed25519_private_to_bytes,
    ed25519_private_from_bytes,
)
from shared.crypto.key_exchange import (
    generate_x25519_keypair,
    x25519_public_to_bytes,
    x25519_public_from_bytes,
    x25519_private_to_bytes,
    x25519_private_from_bytes,
)
from shared.crypto.primitives import (
    encrypt_bytes_aes_gcm,
    decrypt_bytes_aes_gcm,
    derive_hkdf_key,
)
from shared.utils.identifiers import generate_device_id
from shared.utils.serialization import canonical_json_bytes, b64encode_str, b64decode_str
from shared.crypto.exceptions import SignatureVerificationError, AuthorizationError, DecryptionError

log = logging.getLogger(__name__)


@dataclass
class DeviceRegistrationRequest:
    """Offline device registration request exported to owner."""
    magic: str = "DEVICE_REG_REQUEST_V1"
    device_id: str = ""
    device_name: str = ""
    public_sign_key: str = ""  # Base64 Ed25519 pubkey
    public_enc_key: str = ""   # Base64 X25519 pubkey
    timestamp: str = ""
    device_signature: str = ""  # Base64 signature by device private sign key

    def get_signable_bytes(self) -> bytes:
        data = {
            "magic": self.magic,
            "device_id": self.device_id,
            "device_name": self.device_name,
            "public_sign_key": self.public_sign_key,
            "public_enc_key": self.public_enc_key,
            "timestamp": self.timestamp,
        }
        return canonical_json_bytes(data)

    def verify(self) -> bool:
        """Verify device registration request signature."""
        try:
            pub_bytes = b64decode_str(self.public_sign_key)
            pub = ed25519_public_from_bytes(pub_bytes)
            sig_bytes = b64decode_str(self.device_signature)
            return verify_signature_ed25519(self.get_signable_bytes(), sig_bytes, pub)
        except Exception:
            return False


@dataclass
class DeviceCertificate:
    """Owner-signed registration certificate granting device authorization."""
    magic: str = "DEVICE_CERTIFICATE_V1"
    device_id: str = ""
    owner_id: str = ""
    public_sign_key: str = ""
    public_enc_key: str = ""
    status: str = "APPROVED"  # APPROVED or REVOKED
    issued_at: str = ""
    owner_signature: str = ""  # Base64 Ed25519 signature from owner

    def get_signable_bytes(self) -> bytes:
        data = {
            "magic": self.magic,
            "device_id": self.device_id,
            "owner_id": self.owner_id,
            "public_sign_key": self.public_sign_key,
            "public_enc_key": self.public_enc_key,
            "status": self.status,
            "issued_at": self.issued_at,
        }
        return canonical_json_bytes(data)

    def verify_owner(self, owner_public_sign_key: ed25519.Ed25519PublicKey) -> bool:
        """Verify owner signature on this certificate."""
        try:
            sig_bytes = b64decode_str(self.owner_signature)
            return verify_signature_ed25519(self.get_signable_bytes(), sig_bytes, owner_public_sign_key)
        except Exception:
            return False


class DeviceKeyManager:
    """Manages local cryptographic identity and hardened keystore storage with Scrypt KDF."""

    @staticmethod
    def create_device_identity(device_name: str) -> Tuple[str, ed25519.Ed25519PrivateKey, x25519.X25519PrivateKey]:
        """Generate new device signing and encryption key pairs and derived device ID."""
        sign_priv, sign_pub = generate_ed25519_keypair()
        enc_priv, enc_pub = generate_x25519_keypair()

        sign_pub_bytes = ed25519_public_to_bytes(sign_pub)
        enc_pub_bytes = x25519_public_to_bytes(enc_pub)

        device_id = generate_device_id(sign_pub_bytes, enc_pub_bytes)
        return device_id, sign_priv, enc_priv

    @staticmethod
    def export_registration_request(
        device_id: str,
        device_name: str,
        sign_priv: ed25519.Ed25519PrivateKey,
        enc_pub: x25519.X25519PublicKey,
    ) -> DeviceRegistrationRequest:
        """Create and sign a registration request."""
        sign_pub = sign_priv.public_key()
        req = DeviceRegistrationRequest(
            device_id=device_id,
            device_name=device_name,
            public_sign_key=b64encode_str(ed25519_public_to_bytes(sign_pub)),
            public_enc_key=b64encode_str(x25519_public_to_bytes(enc_pub)),
            timestamp=datetime.now(timezone.utc).isoformat(),
        )
        sig = sign_data_ed25519(req.get_signable_bytes(), sign_priv)
        req.device_signature = b64encode_str(sig)
        return req

    @staticmethod
    def approve_device_registration(
        request: DeviceRegistrationRequest,
        owner_id: str,
        owner_sign_priv: ed25519.Ed25519PrivateKey,
    ) -> DeviceCertificate:
        """Owner verifies registration request and signs authorization certificate."""
        if not request.verify():
            raise SignatureVerificationError("Device registration request signature is invalid!")

        cert = DeviceCertificate(
            device_id=request.device_id,
            owner_id=owner_id,
            public_sign_key=request.public_sign_key,
            public_enc_key=request.public_enc_key,
            status="APPROVED",
            issued_at=datetime.now(timezone.utc).isoformat(),
        )
        sig = sign_data_ed25519(cert.get_signable_bytes(), owner_sign_priv)
        cert.owner_signature = b64encode_str(sig)
        return cert

    @staticmethod
    def derive_scrypt_key(passphrase: str, salt: bytes, n: int = 16384, r: int = 8, p: int = 1, length: int = 32) -> bytes:
        """Derive cryptographic key using hardened Scrypt password derivation."""
        kdf = Scrypt(
            salt=salt,
            length=length,
            n=n,
            r=r,
            p=p,
        )
        return kdf.derive(passphrase.encode("utf-8"))

    @classmethod
    def save_keystore(
        cls,
        filepath: Path | str,
        passphrase: str,
        sign_priv: ed25519.Ed25519PrivateKey,
        enc_priv: x25519.X25519PrivateKey,
        device_id: str,
    ) -> None:
        """Encrypt and persist private keys with unique per-keystore random salt and Scrypt KDF."""
        salt = os.urandom(16)
        n_param = 16384  # 2**14
        r_param = 8
        p_param = 1
        key_length = 32

        kek = cls.derive_scrypt_key(
            passphrase=passphrase,
            salt=salt,
            n=n_param,
            r=r_param,
            p=p_param,
            length=key_length,
        )

        payload = {
            "device_id": device_id,
            "sign_priv": b64encode_str(ed25519_private_to_bytes(sign_priv)),
            "enc_priv": b64encode_str(x25519_private_to_bytes(enc_priv)),
        }
        canonical = canonical_json_bytes(payload)
        ciphertext, nonce = encrypt_bytes_aes_gcm(canonical, kek, associated_data=device_id.encode("utf-8"))

        keystore_obj = {
            "magic": "OFFLINE_KEYSTORE_V2",
            "kdf": {
                "algorithm": "scrypt",
                "salt": b64encode_str(salt),
                "n": n_param,
                "r": r_param,
                "p": p_param,
                "length": key_length,
            },
            "device_id": device_id,
            "nonce": b64encode_str(nonce),
            "ciphertext": b64encode_str(ciphertext),
        }
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(keystore_obj, f, indent=2)

    @classmethod
    def load_keystore(
        cls,
        filepath: Path | str,
        passphrase: str,
    ) -> Tuple[str, ed25519.Ed25519PrivateKey, x25519.X25519PrivateKey]:
        """Decrypt private keys from local keystore supporting Scrypt V2 and legacy V1 migration."""
        with open(filepath, "r", encoding="utf-8") as f:
            keystore_obj = json.load(f)

        magic = keystore_obj.get("magic")
        device_id = keystore_obj["device_id"]
        nonce = b64decode_str(keystore_obj["nonce"])
        ciphertext = b64decode_str(keystore_obj["ciphertext"])

        if magic == "OFFLINE_KEYSTORE_V2":
            kdf_meta = keystore_obj.get("kdf", {})
            salt = b64decode_str(kdf_meta["salt"])
            n = kdf_meta.get("n", 16384)
            r = kdf_meta.get("r", 8)
            p = kdf_meta.get("p", 1)
            length = kdf_meta.get("length", 32)

            kek = cls.derive_scrypt_key(
                passphrase=passphrase,
                salt=salt,
                n=n,
                r=r,
                p=p,
                length=length,
            )
        elif magic == "OFFLINE_KEYSTORE_V1":
            log.warning("SECURITY WARNING: Decrypting legacy V1 keystore with static salt and HKDF. Migrate to V2 immediately.")
            salt = b"offline-device-keystore-salt"
            kek = derive_hkdf_key(
                ikm=passphrase.encode("utf-8"),
                salt=salt,
                info=b"device-keystore-aes-gcm",
                length=32,
            )
        else:
            raise ValueError(f"Unrecognized keystore magic format: {magic}")

        try:
            decrypted_bytes = decrypt_bytes_aes_gcm(ciphertext, kek, nonce, associated_data=device_id.encode("utf-8"))
        except Exception as e:
            raise DecryptionError(f"Keystore decryption failed (incorrect passphrase or corrupted file): {e}")

        payload = json.loads(decrypted_bytes.decode("utf-8"))
        sign_priv = ed25519_private_from_bytes(b64decode_str(payload["sign_priv"]))
        enc_priv = x25519_private_from_bytes(b64decode_str(payload["enc_priv"]))
        return device_id, sign_priv, enc_priv

    @classmethod
    def migrate_keystore_to_v2(cls, filepath: Path | str, passphrase: str) -> bool:
        """Migrate a legacy V1 keystore to hardened V2 Scrypt format in-place."""
        device_id, sign_priv, enc_priv = cls.load_keystore(filepath, passphrase)
        cls.save_keystore(filepath, passphrase, sign_priv, enc_priv, device_id)
        return True

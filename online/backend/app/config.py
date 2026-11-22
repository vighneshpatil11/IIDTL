"""Application configuration and settings."""

import os
import sys
import logging
from pathlib import Path
from pydantic_settings import BaseSettings, SettingsConfigDict

log = logging.getLogger(__name__)

# Known insecure default/fallback values to explicitly reject in production
KNOWN_INSECURE_SECRETS = {
    "insecure-dev-secret-key-change-in-production-1234567890",
    "4a6f7267656e73656e466f72656e7369635365637265744b6579323536426974",
    "c5d407a4a4135a37e9ea8b4fe3f3ddd6cc8bf8a676dd1ce99adf8ff61144a1a2",
    "66bc7461f571429368915ed92809674afc219312854fa185846f42e606b07163",
    "secret",
    "password",
    "123456",
}


def _is_placeholder(val: str) -> bool:
    """Check if value is a documentation placeholder."""
    val_clean = val.strip()
    return (
        val_clean.startswith("<") and val_clean.endswith(">")
    ) or "REPLACE_WITH" in val_clean.upper()


class Settings(BaseSettings):
    model_config = SettingsConfigDict(case_sensitive=True)

    APP_NAME: str = "Secure Document Distribution System"
    API_V1_PREFIX: str = "/api/v1"
    ENVIRONMENT: str = os.getenv("ENVIRONMENT", "development").lower()
    
    SECRET_KEY: str = os.getenv("APP_SECRET_KEY", "")
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24  # 24 hours
    
    # Forensic Master Key for Watermark Vault (32 bytes hex)
    FORENSIC_MASTER_KEY_HEX: str = os.getenv("FORENSIC_MASTER_KEY_HEX", "")

    # Persistent Owner Administrative Signing Key (32 bytes hex Ed25519 seed/private key)
    OWNER_SIGNING_KEY_HEX: str = os.getenv("OWNER_SIGNING_KEY_HEX", "")

    # Paths
    BASE_DIR: Path = Path(__file__).resolve().parent.parent.parent.parent

    @property
    def STORAGE_DIR(self) -> Path:
        if os.getenv("VERCEL") == "1" or os.getenv("AWS_LAMBDA_FUNCTION_NAME"):
            p = Path("/tmp") / "data" / "online"
        else:
            p = self.BASE_DIR / "data" / "online"
        try:
            p.mkdir(parents=True, exist_ok=True)
        except Exception:
            pass
        return p

    @property
    def UPLOAD_DIR(self) -> Path:
        p = self.STORAGE_DIR / "uploads"
        try:
            p.mkdir(parents=True, exist_ok=True)
        except Exception:
            pass
        return p

    @property
    def ENCRYPTED_DIR(self) -> Path:
        p = self.STORAGE_DIR / "encrypted"
        try:
            p.mkdir(parents=True, exist_ok=True)
        except Exception:
            pass
        return p

    @property
    def DATABASE_URL(self) -> str:
        env_db = os.getenv("DATABASE_URL")
        if env_db and env_db.strip():
            clean_url = env_db.strip()
            if clean_url.startswith("postgres://"):
                clean_url = clean_url.replace("postgres://", "postgresql://", 1)
            return clean_url
        return f"sqlite:///{self.STORAGE_DIR / 'online_system.db'}"

    def get_owner_signing_keypair(self):
        """Retrieve or initialize the persistent owner Ed25519 signing keypair."""
        from shared.crypto.signatures import (
            generate_ed25519_keypair,
            ed25519_private_to_bytes,
            ed25519_private_from_bytes,
        )
        if self.OWNER_SIGNING_KEY_HEX and not _is_placeholder(self.OWNER_SIGNING_KEY_HEX):
            try:
                raw_bytes = bytes.fromhex(self.OWNER_SIGNING_KEY_HEX)
                priv = ed25519_private_from_bytes(raw_bytes)
                return priv, priv.public_key()
            except Exception as e:
                log.error(f"Failed to load OWNER_SIGNING_KEY_HEX: {e}")

        # Check persistent storage on disk
        key_file = self.STORAGE_DIR / "owner_signing_key.key"
        if key_file.is_file():
            try:
                raw_bytes = key_file.read_bytes()
                if len(raw_bytes) == 32:
                    priv = ed25519_private_from_bytes(raw_bytes)
                    return priv, priv.public_key()
            except Exception as e:
                log.error(f"Failed to load stored owner key file: {e}")

        # Generate persistent keypair and save to STORAGE_DIR
        priv, pub = generate_ed25519_keypair()
        try:
            self.STORAGE_DIR.mkdir(parents=True, exist_ok=True)
            key_file.write_bytes(ed25519_private_to_bytes(priv))
        except Exception:
            pass
        return priv, pub

    def validate_security_config(self) -> None:
        """Strictly validate required secrets during application initialization."""
        is_testing = "pytest" in sys.modules or self.ENVIRONMENT == "testing"
        is_production = self.ENVIRONMENT == "production"

        # Check for placeholder values
        if _is_placeholder(self.SECRET_KEY) or _is_placeholder(self.FORENSIC_MASTER_KEY_HEX):
            raise RuntimeError(
                "FATAL: Application secret configuration contains placeholder values. "
                "You must provide genuine cryptographically secure keys in your environment."
            )

        # Check for known insecure defaults
        if self.SECRET_KEY in KNOWN_INSECURE_SECRETS:
            if is_production:
                raise RuntimeError(
                    "FATAL: Known insecure default SECRET_KEY detected in production environment! Startup aborted."
                )
            else:
                log.warning("SECURITY WARNING: Using default development SECRET_KEY.")

        if self.FORENSIC_MASTER_KEY_HEX in KNOWN_INSECURE_SECRETS:
            if is_production:
                raise RuntimeError(
                    "FATAL: Known insecure default FORENSIC_MASTER_KEY_HEX detected in production environment! Startup aborted."
                )
            else:
                log.warning("SECURITY WARNING: Using default development FORENSIC_MASTER_KEY_HEX.")

        # If keys are empty, generate cryptographically secure random secrets (Master Prompt Rule 9)
        import secrets as _secrets
        if not self.SECRET_KEY:
            if is_testing:
                # Safe deterministic isolated test key
                self.SECRET_KEY = "test-jwt-secret-key-for-automated-tests-only-32bytes"
            else:
                log.warning("SECURITY NOTICE: APP_SECRET_KEY unset. Generated cryptographically secure secret.")
                self.SECRET_KEY = _secrets.token_hex(32)

        if not self.FORENSIC_MASTER_KEY_HEX:
            if is_testing:
                self.FORENSIC_MASTER_KEY_HEX = "4a6f7267656e73656e466f72656e7369635365637265744b6579323536426974"
            else:
                log.warning("SECURITY NOTICE: FORENSIC_MASTER_KEY_HEX unset. Generated cryptographically secure key.")
                while True:
                    candidate = _secrets.token_hex(32)
                    if candidate != self.SECRET_KEY:
                        self.FORENSIC_MASTER_KEY_HEX = candidate
                        break

        # Validate hex length for forensic key
        try:
            raw_forensic = bytes.fromhex(self.FORENSIC_MASTER_KEY_HEX)
            if len(raw_forensic) != 32:
                raise ValueError("Length must be exactly 32 bytes (64 hex characters)")
        except Exception as e:
            raise RuntimeError(f"FATAL: FORENSIC_MASTER_KEY_HEX must be a valid 64-character hex string: {e}")

        # Ensure cryptographic secret separation (domain separation)
        if self.SECRET_KEY == self.FORENSIC_MASTER_KEY_HEX:
            raise RuntimeError("FATAL: APP_SECRET_KEY and FORENSIC_MASTER_KEY_HEX must not share the same raw secret!")
        if self.OWNER_SIGNING_KEY_HEX:
            if _is_placeholder(self.OWNER_SIGNING_KEY_HEX):
                raise RuntimeError("FATAL: OWNER_SIGNING_KEY_HEX contains documentation placeholder values!")
            if self.OWNER_SIGNING_KEY_HEX in KNOWN_INSECURE_SECRETS:
                raise RuntimeError("FATAL: OWNER_SIGNING_KEY_HEX contains a known insecure secret!")
            if self.OWNER_SIGNING_KEY_HEX == self.SECRET_KEY or self.OWNER_SIGNING_KEY_HEX == self.FORENSIC_MASTER_KEY_HEX:
                raise RuntimeError("FATAL: OWNER_SIGNING_KEY_HEX must not share keys with other purposes!")


settings = Settings()
settings.validate_security_config()

# Ensure directories exist
try:
    settings.STORAGE_DIR.mkdir(parents=True, exist_ok=True)
    settings.UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    settings.ENCRYPTED_DIR.mkdir(parents=True, exist_ok=True)
except Exception:
    pass

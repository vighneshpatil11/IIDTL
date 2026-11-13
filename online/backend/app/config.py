"""Application configuration and settings."""

import os
from pathlib import Path
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(case_sensitive=True)

    APP_NAME: str = "Secure Document Distribution System"
    API_V1_PREFIX: str = "/api/v1"
    SECRET_KEY: str = os.getenv("APP_SECRET_KEY", "insecure-dev-secret-key-change-in-production-1234567890")
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24  # 24 hours
    
    # Paths
    BASE_DIR: Path = Path(__file__).resolve().parent.parent.parent.parent
    STORAGE_DIR: Path = BASE_DIR / "data" / "online"
    UPLOAD_DIR: Path = STORAGE_DIR / "uploads"
    ENCRYPTED_DIR: Path = STORAGE_DIR / "encrypted"
    DATABASE_URL: str = f"sqlite:///{STORAGE_DIR / 'online_system.db'}"

    # Forensic Master Key for Watermark Vault (32 bytes hex)
    FORENSIC_MASTER_KEY_HEX: str = os.getenv(
        "FORENSIC_MASTER_KEY_HEX",
        "4a6f7267656e73656e466f72656e7369635365637265744b6579323536426974"  # 32-byte default for test/dev
    )


settings = Settings()

# Ensure directories exist
settings.STORAGE_DIR.mkdir(parents=True, exist_ok=True)
settings.UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
settings.ENCRYPTED_DIR.mkdir(parents=True, exist_ok=True)

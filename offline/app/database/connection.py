"""Offline SQLite database connection manager."""

from pathlib import Path
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session
from offline.app.database.models import OfflineBase

BASE_OFFLINE_DIR = Path(__file__).resolve().parent.parent.parent.parent / "data" / "offline"
BASE_OFFLINE_DIR.mkdir(parents=True, exist_ok=True)

OFFLINE_DB_PATH = BASE_OFFLINE_DIR / "offline_vault.db"
OFFLINE_DATABASE_URL = f"sqlite:///{OFFLINE_DB_PATH}"

offline_engine = create_engine(
    OFFLINE_DATABASE_URL,
    connect_args={"check_same_thread": False},
)

OfflineSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=offline_engine)


def init_offline_db() -> None:
    """Initialize local SQLite database tables."""
    OfflineBase.metadata.create_all(bind=offline_engine)


def get_offline_db() -> Session:
    """Get standalone SQLite database session."""
    return OfflineSessionLocal()

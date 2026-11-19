"""Database connection management and session factory."""

import logging
import os
from typing import Generator

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session

from online.backend.app.config import settings
from online.backend.app.database.models import Base

log = logging.getLogger(__name__)


def _make_engine():
    db_url = settings.DATABASE_URL
    kwargs = {}
    if db_url.startswith("sqlite"):
        kwargs["connect_args"] = {"check_same_thread": False}
    else:
        # PostgreSQL (Neon / Supabase etc.)
        kwargs["pool_pre_ping"] = True
        kwargs["pool_size"] = 1
        kwargs["max_overflow"] = 0
    try:
        return create_engine(db_url, **kwargs)
    except Exception as e:
        fallback = "sqlite:////tmp/data/online/online_system.db"
        log.error(f"DB engine creation failed ({e}), falling back to SQLite")
        return create_engine(fallback, connect_args={"check_same_thread": False})


engine = _make_engine()
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def init_db() -> None:
    """Create tables if they do not exist and seed the predefined master owner."""
    try:
        Base.metadata.create_all(bind=engine)
    except Exception as e:
        log.error(f"init_db create_all failed: {e}")
        return

    owner_email = os.getenv("OWNER_EMAIL", "admin@docfortress.internal").strip().lower()
    owner_pass = os.getenv("OWNER_PASSWORD", "AdminMaster2026!").strip()
    owner_name = os.getenv("OWNER_NAME", "Master Document Owner").strip()

    from online.backend.app.database.models import User
    from online.backend.app.security.passwords import hash_password

    db = SessionLocal()
    try:
        existing = db.query(User).filter(User.email == owner_email).first()
        if not existing:
            owner = User(
                id="USR-MASTER-OWNER",
                email=owner_email,
                full_name=owner_name,
                password_hash=hash_password(owner_pass),
                role="OWNER",
            )
            db.add(owner)
            db.commit()
    except Exception:
        db.rollback()
    finally:
        db.close()


def get_db() -> Generator[Session, None, None]:
    """FastAPI dependency to provide a transactional database session."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

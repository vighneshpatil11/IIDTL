"""Database connection management and session factory."""

import logging
import os
import sys
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
    """Create tables if they do not exist, run migrations, and seed the predefined master owner."""
    try:
        Base.metadata.create_all(bind=engine)
    except Exception as e:
        log.error(f"init_db create_all failed: {e}")
        return

    # Safe lightweight schema migrations for existing databases
    with engine.begin() as conn:
        from sqlalchemy import text
        # Purge any legacy private keys from database records to ensure strict key custody
        for purge_stmt in [
            "UPDATE users SET private_key = NULL WHERE private_key IS NOT NULL",
            "UPDATE recipients SET private_key = NULL WHERE private_key IS NOT NULL",
        ]:
            try:
                conn.execute(text(purge_stmt))
            except Exception:
                pass  # Column does not exist in new database schema

        for stmt in [
            "ALTER TABLE documents ADD COLUMN file_content_b64 TEXT",
            "ALTER TABLE distributions ADD COLUMN package_content_b64 TEXT",
        ]:
            try:
                conn.execute(text(stmt))
            except Exception:
                pass  # Column already exists or table not ready

    owner_email = os.getenv("OWNER_EMAIL", "admin@docfortress.internal").strip().lower()
    owner_name = os.getenv("OWNER_NAME", "Master Document Owner").strip()

    # OWNER_PASSWORD must be explicitly set; never use a hardcoded default.
    owner_pass = os.getenv("OWNER_PASSWORD", "").strip()
    is_testing = "pytest" in sys.modules
    is_production = os.getenv("ENVIRONMENT", "development").lower() == "production" or os.getenv("VERCEL") == "1"

    if not owner_pass:
        if is_testing:
            owner_pass = "TestOwnerPass!99"  # Deterministic safe test-only password
        elif is_production:
            # Fail loudly — no silent insecure fallback in production
            log.error(
                "FATAL: OWNER_PASSWORD environment variable is not set. "
                "Master owner account will NOT be seeded. Set OWNER_PASSWORD in your environment."
            )
            return
        else:
            # Development fallback: use a strong ephemeral password and warn loudly
            import secrets as _secrets
            owner_pass = _secrets.token_urlsafe(24)
            log.warning(
                "SECURITY WARNING: OWNER_PASSWORD env var not set. "
                f"Generated ephemeral dev password for {owner_email}: {owner_pass}"
            )

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

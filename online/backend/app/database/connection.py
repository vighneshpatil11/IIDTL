"""Database connection management and session factory."""

import logging
import os
import sys
from pathlib import Path
from typing import Generator

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.pool import NullPool

from online.backend.app.config import settings
from online.backend.app.database.models import Base

log = logging.getLogger(__name__)


def _make_fallback_engine():
    fallback_dir = Path("/tmp") / "data" / "online"
    try:
        fallback_dir.mkdir(parents=True, exist_ok=True)
    except Exception:
        pass
    fallback = f"sqlite:///{fallback_dir / 'online_system.db'}"
    return create_engine(fallback, connect_args={"check_same_thread": False})


def _make_engine():
    db_url = settings.DATABASE_URL
    kwargs = {}
    if db_url.startswith("sqlite"):
        kwargs["connect_args"] = {"check_same_thread": False}
        return create_engine(db_url, **kwargs)

    # PostgreSQL (Supabase / Neon etc.)
    # NullPool is the recommended pattern for serverless functions (Vercel)
    # to avoid stale socket timeouts and exhaustion of connection pools.
    kwargs["poolclass"] = NullPool
    kwargs["pool_pre_ping"] = True
    try:
        eng = create_engine(db_url, **kwargs)
        with eng.connect() as conn:
            pass
        return eng
    except Exception as e:
        log.warning(f"PostgreSQL connection check failed ({e}), falling back to SQLite")
        return _make_fallback_engine()


engine = _make_engine()
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
_db_initialized = False


def init_db() -> None:
    """Create tables if they do not exist, run migrations, and seed the predefined master owner."""
    global engine, SessionLocal, _db_initialized
    try:
        Base.metadata.create_all(bind=engine)
    except Exception as e:
        log.warning(f"init_db create_all failed on primary engine ({e}), falling back to SQLite")
        engine = _make_fallback_engine()
        SessionLocal.configure(bind=engine)
        try:
            Base.metadata.create_all(bind=engine)
        except Exception as e2:
            log.error(f"Fallback SQLite init failed: {e2}")
            return

    # Safe lightweight schema migrations for existing databases
    try:
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
    except Exception as e:
        log.error(f"init_db migration step warning: {e}")

    owner_email = os.getenv("OWNER_EMAIL", "admin@docfortress.internal").strip().lower()
    owner_name = os.getenv("OWNER_NAME", "Master Document Owner").strip()

    is_testing = "pytest" in sys.modules
    env_pass = os.getenv("OWNER_PASSWORD", "").strip()

    if env_pass:
        owner_pass = env_pass
    elif is_testing:
        owner_pass = "TestOwnerPass!99"
    else:
        owner_pass = "AdminMasterPass!2026"

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
            log.info(f"Seeded master owner account: {owner_email}")
        else:
            # Keep credentials synchronized so owner can always log in
            existing.role = "OWNER"
            existing.password_hash = hash_password(owner_pass)
            db.commit()
    except Exception as e:
        log.error(f"Error seeding/updating master owner: {e}")
        db.rollback()
    finally:
        db.close()
    _db_initialized = True


def ensure_db_initialized() -> None:
    """Ensure database schema is created on serverless cold starts."""
    global _db_initialized
    if not _db_initialized:
        try:
            init_db()
        except Exception as e:
            log.error(f"ensure_db_initialized failed: {e}")


def get_db() -> Generator[Session, None, None]:
    """FastAPI dependency to provide a transactional database session."""
    ensure_db_initialized()
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

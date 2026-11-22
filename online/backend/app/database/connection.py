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

db_diagnostics = {
    "is_persistent": False,
    "engine_type": "sqlite",
    "driver": None,
    "host": None,
    "last_error": None,
    "attempted_errors": [],
}


def _make_fallback_engine():
    fallback_dir = Path("/tmp") / "data" / "online"
    try:
        fallback_dir.mkdir(parents=True, exist_ok=True)
    except Exception:
        pass
    fallback = f"sqlite:///{fallback_dir / 'online_system.db'}"
    return create_engine(fallback, connect_args={"check_same_thread": False})


def _make_engine():
    global db_diagnostics
    db_url = settings.DATABASE_URL
    kwargs = {}

    if db_url.startswith("sqlite"):
        kwargs["connect_args"] = {"check_same_thread": False}
        eng = create_engine(db_url, **kwargs)
        is_tmp = "/tmp" in db_url
        db_diagnostics["engine_type"] = "sqlite"
        db_diagnostics["is_persistent"] = not is_tmp
        db_diagnostics["driver"] = "sqlite3"
        db_diagnostics["last_error"] = (
            "Ephemeral storage active. Connect Supabase (set DATABASE_URL or POSTGRES_URL) for permanent data persistence."
            if is_tmp else None
        )
        return eng

    # PostgreSQL (Supabase / Neon etc.)
    # NullPool is the recommended pattern for serverless functions (Vercel)
    # to avoid stale socket timeouts and exhaustion of connection pools.
    kwargs["poolclass"] = NullPool
    kwargs["pool_pre_ping"] = True

    # Strip existing driver scheme to build candidate variations
    clean_url = db_url.strip()
    if "://" in clean_url:
        _, rest = clean_url.split("://", 1)
    else:
        rest = clean_url

    # Extract host for diagnostic reporting (without password)
    try:
        if "@" in rest:
            host_part = rest.split("@", 1)[1].split("/", 1)[0]
            db_diagnostics["host"] = host_part
    except Exception:
        pass

    # Ensure sslmode=require for cloud PostgreSQL
    rest_ssl = rest
    if "sslmode=" not in rest_ssl:
        sep = "&" if "?" in rest_ssl else "?"
        rest_ssl = f"{rest_ssl}{sep}sslmode=require"

    # Multi-driver candidate fallback order
    candidates = [
        f"postgresql+psycopg2://{rest_ssl}",
        f"postgresql+psycopg://{rest_ssl}",
        f"postgresql://{rest_ssl}",
        f"postgresql+psycopg2://{rest}",
        f"postgresql+psycopg://{rest}",
        f"postgresql://{rest}",
    ]

    from sqlalchemy import text
    last_err = None
    for cand_url in candidates:
        try:
            eng = create_engine(cand_url, **kwargs)
            with eng.connect() as conn:
                conn.execute(text("SELECT 1"))
            log.info(f"Connected to PostgreSQL successfully using {eng.dialect.driver}")
            db_diagnostics["is_persistent"] = True
            db_diagnostics["engine_type"] = "postgresql"
            db_diagnostics["driver"] = eng.dialect.driver
            db_diagnostics["last_error"] = None
            return eng
        except Exception as e:
            last_err = e
            clean_diag = str(cand_url).split("@")[-1] if "@" in str(cand_url) else str(cand_url)[:35]
            db_diagnostics["attempted_errors"].append(f"{clean_diag}: {str(e)}")
            continue

    log.warning(f"All PostgreSQL drivers failed ({last_err}), falling back to SQLite")
    db_diagnostics["is_persistent"] = False
    db_diagnostics["engine_type"] = "sqlite"
    db_diagnostics["driver"] = "sqlite3 (fallback)"
    db_diagnostics["last_error"] = str(last_err)
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
                "ALTER TABLE access_logs DROP CONSTRAINT IF EXISTS access_logs_document_id_fkey",
                "ALTER TABLE access_logs DROP CONSTRAINT IF EXISTS access_logs_recipient_id_fkey",
                "ALTER TABLE access_logs ALTER COLUMN document_id DROP NOT NULL",
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


def get_db_diagnostics() -> dict:
    """Retrieve comprehensive runtime database diagnostic data."""
    from online.backend.app.database.models import User, Recipient, Document, Distribution, AccessLog

    env_vars = {
        "DATABASE_URL": bool(os.getenv("DATABASE_URL")),
        "POSTGRES_URL": bool(os.getenv("POSTGRES_URL")),
        "POSTGRES_PRISMA_URL": bool(os.getenv("POSTGRES_PRISMA_URL")),
        "POSTGRES_URL_NON_POOLING": bool(os.getenv("POSTGRES_URL_NON_POOLING")),
        "SUPABASE_URL": bool(os.getenv("SUPABASE_URL")),
        "SUPABASE_ANON_KEY": bool(os.getenv("SUPABASE_ANON_KEY")),
    }
    counts = {}
    try:
        db = SessionLocal()
        counts["users"] = db.query(User).count()
        counts["recipients"] = db.query(Recipient).count()
        counts["documents"] = db.query(Document).count()
        counts["distributions"] = db.query(Distribution).count()
        counts["access_logs"] = db.query(AccessLog).count()
        db.close()
    except Exception as e:
        counts["error"] = str(e)

    return {
        "is_persistent": db_diagnostics.get("is_persistent", False),
        "engine_type": db_diagnostics.get("engine_type", "unknown"),
        "driver": db_diagnostics.get("driver"),
        "host": db_diagnostics.get("host"),
        "last_error": db_diagnostics.get("last_error"),
        "recent_probe_errors": db_diagnostics.get("attempted_errors", [])[-3:],
        "env_vars": env_vars,
        "counts": counts,
    }

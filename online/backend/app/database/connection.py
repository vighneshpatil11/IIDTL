"""Database connection management and session factory."""

from typing import Generator
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session

from online.backend.app.config import settings
from online.backend.app.database.models import Base

engine = create_engine(
    settings.DATABASE_URL,
    connect_args={"check_same_thread": False} if settings.DATABASE_URL.startswith("sqlite") else {},
    pool_pre_ping=True,
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def init_db() -> None:
    """Create tables if they do not exist and seed the predefined master owner."""
    Base.metadata.create_all(bind=engine)

    import os
    from online.backend.app.database.models import User
    from online.backend.app.security.passwords import hash_password

    owner_email = os.getenv("OWNER_EMAIL", "admin@docfortress.internal").strip().lower()
    owner_pass = os.getenv("OWNER_PASSWORD", "AdminMaster2026!").strip()
    owner_name = os.getenv("OWNER_NAME", "Master Document Owner").strip()

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

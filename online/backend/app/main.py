"""Main FastAPI application entry point for the Online Prototype."""

from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pathlib import Path

from online.backend.app.config import settings
from online.backend.app.database.connection import init_db
from online.backend.app.api import (
    auth,
    documents,
    recipients,
    distribution,
    investigation,
    audit,
)


# Ensure database tables exist at startup
init_db()

app = FastAPI(
    title=settings.APP_NAME,
    version="1.0.0",
    description="Secure Document Distribution with Cryptographic Access Control and Forensic Watermarking",
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register API v1 routes
prefix = settings.API_V1_PREFIX
app.include_router(auth.router, prefix=prefix)
app.include_router(documents.router, prefix=prefix)
app.include_router(recipients.router, prefix=prefix)
app.include_router(distribution.router, prefix=prefix)
app.include_router(investigation.router, prefix=prefix)
app.include_router(audit.router, prefix=prefix)


# Health check
@app.get("/health")
def health_check():
    return {
        "status": "healthy",
        "service": settings.APP_NAME,
        "version": "1.0.0",
        "api_prefix": settings.API_V1_PREFIX,
    }


# Mount web client UI if directory exists
frontend_dir = settings.BASE_DIR / "online" / "frontend" / "public"
if frontend_dir.is_dir():
    app.mount("/", StaticFiles(directory=str(frontend_dir), html=True), name="frontend")

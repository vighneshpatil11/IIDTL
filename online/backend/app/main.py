"""Main FastAPI application entry point for the Online Prototype."""

import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles

from online.backend.app.config import settings
from online.backend.app.database.connection import init_db, get_db_diagnostics
from online.backend.app.api import (
    auth,
    documents,
    recipients,
    distribution,
    investigation,
    audit,
)

log = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup: validate security config and initialise DB safely."""
    try:
        settings.validate_security_config()
    except Exception as e:
        log.error(f"Startup security config validation warning: {e}")
    try:
        init_db()
    except Exception as e:
        log.error(f"Startup init_db error: {e}")
    yield
    # Shutdown — nothing to clean up


app = FastAPI(
    title=settings.APP_NAME,
    version="1.0.0",
    description="Secure Document Distribution with Cryptographic Access Control and Forensic Watermarking",
    lifespan=lifespan,
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register API routes under both /api/v1 and /v1 for Vercel compatibility
for prefix in ["/api/v1", "/v1"]:
    app.include_router(auth.router, prefix=prefix)
    app.include_router(documents.router, prefix=prefix)
    app.include_router(recipients.router, prefix=prefix)
    app.include_router(distribution.router, prefix=prefix)
    app.include_router(investigation.router, prefix=prefix)
    app.include_router(audit.router, prefix=prefix)


# Health and Live Database Diagnostics
@app.get("/health")
@app.get("/api/health")
@app.get("/api/v1/system/db-status")
@app.get("/v1/system/db-status")
def health_check():
    diag = get_db_diagnostics()
    return {
        "status": "healthy" if diag.get("is_persistent") else "degraded",
        "service": settings.APP_NAME,
        "version": "1.0.0",
        "api_prefix": settings.API_V1_PREFIX,
        "database": diag,
    }


def get_frontend_html() -> str:
    candidates = [
        settings.BASE_DIR / "public" / "index.html",
        settings.BASE_DIR / "online" / "frontend" / "public" / "index.html",
        settings.BASE_DIR / "api" / "index.html",
        Path(__file__).resolve().parent.parent.parent.parent / "public" / "index.html",
        Path(__file__).resolve().parent.parent.parent.parent / "online" / "frontend" / "public" / "index.html",
        Path(__file__).resolve().parent.parent.parent.parent / "api" / "index.html",
        Path.cwd() / "public" / "index.html",
        Path.cwd() / "online" / "frontend" / "public" / "index.html",
        Path.cwd() / "api" / "index.html",
        Path("/var/task/public/index.html"),
        Path("/var/task/online/frontend/public/index.html"),
        Path("/var/task/api/index.html"),
    ]
    for c in candidates:
        try:
            if c.is_file():
                return c.read_text(encoding="utf-8")
        except Exception:
            continue
    return "<h1>DocFortress Secure Document Distribution</h1><p>API is active.</p>"


@app.get("/", response_class=HTMLResponse)
@app.get("/api", response_class=HTMLResponse)
@app.get("/api/", response_class=HTMLResponse)
def root_view():
    """Serve the single-page application frontend with no-cache headers."""
    return HTMLResponse(
        content=get_frontend_html(),
        status_code=200,
        headers={
            "Cache-Control": "no-cache, no-store, must-revalidate",
            "Pragma": "no-cache",
            "Expires": "0",
        },
    )


# Mount static files if directory exists
frontend_dir = settings.BASE_DIR / "online" / "frontend" / "public"
if frontend_dir.is_dir():
    try:
        app.mount("/static", StaticFiles(directory=str(frontend_dir)), name="static")
    except Exception:
        pass

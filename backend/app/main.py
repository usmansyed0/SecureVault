from __future__ import annotations

import uuid
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse

from .account import router as account_router
from .auth import router as auth_router
from .backups import router as backups_router
from .config import assert_production_secrets, get_settings
from .devices import router as devices_router
from .health import router as health_router
from .logging_config import configure_logging, get_logger
from .objects import router as objects_router
from .shares import router as shares_router
from .vault_sync import router as sync_router

_log = get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings()

    # Configure structured JSON logging early so every startup message is captured
    configure_logging(
        level="DEBUG" if settings.environment == "development" else "INFO",
        json_logs=settings.environment != "development",
    )

    # Refuse to start in production with weak/missing secrets.
    assert_production_secrets(settings)

    if settings.environment == "production" and "sqlite" in settings.database_url.lower():
        # assert_production_secrets above would have already raised, but belt-and-suspenders:
        raise RuntimeError(
            "SQLite database_url detected in production environment. "
            "This is not supported. Set SECUREVAULT_DATABASE_URL to a PostgreSQL URL."
        )

    if "sqlite" in settings.database_url.lower():
        from .models import Base
        from .database import session_factory
        engine = session_factory(settings.database_url).kw["bind"]
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

    _log.info("securevault_api_started", environment=settings.environment)
    yield
    _log.info("securevault_api_stopped")


app = FastAPI(
    title="SecureVault API",
    # Disable interactive docs in production (re-enable by setting environment != production)
    docs_url=None,
    redoc_url=None,
    lifespan=lifespan,
)

# ── Routers ──────────────────────────────────────────────────────────────────
app.include_router(health_router)    # /healthz + /readyz (no auth, no rate-limit)
app.include_router(auth_router)
app.include_router(devices_router)
app.include_router(sync_router)
app.include_router(objects_router)
app.include_router(shares_router)
app.include_router(backups_router)
app.include_router(account_router)   # DELETE /v1/account


# ── Request ID middleware ─────────────────────────────────────────────────────
@app.middleware("http")
async def request_id_middleware(request: Request, call_next):
    """Attach a unique request ID to every request for tracing."""
    req_id = request.headers.get("X-Request-Id") or str(uuid.uuid4())
    request.state.request_id = req_id
    response = await call_next(request)
    response.headers["X-Request-Id"] = req_id
    return response


# ── Security headers + request size middleware ────────────────────────────────
@app.middleware("http")
async def security_headers(request: Request, call_next):
    # Request size limit: 50 MB for object uploads, 1 MB for everything else
    max_size = 52_428_800 if request.url.path.startswith("/v1/objects") else 1_048_576
    cl = request.headers.get("content-length", "0")
    if cl.isdigit() and int(cl) > max_size:
        raise HTTPException(413, "request too large")

    response = await call_next(request)

    # Security headers — applied to every response
    response.headers["Cache-Control"] = "no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = (
        "accelerometer=(), camera=(), geolocation=(), gyroscope=(), "
        "magnetometer=(), microphone=(), payment=(), usb=()"
    )
    response.headers["Content-Security-Policy"] = (
        "default-src 'none'; frame-ancestors 'none'"
    )

    settings = get_settings()
    if settings.environment == "production":
        # HSTS: 1 year, include sub-domains, preload-eligible
        response.headers["Strict-Transport-Security"] = (
            "max-age=31536000; includeSubDomains; preload"
        )

    return response


# ── Request logging middleware ────────────────────────────────────────────────
@app.middleware("http")
async def access_log(request: Request, call_next):
    """Emit a structured access log line for every request (no sensitive headers logged)."""
    import time
    start = time.monotonic()
    response = await call_next(request)
    duration_ms = round((time.monotonic() - start) * 1000, 1)
    req_id = getattr(request.state, "request_id", "-")
    # Only log path, method, status — never query strings or body (may contain secrets)
    _log.info(
        "http_request",
        method=request.method,
        path=request.url.path,
        status=response.status_code,
        duration_ms=duration_ms,
        request_id=req_id,
    )
    return response


# ── Static pages & Disclosure ────────────────────────────────────────────────
@app.get("/emergency", response_class=HTMLResponse, include_in_schema=False)
async def emergency_page() -> HTMLResponse:
    from pathlib import Path
    html_path = Path(__file__).parent / "static" / "emergency.html"
    return HTMLResponse(content=html_path.read_text(encoding="utf-8"))


@app.get("/account-deletion", response_class=HTMLResponse, include_in_schema=False)
async def account_deletion_page() -> HTMLResponse:
    from pathlib import Path
    html_path = Path(__file__).parent / "static" / "account-deletion.html"
    return HTMLResponse(content=html_path.read_text(encoding="utf-8"))


@app.get("/.well-known/security.txt", response_class=PlainTextResponse, include_in_schema=False)
async def security_txt() -> PlainTextResponse:
    from pathlib import Path
    sec_path = Path(__file__).parent / "static" / ".well-known" / "security.txt"
    return PlainTextResponse(content=sec_path.read_text(encoding="utf-8"), media_type="text/plain; charset=utf-8")


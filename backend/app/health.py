"""
/healthz  — liveness probe (fast, no DB): returns 200 if the process is alive.
/readyz   — readiness probe (DB ping): returns 200 only when the DB is reachable.

These endpoints are excluded from the security-headers middleware and from API docs.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Response
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from .database import session

router = APIRouter(tags=["ops"])


@router.get("/healthz", include_in_schema=False)
async def liveness() -> dict[str, str]:
    """Liveness probe — always 200 if the process is running."""
    return {"status": "ok"}


@router.get("/readyz", include_in_schema=False)
async def readiness(db: AsyncSession = Depends(session)) -> Response:
    """Readiness probe — 200 when the database is reachable, 503 otherwise."""
    try:
        await db.execute(text("SELECT 1"))
        return Response(content='{"status":"ready"}', media_type="application/json", status_code=200)
    except Exception:
        return Response(content='{"status":"unavailable","detail":"database unreachable"}',
                        media_type="application/json", status_code=503)

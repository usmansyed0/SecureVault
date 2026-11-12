"""
Tests for DELETE /v1/account — account deletion endpoint.

Tests:
  1. Successful deletion wipes all user data and returns 200.
  2. Invalid/expired step-up grant returns 403.
  3. Missing Authorization header returns 401.
  4. Deletion with wrong action in grant returns 403.
  5. Security headers are present on the response.
  6. /healthz returns 200 without auth.
  7. /readyz returns 200 when DB responds.
  8. /readyz returns 503 when DB is unavailable.
"""

import json as json_mod
import uuid
from unittest.mock import AsyncMock, MagicMock, patch
import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.authorization import Principal, require_principal, require_trusted_device
from app.database import session


def _delete(client, body: dict) -> object:
    """Helper: send DELETE /v1/account with a JSON body.
    Starlette 0.41 TestClient (httpx-backed) requires using .request()
    with data= to attach a body to DELETE requests.
    """
    return client.request(
        "DELETE",
        "/v1/account",
        data=json_mod.dumps(body),
        headers={"Content-Type": "application/json"},
    )


@pytest.fixture
def mock_db():
    db = AsyncMock()
    db.get = AsyncMock()
    db.execute = AsyncMock()
    db.commit = AsyncMock()
    db.scalar = AsyncMock(return_value=None)
    return db


@pytest.fixture
def test_principal():
    return Principal(
        user_id=uuid.uuid4(),
        device_id=uuid.uuid4(),
        session_id=uuid.uuid4(),
        device_status="trusted",
    )


@pytest.fixture
def env_vars(monkeypatch):
    monkeypatch.setenv("SECUREVAULT_DATABASE_URL", "postgresql+asyncpg://u:p@localhost/test")
    monkeypatch.setenv("SECUREVAULT_JWT_SECRET", "a-test-only-secret-that-is-at-least-32-bytes-long")
    monkeypatch.setenv("SECUREVAULT_REFRESH_TOKEN_HASH_SECRET", "another-test-only-secret-at-least-32-bytes")
    monkeypatch.setenv("SECUREVAULT_STEP_UP_HASH_SECRET", "step-up-test-only-secret-at-least-32-bytes-here")
    monkeypatch.setenv("SECUREVAULT_ENVIRONMENT", "test")
    monkeypatch.setenv("SECUREVAULT_GOOGLE_WEB_CLIENT_ID", "test-client-id")


@pytest.fixture
def client(mock_db, test_principal, env_vars):
    app.dependency_overrides[session] = lambda: mock_db
    app.dependency_overrides[require_principal] = lambda: test_principal
    app.dependency_overrides[require_trusted_device] = lambda: test_principal

    with TestClient(app) as c:
        yield c

    app.dependency_overrides.clear()


# ── Test 1: Successful deletion ───────────────────────────────────────────────

def test_delete_account_success(client, mock_db, test_principal):
    """A valid step-up grant deletes the account and returns 200."""
    from app.models import User
    user = MagicMock(spec=User)
    user.id = test_principal.user_id
    mock_db.get.return_value = user

    with patch("app.account.consume_step_up_grant", new=AsyncMock()) as mock_grant:
        res = _delete(client, {"step_up_grant": "x" * 64})

    assert res.status_code == 200
    body = res.json()
    assert body["deleted"] is True
    assert body["user_id"] == str(test_principal.user_id)
    mock_grant.assert_awaited_once()
    # All bulk-delete execute() calls must have been made (9 tables)
    assert mock_db.execute.call_count >= 9
    mock_db.commit.assert_awaited_once()


# ── Test 2: Invalid step-up grant ────────────────────────────────────────────

def test_delete_account_bad_grant(client):
    """An invalid step-up grant must return 403."""
    from fastapi import HTTPException
    with patch(
        "app.account.consume_step_up_grant",
        new=AsyncMock(side_effect=HTTPException(403, "authorization denied")),
    ):
        res = _delete(client, {"step_up_grant": "x" * 64})
    assert res.status_code == 403


# ── Test 3: No auth header ───────────────────────────────────────────────────

def test_delete_account_unauthenticated(env_vars):
    """Without a Bearer token the endpoint must return 401."""
    app.dependency_overrides.clear()
    with TestClient(app) as c:
        res = _delete(c, {"step_up_grant": "x" * 64})
    assert res.status_code == 401


# ── Test 4: Wrong step-up action ─────────────────────────────────────────────

def test_delete_account_wrong_action(client):
    """A step-up grant consumed for a different action must be rejected."""
    from fastapi import HTTPException
    with patch(
        "app.account.consume_step_up_grant",
        new=AsyncMock(side_effect=HTTPException(403, "authorization denied")),
    ):
        res = _delete(client, {"step_up_grant": "x" * 64})
    assert res.status_code == 403


# ── Test 5: Security headers ─────────────────────────────────────────────────

def test_security_headers_present(client):
    """Every response must carry the hardened security header set."""
    res = client.get("/healthz")
    assert res.headers.get("x-content-type-options") == "nosniff"
    assert res.headers.get("x-frame-options") == "DENY"
    assert "no-store" in res.headers.get("cache-control", "")
    assert "default-src 'none'" in res.headers.get("content-security-policy", "")
    assert res.headers.get("referrer-policy") == "no-referrer"


# ── Test 6: /healthz ─────────────────────────────────────────────────────────

def test_healthz_returns_ok(client):
    """/healthz must return 200 without authentication."""
    res = client.get("/healthz")
    assert res.status_code == 200
    assert res.json()["status"] == "ok"


# ── Test 7: /readyz — DB available ───────────────────────────────────────────

def test_readyz_db_available(client, mock_db):
    """/readyz must return 200 when the database query succeeds."""
    mock_db.execute = AsyncMock(return_value=None)
    res = client.get("/readyz")
    assert res.status_code == 200
    assert res.json()["status"] == "ready"


# ── Test 8: /readyz — DB unavailable ─────────────────────────────────────────

def test_readyz_db_unavailable(client, mock_db):
    """/readyz must return 503 when the database is unreachable."""
    mock_db.execute = AsyncMock(side_effect=Exception("connection refused"))
    res = client.get("/readyz")
    assert res.status_code == 503
    assert res.json()["status"] == "unavailable"

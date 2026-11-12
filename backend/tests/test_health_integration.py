def test_healthz_liveness(monkeypatch):
    monkeypatch.setenv("SECUREVAULT_DATABASE_URL", "postgresql+asyncpg://user:password@localhost/test")
    monkeypatch.setenv("SECUREVAULT_JWT_SECRET", "a-test-only-secret-that-is-at-least-32-bytes")
    monkeypatch.setenv("SECUREVAULT_REFRESH_TOKEN_HASH_SECRET", "another-test-only-secret-that-is-at-least-32-bytes")
    monkeypatch.setenv("SECUREVAULT_STEP_UP_HASH_SECRET", "step-up-test-only-secret-that-is-at-least-32-bytes")
    from fastapi.testclient import TestClient
    from app.main import app
    response = TestClient(app).get("/healthz")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}
    # Security headers must be present even on probe endpoints
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["x-content-type-options"] == "nosniff"

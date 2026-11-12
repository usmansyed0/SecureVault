"""
Tests for assert_production_secrets() — Task 3.

Each test verifies that one missing production requirement causes startup refusal.
"""
import pytest

# Minimal valid secrets (long enough, no weak patterns).
_DB_POSTGRES = "postgresql+asyncpg://user:pass@host/db"
_JWT = "a-test-only-secret-that-is-at-least-32-bytes-long"
_REFRESH = "another-test-only-secret-that-is-at-least-32-bytes-long!!"
_STEP_UP = "step-up-test-only-secret-that-is-at-least-32-bytes-long!!"


def _prod_settings(**overrides):
    """Return a Settings-like object for production environment."""
    from app.config import Settings
    defaults = {
        "SECUREVAULT_DATABASE_URL": _DB_POSTGRES,
        "SECUREVAULT_JWT_SECRET": _JWT,
        "SECUREVAULT_REFRESH_TOKEN_HASH_SECRET": _REFRESH,
        "SECUREVAULT_STEP_UP_HASH_SECRET": _STEP_UP,
        "SECUREVAULT_GOOGLE_WEB_CLIENT_ID": "correct-client-id.apps.googleusercontent.com",
        "SECUREVAULT_ENVIRONMENT": "production",
        "SECUREVAULT_REQUIRE_DEVICE_SIGNATURE": "true",
        "SECUREVAULT_REDIS_URL": "redis://localhost:6379/0",
    }
    defaults.update({k.upper() if not k.startswith("SECUREVAULT_") else k: v for k, v in overrides.items()})
    import os
    old = {k: os.environ.get(k) for k in defaults}
    for k, v in defaults.items():
        os.environ[k] = str(v)
    try:
        s = Settings()
    finally:
        for k, v in old.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
    return s


class TestAssertProductionSecrets:
    def test_passes_with_all_valid_settings(self):
        from app.config import assert_production_secrets
        s = _prod_settings()
        assert_production_secrets(s)  # must not raise

    def test_skips_check_in_development(self):
        from app.config import assert_production_secrets, Settings
        import os
        env = {
            "SECUREVAULT_DATABASE_URL": "sqlite:///test.db",
            "SECUREVAULT_JWT_SECRET": _JWT,
            "SECUREVAULT_REFRESH_TOKEN_HASH_SECRET": _REFRESH,
            "SECUREVAULT_STEP_UP_HASH_SECRET": _STEP_UP,
            "SECUREVAULT_ENVIRONMENT": "development",
            "SECUREVAULT_REQUIRE_DEVICE_SIGNATURE": "false",
        }
        old = {k: os.environ.get(k) for k in env}
        for k, v in env.items():
            os.environ[k] = v
        try:
            s = Settings()
            assert_production_secrets(s)  # must not raise in dev
        finally:
            for k, v in old.items():
                if v is None:
                    os.environ.pop(k, None)
                else:
                    os.environ[k] = v

    def test_fails_missing_google_client_id(self):
        from app.config import assert_production_secrets
        s = _prod_settings(SECUREVAULT_GOOGLE_WEB_CLIENT_ID="")
        with pytest.raises(RuntimeError, match="GOOGLE_WEB_CLIENT_ID"):
            assert_production_secrets(s)

    def test_fails_require_device_signature_false(self):
        from app.config import assert_production_secrets
        s = _prod_settings(SECUREVAULT_REQUIRE_DEVICE_SIGNATURE="false")
        with pytest.raises(RuntimeError, match="REQUIRE_DEVICE_SIGNATURE"):
            assert_production_secrets(s)

    def test_fails_sqlite_database_url(self):
        from app.config import assert_production_secrets
        s = _prod_settings(SECUREVAULT_DATABASE_URL="sqlite:///prod.db")
        with pytest.raises(RuntimeError, match="PostgreSQL"):
            assert_production_secrets(s)

    def test_fails_missing_redis_url(self):
        from app.config import assert_production_secrets
        s = _prod_settings(SECUREVAULT_REDIS_URL="")
        with pytest.raises(RuntimeError, match="REDIS_URL"):
            assert_production_secrets(s)

    def test_reports_all_failures_together(self):
        """All four missing values should be reported in a single error, not just the first."""
        from app.config import assert_production_secrets
        s = _prod_settings(
            SECUREVAULT_GOOGLE_WEB_CLIENT_ID="",
            SECUREVAULT_REQUIRE_DEVICE_SIGNATURE="false",
            SECUREVAULT_DATABASE_URL="sqlite:///prod.db",
            SECUREVAULT_REDIS_URL="",
        )
        with pytest.raises(RuntimeError) as exc_info:
            assert_production_secrets(s)
        msg = str(exc_info.value)
        assert "GOOGLE_WEB_CLIENT_ID" in msg
        assert "REQUIRE_DEVICE_SIGNATURE" in msg
        assert "PostgreSQL" in msg
        assert "REDIS_URL" in msg

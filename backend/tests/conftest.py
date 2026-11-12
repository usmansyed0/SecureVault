"""
Shared pytest configuration for the SecureVault backend test suite.

Sets environment variables that satisfy the `Settings` validator
(secrets >= 32 chars, no placeholder patterns) *before* any test module
imports `app.config.Settings`.  This prevents the real `.env` file
(which contains placeholder secrets) from causing `ValidationError` in tests.
"""

import os
import pytest

# These are set at import time so they are available before any test module
# triggers Settings() initialization (e.g. via module-level TestClient()).
_TEST_ENVVARS = {
    "SECUREVAULT_DATABASE_URL": "postgresql+asyncpg://user:password@localhost/test",
    "SECUREVAULT_JWT_SECRET": "test-jwt-secret-value-that-is-at-least-32-bytes",
    "SECUREVAULT_REFRESH_TOKEN_HASH_SECRET": "test-refresh-hash-secret-that-is-at-least-32b",
    "SECUREVAULT_STEP_UP_HASH_SECRET": "test-stepup-hash-secret-that-is-at-least-32b!",
    "SECUREVAULT_ENVIRONMENT": "test",
    "SECUREVAULT_GOOGLE_WEB_CLIENT_ID": "test-google-client-id.apps.googleusercontent.com",
    # require_device_signature default changed to True in production.
    # Tests operate with an in-memory mock DB, not real device keys, so disable it here.
    "SECUREVAULT_REQUIRE_DEVICE_SIGNATURE": "false",
}

for key, value in _TEST_ENVVARS.items():
    os.environ.setdefault(key, value)

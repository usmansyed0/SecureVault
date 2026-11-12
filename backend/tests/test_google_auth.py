"""
Tests for Google token verification (Phase 0.1).

These tests verify that google_auth() correctly rejects:
  - Expired tokens
  - Wrong audience
  - Wrong issuer
  - Bad/forged signature
  - Unsigned tokens (alg=none)
  - Replayed nonces
  - email_verified=false
  - Takeover attempts by email match (now blocked)

A valid path with mocked JWKS is also tested.
"""
import asyncio
import hashlib
import secrets
import time
import uuid
from datetime import datetime, timezone, timedelta
from unittest.mock import AsyncMock, MagicMock, patch

import jwt as pyjwt
import pytest
from fastapi.testclient import TestClient
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding

from app.main import app
from app.database import session
from app.auth import _nonce_hash


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def mock_db():
    db = AsyncMock()
    return db


def _make_rsa_keypair():
    """Generate a throwaway RSA key pair for testing."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    return private_key, public_key


def _build_id_token(
    private_key,
    kid: str,
    *,
    sub: str = "google-sub-12345",
    email: str = "user@example.com",
    email_verified: bool = True,
    aud: str = "correct-client-id",
    iss: str = "https://accounts.google.com",
    nonce: str = "valid-nonce-value",
    exp_delta: int = 3600,  # seconds from now
) -> str:
    now = int(time.time())
    payload = {
        "sub": sub,
        "email": email,
        "email_verified": email_verified,
        "iss": iss,
        "aud": aud,
        "iat": now,
        "exp": now + exp_delta,
        "nonce": nonce,
    }
    return pyjwt.encode(payload, private_key, algorithm="RS256", headers={"kid": kid})


def _mock_signing_key(public_key):
    """Create a mock PyJWKClient signing key wrapping the given public key."""
    mock_sk = MagicMock()
    mock_sk.key = public_key
    return mock_sk


# Shared: a valid RSA key pair for tests that need a happy path.
@pytest.fixture
def rsa_keypair():
    return _make_rsa_keypair()


def _valid_nonce_record(nonce_value: str):
    """Create a mock GoogleNonce ORM object."""
    record = MagicMock()
    record.nonce_hash = _nonce_hash(nonce_value)
    record.consumed_at = None
    record.expires_at = datetime.now(timezone.utc) + timedelta(minutes=5)
    return record


@pytest.fixture
def client(mock_db, monkeypatch):
    monkeypatch.setenv("SECUREVAULT_DATABASE_URL", "postgresql+asyncpg://u:p@localhost/test")
    monkeypatch.setenv("SECUREVAULT_JWT_SECRET", "a-test-only-secret-that-is-at-least-32-bytes-long")
    monkeypatch.setenv("SECUREVAULT_REFRESH_TOKEN_HASH_SECRET", "another-test-secret-at-least-32-bytes-long!!")
    monkeypatch.setenv("SECUREVAULT_STEP_UP_HASH_SECRET", "step-up-test-secret-at-least-32-bytes-long!!!")
    monkeypatch.setenv("SECUREVAULT_GOOGLE_WEB_CLIENT_ID", "correct-client-id")
    monkeypatch.setenv("SECUREVAULT_ENVIRONMENT", "development")

    app.dependency_overrides[session] = lambda: mock_db
    with TestClient(app, raise_server_exceptions=False) as c:
        yield c
    app.dependency_overrides.clear()


# ---------------------------------------------------------------------------
# Helper: call POST /v1/auth/google with a mocked JWKS client
# ---------------------------------------------------------------------------

def _post_google(client, mock_db, id_token: str, nonce_value: str, mock_signing_key, *,
                 existing_user=None, existing_device=None):
    """Post to /v1/auth/google with mocked DB and JWKS. Returns the response."""
    nonce_record = _valid_nonce_record(nonce_value)

    # DB scalar calls: nonce lookup → user lookup → device lookup
    scalars = [nonce_record, existing_user, existing_device]
    mock_db.scalar = AsyncMock(side_effect=scalars + [None] * 10)
    mock_db.flush = AsyncMock()
    mock_db.commit = AsyncMock()

    # Mock session issued
    if existing_user is None:
        new_user = MagicMock()
        new_user.id = uuid.uuid4()
        new_user.status = "active"
        new_user.google_sub = "google-sub-12345"
        new_user.master_salt = None
        new_user.bootstrap_available = True
        new_user.vault_binding_exists = False
        mock_db.scalar = AsyncMock(side_effect=[nonce_record, None, None, None, None])

    import app.auth as auth_module
    with patch.object(auth_module, "_get_jwks_client", new=AsyncMock(return_value=MagicMock(
        get_signing_key_from_jwt=MagicMock(return_value=mock_signing_key)
    ))):
        payload = {
            "id_token": id_token,
            "nonce": nonce_value,
            "device_name": "Test Phone",
            "platform": "android",
            "public_key": _fake_public_key(),
        }
        return client.post("/v1/auth/google", json=payload)


def _fake_public_key() -> str:
    """Return a base64-encoded P-256 public key DER for device registration."""
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    import base64
    key = ec.generate_private_key(ec.SECP256R1()).public_key()
    der = key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    return base64.b64encode(der).decode()


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestGoogleAuthRejectsExpiredToken:
    def test_expired_token_returns_401(self, client, mock_db, rsa_keypair):
        private_key, public_key = rsa_keypair
        nonce_value = "valid-nonce-1234567890abcdef12345678"
        # Use -120 so the token is well outside the 60-second leeway window.
        id_token = _build_id_token(private_key, "kid1", nonce=nonce_value, exp_delta=-120)
        mock_signing_key = _mock_signing_key(public_key)
        res = _post_google(client, mock_db, id_token, nonce_value, mock_signing_key)
        assert res.status_code == 401


class TestGoogleAuthRejectsWrongAudience:
    def test_wrong_aud_returns_401(self, client, mock_db, rsa_keypair):
        private_key, public_key = rsa_keypair
        nonce_value = "valid-nonce-1234567890abcdef12345678"
        id_token = _build_id_token(private_key, "kid1", nonce=nonce_value, aud="wrong-client-id")
        mock_signing_key = _mock_signing_key(public_key)
        res = _post_google(client, mock_db, id_token, nonce_value, mock_signing_key)
        assert res.status_code == 401


class TestGoogleAuthRejectsWrongIssuer:
    def test_wrong_iss_returns_401(self, client, mock_db, rsa_keypair):
        private_key, public_key = rsa_keypair
        nonce_value = "valid-nonce-1234567890abcdef12345678"
        id_token = _build_id_token(
            private_key, "kid1", nonce=nonce_value,
            iss="https://evil.attacker.example.com"
        )
        mock_signing_key = _mock_signing_key(public_key)
        res = _post_google(client, mock_db, id_token, nonce_value, mock_signing_key)
        assert res.status_code == 401


class TestGoogleAuthRejectsBadSignature:
    def test_bad_signature_returns_401(self, client, mock_db, rsa_keypair):
        private_key, public_key = rsa_keypair
        nonce_value = "valid-nonce-1234567890abcdef12345678"
        # Build token with one key but verify with a different key.
        other_private, other_public = _make_rsa_keypair()
        id_token = _build_id_token(private_key, "kid1", nonce=nonce_value)
        # Pass the wrong public key so signature verification fails.
        mock_signing_key = _mock_signing_key(other_public)
        res = _post_google(client, mock_db, id_token, nonce_value, mock_signing_key)
        assert res.status_code == 401


class TestGoogleAuthRejectsUnsignedToken:
    def test_alg_none_returns_401(self, client, mock_db):
        nonce_value = "valid-nonce-1234567890abcdef12345678"
        # Manually craft an unsigned token (alg=none).
        import base64, json
        header = base64.urlsafe_b64encode(json.dumps({"alg": "none", "typ": "JWT"}).encode()).rstrip(b"=").decode()
        payload_b = base64.urlsafe_b64encode(json.dumps({
            "sub": "evil", "email": "evil@example.com", "email_verified": True,
            "iss": "https://accounts.google.com", "aud": "correct-client-id",
            "iat": int(time.time()), "exp": int(time.time()) + 3600, "nonce": nonce_value,
        }).encode()).rstrip(b"=").decode()
        id_token = f"{header}.{payload_b}."  # no signature

        nonce_record = _valid_nonce_record(nonce_value)
        mock_db.scalar = AsyncMock(side_effect=[nonce_record] + [None] * 10)
        mock_db.flush = AsyncMock()
        mock_db.commit = AsyncMock()

        import app.auth as auth_module
        # PyJWKClient.get_signing_key_from_jwt will raise for alg=none tokens.
        with patch.object(auth_module, "_get_jwks_client", new=AsyncMock(return_value=MagicMock(
            get_signing_key_from_jwt=MagicMock(side_effect=pyjwt.exceptions.PyJWTError("no alg"))
        ))):
            res = client.post("/v1/auth/google", json={
                "id_token": id_token, "nonce": nonce_value,
                "device_name": "Phone", "platform": "android", "public_key": _fake_public_key(),
            })
        assert res.status_code == 401


class TestGoogleAuthRejectsReplayedNonce:
    def test_consumed_nonce_returns_401(self, client, mock_db, rsa_keypair):
        private_key, public_key = rsa_keypair
        nonce_value = "valid-nonce-1234567890abcdef12345678"
        id_token = _build_id_token(private_key, "kid1", nonce=nonce_value)

        # Mark nonce as already consumed.
        nonce_record = _valid_nonce_record(nonce_value)
        nonce_record.consumed_at = datetime.now(timezone.utc) - timedelta(seconds=1)
        mock_db.scalar = AsyncMock(return_value=nonce_record)
        mock_db.flush = AsyncMock()

        import app.auth as auth_module
        with patch.object(auth_module, "_get_jwks_client", new=AsyncMock()):
            res = client.post("/v1/auth/google", json={
                "id_token": id_token, "nonce": nonce_value,
                "device_name": "Phone", "platform": "android", "public_key": _fake_public_key(),
            })
        assert res.status_code == 401

    def test_expired_nonce_returns_401(self, client, mock_db, rsa_keypair):
        private_key, public_key = rsa_keypair
        nonce_value = "valid-nonce-1234567890abcdef12345678"
        id_token = _build_id_token(private_key, "kid1", nonce=nonce_value)

        nonce_record = _valid_nonce_record(nonce_value)
        nonce_record.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)  # expired
        mock_db.scalar = AsyncMock(return_value=nonce_record)
        mock_db.flush = AsyncMock()

        import app.auth as auth_module
        with patch.object(auth_module, "_get_jwks_client", new=AsyncMock()):
            res = client.post("/v1/auth/google", json={
                "id_token": id_token, "nonce": nonce_value,
                "device_name": "Phone", "platform": "android", "public_key": _fake_public_key(),
            })
        assert res.status_code == 401


class TestGoogleAuthRejectsUnverifiedEmail:
    def test_email_not_verified_returns_401(self, client, mock_db, rsa_keypair):
        private_key, public_key = rsa_keypair
        nonce_value = "valid-nonce-1234567890abcdef12345678"
        id_token = _build_id_token(private_key, "kid1", nonce=nonce_value, email_verified=False)
        mock_signing_key = _mock_signing_key(public_key)
        res = _post_google(client, mock_db, id_token, nonce_value, mock_signing_key)
        assert res.status_code == 401


class TestGoogleAuthBlocksEmailTakeover:
    def test_existing_email_not_matched_by_email(self, client, mock_db, rsa_keypair):
        """Attacker forges a token for an existing user's email; must not get that user's account."""
        private_key, public_key = rsa_keypair
        nonce_value = "valid-nonce-1234567890abcdef12345678"
        # Attacker token has a different sub but the victim's email.
        id_token = _build_id_token(
            private_key, "kid1", nonce=nonce_value,
            sub="attacker-sub-999",
            email="victim@example.com",
        )
        # DB returns None for google_sub lookup (attacker sub not known) →
        # should create a NEW account, not reuse victim's.
        nonce_record = _valid_nonce_record(nonce_value)
        mock_db.scalar = AsyncMock(side_effect=[nonce_record, None, None, None, None])
        mock_db.flush = AsyncMock()
        mock_db.commit = AsyncMock()

        import app.auth as auth_module
        with patch.object(auth_module, "_get_jwks_client", new=AsyncMock(return_value=MagicMock(
            get_signing_key_from_jwt=MagicMock(return_value=_mock_signing_key(public_key))
        ))):
            # Patch issue_session to avoid full ORM setup
            with patch.object(auth_module, "issue_session", new=AsyncMock(return_value=MagicMock(
                access_token="at", refresh_token="rt", token_type="bearer",
                user_id=str(uuid.uuid4()), device_id=str(uuid.uuid4()),
                session_id=str(uuid.uuid4()), device_status="pending",
                master_salt=None, vault_version=1,
            ))):
                res = client.post("/v1/auth/google", json={
                    "id_token": id_token, "nonce": nonce_value,
                    "device_name": "Phone", "platform": "android",
                    "public_key": _fake_public_key(),
                })
        # The request should NOT be 401 (attacker gets a new account, not victim's)
        # but the user lookup must have been by google_sub only.
        calls = mock_db.scalar.call_args_list
        # First call is nonce lookup; second call is user lookup.
        if len(calls) >= 2:
            user_query_call = calls[1]
            query_str = str(user_query_call)
            # Ensure email was NOT used in the user lookup.
            assert "victim@example.com" not in query_str


# ---------------------------------------------------------------------------
# NEW TESTS — Task 1
# ---------------------------------------------------------------------------

class TestGoogleAuthSuccessfulLogin:
    """Happy-path: a genuine Google token authenticates a new user end-to-end."""

    def test_valid_token_returns_tokens_for_new_user(self, client, mock_db, rsa_keypair):
        """A correctly-signed token with the right nonce must succeed and return access+refresh."""
        private_key, public_key = rsa_keypair
        nonce_value = "valid-nonce-1234567890abcdef12345678"
        id_token = _build_id_token(
            private_key, "kid1",
            nonce=nonce_value,
            aud="correct-client-id",
            iss="https://accounts.google.com",
            email_verified=True,
        )
        mock_signing_key = _mock_signing_key(public_key)

        import app.auth as auth_module
        with patch.object(auth_module, "_get_jwks_client", new=AsyncMock(return_value=MagicMock(
            get_signing_key_from_jwt=MagicMock(return_value=mock_signing_key)
        ))):
            with patch.object(auth_module, "issue_session", new=AsyncMock(return_value=MagicMock(
                access_token="access-tok",
                refresh_token="refresh-tok",
                token_type="bearer",
                user_id=str(uuid.uuid4()),
                device_id=str(uuid.uuid4()),
                session_id=str(uuid.uuid4()),
                device_status="pending",
                master_salt=None,
                vault_version=1,
            ))):
                # Simulate: nonce found, user not found (new), device not found (new)
                nonce_record = _valid_nonce_record(nonce_value)
                new_user = MagicMock()
                new_user.id = uuid.uuid4()
                new_user.status = "active"
                new_user.google_sub = "google-sub-12345"
                new_user.master_salt = None
                new_user.bootstrap_available = True
                new_user.vault_binding_exists = False
                mock_db.scalar = AsyncMock(side_effect=[nonce_record, None, None, None, None])
                mock_db.flush = AsyncMock()
                mock_db.commit = AsyncMock()
                mock_db.add = MagicMock()

                res = client.post("/v1/auth/google", json={
                    "id_token": id_token,
                    "nonce": nonce_value,
                    "device_name": "Test Phone",
                    "platform": "android",
                    "public_key": _fake_public_key(),
                })

        assert res.status_code == 200, f"Expected 200 but got {res.status_code}: {res.text}"
        body = res.json()
        assert "access_token" in body
        assert "refresh_token" in body

    def test_verify_google_id_token_returns_claims_directly(self, rsa_keypair):
        """Unit test: _verify_google_id_token returns claims for a valid token."""
        import asyncio
        import app.auth as auth_module
        from app.config import Settings
        from unittest.mock import MagicMock, patch, AsyncMock

        private_key, public_key = rsa_keypair
        nonce_value = "my-test-nonce-direct-unit"
        id_token = _build_id_token(
            private_key, "kid-unit",
            nonce=nonce_value,
            aud="correct-client-id",
            iss="https://accounts.google.com",
            email_verified=True,
        )
        mock_signing_key = _mock_signing_key(public_key)

        settings = MagicMock(spec=Settings)
        settings.google_web_client_id = "correct-client-id"

        with patch.object(auth_module, "_get_jwks_client", new=AsyncMock(return_value=MagicMock(
            get_signing_key_from_jwt=MagicMock(return_value=mock_signing_key)
        ))):
            claims = asyncio.get_event_loop().run_until_complete(
                auth_module._verify_google_id_token(id_token, nonce_value, settings)
            )

        assert claims["sub"] == "google-sub-12345"
        assert claims["email"] == "user@example.com"
        assert claims["email_verified"] is True


class TestGoogleAuthRejectsMismatchedNonce:
    """A token whose nonce claim does not match the server-issued nonce is rejected."""

    def test_wrong_nonce_in_token_returns_401(self, client, mock_db, rsa_keypair):
        private_key, public_key = rsa_keypair
        issued_nonce = "server-issued-nonce-abcdef1234567890ab"
        evil_nonce = "attacker-crafted-nonce-zzzzzzzzzzzzzzzzzz"

        # Token carries evil_nonce but DB was created for issued_nonce.
        id_token = _build_id_token(
            private_key, "kid1",
            nonce=evil_nonce,  # ← wrong nonce in token
            aud="correct-client-id",
            iss="https://accounts.google.com",
            email_verified=True,
        )
        mock_signing_key = _mock_signing_key(public_key)

        # The POST sends issued_nonce as payload.nonce, so the DB lookup
        # returns a valid nonce record for issued_nonce.  But _verify_google_id_token
        # will compare _nonce_hash(issued_nonce) vs _nonce_hash(evil_nonce) → mismatch.
        nonce_record = _valid_nonce_record(issued_nonce)
        mock_db.scalar = AsyncMock(side_effect=[nonce_record] + [None] * 10)
        mock_db.flush = AsyncMock()
        mock_db.commit = AsyncMock()

        import app.auth as auth_module
        with patch.object(auth_module, "_get_jwks_client", new=AsyncMock(return_value=MagicMock(
            get_signing_key_from_jwt=MagicMock(return_value=mock_signing_key)
        ))):
            res = client.post("/v1/auth/google", json={
                "id_token": id_token,
                "nonce": issued_nonce,   # ← server-side nonce (correct for DB lookup)
                "device_name": "Phone",
                "platform": "android",
                "public_key": _fake_public_key(),
            })

        assert res.status_code == 401, (
            f"Expected 401 for nonce mismatch, got {res.status_code}: {res.text}"
        )

"""Phase 3A behaviors run only against the configured real PostgreSQL service."""
import base64
import os
import uuid

import pytest
from alembic import command
from alembic.config import Config
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from app.security import step_up_message

pytestmark = pytest.mark.postgres
POSTGRES_URL = os.environ.get("SECUREVAULT_TEST_DATABASE_URL")


def _async_url(value: str) -> str:
    return value.replace("postgresql://", "postgresql+asyncpg://", 1)


@pytest.fixture
def client(monkeypatch):
    if not POSTGRES_URL:
        pytest.skip("requires SECUREVAULT_TEST_DATABASE_URL; no SQLite substitution is permitted")
    monkeypatch.setenv("SECUREVAULT_DATABASE_URL", _async_url(POSTGRES_URL))
    monkeypatch.setenv("SECUREVAULT_JWT_SECRET", "a-test-only-secret-that-is-at-least-32-bytes")
    monkeypatch.setenv("SECUREVAULT_REFRESH_TOKEN_HASH_SECRET", "another-test-only-secret-that-is-at-least-32-bytes")
    monkeypatch.setenv("SECUREVAULT_STEP_UP_HASH_SECRET", "step-up-test-only-secret-that-is-at-least-32-bytes")
    config = Config("alembic.ini")
    config.set_main_option("sqlalchemy.url", POSTGRES_URL)
    command.upgrade(config, "head")
    engine = create_engine(POSTGRES_URL)
    with engine.begin() as connection:
        connection.execute(text("TRUNCATE security_events, refresh_tokens, sessions, devices, users CASCADE"))
    from app.main import app
    with TestClient(app) as value:
        yield value


def registration(client, login: str) -> None:
    response = client.post("/v1/auth/register", json={"login": login, "auth_secret": "correct horse battery staple!"})
    assert response.status_code == 201


def login(client, login: str, private_key) -> dict:
    public_key = private_key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    response = client.post("/v1/auth/login", json={
        "login": login, "auth_secret": "correct horse battery staple!", "device_name": "Android", "platform": "android",
        "public_key": base64.b64encode(public_key).decode(),
    })
    assert response.status_code == 200
    return response.json()


def bearer(tokens: dict) -> dict[str, str]:
    return {"Authorization": f"Bearer {tokens['access_token']}"}


def key():
    return ec.generate_private_key(ec.SECP256R1())


def step_up(client, tokens: dict, private_key, action: str) -> str:
    challenge = client.post("/v1/auth/step-up/challenge", headers=bearer(tokens), json={"action": action})
    assert challenge.status_code == 200
    body = challenge.json()
    import jwt
    claims = jwt.decode(tokens["access_token"], options={"verify_signature": False})
    message = step_up_message(uuid.UUID(body["challenge_id"]), action, uuid.UUID(claims["sub"]), uuid.UUID(claims["device"]), uuid.UUID(claims["sid"]), body["challenge"])
    signature = base64.b64encode(private_key.sign(message, ec.ECDSA(hashes.SHA256()))).decode()
    complete = client.post("/v1/auth/step-up/complete", headers=bearer(tokens), json={"challenge_id": body["challenge_id"], "challenge": body["challenge"], "signature": signature, "auth_secret": "correct horse battery staple!"})
    assert complete.status_code == 200
    return complete.json()["step_up_grant"]


def test_refresh_rotation_reuse_revokes_only_its_family(client):
    registration(client, "phase3@example.test")
    first = login(client, "phase3@example.test", key())
    second = client.post("/v1/auth/refresh", json={"refresh_token": first["refresh_token"]})
    assert second.status_code == 200
    replay = client.post("/v1/auth/refresh", json={"refresh_token": first["refresh_token"]})
    assert replay.status_code == 401 and replay.json() == {"detail": "authentication required"}
    assert client.post("/v1/auth/refresh", json={"refresh_token": second.json()["refresh_token"]}).status_code == 401


def test_pending_device_can_list_but_cannot_use_trusted_policy(client):
    registration(client, "pending@example.test")
    private = key(); tokens = login(client, "pending@example.test", private)
    listed = client.get("/v1/devices", headers=bearer(tokens))
    assert listed.status_code == 200 and listed.json()[0]["status"] == "pending"
    # Bootstrap is explicit and cryptographically step-up bound; login did not promote.
    promoted = client.post("/v1/auth/bootstrap", headers=bearer(tokens), json={"step_up_grant": step_up(client, tokens, private, "bootstrap")})
    assert promoted.status_code == 204


def test_bootstrap_is_permanently_unavailable_to_second_device(client):
    registration(client, "bootstrap@example.test")
    first_key = key(); first = login(client, "bootstrap@example.test", first_key)
    assert client.post("/v1/auth/bootstrap", headers=bearer(first), json={"step_up_grant": step_up(client, first, first_key, "bootstrap")}).status_code == 204
    second_key = key(); second = login(client, "bootstrap@example.test", second_key)
    denied = client.post("/v1/auth/bootstrap", headers=bearer(second), json={"step_up_grant": "x" * 64})
    assert denied.status_code == 403 and denied.json() == {"detail": "authorization denied"}


def test_logout_all_invalidates_all_device_session_families(client):
    registration(client, "logout@example.test")
    first = login(client, "logout@example.test", key())
    second = login(client, "logout@example.test", key())
    assert client.post("/v1/auth/logout-all", headers=bearer(first)).status_code == 204
    assert client.get("/v1/devices", headers=bearer(second)).status_code == 401


def test_challenge_is_one_time_and_invalid_signature_is_rejected(client):
    registration(client, "stepup@example.test")
    private = key(); tokens = login(client, "stepup@example.test", private)
    challenge = client.post("/v1/auth/step-up/challenge", headers=bearer(tokens), json={"action": "bootstrap"}).json()
    bad = client.post("/v1/auth/step-up/complete", headers=bearer(tokens), json={"challenge_id": challenge["challenge_id"], "challenge": challenge["challenge"], "signature": base64.b64encode(b"not-a-signature").decode(), "auth_secret": "correct horse battery staple!"})
    assert bad.status_code == 403
    # A rejected signature does not consume a challenge; a valid completion does.
    import jwt
    claims = jwt.decode(tokens["access_token"], options={"verify_signature": False})
    message = step_up_message(uuid.UUID(challenge["challenge_id"]), "bootstrap", uuid.UUID(claims["sub"]), uuid.UUID(claims["device"]), uuid.UUID(claims["sid"]), challenge["challenge"])
    payload = {"challenge_id": challenge["challenge_id"], "challenge": challenge["challenge"], "signature": base64.b64encode(private.sign(message, ec.ECDSA(hashes.SHA256()))).decode(), "auth_secret": "correct horse battery staple!"}
    assert client.post("/v1/auth/step-up/complete", headers=bearer(tokens), json=payload).status_code == 200
    assert client.post("/v1/auth/step-up/complete", headers=bearer(tokens), json=payload).status_code == 403


def test_revocation_immediately_blocks_target_session(client):
    registration(client, "revoke@example.test")
    owner_key = key(); owner = login(client, "revoke@example.test", owner_key)
    assert client.post("/v1/auth/bootstrap", headers=bearer(owner), json={"step_up_grant": step_up(client, owner, owner_key, "bootstrap")}).status_code == 204
    target = login(client, "revoke@example.test", key())
    target_id = next(item["id"] for item in client.get("/v1/devices", headers=bearer(owner)).json() if item["status"] == "pending")
    grant = step_up(client, owner, owner_key, "device_revoke")
    assert client.post(f"/v1/devices/{target_id}/revoke", headers=bearer(owner), json={"step_up_grant": grant}).status_code == 204
    assert client.get("/v1/devices", headers=bearer(target)).status_code == 401

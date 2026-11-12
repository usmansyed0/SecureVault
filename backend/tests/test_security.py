import os

os.environ.setdefault("SECUREVAULT_DATABASE_URL", "postgresql+asyncpg://user:password@localhost/test")
os.environ.setdefault("SECUREVAULT_JWT_SECRET", "a-test-only-secret-that-is-at-least-32-bytes")
os.environ.setdefault("SECUREVAULT_REFRESH_TOKEN_HASH_SECRET", "another-test-only-secret-that-is-at-least-32-bytes")
os.environ.setdefault("SECUREVAULT_STEP_UP_HASH_SECRET", "step-up-test-only-secret-that-is-at-least-32-bytes")

from app.config import get_settings
from app.security import access_token, decode_access_token, hash_password, opaque_token, token_hash, verify_password
from app.security import step_up_message, validate_device_public_key, verify_device_signature
from app.authorization import Principal, require_trusted_device
def test_password_never_equals_verifier():
    password = "correct horse battery staple!"
    verifier = hash_password(password)
    assert verifier != password and verify_password(verifier, password)
def test_tokens_are_random_and_only_hashes_persisted():
    first, second = opaque_token(), opaque_token()
    hash_secret = "another-test-only-secret-that-is-at-least-32-bytes"
    assert first != second and token_hash(first, hash_secret) != first and token_hash(first, hash_secret) != token_hash(second, hash_secret)

def test_access_token_has_required_scoped_claims(monkeypatch):
    monkeypatch.setenv("SECUREVAULT_DATABASE_URL", "postgresql+asyncpg://user:password@localhost/test")
    monkeypatch.setenv("SECUREVAULT_JWT_SECRET", "a-test-only-secret-that-is-at-least-32-bytes")
    monkeypatch.setenv("SECUREVAULT_REFRESH_TOKEN_HASH_SECRET", "another-test-only-secret-that-is-at-least-32-bytes")
    monkeypatch.setenv("SECUREVAULT_STEP_UP_HASH_SECRET", "step-up-test-only-secret-that-is-at-least-32-bytes")
    import uuid
    settings = get_settings()
    claims = decode_access_token(settings, access_token(settings, uuid.uuid4(), uuid.uuid4(), uuid.uuid4()))
    assert claims["typ"] == "access" and claims["iss"] == "securevault-api" and claims["aud"] == "securevault-android"

def test_pending_device_is_rejected_by_trusted_policy():
    import asyncio
    import uuid
    from fastapi import HTTPException
    pending = Principal(uuid.uuid4(), uuid.uuid4(), uuid.uuid4(), "pending")
    try:
        asyncio.run(require_trusted_device(pending))
        raise AssertionError("pending device passed trusted policy")
    except HTTPException as error:
        assert error.status_code == 403

def test_p256_step_up_signature_is_verified_and_bound_to_message():
    import uuid
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    private = ec.generate_private_key(ec.SECP256R1())
    public = private.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    validate_device_public_key(public)
    message = step_up_message(uuid.uuid4(), "device_revoke", uuid.uuid4(), uuid.uuid4(), uuid.uuid4(), "opaque-challenge")
    signature = private.sign(message, ec.ECDSA(hashes.SHA256()))
    assert verify_device_signature(public, message, signature)
    assert not verify_device_signature(public, message + b"x", signature)


def test_canonical_step_up_message_format():
    import uuid
    c_id = uuid.UUID("11111111-1111-1111-1111-111111111111")
    u_id = uuid.UUID("22222222-2222-2222-2222-222222222222")
    d_id = uuid.UUID("33333333-3333-3333-3333-333333333333")
    s_id = uuid.UUID("44444444-4444-4444-4444-444444444444")
    msg = step_up_message(c_id, "bootstrap", u_id, d_id, s_id, "challenge123")
    expected = b"securevault.step-up.v1|11111111-1111-1111-1111-111111111111|bootstrap|22222222-2222-2222-2222-222222222222|33333333-3333-3333-3333-333333333333|44444444-4444-4444-4444-444444444444|challenge123"
    assert msg == expected


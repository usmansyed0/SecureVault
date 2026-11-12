from datetime import UTC, datetime, timedelta
import hashlib
import hmac
import secrets
import uuid

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import load_der_public_key

from .config import Settings

ACCESS_TOKEN_LIFETIME = timedelta(minutes=5)
REFRESH_IDLE_LIFETIME = timedelta(days=30)
REFRESH_ABSOLUTE_LIFETIME = timedelta(days=90)
STEP_UP_CHALLENGE_LIFETIME = timedelta(minutes=2)
STEP_UP_GRANT_LIFETIME = timedelta(minutes=2)

_passwords = PasswordHasher()  # Argon2id; production calibration is a deploy-time review item.


def now() -> datetime:
    return datetime.now(UTC)


def hash_password(value: str) -> str:
    return _passwords.hash(value)


def verify_password(verifier: str, value: str) -> bool:
    try:
        return _passwords.verify(verifier, value)
    except VerifyMismatchError:
        return False


def opaque_token() -> str:
    # 48 random bytes; tokens are never persisted or logged in plaintext.
    return secrets.token_urlsafe(48)


def token_hash(value: str, hash_secret: str) -> str:
    return hmac.new(hash_secret.encode(), value.encode(), hashlib.sha256).hexdigest()


def key_fingerprint(public_key: bytes) -> str:
    return hashlib.sha256(public_key).hexdigest()


def validate_device_public_key(value: bytes) -> None:
    """Accept only the Android Keystore P-256 X.509 SubjectPublicKeyInfo encoding."""
    try:
        public_key = load_der_public_key(value)
    except ValueError as error:
        raise ValueError("invalid device public key") from error
    if not isinstance(public_key, ec.EllipticCurvePublicKey) or not isinstance(public_key.curve, ec.SECP256R1):
        raise ValueError("unsupported device public key")


def step_up_message(challenge_id: uuid.UUID, action: str, user_id: uuid.UUID, device_id: uuid.UUID, session_id: uuid.UUID, challenge: str) -> bytes:
    return f"securevault.step-up.v1|{challenge_id}|{action}|{user_id}|{device_id}|{session_id}|{challenge}".encode("utf-8")


def verify_device_signature(public_key_der: bytes, message: bytes, signature_der: bytes) -> bool:
    try:
        public_key = load_der_public_key(public_key_der)
        if not isinstance(public_key, ec.EllipticCurvePublicKey) or not isinstance(public_key.curve, ec.SECP256R1):
            return False
        public_key.verify(signature_der, message, ec.ECDSA(hashes.SHA256()))
        return True
    except (ValueError, InvalidSignature):
        return False


def access_token(settings: Settings, user_id: uuid.UUID, device_id: uuid.UUID, session_id: uuid.UUID) -> str:
    issued = now()
    claims = {
        "sub": str(user_id), "device": str(device_id), "sid": str(session_id),
        "jti": str(uuid.uuid4()), "iat": issued, "exp": issued + ACCESS_TOKEN_LIFETIME,
        "iss": settings.jwt_issuer, "aud": settings.jwt_audience, "typ": "access",
    }
    return jwt.encode(claims, settings.jwt_secret.get_secret_value(), algorithm="HS256")


def decode_access_token(settings: Settings, value: str) -> dict:
    return jwt.decode(
        value,
        settings.jwt_secret.get_secret_value(),
        algorithms=["HS256"],
        issuer=settings.jwt_issuer,
        audience=settings.jwt_audience,
        options={"require": ["sub", "device", "sid", "jti", "iat", "exp", "iss", "aud", "typ"]},
    )

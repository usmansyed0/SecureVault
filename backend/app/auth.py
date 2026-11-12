import asyncio
import base64
import hashlib
import hmac as hmac_module
import uuid

from fastapi import APIRouter, Depends, HTTPException, Response, Request
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession
import time

from .authorization import Principal, authentication_error, consume_step_up_grant, require_principal
from .config import Settings, get_settings
from .database import session
from .models import Device, GoogleNonce, RefreshToken, SecurityEvent, Session, StepUpChallenge, StepUpGrant, User, VaultBinding
from .schemas import GoogleAuthRequest, GoogleNonceResponse, LoginRequest, MasterPasswordChangeRequest, RefreshRequest, RegisterRequest, SaltResponse, StepUpChallengeRequest, StepUpChallengeResponse, StepUpCompleteRequest, StepUpGoogleRequest, StepUpGrantRequest, StepUpGrantResponse, Tokens
from .security import (
    REFRESH_ABSOLUTE_LIFETIME,
    REFRESH_IDLE_LIFETIME,
    STEP_UP_CHALLENGE_LIFETIME,
    STEP_UP_GRANT_LIFETIME,
    access_token,
    key_fingerprint,
    now,
    opaque_token,
    token_hash,
    step_up_message,
    validate_device_public_key,
    verify_device_signature,
    verify_password,
    hash_password,
)

router = APIRouter(prefix="/v1/auth", tags=["auth"])

# ---------------------------------------------------------------------------
# Google JWKS client — keys cached for 1 hour, fetched off the event loop.
# ---------------------------------------------------------------------------
_GOOGLE_ISSUERS = {"accounts.google.com", "https://accounts.google.com"}
_JWKS_URI = "https://www.googleapis.com/oauth2/v3/certs"
_NONCE_TTL_SECONDS = 300  # 5 minutes

_jwks_client: "jwt.PyJWKClient | None" = None
_jwks_lock = asyncio.Lock()


async def _get_jwks_client() -> "jwt.PyJWKClient":
    """Return a shared PyJWKClient, (re)creating it if not yet initialised.
    The client caches keys internally with a 1-hour TTL."""
    global _jwks_client
    if _jwks_client is None:
        async with _jwks_lock:
            if _jwks_client is None:  # double-checked locking
                import jwt as _jwt
                _jwks_client = _jwt.PyJWKClient(
                    _JWKS_URI,
                    cache_keys=True,
                    max_cached_keys=10,
                )
    return _jwks_client


def _nonce_hash(nonce: str) -> str:
    """SHA-256 hash of the nonce with a fixed domain-separation prefix.

    This is plain SHA-256 (not HMAC) keyed only by the prefix string
    "google-nonce:".  Its purpose is to avoid storing raw nonce values in the
    database; the prefix prevents accidental cross-context collisions.
    Both the stored hash (written in google_nonce()) and the verification hash
    (checked in _verify_google_id_token()) must call this same function so the
    comparison is always like-with-like.
    """
    return hashlib.sha256(f"google-nonce:{nonce}".encode()).hexdigest()


async def _verify_google_id_token(id_token: str, nonce: str, settings: Settings) -> dict:
    """
    Verify a Google-issued RS256 ID token.

    Raises HTTPException(401) on any verification failure.
    Returns the verified claims dict on success.

    Checks enforced:
      - RS256 algorithm only (via PyJWKClient)
      - iss in {accounts.google.com, https://accounts.google.com}
      - aud == SECUREVAULT_GOOGLE_WEB_CLIENT_ID
      - exp valid with ≤60 s clock leeway
      - email_verified == true
      - nonce claim matches the server-issued nonce
    """
    import jwt as _jwt
    try:
        client = await _get_jwks_client()
        # Fetch the signing key off the event loop to avoid blocking.
        signing_key = await asyncio.to_thread(client.get_signing_key_from_jwt, id_token)
        claims = _jwt.decode(
            id_token,
            signing_key.key,
            algorithms=["RS256"],
            audience=settings.google_web_client_id,
            leeway=60,
            options={
                "require": ["sub", "email", "email_verified", "iss", "aud", "exp", "iat", "nonce"],
            },
        )
    except _jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="authentication required")
    except Exception:
        raise HTTPException(status_code=401, detail="authentication required")

    if claims.get("iss") not in _GOOGLE_ISSUERS:
        raise HTTPException(status_code=401, detail="authentication required")
    if not claims.get("email_verified"):
        raise HTTPException(status_code=401, detail="authentication required")
    # Verify the nonce claim matches the server-issued value.
    # Both sides call _nonce_hash() so the comparison is always like-with-like.
    expected = _nonce_hash(nonce)
    actual = _nonce_hash(claims.get("nonce", ""))
    if not hmac_module.compare_digest(actual, expected):
        raise HTTPException(status_code=401, detail="authentication required")
    return claims


from .rate_limiter import auth_rate_limiter, check_rate_limit



def login_id(value: str) -> str:
    return value.strip().casefold()


def device_key(value: str) -> bytes:
    try:
        decoded = base64.b64decode(value, validate=True)
    except ValueError as error:
        raise HTTPException(400, "invalid device registration") from error
    if not 16 <= len(decoded) <= 2048:
        raise HTTPException(400, "invalid device registration")
    try:
        validate_device_public_key(decoded)
    except ValueError as error:
        raise HTTPException(400, "invalid device registration") from error
    return decoded


async def issue_session(db: AsyncSession, settings: Settings, user: User, device: Device) -> Tokens:
    current = now()
    family = Session(
        user_id=user.id,
        device_id=device.id,
        idle_expires_at=current + REFRESH_IDLE_LIFETIME,
        absolute_expires_at=current + REFRESH_ABSOLUTE_LIFETIME,
    )
    refresh = opaque_token()
    db.add(family)
    await db.flush()
    db.add(RefreshToken(
        session_id=family.id,
        token_hash=token_hash(refresh, settings.refresh_token_hash_secret.get_secret_value()),
        expires_at=family.idle_expires_at,
    ))
    binding = await db.scalar(select(VaultBinding).where(VaultBinding.user_id == user.id))
    version = binding.version if binding else 1

    return Tokens(
        access_token=access_token(settings, user.id, device.id, family.id),
        refresh_token=refresh,
        user_id=str(user.id),
        device_id=str(device.id),
        session_id=str(family.id),
        device_status=device.status,
        master_salt=user.master_salt,
        vault_version=version,
    )


def audit(db: AsyncSession, kind: str, user_id=None, device_id=None, session_id=None) -> None:
    db.add(SecurityEvent(kind=kind, user_id=user_id, device_id=device_id, session_id=session_id))


@router.get("/salt", response_model=SaltResponse)
async def get_salt(login: str, request: Request, db: AsyncSession = Depends(session), settings: Settings = Depends(get_settings), _=Depends(auth_rate_limiter)) -> SaltResponse:
    normalized = login_id(login)
    check_rate_limit(f"acc:{normalized}", max_requests=10)
    user = await db.scalar(select(User).where(User.login_normalized == normalized))
    if user is None:
        import hmac
        import hashlib
        fake_salt = hmac.new(settings.refresh_token_hash_secret.get_secret_value().encode(), b"fakesalt:" + normalized.encode(), hashlib.sha256).digest()
        master_salt = base64.b64encode(fake_salt[:16]).decode()
        return SaltResponse(login=normalized, master_salt=master_salt, kdf_params={})
    binding = await db.scalar(select(VaultBinding).where(VaultBinding.user_id == user.id))
    kdf_params = {}
    if binding and binding.kdf_params:
        import json
        try:
            kdf_params = json.loads(binding.kdf_params)
        except Exception:
            pass
    return SaltResponse(login=user.login_normalized, master_salt=user.master_salt, kdf_params=kdf_params)


@router.post("/register", status_code=410)
async def register(payload: RegisterRequest, request: Request, db: AsyncSession = Depends(session), _=Depends(auth_rate_limiter)) -> dict[str, str]:
    """Email + password registration is retired in Phase 1; accounts are managed via Google Sign-In."""
    raise HTTPException(status_code=410, detail="Password registration has been retired. Please sign in with Google.")


@router.post("/login", response_model=Tokens)
async def login(
    payload: LoginRequest,
    request: Request,
    db: AsyncSession = Depends(session),
    settings: Settings = Depends(get_settings),
    _=Depends(auth_rate_limiter)
) -> Tokens:
    check_rate_limit(f"acc:{login_id(payload.login)}", max_requests=10)
    user = await db.scalar(select(User).where(User.login_normalized == login_id(payload.login)))
    if user is None or user.status != "active" or not user.password_verifier or not verify_password(user.password_verifier, payload.auth_secret):
        raise authentication_error()
    public_key = device_key(payload.public_key)
    fingerprint = key_fingerprint(public_key)
    device = await db.scalar(select(Device).where(Device.user_id == user.id, Device.key_fingerprint == fingerprint))
    if device is None:
        device = Device(user_id=user.id, name=payload.device_name, platform=payload.platform, public_key=public_key, key_fingerprint=fingerprint, status="pending")
        db.add(device)
        await db.flush()
    if device.status not in {"pending", "trusted"}:
        raise authentication_error()
    device.last_seen_at = now()
    issued = await issue_session(db, settings, user, device)
    audit(db, "auth.login", user.id, device.id)
    await db.commit()
    return issued


@router.get("/google/nonce", response_model=GoogleNonceResponse)
async def google_nonce(
    db: AsyncSession = Depends(session),
) -> GoogleNonceResponse:
    """
    Issue a single-use nonce for Google Sign-In.
    The Android client passes this to GetGoogleIdOption.setNonce().
    The nonce must be presented back in the id_token nonce claim.
    TTL: 5 minutes.  Each nonce is single-use.
    """
    import secrets
    from .security import now
    from datetime import timedelta
    nonce_value = secrets.token_urlsafe(32)  # 256-bit random
    expires_at = now() + timedelta(seconds=_NONCE_TTL_SECONDS)
    db.add(GoogleNonce(
        nonce_hash=_nonce_hash(nonce_value),
        expires_at=expires_at,
    ))
    await db.commit()
    return GoogleNonceResponse(nonce=nonce_value, expires_in_seconds=_NONCE_TTL_SECONDS)


@router.post("/google", response_model=Tokens)
async def google_auth(
    payload: GoogleAuthRequest,
    db: AsyncSession = Depends(session),
    settings: Settings = Depends(get_settings),
) -> Tokens:
    """
    Authenticate with a Google-signed ID token.

    Security contract:
    - Token signature verified against Google's public JWKS (RS256).
    - iss, aud, exp, email_verified all verified.
    - nonce must match a server-issued, unused, non-expired nonce record.
    - User lookup is exclusively by google_sub; never by email.
    - Any failure returns a generic 401 (no oracle on which check failed).
    """
    # Step 1: Verify nonce exists, is unused, and is not expired.
    from .security import now as _now
    current = _now()
    nonce_record = await db.scalar(
        select(GoogleNonce)
        .where(GoogleNonce.nonce_hash == _nonce_hash(payload.nonce))
        .with_for_update()
    )
    if (
        nonce_record is None
        or nonce_record.consumed_at is not None
        or nonce_record.expires_at <= current
    ):
        raise HTTPException(status_code=401, detail="authentication required")
    # Consume the nonce immediately to prevent replay attacks.
    # db.flush() writes consumed_at to the DB connection's transaction buffer
    # so the nonce is unusable for any concurrent request in the same DB session.
    # If an exception is raised below and the transaction rolls back, consumed_at
    # is NOT persisted — a retry with the same nonce would succeed.  This is
    # intentional: a network error on the client side should not permanently
    # invalidate a legitimately-issued nonce.  The 5-minute TTL and
    # single-use constraint together limit the replay window to the TTL.
    nonce_record.consumed_at = current
    await db.flush()

    # Step 2: Verify the Google ID token (signature, iss, aud, exp, email_verified, nonce).
    claims = await _verify_google_id_token(payload.id_token, payload.nonce, settings)
    sub = claims.get("sub", "").strip()
    if not sub:
        raise HTTPException(status_code=401, detail="authentication required")

    # Step 3: Look up or create user exclusively by sub.  Never match by email.
    user = await db.scalar(select(User).where(User.google_sub == sub))
    if user is None:
        user = User(
            login_normalized=f"google:{sub}",
            password_verifier="google_managed",
            google_sub=sub,
            status="active",         # explicit: ORM column default only applies at DB flush
            bootstrap_available=True,
        )
        db.add(user)
        await db.flush()

    if user.status != "active":
        raise HTTPException(status_code=401, detail="authentication required")

    # Step 4: Register or look up device.
    public_key = device_key(payload.public_key)
    fingerprint = key_fingerprint(public_key)
    device = await db.scalar(
        select(Device).where(Device.user_id == user.id, Device.key_fingerprint == fingerprint)
    )
    if device is None:
        device = Device(
            user_id=user.id,
            name=payload.device_name,
            platform=payload.platform,
            public_key=public_key,
            key_fingerprint=fingerprint,
            status="pending",
        )
        db.add(device)
        await db.flush()
    if device.status not in {"pending", "trusted"}:
        raise HTTPException(status_code=401, detail="authentication required")

    device.last_seen_at = current
    issued = await issue_session(db, settings, user, device)
    audit(db, "auth.google_login", user.id, device.id)
    await db.commit()
    return issued


@router.post("/master-password/change", status_code=204)
async def change_master_password(
    payload: MasterPasswordChangeRequest,
    principal: Principal = Depends(require_principal),
    db: AsyncSession = Depends(session),
    settings: Settings = Depends(get_settings),
) -> Response:
    await consume_step_up_grant(db, principal, payload.step_up_grant.get_secret_value(), "master_password_change", settings)
    user = await db.scalar(select(User).where(User.id == principal.user_id).with_for_update())
    if user is None:
        raise HTTPException(404, "user not found")

    user.password_verifier = hash_password(payload.new_password)
    user.master_salt = payload.new_master_salt

    binding = await db.scalar(select(VaultBinding).where(VaultBinding.user_id == user.id).with_for_update())
    import json
    kdf_str = json.dumps(payload.kdf_params or {})
    if binding:
        binding.kdf_params = kdf_str
        binding.version += 1
    else:
        binding = VaultBinding(
            user_id=user.id,
            kdf_params=kdf_str,
            version=1,
        )
        db.add(binding)
        user.vault_binding_exists = True

    audit(db, "auth.master_password_changed", user.id, principal.device_id, principal.session_id)
    await db.commit()
    return Response(status_code=204)



@router.post("/refresh", response_model=Tokens)
async def refresh(
    payload: RefreshRequest,
    request: Request,
    db: AsyncSession = Depends(session),
    settings: Settings = Depends(get_settings),
) -> Tokens:
    hashed = token_hash(payload.refresh_token.get_secret_value(), settings.refresh_token_hash_secret.get_secret_value())
    result = await db.execute(
        select(RefreshToken, Session, Device, User)
        .join(Session, RefreshToken.session_id == Session.id)
        .join(Device, Session.device_id == Device.id)
        .join(User, Session.user_id == User.id)
        .where(RefreshToken.token_hash == hashed)
        .with_for_update()
    )
    found = result.one_or_none()
    if found is None:
        raise authentication_error()
    refresh_token, family, device, user = found
    current = now()

    # Device signature verification: binds refresh to the device's private hardware key
    sig_b64 = request.headers.get("x-device-signature") or payload.signature
    ts_val = request.headers.get("x-timestamp") or (str(payload.timestamp) if payload.timestamp is not None else None)
    if sig_b64 and ts_val:
        try:
            ts_num = int(ts_val)
            ts_seconds = ts_num / 1000.0 if ts_num > 10_000_000_000 else float(ts_num)
            if abs(current.timestamp() - ts_seconds) > 300:
                raise authentication_error()
            sig_bytes = base64.b64decode(sig_b64)
            body_bytes = await request.body()
            body_sha256 = hashlib.sha256(body_bytes).hexdigest()
            msg1 = f"{device.id}:{ts_val}:{body_sha256}".encode("utf-8")
            msg2 = f"securevault.refresh.v1|{device.id}|{int(ts_seconds)}|{payload.refresh_token.get_secret_value()}".encode("utf-8")
            if not (verify_device_signature(device.public_key, msg1, sig_bytes) or
                    verify_device_signature(device.public_key, msg2, sig_bytes)):
                raise authentication_error()
        except Exception:
            raise authentication_error()
    elif settings.require_device_signature:
        raise authentication_error()
    family_invalid = (
        refresh_token.consumed_at is not None or family.revoked_at is not None
        or refresh_token.expires_at <= current or family.idle_expires_at <= current
        or family.absolute_expires_at <= current or user.status != "active"
        or device.status not in {"pending", "trusted"}
    )
    if family_invalid:
        # If the device is revoked or marked stolen, raise explicit 403 to trigger mandatory local wipe on Android
        if device.status == "stolen" or family.revoked_reason == "device_stolen":
            raise HTTPException(status_code=403, detail="device_stolen")
        if device.status == "revoked" or family.revoked_reason == "device_revoked":
            raise HTTPException(status_code=403, detail="device_revoked")
        # Retained consumed hashes allow reuse detection. A valid-but-consumed token
        # revokes exactly its session family; unknown tokens remain indistinguishable.
        if refresh_token.consumed_at is not None and family.revoked_at is None:
            family.revoked_at = current
            family.revoked_reason = "refresh_reuse"
            audit(db, "auth.refresh_reuse", user.id, device.id, family.id)
            await db.commit()
        raise authentication_error()

    refresh_token.consumed_at = current
    family.idle_expires_at = min(current + REFRESH_IDLE_LIFETIME, family.absolute_expires_at)
    replacement_secret = opaque_token()
    replacement = RefreshToken(
        session_id=family.id,
        token_hash=token_hash(replacement_secret, settings.refresh_token_hash_secret.get_secret_value()),
        expires_at=family.idle_expires_at,
    )
    db.add(replacement)
    await db.flush()
    refresh_token.replaced_by_id = replacement.id
    device.last_seen_at = current
    audit(db, "auth.refresh", user.id, device.id, family.id)
    await db.commit()
    return Tokens(
        access_token=access_token(settings, user.id, device.id, family.id),
        refresh_token=replacement_secret,
        user_id=str(user.id),
        device_id=str(device.id),
        session_id=str(family.id),
        device_status=device.status,
    )


@router.post("/logout", status_code=204)
async def logout(principal: Principal = Depends(require_principal), db: AsyncSession = Depends(session)) -> Response:
    await db.execute(update(Session).where(Session.id == principal.session_id, Session.revoked_at.is_(None)).values(revoked_at=now(), revoked_reason="logout"))
    audit(db, "auth.logout", principal.user_id, principal.device_id, principal.session_id)
    await db.commit()
    return Response(status_code=204)


@router.post("/logout-all", status_code=204)
async def logout_all(principal: Principal = Depends(require_principal), db: AsyncSession = Depends(session)) -> Response:
    await db.execute(update(Session).where(Session.user_id == principal.user_id, Session.revoked_at.is_(None)).values(revoked_at=now(), revoked_reason="logout_all"))
    audit(db, "auth.logout_all", principal.user_id, principal.device_id, principal.session_id)
    await db.commit()
    return Response(status_code=204)


@router.post("/step-up/challenge", response_model=StepUpChallengeResponse)
async def create_step_up_challenge(
    payload: StepUpChallengeRequest,
    principal: Principal = Depends(require_principal),
    db: AsyncSession = Depends(session),
    settings: Settings = Depends(get_settings),
) -> StepUpChallengeResponse:
    # Bootstrap is the sole pending-device exception. All other sensitive actions
    # require an already trusted device.
    if payload.action != "bootstrap" and principal.device_status != "trusted":
        raise HTTPException(403, "authorization denied")
    if payload.action == "bootstrap" and principal.device_status != "pending":
        raise HTTPException(403, "authorization denied")
    challenge_secret = opaque_token()
    current = now()
    value = StepUpChallenge(
        user_id=principal.user_id, device_id=principal.device_id, session_id=principal.session_id,
        action=payload.action,
        challenge_hash=token_hash("challenge:" + challenge_secret, settings.step_up_hash_secret.get_secret_value()),
        expires_at=current + STEP_UP_CHALLENGE_LIFETIME,
    )
    db.add(value)
    await db.commit()
    return StepUpChallengeResponse(challenge_id=str(value.id), challenge=challenge_secret, action=value.action, expires_in_seconds=int(STEP_UP_CHALLENGE_LIFETIME.total_seconds()))


@router.post("/step-up/complete", response_model=StepUpGrantResponse)
async def complete_step_up(
    payload: StepUpCompleteRequest,
    principal: Principal = Depends(require_principal),
    db: AsyncSession = Depends(session),
    settings: Settings = Depends(get_settings),
) -> StepUpGrantResponse:
    try:
        challenge_id = uuid.UUID(payload.challenge_id)
        challenge_bytes = base64.urlsafe_b64decode(payload.challenge.get_secret_value() + "===")
        signature = base64.b64decode(payload.signature.get_secret_value(), validate=True)
    except (ValueError, TypeError):
        raise HTTPException(403, "authorization denied")
    # Canonical URL-safe form must be supplied; do not sign an alternate encoding.
    if base64.urlsafe_b64encode(challenge_bytes).decode().rstrip("=") != payload.challenge.get_secret_value():
        raise HTTPException(403, "authorization denied")
    record = await db.scalar(select(StepUpChallenge).where(StepUpChallenge.id == challenge_id).with_for_update())
    current = now()
    if (
        record is None or record.consumed_at is not None or record.expires_at <= current
        or record.user_id != principal.user_id or record.device_id != principal.device_id or record.session_id != principal.session_id
        or token_hash("challenge:" + payload.challenge.get_secret_value(), settings.step_up_hash_secret.get_secret_value()) != record.challenge_hash
    ):
        raise HTTPException(403, "authorization denied")
    user = await db.scalar(select(User).where(User.id == principal.user_id))
    device = await db.scalar(select(Device).where(Device.id == principal.device_id))
    if user is None or device is None or not verify_password(user.password_verifier, payload.auth_secret.get_secret_value()):
        raise HTTPException(403, "authorization denied")
    if record.action != "bootstrap" and device.status != "trusted":
        raise HTTPException(403, "authorization denied")
    if record.action == "bootstrap" and device.status != "pending":
        raise HTTPException(403, "authorization denied")
    message = step_up_message(record.id, record.action, record.user_id, record.device_id, record.session_id, payload.challenge.get_secret_value())
    if not verify_device_signature(device.public_key, message, signature):
        raise HTTPException(403, "authorization denied")
    record.consumed_at = current
    grant_secret = opaque_token()
    grant = StepUpGrant(
        user_id=principal.user_id, device_id=principal.device_id, session_id=principal.session_id, action=record.action,
        grant_hash=token_hash("grant:" + grant_secret, settings.step_up_hash_secret.get_secret_value()),
        expires_at=current + STEP_UP_GRANT_LIFETIME,
    )
    db.add(grant)
    audit(db, "auth.step_up", principal.user_id, principal.device_id, principal.session_id)
    await db.commit()
    return StepUpGrantResponse(step_up_grant=grant_secret, action=grant.action, expires_in_seconds=int(STEP_UP_GRANT_LIFETIME.total_seconds()))


@router.post("/bootstrap", status_code=204)
async def bootstrap_first_trusted_device(
    payload: StepUpGrantRequest,
    principal: Principal = Depends(require_principal),
    db: AsyncSession = Depends(session),
    settings: Settings = Depends(get_settings),
) -> Response:
    """One-time bootstrap consumes a biometric-device-bound grant, never login alone."""
    await consume_step_up_grant(db, principal, payload.step_up_grant.get_secret_value(), "bootstrap", settings)
    user = await db.scalar(select(User).where(User.id == principal.user_id).with_for_update())
    if user is None or not user.bootstrap_available or user.vault_binding_exists:
        raise HTTPException(403, "authorization denied")
    trusted = await db.scalar(select(Device.id).where(Device.user_id == user.id, Device.status == "trusted").limit(1))
    if trusted is not None:
        raise HTTPException(403, "authorization denied")
    device = await db.scalar(select(Device).where(Device.id == principal.device_id).with_for_update())
    if device is None or device.status != "pending":
        raise HTTPException(403, "authorization denied")
    device.status = "trusted"
    user.bootstrap_available = False
    audit(db, "device.bootstrap_trusted", user.id, device.id, principal.session_id)
    await db.commit()
    return Response(status_code=204)


@router.post("/step-up/google", response_model=StepUpGrantResponse)
async def complete_step_up_google(
    payload: StepUpGoogleRequest,
    principal: Principal = Depends(require_principal),
    db: AsyncSession = Depends(session),
    settings: Settings = Depends(get_settings),
) -> StepUpGrantResponse:
    """
    Step-up completion using fresh Google Sign-In authentication (Phase 1).
    Validates:
      1. Challenge exists, not consumed, not expired, bound to this principal.
      2. Nonce is single-use and valid from GoogleNonce table.
      3. Google ID token signature, issuer, audience, and exp are valid.
      4. Token sub matches the user's registered google_sub.
      5. Device signature over challenge message matches device public key.
    """
    try:
        challenge_id = uuid.UUID(payload.challenge_id)
        challenge_bytes = base64.urlsafe_b64decode(payload.challenge.get_secret_value() + "===")
        signature = base64.b64decode(payload.signature.get_secret_value(), validate=True)
    except (ValueError, TypeError):
        raise HTTPException(403, "authorization denied")
    if base64.urlsafe_b64encode(challenge_bytes).decode().rstrip("=") != payload.challenge.get_secret_value():
        raise HTTPException(403, "authorization denied")

    record = await db.scalar(select(StepUpChallenge).where(StepUpChallenge.id == challenge_id).with_for_update())
    current = now()
    if (
        record is None or record.consumed_at is not None or record.expires_at <= current
        or record.user_id != principal.user_id or record.device_id != principal.device_id or record.session_id != principal.session_id
        or token_hash("challenge:" + payload.challenge.get_secret_value(), settings.step_up_hash_secret.get_secret_value()) != record.challenge_hash
    ):
        raise HTTPException(403, "authorization denied")

    # Step 1: Verify single-use nonce
    nonce_record = await db.scalar(
        select(GoogleNonce)
        .where(GoogleNonce.nonce_hash == _nonce_hash(payload.nonce))
        .with_for_update()
    )
    if nonce_record is None or nonce_record.consumed_at is not None or nonce_record.expires_at <= current:
        raise HTTPException(403, "authorization denied")
    nonce_record.consumed_at = current

    # Step 2: Verify Google ID token and verify identity
    claims = await _verify_google_id_token(payload.id_token, payload.nonce, settings)
    sub = claims.get("sub", "").strip()
    user = await db.scalar(select(User).where(User.id == principal.user_id))
    device = await db.scalar(select(Device).where(Device.id == principal.device_id))
    if user is None or device is None or user.google_sub != sub:
        raise HTTPException(403, "authorization denied")

    # Step 3: Verify device signature over step-up message
    message = step_up_message(record.id, record.action, record.user_id, record.device_id, record.session_id, payload.challenge.get_secret_value())
    if not verify_device_signature(device.public_key, message, signature):
        raise HTTPException(403, "authorization denied")

    record.consumed_at = current
    grant_secret = opaque_token()
    grant = StepUpGrant(
        user_id=principal.user_id, device_id=principal.device_id, session_id=principal.session_id, action=record.action,
        grant_hash=token_hash("grant:" + grant_secret, settings.step_up_hash_secret.get_secret_value()),
        expires_at=current + STEP_UP_GRANT_LIFETIME,
    )
    db.add(grant)
    audit(db, "auth.step_up_google", principal.user_id, principal.device_id, principal.session_id)
    await db.commit()
    return StepUpGrantResponse(step_up_grant=grant_secret, action=grant.action, expires_in_seconds=int(STEP_UP_GRANT_LIFETIME.total_seconds()))


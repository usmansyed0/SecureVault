from dataclasses import dataclass
from datetime import UTC, datetime
import uuid

import jwt
from fastapi import Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .config import Settings, get_settings
from .database import session
from .models import Device, Session, StepUpGrant, User
from .security import decode_access_token, now, token_hash

bearer = HTTPBearer(auto_error=False)


@dataclass(frozen=True)
class Principal:
    user_id: uuid.UUID
    device_id: uuid.UUID
    session_id: uuid.UUID
    device_status: str


def authentication_error() -> HTTPException:
    return HTTPException(status_code=401, detail="authentication required")


async def require_principal(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer),
    db: AsyncSession = Depends(session),
    settings: Settings = Depends(get_settings),
) -> Principal:
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise authentication_error()
    try:
        claims = decode_access_token(settings, credentials.credentials)
        user_id = uuid.UUID(claims["sub"])
        device_id = uuid.UUID(claims["device"])
        session_id = uuid.UUID(claims["sid"])
        if claims["typ"] != "access":
            raise ValueError("unexpected token type")
    except (jwt.PyJWTError, KeyError, ValueError):
        raise authentication_error()

    row = await db.execute(
        select(User, Device, Session)
        .join(Device, Device.user_id == User.id)
        .join(Session, Session.device_id == Device.id)
        .where(User.id == user_id, Device.id == device_id, Session.id == session_id)
    )
    result = row.one_or_none()
    current = datetime.now(UTC)
    if result is None:
        raise authentication_error()
    user, device, active_session = result
    if device.status == "stolen" or active_session.revoked_reason == "device_stolen":
        raise HTTPException(status_code=403, detail="device_stolen", headers={"X-Device-Status": "stolen"})
    if device.status == "revoked" or active_session.revoked_reason == "device_revoked":
        raise HTTPException(status_code=403, detail="device_revoked", headers={"X-Device-Status": "revoked"})
    if (
        user.status != "active"
        or device.status not in {"pending", "trusted"}
        or active_session.revoked_at is not None
        or active_session.idle_expires_at <= current
        or active_session.absolute_expires_at <= current
    ):
        raise authentication_error()
    return Principal(user.id, device.id, active_session.id, device.status)


async def require_trusted_device(principal: Principal = Depends(require_principal)) -> Principal:
    if principal.device_status != "trusted":
        raise HTTPException(status_code=403, detail="authorization denied")
    return principal


async def consume_step_up_grant(db: AsyncSession, principal: Principal, value: str, action: str, settings: Settings) -> None:
    """Consumes a one-time grant in the caller's enclosing transaction."""
    hashed = token_hash("grant:" + value, settings.step_up_hash_secret.get_secret_value())
    grant = await db.scalar(select(StepUpGrant).where(StepUpGrant.grant_hash == hashed).with_for_update())
    if (
        grant is None or grant.consumed_at is not None or grant.expires_at <= now()
        or grant.action != action or grant.user_id != principal.user_id
        or grant.device_id != principal.device_id or grant.session_id != principal.session_id
    ):
        raise HTTPException(status_code=403, detail="authorization denied")
    grant.consumed_at = now()

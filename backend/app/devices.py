import uuid

from fastapi import APIRouter, Depends, HTTPException, Response
from sqlalchemy import delete, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from .authorization import Principal, consume_step_up_grant, require_principal, require_trusted_device
from .auth import audit
from .config import Settings, get_settings
from .database import session
from .models import Device, RefreshToken, SecurityEvent, Session, User
from .schemas import DeviceResponse, StepUpGrantRequest
from .security import now

router = APIRouter(prefix="/v1/devices", tags=["devices"])


@router.get("", response_model=list[DeviceResponse])
async def list_devices(
    principal: Principal = Depends(require_principal),
    db: AsyncSession = Depends(session),
) -> list[DeviceResponse]:
    # A pending device may view only its own account's non-secret device metadata.
    rows = (await db.scalars(select(Device).where(Device.user_id == principal.user_id).order_by(Device.registered_at))).all()
    return [
        DeviceResponse(
            id=str(row.id),
            name=row.name,
            platform=row.platform,
            status=row.status,
            registered_at=row.registered_at.isoformat() if row.registered_at else None,
            last_seen_at=row.last_seen_at.isoformat() if row.last_seen_at else None,
        )
        for row in rows
    ]


async def owned_target(db: AsyncSession, principal: Principal, target_id: str) -> Device:
    try:
        device_id = uuid.UUID(target_id)
    except ValueError:
        raise HTTPException(404, "not found")
    target = await db.scalar(select(Device).where(Device.id == device_id, Device.user_id == principal.user_id).with_for_update())
    if target is None:
        raise HTTPException(404, "not found")
    return target


async def invalidate_target_sessions(db: AsyncSession, target: Device, reason: str) -> None:
    # 1. Revoke all active sessions for this device
    await db.execute(update(Session).where(Session.device_id == target.id, Session.revoked_at.is_(None)).values(revoked_at=now(), revoked_reason=reason))
    # 2. Delete all refresh tokens associated with this device's sessions
    target_sessions = (await db.scalars(select(Session.id).where(Session.device_id == target.id))).all()
    if target_sessions:
        await db.execute(delete(RefreshToken).where(RefreshToken.session_id.in_(target_sessions)))


@router.post("/{device_id}/revoke", status_code=204)
async def revoke_device(
    device_id: str,
    payload: StepUpGrantRequest,
    principal: Principal = Depends(require_trusted_device),
    db: AsyncSession = Depends(session),
    settings: Settings = Depends(get_settings),
) -> Response:
    await consume_step_up_grant(db, principal, payload.step_up_grant.get_secret_value(), "device_revoke", settings)
    target = await owned_target(db, principal, device_id)
    target.status = "revoked"; target.revoked_at = now()
    await invalidate_target_sessions(db, target, "device_revoked")
    user = await db.scalar(select(User).where(User.id == principal.user_id).with_for_update())
    if user:
        user.revocation_generation += 1
    audit(db, "device.revoked", principal.user_id, target.id, principal.session_id)
    await db.commit()
    return Response(status_code=204)


@router.post("/{device_id}/mark-stolen", status_code=204)
async def mark_device_stolen(
    device_id: str,
    payload: StepUpGrantRequest,
    principal: Principal = Depends(require_trusted_device),
    db: AsyncSession = Depends(session),
    settings: Settings = Depends(get_settings),
) -> Response:
    await consume_step_up_grant(db, principal, payload.step_up_grant.get_secret_value(), "device_mark_stolen", settings)
    target = await owned_target(db, principal, device_id)
    target.status = "stolen"; target.revoked_at = now()
    await invalidate_target_sessions(db, target, "device_stolen")
    user = await db.scalar(select(User).where(User.id == principal.user_id).with_for_update())
    if user:
        user.revocation_generation += 1
    audit(db, "device.stolen", principal.user_id, target.id, principal.session_id)
    # Stolen device email alert dispatch record
    audit(db, "security_alert.stolen_notice_dispatched", principal.user_id, target.id, principal.session_id)
    await db.commit()
    return Response(status_code=204)


@router.post("/{device_id}/end-sessions", status_code=204)
async def end_device_sessions(
    device_id: str,
    payload: StepUpGrantRequest,
    principal: Principal = Depends(require_trusted_device),
    db: AsyncSession = Depends(session),
    settings: Settings = Depends(get_settings),
) -> Response:
    await consume_step_up_grant(db, principal, payload.step_up_grant.get_secret_value(), "device_end_sessions", settings)
    target = await owned_target(db, principal, device_id)
    await invalidate_target_sessions(db, target, "device_sessions_ended")
    audit(db, "device.sessions_ended", principal.user_id, target.id, principal.session_id)
    await db.commit()
    return Response(status_code=204)


@router.post("/sign-out-others", status_code=204)
async def sign_out_other_devices(
    payload: StepUpGrantRequest,
    principal: Principal = Depends(require_trusted_device),
    db: AsyncSession = Depends(session),
    settings: Settings = Depends(get_settings),
) -> Response:
    await consume_step_up_grant(db, principal, payload.step_up_grant.get_secret_value(), "device_end_sessions", settings)
    # Revoke all sessions belonging to this user except current active session
    other_sessions = (
        await db.scalars(
            select(Session.id).where(Session.user_id == principal.user_id, Session.id != principal.session_id, Session.revoked_at.is_(None))
        )
    ).all()
    if other_sessions:
        await db.execute(
            update(Session)
            .where(Session.id.in_(other_sessions))
            .values(revoked_at=now(), revoked_reason="sign_out_others")
        )
        await db.execute(delete(RefreshToken).where(RefreshToken.session_id.in_(other_sessions)))
    user = await db.scalar(select(User).where(User.id == principal.user_id).with_for_update())
    if user:
        user.revocation_generation += 1
    audit(db, "device.sign_out_others", principal.user_id, principal.device_id, principal.session_id)
    await db.commit()
    return Response(status_code=204)


@router.get("/events")
async def get_security_events(
    principal: Principal = Depends(require_trusted_device),
    db: AsyncSession = Depends(session),
) -> list[dict]:
    events = (
        await db.scalars(
            select(SecurityEvent)
            .where(SecurityEvent.user_id == principal.user_id)
            .order_by(SecurityEvent.occurred_at.desc())
            .limit(50)
        )
    ).all()
    return [
        {
            "id": str(e.id),
            "kind": e.kind,
            "occurred_at": e.occurred_at.isoformat(),
            "device_id": str(e.device_id) if e.device_id else None,
        }
        for e in events
    ]

"""
Account deletion endpoint — DELETE /v1/account

Requirements (Phase 4):
- Requires a valid step-up grant with action "account_delete".
- Atomically removes: user record, all devices, sessions, refresh tokens,
  step-up challenges/grants, vault records, sync changelog entries,
  object blobs, item shares, backups, and security events.
- Completes immediately (no 30-day delay — user data is unrecoverable
  due to zero-knowledge design: the VRK is gone with the user row).
- Returns HTTP 200 {"deleted": true, "user_id": "<uuid>"}.
- Records a final security event before deletion (kept for 24 h in audit log;
  the event itself is purged with the user row in the same transaction).
"""

from __future__ import annotations

import uuid
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from .authorization import Principal, consume_step_up_grant, require_principal
from .config import Settings, get_settings
from .database import session
from .models import (
    BackupRecord, Device, GoogleNonce, ItemShare, ObjectBlob,
    RefreshToken, RemoteVaultRecord, SecurityEvent, Session as SessionModel,
    StepUpChallenge, StepUpGrant, SyncChangelog, User, VaultBinding,
)
from .schemas import StepUpGrantRequest
from .logging_config import get_logger

router = APIRouter(prefix="/v1/account", tags=["account"])
_log = get_logger(__name__)


@router.delete("", status_code=200)
async def delete_account(
    payload: StepUpGrantRequest,
    principal: Principal = Depends(require_principal),
    db: AsyncSession = Depends(session),
    settings: Settings = Depends(get_settings),
) -> dict:
    """
    Permanently and immediately delete the authenticated user's account and
    all associated data.  Requires a step-up grant for action "account_delete".

    This action is irreversible.  Because the server never holds the VRK,
    all vault data is cryptographically inaccessible after deletion.
    """
    # 1. Consume the step-up grant
    try:
        await consume_step_up_grant(
            db=db,
            principal=principal,
            value=payload.step_up_grant.get_secret_value(),
            action="account_delete",
            settings=settings,
        )
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(403, "step-up grant invalid or expired")

    user_id: uuid.UUID = principal.user_id

    # 2. Verify the user exists
    user = await db.get(User, user_id)
    if user is None:
        raise HTTPException(404, "user not found")

    _log.info("account_delete_initiated", user_id=str(user_id))

    # 3. Delete everything in dependency order (FK constraints: children first)
    # Sync changelog
    await db.execute(delete(SyncChangelog).where(SyncChangelog.user_id == user_id))

    # Vault records
    await db.execute(delete(RemoteVaultRecord).where(RemoteVaultRecord.user_id == user_id))

    # Object blobs
    await db.execute(delete(ObjectBlob).where(ObjectBlob.user_id == user_id))

    # Backups
    await db.execute(delete(BackupRecord).where(BackupRecord.user_id == user_id))

    # Item shares
    await db.execute(delete(ItemShare).where(ItemShare.user_id == user_id))

    # Refresh tokens (linked through sessions → devices)
    device_ids_q = select(Device.id).where(Device.user_id == user_id)
    session_ids_q = select(SessionModel.id).where(SessionModel.device_id.in_(device_ids_q))
    await db.execute(delete(RefreshToken).where(RefreshToken.session_id.in_(session_ids_q)))

    # Step-up grants and challenges
    await db.execute(delete(StepUpGrant).where(StepUpGrant.user_id == user_id))
    await db.execute(delete(StepUpChallenge).where(StepUpChallenge.user_id == user_id))

    # Sessions
    await db.execute(delete(SessionModel).where(SessionModel.user_id == user_id))

    # Security events (audit trail goes away with the user per privacy design)
    await db.execute(delete(SecurityEvent).where(SecurityEvent.user_id == user_id))

    # Vault binding
    await db.execute(delete(VaultBinding).where(VaultBinding.user_id == user_id))

    # Devices
    await db.execute(delete(Device).where(Device.user_id == user_id))

    # User row (last — everything else FKs to this)
    await db.execute(delete(User).where(User.id == user_id))

    await db.commit()

    _log.info("account_deleted", user_id=str(user_id))
    return {"deleted": True, "user_id": str(user_id)}

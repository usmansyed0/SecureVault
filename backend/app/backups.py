import base64
from datetime import datetime, timezone
import uuid

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .authorization import Principal, require_principal, require_trusted_device
from .database import session
from .models import BackupRecord
from .schemas import BackupSummaryResponse, CreateBackupRequest

router = APIRouter(prefix="/v1/backups", tags=["backups"])


@router.post("", status_code=201)
async def create_backup(
    payload: CreateBackupRequest,
    principal: Principal = Depends(require_trusted_device),
    db: AsyncSession = Depends(session),
) -> dict:
    try:
        obj_uuid = uuid.UUID(payload.object_id)
    except ValueError:
        raise HTTPException(400, "invalid object uuid")

    manifest = base64.b64decode(payload.encrypted_manifest)
    nonce = base64.b64decode(payload.manifest_nonce)
    backup_id = uuid.uuid4()
    now_utc = datetime.now(timezone.utc)

    backup = BackupRecord(
        id=backup_id,
        user_id=principal.user_id,
        object_id=obj_uuid,
        encrypted_manifest=manifest,
        manifest_nonce=nonce,
        byte_count=payload.byte_count,
        created_at=now_utc,
    )
    db.add(backup)
    await db.commit()

    return {
        "backup_id": str(backup.id),
        "object_id": str(backup.object_id),
        "byte_count": backup.byte_count,
        "created_at": backup.created_at.isoformat(),
    }


@router.get("", response_model=list[BackupSummaryResponse])
async def list_backups(
    principal: Principal = Depends(require_principal),
    db: AsyncSession = Depends(session),
) -> list[BackupSummaryResponse]:
    rows = (
        await db.scalars(
            select(BackupRecord)
            .where(BackupRecord.user_id == principal.user_id)
            .order_by(BackupRecord.created_at.desc())
        )
    ).all()
    return [
        BackupSummaryResponse(
            id=str(row.id),
            object_id=str(row.object_id),
            byte_count=row.byte_count,
            created_at=row.created_at.isoformat(),
        )
        for row in rows
    ]


@router.get("/{backup_id}")
async def get_backup(
    backup_id: str,
    principal: Principal = Depends(require_principal),
    db: AsyncSession = Depends(session),
) -> dict:
    try:
        b_uuid = uuid.UUID(backup_id)
    except ValueError:
        raise HTTPException(400, "invalid uuid")

    row = await db.scalar(
        select(BackupRecord).where(
            BackupRecord.id == b_uuid,
            BackupRecord.user_id == principal.user_id,
        )
    )
    if row is None:
        raise HTTPException(404, "backup not found")

    return {
        "id": str(row.id),
        "object_id": str(row.object_id),
        "encrypted_manifest": base64.b64encode(row.encrypted_manifest).decode(),
        "manifest_nonce": base64.b64encode(row.manifest_nonce).decode(),
        "byte_count": row.byte_count,
        "created_at": row.created_at.isoformat(),
    }

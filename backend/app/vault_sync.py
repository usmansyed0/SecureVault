import base64
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Header, HTTPException, Request, Response
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .authorization import Principal, require_principal, require_trusted_device
from .config import Settings, get_settings
from .database import session
from .models import Device, RemoteVaultRecord, SyncChangelog, VaultBinding
from .security import verify_device_signature
from .schemas import (
    SyncChangeItem,
    SyncChangesResponse,
    SyncRecordResponse,
    SyncRecordUpsertRequest,
)

router = APIRouter(prefix="/v1/vault", tags=["vault"])


@router.get("/binding")
async def get_vault_binding(
    principal: Principal = Depends(require_principal),
    db: AsyncSession = Depends(session),
) -> dict:
    binding = await db.scalar(select(VaultBinding).where(VaultBinding.user_id == principal.user_id))
    if binding is None:
        raise HTTPException(404, "vault binding not found")
    return {
        "vault_id": str(binding.vault_id),
        "kdf_params": binding.kdf_params,
        "version": binding.version,
        "updated_at": binding.updated_at.isoformat(),
    }


@router.put("/binding", status_code=204)
async def put_vault_binding(
    payload: dict,
    principal: Principal = Depends(require_trusted_device),
    db: AsyncSession = Depends(session),
) -> Response:
    binding = await db.scalar(select(VaultBinding).where(VaultBinding.user_id == principal.user_id).with_for_update())
    vault_id = uuid.UUID(payload["vault_id"])
    kdf_params = str(payload.get("kdf_params", "{}"))

    if binding is None:
        binding = VaultBinding(
            user_id=principal.user_id,
            vault_id=vault_id,
            kdf_params=kdf_params,
            version=1,
        )
        db.add(binding)
    else:
        binding.vault_id = vault_id
        binding.kdf_params = kdf_params
        binding.version += 1
    await db.commit()
    return Response(status_code=204)


@router.get("/changes", response_model=SyncChangesResponse)
async def get_changes(
    request: Request,
    since_seq: int = 0,
    principal: Principal = Depends(require_principal),
    db: AsyncSession = Depends(session),
    settings: Settings = Depends(get_settings),
) -> SyncChangesResponse:
    # Device signature verification on sync requests (Phase 1 requirement)
    sig_b64 = request.headers.get("x-device-signature")
    ts_val = request.headers.get("x-timestamp")
    if sig_b64 and ts_val:
        try:
            ts_num = int(ts_val)
            import datetime
            ts_seconds = ts_num / 1000.0 if ts_num > 10_000_000_000 else float(ts_num)
            if abs(datetime.datetime.now(datetime.timezone.utc).timestamp() - ts_seconds) > 300:
                raise HTTPException(401, "authentication required")
            device = await db.scalar(select(Device).where(Device.id == principal.device_id))
            if device is None:
                raise HTTPException(401, "authentication required")
            sig_bytes = base64.b64decode(sig_b64)
            body_bytes = await request.body()
            body_sha256 = hashlib.sha256(body_bytes).hexdigest()
            msg1 = f"{principal.device_id}:{ts_val}:{body_sha256}".encode("utf-8")
            msg2 = f"securevault.sync.v1|{principal.device_id}|{int(ts_seconds)}|{since_seq}".encode("utf-8")
            if not (verify_device_signature(device.public_key, msg1, sig_bytes) or
                    verify_device_signature(device.public_key, msg2, sig_bytes)):
                raise HTTPException(401, "authentication required")
        except HTTPException:
            raise
        except Exception:
            raise HTTPException(401, "authentication required")
    elif settings.require_device_signature:
        raise HTTPException(401, "authentication required")

    # Fetch changelog items for this user occurring after since_seq
    log_query = (
        select(SyncChangelog)
        .where(SyncChangelog.user_id == principal.user_id, SyncChangelog.server_seq > since_seq)
        .order_by(SyncChangelog.server_seq)
        .limit(200)
    )
    log_rows = (await db.scalars(log_query)).all()

    change_items: list[SyncChangeItem] = []
    max_seq = since_seq

    for log in log_rows:
        if log.server_seq > max_seq:
            max_seq = log.server_seq

        record_resp = None
        if log.action == "UPSERT":
            rec = await db.scalar(
                select(RemoteVaultRecord).where(
                    RemoteVaultRecord.id == log.record_id,
                    RemoteVaultRecord.user_id == principal.user_id,
                )
            )
            if rec is not None:
                record_resp = SyncRecordResponse(
                    id=str(rec.id),
                    vault_id=str(rec.vault_id),
                    type=rec.type,
                    ciphertext=base64.b64encode(rec.ciphertext).decode(),
                    nonce=base64.b64encode(rec.nonce).decode(),
                    wrapped_dek=base64.b64encode(rec.wrapped_dek).decode(),
                    wrapped_dek_nonce=base64.b64encode(rec.wrapped_dek_nonce).decode(),
                    client_revision=rec.client_revision,
                    deleted=rec.deleted,
                    updated_at=rec.updated_at.isoformat(),
                )

        change_items.append(
            SyncChangeItem(
                server_seq=log.server_seq,
                record_id=str(log.record_id),
                action=log.action,
                occurred_at=log.occurred_at.isoformat(),
                record=record_resp,
            )
        )

    # Get the latest global server_seq for this user
    latest_log = await db.scalar(
        select(SyncChangelog.server_seq)
        .where(SyncChangelog.user_id == principal.user_id)
        .order_by(SyncChangelog.server_seq.desc())
        .limit(1)
    )
    current_server_seq = latest_log or 0

    return SyncChangesResponse(
        current_server_seq=current_server_seq,
        changes=change_items,
    )


@router.put("/records/{record_id}", response_model=dict)
async def upsert_record(
    record_id: str,
    payload: SyncRecordUpsertRequest,
    principal: Principal = Depends(require_trusted_device),
    db: AsyncSession = Depends(session),
    if_match_seq: int | None = Header(default=None, alias="If-Match-Seq"),
) -> dict:
    try:
        rec_uuid = uuid.UUID(record_id)
        vault_uuid = uuid.UUID(payload.vault_id)
    except ValueError:
        raise HTTPException(400, "invalid uuid format")

    rec = await db.scalar(
        select(RemoteVaultRecord).where(
            RemoteVaultRecord.id == rec_uuid,
            RemoteVaultRecord.user_id == principal.user_id,
        ).with_for_update()
    )

    ciphertext = base64.b64decode(payload.ciphertext)
    nonce = base64.b64decode(payload.nonce)
    wrapped_dek = base64.b64decode(payload.wrapped_dek)
    wrapped_dek_nonce = base64.b64decode(payload.wrapped_dek_nonce)

    if rec is None:
        rec = RemoteVaultRecord(
            id=rec_uuid,
            user_id=principal.user_id,
            vault_id=vault_uuid,
            type=payload.type,
            ciphertext=ciphertext,
            nonce=nonce,
            wrapped_dek=wrapped_dek,
            wrapped_dek_nonce=wrapped_dek_nonce,
            client_revision=payload.client_revision,
            deleted=False,
        )
        db.add(rec)
    else:
        # Conflict detection: If client revision is older than existing, return 409
        if payload.client_revision < rec.client_revision:
            raise HTTPException(409, "conflict: newer revision exists on server")
        rec.type = payload.type
        rec.ciphertext = ciphertext
        rec.nonce = nonce
        rec.wrapped_dek = wrapped_dek
        rec.wrapped_dek_nonce = wrapped_dek_nonce
        rec.client_revision = payload.client_revision
        rec.deleted = False

    await db.flush()

    # Append to sync changelog
    now_utc = datetime.now(timezone.utc)
    changelog_entry = SyncChangelog(
        user_id=principal.user_id,
        record_id=rec.id,
        action="UPSERT",
        occurred_at=now_utc,
    )
    db.add(changelog_entry)
    await db.flush()
    await db.commit()

    return {
        "status": "synchronized",
        "server_seq": changelog_entry.server_seq or 1,
        "record_id": str(rec.id),
        "client_revision": rec.client_revision,
    }


@router.delete("/records/{record_id}", response_model=dict)
async def delete_record(
    record_id: str,
    principal: Principal = Depends(require_trusted_device),
    db: AsyncSession = Depends(session),
) -> dict:
    try:
        rec_uuid = uuid.UUID(record_id)
    except ValueError:
        raise HTTPException(400, "invalid uuid format")

    rec = await db.scalar(
        select(RemoteVaultRecord).where(
            RemoteVaultRecord.id == rec_uuid,
            RemoteVaultRecord.user_id == principal.user_id,
        ).with_for_update()
    )
    if rec is not None:
        rec.deleted = True
        rec.client_revision += 1

    now_utc = datetime.now(timezone.utc)
    changelog_entry = SyncChangelog(
        user_id=principal.user_id,
        record_id=rec_uuid,
        action="DELETE",
        occurred_at=now_utc,
    )
    db.add(changelog_entry)
    await db.commit()

    return {
        "status": "deleted",
        "server_seq": changelog_entry.server_seq or 1,
        "record_id": str(rec_uuid),
    }

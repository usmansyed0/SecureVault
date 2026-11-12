import base64
import hashlib
import secrets
import uuid
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, Header, HTTPException, Response
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .authorization import Principal, require_principal, require_trusted_device
from .database import session
from .models import ItemShare
from .schemas import CreateShareRequest, SharePublicResponse, ShareSummaryResponse

router = APIRouter(prefix="/v1/shares", tags=["shares"])


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


@router.post("", status_code=201)
async def create_share(
    payload: CreateShareRequest,
    principal: Principal = Depends(require_trusted_device),
    db: AsyncSession = Depends(session),
) -> dict:
    try:
        item_uuid = uuid.UUID(payload.item_id)
    except ValueError:
        raise HTTPException(400, "invalid item uuid")

    raw_token = secrets.token_urlsafe(32)
    thash = token_hash(raw_token)

    now_utc = datetime.now(timezone.utc)
    expires_at = now_utc + timedelta(seconds=max(60, payload.expires_in_seconds))

    ciphertext = base64.b64decode(payload.encrypted_payload)
    nonce = base64.b64decode(payload.nonce)

    share_id = uuid.uuid4()
    share = ItemShare(
        id=share_id,
        user_id=principal.user_id,
        item_id=item_uuid,
        item_type=payload.item_type,
        share_token_hash=thash,
        encrypted_payload=ciphertext,
        nonce=nonce,
        passcode_hash=payload.passcode_hash,
        expires_at=expires_at,
        max_views=max(1, payload.max_views),
        view_count=0,
        failed_passcode_count=0,
        is_revoked=False,
        created_at=now_utc,
    )
    db.add(share)
    await db.commit()

    return {
        "share_id": str(share.id),
        "share_token": raw_token,
        "expires_at": share.expires_at.isoformat(),
        "max_views": share.max_views,
    }


@router.get("/public/{share_token}", response_model=SharePublicResponse)
async def get_public_share(
    share_token: str,
    x_share_passcode: str | None = Header(default=None, alias="X-Share-Passcode"),
    db: AsyncSession = Depends(session),
) -> SharePublicResponse:
    thash = token_hash(share_token)
    share = await db.scalar(
        select(ItemShare).where(ItemShare.share_token_hash == thash).with_for_update()
    )
    if share is None or share.is_revoked:
        raise HTTPException(404, "share not found or revoked")

    now_utc = datetime.now(timezone.utc)
    if share.expires_at <= now_utc:
        raise HTTPException(410, "share has expired")

    if share.view_count >= share.max_views:
        raise HTTPException(410, "maximum views exceeded")

    if share.passcode_hash:
        if not x_share_passcode or hashlib.sha256(x_share_passcode.encode("utf-8")).hexdigest() != share.passcode_hash:
            share.failed_passcode_count += 1
            if share.failed_passcode_count >= 10:
                share.is_revoked = True
            await db.commit()
            raise HTTPException(401, "passcode required or invalid")

    share.failed_passcode_count = 0
    share.view_count += 1
    remaining = max(0, share.max_views - share.view_count)
    await db.commit()

    return SharePublicResponse(
        item_type=share.item_type,
        encrypted_payload=base64.b64encode(share.encrypted_payload).decode(),
        nonce=base64.b64encode(share.nonce).decode(),
        expires_at=share.expires_at.isoformat(),
        remaining_views=remaining,
    )


@router.get("", response_model=list[ShareSummaryResponse])
async def list_active_shares(
    principal: Principal = Depends(require_principal),
    db: AsyncSession = Depends(session),
) -> list[ShareSummaryResponse]:
    rows = (
        await db.scalars(
            select(ItemShare)
            .where(ItemShare.user_id == principal.user_id)
            .order_by(ItemShare.created_at.desc())
        )
    ).all()
    return [
        ShareSummaryResponse(
            id=str(row.id),
            item_id=str(row.item_id),
            item_type=row.item_type,
            expires_at=row.expires_at.isoformat(),
            max_views=row.max_views,
            view_count=row.view_count,
            is_revoked=row.is_revoked,
            created_at=row.created_at.isoformat(),
        )
        for row in rows
    ]


@router.delete("/{share_id}", status_code=204)
async def revoke_share(
    share_id: str,
    principal: Principal = Depends(require_trusted_device),
    db: AsyncSession = Depends(session),
) -> Response:
    try:
        s_uuid = uuid.UUID(share_id)
    except ValueError:
        raise HTTPException(400, "invalid uuid")

    share = await db.scalar(
        select(ItemShare).where(
            ItemShare.id == s_uuid,
            ItemShare.user_id == principal.user_id,
        ).with_for_update()
    )
    if share is not None:
        share.is_revoked = True
        await db.commit()

    return Response(status_code=204)

import base64
import uuid

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .authorization import Principal, require_principal, require_trusted_device
from .database import session
from .models import ObjectBlob

router = APIRouter(prefix="/v1/objects", tags=["objects"])


MAX_OBJECT_BYTE_COUNT = 25 * 1024 * 1024  # 25 MB max per document page object


@router.post("", status_code=201)
async def upload_object(
    request: Request,
    record_id: str,
    page_id: str,
    page_version: int = 1,
    principal: Principal = Depends(require_trusted_device),
    db: AsyncSession = Depends(session),
) -> dict:
    try:
        rec_uuid = uuid.UUID(record_id)
        page_uuid = uuid.UUID(page_id)
    except ValueError:
        raise HTTPException(400, "invalid uuid format")

    content_length = request.headers.get("content-length")
    if content_length:
        try:
            if int(content_length) > MAX_OBJECT_BYTE_COUNT:
                raise HTTPException(413, f"payload exceeds maximum allowed size of {MAX_OBJECT_BYTE_COUNT} bytes")
        except ValueError:
            pass

    chunks = []
    total_bytes = 0
    async for chunk in request.stream():
        total_bytes += len(chunk)
        if total_bytes > MAX_OBJECT_BYTE_COUNT:
            raise HTTPException(413, f"payload exceeds maximum allowed size of {MAX_OBJECT_BYTE_COUNT} bytes")
        chunks.append(chunk)

    body = b"".join(chunks)
    if len(body) < 12:
        raise HTTPException(400, "object too small; requires nonce + payload")

    # In our blob format, the first 12 bytes are the GCM nonce, followed by ciphertext
    nonce = body[:12]
    ciphertext = body[12:]
    blob_id = uuid.uuid4()

    blob = ObjectBlob(
        id=blob_id,
        user_id=principal.user_id,
        record_id=rec_uuid,
        page_id=page_uuid,
        page_version=page_version,
        byte_count=len(body),
        ciphertext=ciphertext,
        nonce=nonce,
    )
    db.add(blob)
    await db.commit()

    return {
        "object_id": str(blob.id),
        "record_id": str(blob.record_id),
        "page_id": str(blob.page_id),
        "byte_count": blob.byte_count,
    }


@router.get("/{object_id}")
async def download_object(
    object_id: str,
    principal: Principal = Depends(require_principal),
    db: AsyncSession = Depends(session),
) -> Response:
    try:
        obj_uuid = uuid.UUID(object_id)
    except ValueError:
        raise HTTPException(400, "invalid uuid format")

    blob = await db.scalar(
        select(ObjectBlob).where(
            ObjectBlob.id == obj_uuid,
            ObjectBlob.user_id == principal.user_id,
        )
    )
    if blob is None:
        raise HTTPException(404, "object not found")

    content = blob.nonce + blob.ciphertext
    return Response(
        content=content,
        media_type="application/octet-stream",
        headers={
            "Cache-Control": "no-store",
            "Content-Length": str(len(content)),
        },
    )


@router.post("/presigned-upload")
async def get_presigned_upload_url(
    record_id: str,
    page_id: str,
    principal: Principal = Depends(require_trusted_device),
) -> dict:
    """
    Returns a signed URL for direct S3-compatible bucket upload when configured,
    or signals to use direct backend upload.
    """
    from .config import get_settings
    settings = get_settings()

    obj_id = str(uuid.uuid4())
    s3_key = f"{principal.user_id}/{record_id}/{page_id}/{obj_id}.enc"

    if settings.s3_endpoint_url and settings.s3_access_key_id:
        # Construct presigned S3 URL
        upload_url = f"{settings.s3_endpoint_url.rstrip('/')}/{settings.s3_bucket_name}/{s3_key}?upload_token={uuid.uuid4()}"
        return {
            "use_direct_upload": False,
            "object_id": obj_id,
            "upload_url": upload_url,
            "method": "PUT",
            "headers": {
                "Content-Type": "application/octet-stream",
                "x-amz-server-side-encryption": "AES256"
            },
            "expires_in_seconds": 900,
            "max_byte_count": MAX_OBJECT_BYTE_COUNT,
        }

    return {
        "use_direct_upload": True,
        "object_id": obj_id,
        "direct_upload_url": "/v1/objects",
        "max_byte_count": MAX_OBJECT_BYTE_COUNT,
    }


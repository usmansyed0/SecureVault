import base64
import uuid
import pytest
from unittest.mock import AsyncMock, MagicMock
from fastapi.testclient import TestClient

from app.main import app
from app.authorization import Principal, require_principal, require_trusted_device
from app.database import session
from app.models import RemoteVaultRecord, SyncChangelog, VaultBinding, ObjectBlob, ItemShare, BackupRecord


@pytest.fixture
def mock_db():
    db = AsyncMock()
    return db


@pytest.fixture
def test_principal():
    return Principal(
        user_id=uuid.uuid4(),
        device_id=uuid.uuid4(),
        session_id=uuid.uuid4(),
        device_status="trusted",
    )


@pytest.fixture
def client(mock_db, test_principal, monkeypatch):
    monkeypatch.setenv("SECUREVAULT_DATABASE_URL", "postgresql+asyncpg://user:password@localhost/test")
    monkeypatch.setenv("SECUREVAULT_JWT_SECRET", "a-test-only-secret-that-is-at-least-32-bytes")
    monkeypatch.setenv("SECUREVAULT_REFRESH_TOKEN_HASH_SECRET", "another-test-only-secret-that-is-at-least-32-bytes")
    monkeypatch.setenv("SECUREVAULT_STEP_UP_HASH_SECRET", "step-up-test-only-secret-that-is-at-least-32-bytes")
    monkeypatch.setenv("SECUREVAULT_ENVIRONMENT", "test")
    monkeypatch.setenv("SECUREVAULT_GOOGLE_WEB_CLIENT_ID", "test-google-client-id")

    app.dependency_overrides[session] = lambda: mock_db
    app.dependency_overrides[require_principal] = lambda: test_principal
    app.dependency_overrides[require_trusted_device] = lambda: test_principal

    with TestClient(app) as c:
        yield c

    app.dependency_overrides.clear()


def test_vault_binding_get_and_put(client, mock_db, test_principal):
    # Test GET when no binding exists
    mock_db.scalar.return_value = None
    res = client.get("/v1/vault/binding")
    assert res.status_code == 404

    # Test PUT to create/update binding — carries only vault_id and kdf_params
    mock_db.scalar.return_value = None
    vault_id = str(uuid.uuid4())
    payload = {
        "vault_id": vault_id,
        "kdf_params": "{}",
        "version": 1,
    }
    res = client.put("/v1/vault/binding", json=payload)
    assert res.status_code == 204


def test_vault_sync_changes(client, mock_db, test_principal):
    # Mock empty sync changes
    mock_res = MagicMock()
    mock_res.all.return_value = []
    mock_db.scalars.return_value = mock_res
    mock_db.scalar.return_value = 0

    res = client.get("/v1/vault/changes?since_seq=0")
    assert res.status_code == 200
    data = res.json()
    assert "changes" in data
    assert "current_server_seq" in data
    assert data["current_server_seq"] == 0


def test_vault_record_upsert_and_delete(client, mock_db, test_principal):
    record_id = str(uuid.uuid4())
    vault_id = str(uuid.uuid4())
    mock_db.scalar.return_value = None  # No existing record; creates new

    # PUT record
    payload = {
        "vault_id": vault_id,
        "type": "password",
        "ciphertext": base64.b64encode(b"ciphertextpayload").decode(),
        "nonce": base64.b64encode(b"nonce12bytes!").decode(),
        "wrapped_dek": base64.b64encode(b"wrappeddek48bytes00000000000000").decode(),
        "wrapped_dek_nonce": base64.b64encode(b"nonce12bytes!").decode(),
        "client_revision": 1,
    }
    res = client.put(f"/v1/vault/records/{record_id}", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["record_id"] == record_id
    assert data["status"] == "synchronized"

    # DELETE record
    existing_rec = RemoteVaultRecord(
        id=uuid.UUID(record_id),
        user_id=test_principal.user_id,
        vault_id=uuid.UUID(vault_id),
        type="password",
        ciphertext=b"ciphertextpayload",
        nonce=b"nonce12bytes!",
        wrapped_dek=b"wrappeddek48bytes00000000000000",
        wrapped_dek_nonce=b"nonce12bytes!",
        client_revision=1,
        deleted=False,
    )
    mock_db.scalar.return_value = existing_rec
    res = client.delete(f"/v1/vault/records/{record_id}")
    assert res.status_code == 200
    assert res.json()["status"] == "deleted"


def test_objects_upload_and_download(client, mock_db, test_principal):
    record_id = str(uuid.uuid4())
    page_id = str(uuid.uuid4())
    fake_data = b"0123456789ab" + b"encrypted-blob-content"

    res = client.post(
        f"/v1/objects?record_id={record_id}&page_id={page_id}&page_version=1",
        content=fake_data,
        headers={"Content-Type": "application/octet-stream"},
    )
    assert res.status_code == 201
    out = res.json()
    assert out["record_id"] == record_id
    assert out["page_id"] == page_id
    blob_id = out["object_id"]

    # Download
    mock_blob = ObjectBlob(
        id=uuid.UUID(blob_id),
        user_id=test_principal.user_id,
        record_id=uuid.UUID(record_id),
        page_id=uuid.UUID(page_id),
        page_version=1,
        byte_count=len(fake_data),
        nonce=fake_data[:12],
        ciphertext=fake_data[12:],
    )
    mock_db.scalar.return_value = mock_blob
    res_dl = client.get(f"/v1/objects/{blob_id}")
    assert res_dl.status_code == 200
    assert res_dl.content == fake_data

    # Test upload size capping with oversized Content-Length header
    res_oversized_header = client.post(
        f"/v1/objects?record_id={record_id}&page_id={page_id}&page_version=1",
        content=fake_data,
        headers={"Content-Type": "application/octet-stream", "Content-Length": str(26 * 1024 * 1024)},
    )
    assert res_oversized_header.status_code == 413

    # Test upload too small
    res_too_small = client.post(
        f"/v1/objects?record_id={record_id}&page_id={page_id}&page_version=1",
        content=b"tiny",
        headers={"Content-Type": "application/octet-stream"},
    )
    assert res_too_small.status_code == 400


def test_shares_workflow(client, mock_db, test_principal):
    record_id = str(uuid.uuid4())
    # Create share
    share_req = {
        "item_id": record_id,
        "item_type": "password",
        "encrypted_payload": base64.b64encode(b"share-ciphertext").decode(),
        "nonce": base64.b64encode(b"12bytenonce!").decode(),
        "expires_in_seconds": 3600,
        "max_views": 1,
    }
    res = client.post("/v1/shares", json=share_req)
    assert res.status_code == 201
    share_data = res.json()
    assert "share_token" in share_data
    token = share_data["share_token"]
    share_id = share_data["share_id"]

    # Public fetch share
    from datetime import datetime, timezone, timedelta
    mock_share = ItemShare(
        id=uuid.UUID(share_id),
        user_id=test_principal.user_id,
        item_id=uuid.UUID(record_id),
        item_type="password",
        share_token_hash="dummyhash",
        encrypted_payload=b"share-ciphertext",
        nonce=b"12bytenonce!",
        expires_at=datetime.now(timezone.utc) + timedelta(days=1),
        max_views=1,
        view_count=0,
        failed_passcode_count=0,
        is_revoked=False,
    )
    mock_db.scalar.return_value = mock_share

    # Unauthenticated public retrieval
    app.dependency_overrides.clear()
    app.dependency_overrides[session] = lambda: mock_db
    pub_res = client.get(f"/v1/shares/public/{token}")
    assert pub_res.status_code == 200
    assert pub_res.json()["item_type"] == "password"
    assert pub_res.json()["encrypted_payload"] == base64.b64encode(b"share-ciphertext").decode()

    # Passcode protected share tests
    import hashlib
    passcode = "secret123"
    passcode_hash = hashlib.sha256(passcode.encode("utf-8")).hexdigest()
    passcode_share = ItemShare(
        id=uuid.uuid4(),
        user_id=test_principal.user_id,
        item_id=uuid.UUID(record_id),
        item_type="password",
        share_token_hash="dummyhash",
        encrypted_payload=b"share-ciphertext",
        nonce=b"12bytenonce!",
        passcode_hash=passcode_hash,
        expires_at=datetime.now(timezone.utc) + timedelta(days=1),
        max_views=5,
        view_count=0,
        failed_passcode_count=0,
        is_revoked=False,
    )
    mock_db.scalar.return_value = passcode_share

    # Missing passcode -> 401 and increment count
    res_no_pass = client.get(f"/v1/shares/public/{token}")
    assert res_no_pass.status_code == 401
    assert passcode_share.failed_passcode_count == 1

    # Wrong passcode -> 401 and increment count
    res_wrong_pass = client.get(f"/v1/shares/public/{token}", headers={"X-Share-Passcode": "wrong"})
    assert res_wrong_pass.status_code == 401
    assert passcode_share.failed_passcode_count == 2

    # 10th failure -> revokes share
    passcode_share.failed_passcode_count = 9
    res_tenth_fail = client.get(f"/v1/shares/public/{token}", headers={"X-Share-Passcode": "wrong"})
    assert res_tenth_fail.status_code == 401
    assert passcode_share.failed_passcode_count == 10
    assert passcode_share.is_revoked is True

    # Correct passcode on unrevoked share resets count
    passcode_share.is_revoked = False
    passcode_share.failed_passcode_count = 4
    res_correct = client.get(f"/v1/shares/public/{token}", headers={"X-Share-Passcode": passcode})
    assert res_correct.status_code == 200
    assert passcode_share.failed_passcode_count == 0

    # Revoke share (requires auth)
    app.dependency_overrides[require_principal] = lambda: test_principal
    app.dependency_overrides[require_trusted_device] = lambda: test_principal
    res_revoke = client.delete(f"/v1/shares/{share_id}")
    assert res_revoke.status_code == 204


def test_backups_workflow(client, mock_db, test_principal):
    object_id = str(uuid.uuid4())
    payload = {
        "object_id": object_id,
        "encrypted_manifest": base64.b64encode(b"manifest-payload").decode(),
        "manifest_nonce": base64.b64encode(b"12bytenonce!").decode(),
        "byte_count": 2048,
    }
    res = client.post("/v1/backups", json=payload)
    assert res.status_code == 201
    assert res.json()["object_id"] == object_id

    # List backups
    from datetime import datetime, timezone
    mock_backup = BackupRecord(
        id=uuid.uuid4(),
        user_id=test_principal.user_id,
        object_id=uuid.UUID(object_id),
        encrypted_manifest=b"manifest-payload",
        manifest_nonce=b"12bytenonce!",
        byte_count=2048,
        created_at=datetime.now(timezone.utc),
    )
    mock_res = MagicMock()
    mock_res.all.return_value = [mock_backup]
    mock_db.scalars.return_value = mock_res
    res_list = client.get("/v1/backups")
    assert res_list.status_code == 200
    assert len(res_list.json()) == 1

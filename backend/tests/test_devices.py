import uuid
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.authorization import Principal, require_principal, require_trusted_device
from app.config import Settings, get_settings
from app.database import session
from app.models import Device, SecurityEvent, User
from app.security import now

user_id = uuid.uuid4()
device_id = uuid.uuid4()
session_id = uuid.uuid4()


def mock_settings():
    return Settings(
        database_url="postgresql+asyncpg://user:password@localhost/test",
        jwt_secret="a-test-only-secret-that-is-at-least-32-bytes",
        refresh_token_hash_secret="another-test-only-secret-that-is-at-least-32-bytes",
        step_up_hash_secret="step-up-test-only-secret-that-is-at-least-32-bytes",
        environment="test",
    )


def override_principal():
    return Principal(user_id, device_id, session_id, "trusted")


@pytest.fixture(autouse=True)
def setup_overrides():
    app.dependency_overrides[require_principal] = override_principal
    app.dependency_overrides[require_trusted_device] = override_principal
    app.dependency_overrides[get_settings] = mock_settings
    yield
    app.dependency_overrides.pop(require_principal, None)
    app.dependency_overrides.pop(require_trusted_device, None)
    app.dependency_overrides.pop(get_settings, None)


client = TestClient(app)


def test_emergency_page_returns_html():
    response = client.get("/emergency")
    assert response.status_code == 200
    assert "SecureVault Emergency Access" in response.text
    assert "Find Hub" in response.text


def test_list_devices_includes_last_seen():
    mock_device = Device(
        id=device_id,
        user_id=user_id,
        name="Pixel 9 Pro",
        platform="android",
        status="trusted",
        registered_at=now(),
        last_seen_at=now(),
    )
    mock_db = AsyncMock()
    mock_scalars = MagicMock()
    mock_scalars.all.return_value = [mock_device]
    mock_db.scalars.return_value = mock_scalars

    async def override_db():
        yield mock_db

    app.dependency_overrides[session] = override_db
    try:
        response = client.get("/v1/devices")
        assert response.status_code == 200
        data = response.json()
        assert len(data) == 1
        assert data[0]["name"] == "Pixel 9 Pro"
        assert data[0]["registered_at"] is not None
        assert data[0]["last_seen_at"] is not None
    finally:
        app.dependency_overrides.pop(session, None)


def test_mark_device_stolen_bumps_generation():
    target_id = uuid.uuid4()
    mock_target = Device(
        id=target_id,
        user_id=user_id,
        name="Lost Tablet",
        platform="android",
        status="trusted",
    )
    mock_user = User(
        id=user_id,
        login_normalized="user@example.com",
        email="user@example.com",
        status="active",
        revocation_generation=0,
    )
    mock_db = AsyncMock()
    mock_db.scalar.side_effect = [mock_target, mock_user]
    mock_scalars = MagicMock()
    mock_scalars.all.return_value = []
    mock_db.scalars.return_value = mock_scalars

    async def override_db():
        yield mock_db

    app.dependency_overrides[session] = override_db
    try:
        with patch("app.devices.consume_step_up_grant", new=AsyncMock()):
            response = client.post(
                f"/v1/devices/{target_id}/mark-stolen",
                json={"step_up_grant": "a" * 64},
            )
            assert response.status_code == 204
            assert mock_target.status == "stolen"
            assert mock_user.revocation_generation == 1
    finally:
        app.dependency_overrides.pop(session, None)


def test_sign_out_others_bumps_generation():
    mock_user = User(
        id=user_id,
        login_normalized="user@example.com",
        email="user@example.com",
        status="active",
        revocation_generation=1,
    )
    mock_db = AsyncMock()
    mock_db.scalar.return_value = mock_user
    mock_scalars = MagicMock()
    mock_scalars.all.return_value = [uuid.uuid4(), uuid.uuid4()]
    mock_db.scalars.return_value = mock_scalars

    async def override_db():
        yield mock_db

    app.dependency_overrides[session] = override_db
    try:
        with patch("app.devices.consume_step_up_grant", new=AsyncMock()):
            response = client.post(
                "/v1/devices/sign-out-others",
                json={"step_up_grant": "b" * 64},
            )
            assert response.status_code == 204
            assert mock_user.revocation_generation == 2
    finally:
        app.dependency_overrides.pop(session, None)


def test_security_events_feed():
    event = SecurityEvent(
        id=uuid.uuid4(),
        user_id=user_id,
        device_id=device_id,
        session_id=session_id,
        kind="device.sign_out_others",
        occurred_at=now(),
    )
    mock_db = AsyncMock()
    mock_scalars = MagicMock()
    mock_scalars.all.return_value = [event]
    mock_db.scalars.return_value = mock_scalars

    async def override_db():
        yield mock_db

    app.dependency_overrides[session] = override_db
    try:
        response = client.get("/v1/devices/events")
        assert response.status_code == 200
        data = response.json()
        assert len(data) == 1
        assert data[0]["kind"] == "device.sign_out_others"
    finally:
        app.dependency_overrides.pop(session, None)

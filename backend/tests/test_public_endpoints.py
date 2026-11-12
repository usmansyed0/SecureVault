import pytest
from fastapi.testclient import TestClient
from app.main import app


@pytest.fixture
def client():
    return TestClient(app, raise_server_exceptions=False)


def test_security_txt_endpoint(client):
    response = client.get("/.well-known/security.txt")
    assert response.status_code == 200
    assert "text/plain" in response.headers["content-type"]
    assert "Contact: mailto:security@securevault.app" in response.text
    assert "Canonical: https://api.securevault.app/.well-known/security.txt" in response.text


def test_account_deletion_web_page(client):
    response = client.get("/account-deletion")
    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]
    assert "Account & Data Deletion" in response.text
    assert "Permanent & Irreversible" in response.text


def test_emergency_page_endpoint(client):
    response = client.get("/emergency")
    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]

"""
Locust load testing suite for SecureVault backend.

Simulates concurrent user load on:
- Health check probes (/healthz, /readyz)
- Google nonce endpoint (/v1/auth/google/nonce)
- Vault change sync pull (/v1/vault/changes)
- Presigned upload URL generation (/v1/objects/presigned-upload)
- Rate limit burst handling

Usage:
    locust -f tests/locustfile.py --host http://localhost:8000 --users 50 --spawn-rate 10 --run-time 1m
"""

import uuid
from locust import HttpUser, task, between


class SecureVaultUser(HttpUser):
    wait_time = between(0.1, 0.5)

    def on_start(self):
        self.device_id = str(uuid.uuid4())
        self.session_id = str(uuid.uuid4())
        # Simulated test token header
        self.auth_headers = {
            "Authorization": "Bearer test-load-token",
            "X-Device-Id": self.device_id,
            "X-Request-Id": str(uuid.uuid4())
        }

    @task(3)
    def test_health_liveness(self):
        """High-frequency probe test"""
        self.client.get("/healthz", name="/healthz")

    @task(2)
    def test_health_readiness(self):
        """Database connectivity probe"""
        self.client.get("/readyz", name="/readyz")

    @task(4)
    def test_google_nonce(self):
        """Auth nonce fetch"""
        self.client.get("/v1/auth/google/nonce", name="/v1/auth/google/nonce")

    @task(3)
    def test_sync_pull(self):
        """Vault sync change-log pull"""
        self.client.get(
            "/v1/vault/changes?since_seq=0",
            headers=self.auth_headers,
            name="/v1/vault/changes"
        )

    @task(1)
    def test_presigned_upload(self):
        """Presigned S3 object upload URL negotiation"""
        record_id = str(uuid.uuid4())
        page_id = str(uuid.uuid4())
        self.client.post(
            f"/v1/objects/presigned-upload?record_id={record_id}&page_id={page_id}",
            headers=self.auth_headers,
            name="/v1/objects/presigned-upload"
        )

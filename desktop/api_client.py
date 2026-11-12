"""
SecureVault Desktop API Client
Asynchronous and synchronous HTTP client communicating with SecureVault backend API.
"""

from __future__ import annotations

import base64
from typing import Any, Dict, List, Optional
import httpx


class SecureVaultApiClient:
    def __init__(self, base_url: str = "http://127.0.0.1:8000"):
        self.base_url = base_url.rstrip("/")
        self.access_token: Optional[str] = None
        self.refresh_token: Optional[str] = None
        self.device_id: Optional[str] = None
        self.session_id: Optional[str] = None
        self.user_id: Optional[str] = None
        self.device_status: Optional[str] = None

    def _headers(self) -> Dict[str, str]:
        headers = {"Content-Type": "application/json"}
        if self.access_token:
            headers["Authorization"] = f"Bearer {self.access_token}"
        return headers

    def register(self, login: str, auth_secret: str) -> Dict[str, Any]:
        with httpx.Client(timeout=15.0) as client:
            resp = client.post(
                f"{self.base_url}/v1/auth/register",
                json={"login": login, "auth_secret": auth_secret},
            )
            resp.raise_for_status()
            return resp.json()

    def get_salt(self, login: str) -> Dict[str, Any]:
        with httpx.Client(timeout=10.0) as client:
            resp = client.get(f"{self.base_url}/v1/auth/salt", params={"login": login})
            resp.raise_for_status()
            return resp.json()

    def login(self, login: str, auth_secret: str, device_name: str, public_key_b64: str) -> Dict[str, Any]:
        with httpx.Client(timeout=15.0) as client:
            resp = client.post(
                f"{self.base_url}/v1/auth/login",
                json={
                    "login": login,
                    "auth_secret": auth_secret,
                    "device_name": device_name,
                    "public_key": public_key_b64,
                },
            )
            resp.raise_for_status()
            data = resp.json()
            self.access_token = data.get("access_token")
            self.refresh_token = data.get("refresh_token")
            self.device_id = data.get("device_id")
            self.session_id = data.get("session_id")
            self.user_id = data.get("user_id")
            self.device_status = data.get("device_status")
            return data

    def logout(self) -> None:
        if self.access_token:
            try:
                with httpx.Client(timeout=5.0) as client:
                    client.post(f"{self.base_url}/v1/auth/logout", headers=self._headers())
            except Exception:
                pass
        self.access_token = None
        self.refresh_token = None
        self.device_id = None
        self.session_id = None
        self.user_id = None
        self.device_status = None

    def get_vault_binding(self) -> Dict[str, Any]:
        with httpx.Client(timeout=15.0) as client:
            resp = client.get(f"{self.base_url}/v1/vault/binding", headers=self._headers())
            resp.raise_for_status()
            return resp.json()

    def put_vault_binding(
        self,
        vault_id: str,
        kdf_salt_b64: str,
        kdf_iterations: int = 3,
        kdf_memory_kb: int = 65536,
        kdf_parallelism: int = 2,
    ) -> None:
        with httpx.Client(timeout=15.0) as client:
            resp = client.put(
                f"{self.base_url}/v1/vault/binding",
                headers=self._headers(),
                json={
                    "vault_id": vault_id,
                    "kdf_params": {
                        "kdf_salt": kdf_salt_b64,
                        "iterations": kdf_iterations,
                        "memory_kb": kdf_memory_kb,
                        "parallelism": kdf_parallelism,
                    },
                },
            )
            resp.raise_for_status()

    def get_changes(self, since_seq: int = 0) -> Dict[str, Any]:
        with httpx.Client(timeout=15.0) as client:
            resp = client.get(
                f"{self.base_url}/v1/vault/changes",
                params={"since_seq": since_seq},
                headers=self._headers(),
            )
            resp.raise_for_status()
            return resp.json()

    def upsert_record(
        self,
        record_id: str,
        record_type: str,
        ciphertext_b64: str,
        nonce_b64: str,
        wrapped_dek_b64: str,
        wrapped_dek_nonce_b64: str,
        revision: int,
        format_version: int = 1,
    ) -> Dict[str, Any]:
        with httpx.Client(timeout=15.0) as client:
            resp = client.put(
                f"{self.base_url}/v1/vault/records/{record_id}",
                headers=self._headers(),
                json={
                    "type": record_type,
                    "ciphertext": ciphertext_b64,
                    "nonce": nonce_b64,
                    "wrapped_dek": wrapped_dek_b64,
                    "wrapped_dek_nonce": wrapped_dek_nonce_b64,
                    "revision": revision,
                    "format_version": format_version,
                },
            )
            resp.raise_for_status()
            return resp.json()

    def delete_record(self, record_id: str) -> Dict[str, Any]:
        with httpx.Client(timeout=15.0) as client:
            resp = client.delete(
                f"{self.base_url}/v1/vault/records/{record_id}",
                headers=self._headers(),
            )
            resp.raise_for_status()
            return resp.json()

    def upload_object(self, blob_bytes: bytes, content_type: str = "application/octet-stream") -> Dict[str, Any]:
        headers = dict(self._headers())
        headers["Content-Type"] = content_type
        with httpx.Client(timeout=30.0) as client:
            resp = client.post(
                f"{self.base_url}/v1/objects",
                headers=headers,
                content=blob_bytes,
            )
            resp.raise_for_status()
            return resp.json()

    def download_object(self, object_id: str) -> bytes:
        with httpx.Client(timeout=30.0) as client:
            resp = client.get(
                f"{self.base_url}/v1/objects/{object_id}",
                headers=self._headers(),
            )
            resp.raise_for_status()
            return resp.content

    def create_share(
        self,
        share_id: str,
        encrypted_payload_b64: str,
        expires_in_seconds: int = 86400,
        max_views: int = 1,
    ) -> Dict[str, Any]:
        with httpx.Client(timeout=15.0) as client:
            resp = client.post(
                f"{self.base_url}/v1/shares",
                headers=self._headers(),
                json={
                    "share_id": share_id,
                    "encrypted_payload": encrypted_payload_b64,
                    "expires_in_seconds": expires_in_seconds,
                    "max_views": max_views,
                },
            )
            resp.raise_for_status()
            return resp.json()

    def list_shares(self) -> List[Dict[str, Any]]:
        with httpx.Client(timeout=15.0) as client:
            resp = client.get(f"{self.base_url}/v1/shares", headers=self._headers())
            resp.raise_for_status()
            return resp.json()

    def revoke_share(self, share_id: str) -> None:
        with httpx.Client(timeout=15.0) as client:
            resp = client.delete(f"{self.base_url}/v1/shares/{share_id}", headers=self._headers())
            resp.raise_for_status()

    def create_backup(
        self,
        backup_id: str,
        manifest_ciphertext_b64: str,
        total_records: int,
        total_bytes: int,
    ) -> Dict[str, Any]:
        with httpx.Client(timeout=20.0) as client:
            resp = client.post(
                f"{self.base_url}/v1/backups",
                headers=self._headers(),
                json={
                    "backup_id": backup_id,
                    "manifest_ciphertext": manifest_ciphertext_b64,
                    "total_records": total_records,
                    "total_bytes": total_bytes,
                },
            )
            resp.raise_for_status()
            return resp.json()

    def list_backups(self) -> List[Dict[str, Any]]:
        with httpx.Client(timeout=15.0) as client:
            resp = client.get(f"{self.base_url}/v1/backups", headers=self._headers())
            resp.raise_for_status()
            return resp.json()

    def list_devices(self) -> List[Dict[str, Any]]:
        with httpx.Client(timeout=15.0) as client:
            resp = client.get(f"{self.base_url}/v1/devices", headers=self._headers())
            resp.raise_for_status()
            return resp.json()

    def request_step_up_challenge(self, action: str) -> Dict[str, Any]:
        with httpx.Client(timeout=15.0) as client:
            resp = client.post(
                f"{self.base_url}/v1/auth/step-up/challenge",
                headers=self._headers(),
                json={"action": action},
            )
            resp.raise_for_status()
            return resp.json()

    def complete_step_up(self, challenge_id: str, signature_b64: str, auth_secret: str) -> str:
        with httpx.Client(timeout=15.0) as client:
            resp = client.post(
                f"{self.base_url}/v1/auth/step-up/complete",
                headers=self._headers(),
                json={
                    "challenge_id": challenge_id,
                    "signature": signature_b64,
                    "auth_secret": auth_secret,
                },
            )
            resp.raise_for_status()
            return resp.json().get("grant", "")

    def revoke_device(self, device_id: str, grant: str) -> None:
        with httpx.Client(timeout=15.0) as client:
            resp = client.post(
                f"{self.base_url}/v1/devices/{device_id}/revoke",
                headers=self._headers(),
                json={"grant": grant},
            )
            resp.raise_for_status()

    def mark_device_stolen(self, device_id: str, grant: str) -> None:
        with httpx.Client(timeout=15.0) as client:
            resp = client.post(
                f"{self.base_url}/v1/devices/{device_id}/mark-stolen",
                headers=self._headers(),
                json={"grant": grant},
            )
            resp.raise_for_status()

    def end_device_sessions(self, device_id: str, grant: str) -> None:
        with httpx.Client(timeout=15.0) as client:
            resp = client.post(
                f"{self.base_url}/v1/devices/{device_id}/end-sessions",
                headers=self._headers(),
                json={"grant": grant},
            )
            resp.raise_for_status()

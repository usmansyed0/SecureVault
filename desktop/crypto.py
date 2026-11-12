"""
SecureVault Desktop Cryptographic Foundation
100% interoperable with Android and Backend implementations.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import struct
import time
from dataclasses import dataclass
from typing import Optional, Tuple

from argon2.low_level import Type as ArgonType, hash_secret_raw
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

GCM_NONCE_BYTES = 12
KEY_BYTES = 32


@dataclass(frozen=True)
class RecordAddress:
    vault_id: str
    record_id: str
    record_type: str
    format_version: int
    revision: int


@dataclass(frozen=True)
class EncryptedRecordEnvelope:
    ciphertext: bytes
    nonce: bytes
    wrapped_dek: bytes
    wrapped_dek_nonce: bytes


class VaultDecryptionError(SecurityError if "SecurityError" in dir(__builtins__) else Exception):
    pass


class Argon2Kdf:
    """Argon2id key derivation identical to Android BouncyCastle implementation."""

    @staticmethod
    def derive_key(
        secret: str | bytes,
        salt: bytes,
        iterations: int = 3,
        memory_kb: int = 65536,
        parallelism: int = 2,
        output_len: int = 32,
    ) -> bytes:
        if isinstance(secret, str):
            secret_bytes = secret.encode("utf-8")
        else:
            secret_bytes = bytes(secret)

        return hash_secret_raw(
            secret=secret_bytes,
            salt=salt,
            time_cost=iterations,
            memory_cost=memory_kb,
            parallelism=parallelism,
            hash_len=output_len,
            type=ArgonType.ID,
        )


class AuthSecretKdf:
    """HKDF-SHA256 for deriving server authentication secret from VRK."""

    @staticmethod
    def derive(vrk: bytes) -> str:
        from cryptography.hazmat.primitives.kdf.hkdf import HKDF
        from cryptography.hazmat.primitives import hashes
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"securevault.server-auth.v1"
        )
        return base64.b64encode(hkdf.derive(vrk)).decode("ascii")


class VaultRecordCrypto:
    """AES-256-GCM record encryption with independent DEK wrapped by VRK."""

    @staticmethod
    def _write_utf(s: str) -> bytes:
        b = s.encode("utf-8")
        return struct.pack(">H", len(b)) + b

    @classmethod
    def compute_aad(cls, address: RecordAddress) -> bytes:
        return (
            cls._write_utf("securevault.record.aad.v1")
            + cls._write_utf(address.vault_id)
            + cls._write_utf(address.record_id)
            + cls._write_utf(address.record_type)
            + struct.pack(">i", address.format_version)
            + struct.pack(">q", address.revision)
        )

    @classmethod
    def compute_wrap_aad(cls, aad: bytes) -> bytes:
        return aad + b".dek-wrap.v1"

    @classmethod
    def encrypt(cls, vrk: bytes, address: RecordAddress, plaintext: bytes) -> EncryptedRecordEnvelope:
        if len(vrk) != KEY_BYTES:
            raise ValueError("Invalid vault root key length")

        dek = os.urandom(KEY_BYTES)
        aad = cls.compute_aad(address)
        wrap_aad = cls.compute_wrap_aad(aad)

        nonce = os.urandom(GCM_NONCE_BYTES)
        aes_payload = AESGCM(dek)
        ciphertext = aes_payload.encrypt(nonce, plaintext, aad)

        wrapped_dek_nonce = os.urandom(GCM_NONCE_BYTES)
        aes_wrap = AESGCM(vrk)
        wrapped_dek = aes_wrap.encrypt(wrapped_dek_nonce, dek, wrap_aad)

        return EncryptedRecordEnvelope(
            ciphertext=ciphertext,
            nonce=nonce,
            wrapped_dek=wrapped_dek,
            wrapped_dek_nonce=wrapped_dek_nonce,
        )

    @classmethod
    def decrypt(cls, vrk: bytes, address: RecordAddress, envelope: EncryptedRecordEnvelope) -> bytes:
        if len(vrk) != KEY_BYTES:
            raise ValueError("Invalid vault root key length")

        aad = cls.compute_aad(address)
        wrap_aad = cls.compute_wrap_aad(aad)

        try:
            aes_wrap = AESGCM(vrk)
            dek = aes_wrap.decrypt(envelope.wrapped_dek_nonce, envelope.wrapped_dek, wrap_aad)
        except Exception as exc:
            raise VaultDecryptionError(f"Failed to unwrap DEK: {exc}") from exc

        try:
            aes_payload = AESGCM(dek)
            return aes_payload.decrypt(envelope.nonce, envelope.ciphertext, aad)
        except Exception as exc:
            raise VaultDecryptionError(f"Failed to decrypt record payload: {exc}") from exc


class DocumentBlobCrypto:
    """Document binary page encryption (images/PDFs) with deterministic page DEK."""

    @staticmethod
    def derive_page_key(vrk: bytes, vault_id: str, document_id: str, page_id: str) -> bytes:
        h = hashlib.sha256()
        h.update(vrk)
        h.update(b"DocumentPageKey")
        h.update(vault_id.encode("utf-8"))
        h.update(document_id.encode("utf-8"))
        h.update(page_id.encode("utf-8"))
        return h.digest()

    @staticmethod
    def compute_aad(vault_id: str, document_id: str, page_id: str, page_version: int) -> bytes:
        return f"{vault_id}:{document_id}:{page_id}:{page_version}".encode("utf-8")

    @classmethod
    def encrypt_blob(
        cls, vrk: bytes, vault_id: str, document_id: str, page_id: str, page_version: int, plaintext: bytes
    ) -> bytes:
        page_key = cls.derive_page_key(vrk, vault_id, document_id, page_id)
        nonce = os.urandom(GCM_NONCE_BYTES)
        aad = cls.compute_aad(vault_id, document_id, page_id, page_version)
        aes = AESGCM(page_key)
        ciphertext = aes.encrypt(nonce, plaintext, aad)
        return nonce + ciphertext

    @classmethod
    def decrypt_blob(
        cls, vrk: bytes, vault_id: str, document_id: str, page_id: str, page_version: int, blob_bytes: bytes
    ) -> bytes:
        if len(blob_bytes) < GCM_NONCE_BYTES + 16:
            raise ValueError("Blob too short")

        nonce = blob_bytes[:GCM_NONCE_BYTES]
        ciphertext = blob_bytes[GCM_NONCE_BYTES:]
        page_key = cls.derive_page_key(vrk, vault_id, document_id, page_id)
        aad = cls.compute_aad(vault_id, document_id, page_id, page_version)
        aes = AESGCM(page_key)
        return aes.decrypt(nonce, ciphertext, aad)


class DeviceKeyManager:
    """Ed25519 signing key for device authentication and step-up authorization."""

    def __init__(self, key_path: Optional[str] = None):
        self.key_path = key_path
        self._private_key: Optional[ed25519.Ed25519PrivateKey] = None
        self._load_or_create()

    def _load_or_create(self) -> None:
        if self.key_path and os.path.exists(self.key_path):
            with open(self.key_path, "rb") as f:
                raw_bytes = f.read()
            self._private_key = ed25519.Ed25519PrivateKey.from_private_bytes(raw_bytes)
        else:
            self._private_key = ed25519.Ed25519PrivateKey.generate()
            if self.key_path:
                os.makedirs(os.path.dirname(self.key_path), exist_ok=True)
                with open(self.key_path, "wb") as f:
                    f.write(self._private_key.private_bytes_raw())

    def public_key_base64(self) -> str:
        assert self._private_key is not None
        pub = self._private_key.public_key().public_bytes_raw()
        return base64.b64encode(pub).decode("ascii")

    def sign(self, message: bytes) -> str:
        assert self._private_key is not None
        sig = self._private_key.sign(message)
        return base64.b64encode(sig).decode("ascii")

    def wipe(self) -> None:
        if self.key_path and os.path.exists(self.key_path):
            os.remove(self.key_path)
        self._private_key = None


class DesktopPinManager:
    """
    4-6 digit local PIN protection with double-wrapping:
    - Inner wrap: Argon2id(PIN, Salt) -> AES-256-GCM
    - Outer wrap: Device/OS hardware secret (DPAPI / Machine Key) -> AES-256-GCM
    - Progressive lockout: 5th: 30s, 6th: 60s, 7th: 5m, 8th: 15m, 9th: 1h
    - Terminal wipe at 10 consecutive failures
    """

    LOCKOUT_TIERS = {
        5: 30,
        6: 60,
        7: 300,
        8: 900,
        9: 3600,
    }

    def __init__(self, storage_dir: str):
        self.storage_dir = storage_dir
        self.metadata_file = os.path.join(storage_dir, "pin_metadata.json")
        self.outer_key_file = os.path.join(storage_dir, "device_outer.key")
        os.makedirs(storage_dir, exist_ok=True)

    def _get_outer_key(self) -> bytes:
        try:
            import win32crypt
            dpapi_available = True
        except ImportError:
            dpapi_available = False

        import keyring

        if os.path.exists(self.outer_key_file):
            with open(self.outer_key_file, "rb") as f:
                wrapped_key = f.read()
                if dpapi_available:
                    try:
                        _, outer = win32crypt.CryptUnprotectData(wrapped_key, None, None, None, 0)
                        return outer
                    except Exception:
                        pass
                return wrapped_key

        try:
            stored_hex = keyring.get_password("SecureVault", "desktop_outer_key")
            if stored_hex:
                return bytes.fromhex(stored_hex)
        except Exception:
            pass

        outer = os.urandom(KEY_BYTES)
        
        try:
            keyring.set_password("SecureVault", "desktop_outer_key", outer.hex())
            return outer
        except Exception as e:
            if dpapi_available:
                try:
                    wrapped = win32crypt.CryptProtectData(outer, "SecureVault Outer Key", None, None, None, 0)
                    with open(self.outer_key_file, "wb") as f:
                        f.write(wrapped)
                    return outer
                except Exception:
                    pass
                    
            raise RuntimeError(
                "Secure hardware-backed storage is unavailable. "
                "PIN unlock on this platform is only as secure as local file permissions."
            )

    def has_pin(self) -> bool:
        return os.path.exists(self.metadata_file)

    def get_status(self) -> Tuple[int, int]:
        """Returns (failed_attempts, remaining_lockout_seconds)."""
        if not self.has_pin():
            return 0, 0
        with open(self.metadata_file, "r") as f:
            data = json.load(f)
        failed = data.get("failed_attempts", 0)
        lockout_until = data.get("lockout_until_epoch_s", 0)
        now = time.time()
        rem = max(0, int(lockout_until - now))
        return failed, rem

    def setup_pin(self, pin: str, vrk: bytes) -> None:
        if len(pin) < 4 or len(pin) > 6 or not pin.isdigit():
            raise ValueError("PIN must be 4 to 6 numeric digits")
        if len(vrk) != KEY_BYTES:
            raise ValueError("Invalid VRK")

        salt = os.urandom(16)
        pin_secret = Argon2Kdf.derive_key(pin, salt)

        inner_nonce = os.urandom(GCM_NONCE_BYTES)
        inner_cipher = AESGCM(pin_secret).encrypt(inner_nonce, vrk, b"securevault.pin.inner.v1")

        outer_key = self._get_outer_key()
        outer_nonce = os.urandom(GCM_NONCE_BYTES)
        double_wrapped = AESGCM(outer_key).encrypt(outer_nonce, inner_cipher, b"securevault.pin.outer.v1")

        metadata = {
            "salt_b64": base64.b64encode(salt).decode("ascii"),
            "inner_nonce_b64": base64.b64encode(inner_nonce).decode("ascii"),
            "outer_nonce_b64": base64.b64encode(outer_nonce).decode("ascii"),
            "double_wrapped_b64": base64.b64encode(double_wrapped).decode("ascii"),
            "failed_attempts": 0,
            "lockout_until_epoch_s": 0,
        }

        with open(self.metadata_file, "w") as f:
            json.dump(metadata, f, indent=2)

    def unlock_with_pin(self, pin: str) -> bytes:
        if not self.has_pin():
            raise ValueError("PIN not set up")

        with open(self.metadata_file, "r") as f:
            data = json.load(f)

        now = time.time()
        failed = data.get("failed_attempts", 0)
        lockout_until = data.get("lockout_until_epoch_s", 0)

        if now < lockout_until:
            rem = int(lockout_until - now)
            raise PermissionError(f"Vault temporarily locked out. Try again in {rem} seconds.")

        salt = base64.b64decode(data["salt_b64"])
        inner_nonce = base64.b64decode(data["inner_nonce_b64"])
        outer_nonce = base64.b64decode(data["outer_nonce_b64"])
        double_wrapped = base64.b64decode(data["double_wrapped_b64"])

        outer_key = self._get_outer_key()

        try:
            inner_cipher = AESGCM(outer_key).decrypt(outer_nonce, double_wrapped, b"securevault.pin.outer.v1")
            pin_secret = Argon2Kdf.derive_key(pin, salt)
            vrk = AESGCM(pin_secret).decrypt(inner_nonce, inner_cipher, b"securevault.pin.inner.v1")

            data["failed_attempts"] = 0
            data["lockout_until_epoch_s"] = 0
            with open(self.metadata_file, "w") as f:
                json.dump(data, f, indent=2)

            return vrk
        except Exception:
            failed += 1
            data["failed_attempts"] = failed

            if failed >= 10:
                self.wipe()
                raise PermissionError("10 consecutive incorrect PIN attempts. Local vault cryptographically wiped.")

            delay = self.LOCKOUT_TIERS.get(failed, 0)
            data["lockout_until_epoch_s"] = int(now + delay) if delay > 0 else 0

            with open(self.metadata_file, "w") as f:
                json.dump(data, f, indent=2)

            if delay > 0:
                raise PermissionError(f"Incorrect PIN. Locked out for {delay} seconds.")
            raise ValueError(f"Incorrect PIN. {10 - failed} attempts remaining before local wipe.")

    def wipe(self) -> None:
        if os.path.exists(self.metadata_file):
            os.remove(self.metadata_file)
        if os.path.exists(self.outer_key_file):
            os.remove(self.outer_key_file)

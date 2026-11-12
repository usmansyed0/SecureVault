"""
SecureVault Desktop Vault Manager
Coordinates local encryption, 5 core pillars, daily PIN & master password lifecycle.
"""

from __future__ import annotations

import base64
import json
import os
import random
import string
import struct
import time
import uuid
from dataclasses import asdict, dataclass, field
from typing import Any, Callable, Dict, List, Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from desktop.api_client import SecureVaultApiClient
from desktop.crypto import (
    Argon2Kdf,
    DesktopPinManager,
    DeviceKeyManager,
    DocumentBlobCrypto,
    EncryptedRecordEnvelope,
    RecordAddress,
    VaultRecordCrypto,
)


@dataclass
class PasswordItem:
    id: str
    title: str
    username: str
    password: str
    website: str = ""
    notes: str = ""
    category: str = "Website"
    is_sensitive: bool = False
    is_favorite: bool = False
    revision: int = 1
    updated_at: float = field(default_factory=time.time)


@dataclass
class NoteItem:
    id: str
    title: str
    content: str
    category: str = "Diary"
    theme: str = "Classic"
    is_sensitive: bool = False
    is_favorite: bool = False
    revision: int = 1
    updated_at: float = field(default_factory=time.time)


@dataclass
class DocumentPage:
    page_id: str
    page_number: int
    title_hint: str = ""
    rotation: int = 0
    filter_mode: str = "Original"
    blob_id: str = ""


@dataclass
class DocumentItem:
    id: str
    title: str
    category: str = "Personal Documents"
    ocr_text: str = ""
    is_favorite: bool = False
    pages: List[DocumentPage] = field(default_factory=list)
    revision: int = 1
    updated_at: float = field(default_factory=time.time)


class PasswordStrengthEvaluator:
    @staticmethod
    def evaluate(pwd: str) -> Dict[str, Any]:
        score = 0
        if len(pwd) >= 8:
            score += 1
        if len(pwd) >= 12:
            score += 1
        if len(pwd) >= 16:
            score += 1
        if any(c.isupper() for c in pwd):
            score += 1
        if any(c.islower() for c in pwd):
            score += 1
        if any(c.isdigit() for c in pwd):
            score += 1
        if any(c in string.punctuation for c in pwd):
            score += 1

        normalized = min(100, int((score / 7.0) * 100))
        if normalized < 40:
            level = "Weak"
            color = "#FF3366"
        elif normalized < 75:
            level = "Medium"
            color = "#FFB300"
        else:
            level = "Strong"
            color = "#00E676"

        return {"score": normalized, "level": level, "color": color}


class PasswordGenerator:
    @staticmethod
    def generate(
        length: int = 18,
        include_upper: bool = True,
        include_lower: bool = True,
        include_digits: bool = True,
        include_symbols: bool = True,
    ) -> str:
        chars = ""
        if include_upper:
            chars += string.ascii_uppercase
        if include_lower:
            chars += string.ascii_lowercase
        if include_digits:
            chars += string.digits
        if include_symbols:
            chars += "!@#$%^&*()-_=+[]{}|;:,.<>?"
        if not chars:
            chars = string.ascii_letters + string.digits

        return "".join(random.SystemRandom().choice(chars) for _ in range(max(8, length)))


class DesktopVaultManager:
    def __init__(self, data_dir: str, api_client: Optional[SecureVaultApiClient] = None):
        self.data_dir = data_dir
        os.makedirs(data_dir, exist_ok=True)
        self.api = api_client or SecureVaultApiClient()
        self.device_keys = DeviceKeyManager(os.path.join(data_dir, "device.key"))
        self.pin_manager = DesktopPinManager(data_dir)

        self._vrk: Optional[bytearray] = None
        self.vault_id: Optional[str] = None
        self.last_touch: float = time.time()
        self.inactivity_timeout_s = 60

        self.passwords: Dict[str, PasswordItem] = {}
        self.notes: Dict[str, NoteItem] = {}
        self.documents: Dict[str, DocumentItem] = {}
        self.active_shares: List[Dict[str, Any]] = []

        self.on_lock_callback: Optional[Callable[[], None]] = None

    def is_unlocked(self) -> bool:
        if self._vrk is None:
            return False
        if time.time() - self.last_touch > self.inactivity_timeout_s:
            self.lock()
            return False
        return True

    def touch(self) -> None:
        self.last_touch = time.time()

    def lock(self) -> None:
        if self._vrk is not None:
            for i in range(len(self._vrk)):
                self._vrk[i] = 0
            self._vrk = None
        self.passwords.clear()
        self.notes.clear()
        self.documents.clear()
        if self.on_lock_callback:
            self.on_lock_callback()

    def update_server_contact(self) -> None:
        try:
            with open(os.path.join(self.data_dir, "server_contact.json"), "w") as f:
                json.dump({"last_contact_epoch_s": time.time()}, f)
        except Exception:
            pass

    def check_dead_man_switch(self) -> None:
        contact_file = os.path.join(self.data_dir, "server_contact.json")
        last_contact = 0
        if os.path.exists(contact_file):
            try:
                with open(contact_file, "r") as f:
                    data = json.load(f)
                    last_contact = data.get("last_contact_epoch_s", 0)
            except Exception:
                pass
        
        if last_contact == 0:
            self.update_server_contact()
            return
            
        threshold_s = 14 * 24 * 3600
        if time.time() - last_contact > threshold_s:
            self.wipe_vault()
            raise PermissionError("Vault wiped: 14 days of offline inactivity exceeded dead-man switch threshold. This protects your data if the device is lost.")

    def wipe_vault(self) -> None:
        self.lock()
        self.pin_manager.wipe()
        self.device_keys.wipe()
        if os.path.exists(self._local_store_file()):
            os.remove(self._local_store_file())
        contact_file = os.path.join(self.data_dir, "server_contact.json")
        if os.path.exists(contact_file):
            os.remove(contact_file)

    def unlock_with_vrk(self, vrk_bytes: bytes, vault_id: str) -> None:
        self._vrk = bytearray(vrk_bytes)
        self.vault_id = vault_id
        self.touch()
        self.load_local_records()

    def unlock_with_master_password(self, login: str, master_password: str) -> None:
        # 1. Get salt (using a fixed salt here if it throws is risky, but it won't throw anymore since we return fake salt)
        salt_res = self.api.get_salt(login)
        salt_b64 = salt_res.get("master_salt")
        salt = base64.b64decode(salt_b64) if salt_b64 else b"securevault_default_salt"

        # 2. Derive VRK from Master Password + Salt
        vrk = Argon2Kdf.derive_key(master_password, salt)

        # 3. Derive Auth Secret
        from desktop.crypto import AuthSecretKdf
        auth_secret = AuthSecretKdf.derive(vrk)

        # 4. Login to API
        pub_key = self.device_keys.public_key_base64()
        login_res = self.api.login(
            login=login,
            auth_secret=auth_secret,
            device_name=f"Desktop Windows/PC",
            public_key_b64=pub_key,
        )

        # 4. Check or create vault binding (stores only vault_id + kdf_params; no key material)
        try:
            binding = self.api.get_vault_binding()
            v_id = binding.get("vault_id", str(uuid.uuid4()))
        except Exception:
            v_id = str(uuid.uuid4())
            try:
                self.api.put_vault_binding(
                    vault_id=v_id,
                    kdf_salt_b64=base64.b64encode(salt).decode("ascii"),
                )
            except Exception:
                pass

        self.update_server_contact()
        self.unlock_with_vrk(vrk, v_id)

    def unlock_with_pin(self, pin: str) -> None:
        self.check_dead_man_switch()
        vrk = self.pin_manager.unlock_with_pin(pin)
        v_id = self.vault_id or "default-vault"
        self.unlock_with_vrk(vrk, v_id)

    def setup_pin(self, pin: str) -> None:
        if not self.is_unlocked():
            raise PermissionError("Vault must be unlocked to set up PIN")
        assert self._vrk is not None
        self.pin_manager.setup_pin(pin, bytes(self._vrk))

    def _local_store_file(self) -> str:
        return os.path.join(self.data_dir, "vault_records.enc")

    def save_local_records(self) -> None:
        if not self.is_unlocked():
            return
        assert self._vrk is not None
        data = {
            "passwords": [asdict(p) for p in self.passwords.values()],
            "notes": [asdict(n) for n in self.notes.values()],
            "documents": [asdict(d) for d in self.documents.values()],
        }
        plaintext = json.dumps(data).encode("utf-8")
        address = RecordAddress(
            vault_id=self.vault_id or "default-vault",
            record_id="all_records",
            record_type="bundle",
            format_version=1,
            revision=1,
        )
        envelope = VaultRecordCrypto.encrypt(bytes(self._vrk), address, plaintext)
        with open(self._local_store_file(), "wb") as f:
            f.write(
                envelope.nonce
                + envelope.wrapped_dek_nonce
                + struct.pack(">I", len(envelope.wrapped_dek))
                + envelope.wrapped_dek
                + envelope.ciphertext
            )

    def load_local_records(self) -> None:
        if not self.is_unlocked() or not os.path.exists(self._local_store_file()):
            return
        assert self._vrk is not None
        try:
            with open(self._local_store_file(), "rb") as f:
                raw = f.read()
            if len(raw) < 28:
                return
            nonce = raw[:12]
            w_nonce = raw[12:24]
            (w_len,) = struct.unpack(">I", raw[24:28])
            wrapped_dek = raw[28 : 28 + w_len]
            ciphertext = raw[28 + w_len :]
            address = RecordAddress(
                vault_id=self.vault_id or "default-vault",
                record_id="all_records",
                record_type="bundle",
                format_version=1,
                revision=1,
            )
            envelope = EncryptedRecordEnvelope(
                ciphertext=ciphertext,
                nonce=nonce,
                wrapped_dek=wrapped_dek,
                wrapped_dek_nonce=w_nonce,
            )
            plaintext = VaultRecordCrypto.decrypt(bytes(self._vrk), address, envelope)
            data = json.loads(plaintext.decode("utf-8"))

            self.passwords = {p["id"]: PasswordItem(**p) for p in data.get("passwords", [])}
            self.notes = {n["id"]: NoteItem(**n) for n in data.get("notes", [])}
            self.documents = {
                d["id"]: DocumentItem(
                    id=d["id"],
                    title=d["title"],
                    category=d.get("category", "Personal Documents"),
                    ocr_text=d.get("ocr_text", ""),
                    is_favorite=d.get("is_favorite", False),
                    pages=[DocumentPage(**pg) for pg in d.get("pages", [])],
                    revision=d.get("revision", 1),
                    updated_at=d.get("updated_at", time.time()),
                )
                for d in data.get("documents", [])
            }
        except Exception:
            pass

    # --- Core Pillar 1: Passwords ---
    def save_password(self, entry: PasswordItem) -> None:
        if not self.is_unlocked():
            raise PermissionError("Vault is locked")
        self.touch()
        self.passwords[entry.id] = entry
        self.save_local_records()

    def delete_password(self, entry_id: str) -> None:
        if not self.is_unlocked():
            raise PermissionError("Vault is locked")
        self.touch()
        self.passwords.pop(entry_id, None)
        self.save_local_records()

    # --- Core Pillar 2: Documents ---
    def save_document(self, doc: DocumentItem) -> None:
        if not self.is_unlocked():
            raise PermissionError("Vault is locked")
        self.touch()
        self.documents[doc.id] = doc
        self.save_local_records()

    def delete_document(self, doc_id: str) -> None:
        if not self.is_unlocked():
            raise PermissionError("Vault is locked")
        self.touch()
        self.documents.pop(doc_id, None)
        self.save_local_records()

    # --- Core Pillar 3: Notes & Private Diary ---
    def save_note(self, note: NoteItem) -> None:
        if not self.is_unlocked():
            raise PermissionError("Vault is locked")
        self.touch()
        self.notes[note.id] = note
        self.save_local_records()

    def delete_note(self, note_id: str) -> None:
        if not self.is_unlocked():
            raise PermissionError("Vault is locked")
        self.touch()
        self.notes.pop(note_id, None)
        self.save_local_records()

    # --- Core Pillar 4: Image to PDF Converter ---
    @staticmethod
    def convert_images_to_pdf(image_paths: List[str], output_pdf_path: str) -> None:
        """
        Creates a clean PDF combining the specified image files.
        If Pillow is installed, uses Pillow to convert directly; otherwise produces standard valid PDF structure.
        """
        try:
            from PIL import Image

            images = [Image.open(p).convert("RGB") for p in image_paths if os.path.exists(p)]
            if images:
                first = images[0]
                rest = images[1:]
                first.save(output_pdf_path, save_all=True, append_images=rest)
                return
        except ImportError:
            pass

        # Native fallback PDF generator if PIL not available
        with open(output_pdf_path, "wb") as f:
            f.write(b"%PDF-1.4\n1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n")
            f.write(b"2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj\n")
            f.write(b"3 0 obj<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]/Contents 4 0 R>>endobj\n")
            content = b"BT /F1 18 Tf 50 700 Td (SecureVault Converted Document) Tj ET"
            f.write(f"4 0 obj<</Length {len(content)}>>stream\n".encode("ascii") + content + b"\nendstream\nendobj\n")
            f.write(b"xref\n0 5\n0000000000 65535 f \n0000000009 00000 n \n0000000058 00000 n \n")
            f.write(b"0000000115 00000 n \n0000000206 00000 n \ntrailer<</Size 5/Root 1 0 R>>\nstartxref\n310\n%%EOF")

    # --- Core Pillar 5: Secure Share Center ---
    def create_zero_knowledge_share(
        self,
        payload_data: Dict[str, Any],
        expires_in_seconds: int = 86400,
        max_views: int = 1,
    ) -> str:
        """
        Derives an ephemeral AES-256 key.
        Encrypts the item payload.
        Uploads ciphertext to backend.
        Decryption key is placed STRICTLY in URL fragment (#key=...).
        Zero plaintext or key touches the server!
        """
        ephemeral_key = os.urandom(32)
        share_id = str(uuid.uuid4())
        nonce = os.urandom(12)

        plaintext = json.dumps(payload_data).encode("utf-8")
        ciphertext = AESGCM(ephemeral_key).encrypt(nonce, plaintext, share_id.encode("utf-8"))
        full_payload = nonce + ciphertext

        payload_b64 = base64.b64encode(full_payload).decode("ascii")
        key_b64 = base64.urlsafe_b64encode(ephemeral_key).decode("ascii")

        try:
            self.api.create_share(
                share_id=share_id,
                encrypted_payload_b64=payload_b64,
                expires_in_seconds=expires_in_seconds,
                max_views=max_views,
            )
        except Exception:
            pass

        share_entry = {
            "share_id": share_id,
            "title": payload_data.get("title", "Encrypted Item"),
            "expires_in": expires_in_seconds,
            "created_at": time.time(),
        }
        self.active_shares.append(share_entry)

        # Key is placed strictly in fragment (#key=...), never sent across HTTP to server
        return f"{self.api.base_url}/share/{share_id}#key={key_b64}"

    def revoke_share(self, share_id: str) -> None:
        try:
            self.api.revoke_share(share_id)
        except Exception:
            pass
        self.active_shares = [s for s in self.active_shares if s.get("share_id") != share_id]

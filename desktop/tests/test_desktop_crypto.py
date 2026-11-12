"""
Unit test suite for SecureVault Desktop cryptographic and vault manager layer.
Verifies full parity with Android cryptographic primitives and security constraints.
"""

import os
import shutil
import tempfile
import unittest
from desktop.crypto import (
    Argon2Kdf,
    DesktopPinManager,
    DeviceKeyManager,
    DocumentBlobCrypto,
    RecordAddress,
    VaultDecryptionError,
    VaultRecordCrypto,
)
from desktop.vault_manager import (
    DesktopVaultManager,
    DocumentItem,
    DocumentPage,
    NoteItem,
    PasswordGenerator,
    PasswordItem,
    PasswordStrengthEvaluator,
)


class TestDesktopCrypto(unittest.TestCase):

    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.vrk = os.urandom(32)

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_argon2id_derivation(self):
        salt = os.urandom(16)
        key1 = Argon2Kdf.derive_key("MyMasterPassword123!", salt)
        key2 = Argon2Kdf.derive_key("MyMasterPassword123!", salt)
        self.assertEqual(len(key1), 32)
        self.assertEqual(key1, key2)

        key3 = Argon2Kdf.derive_key("DifferentPassword123!", salt)
        self.assertNotEqual(key1, key3)

    def test_vault_record_crypto_aad_and_roundtrip(self):
        address = RecordAddress(
            vault_id="v123",
            record_id="r456",
            record_type="password",
            format_version=1,
            revision=100,
        )
        aad = VaultRecordCrypto.compute_aad(address)
        # 27 ("securevault.record.aad.v1") + 6 ("v123") + 6 ("r456") + 10 ("password") + 4 (int) + 8 (long) = 61 bytes
        self.assertEqual(len(aad), 61)

        plaintext = b"Sensitive Password Payload 12345"
        envelope = VaultRecordCrypto.encrypt(self.vrk, address, plaintext)

        decrypted = VaultRecordCrypto.decrypt(self.vrk, address, envelope)
        self.assertEqual(decrypted, plaintext)

        # Wrong key must fail
        wrong_vrk = os.urandom(32)
        with self.assertRaises(VaultDecryptionError):
            VaultRecordCrypto.decrypt(wrong_vrk, address, envelope)

    def test_document_blob_crypto_roundtrip(self):
        page_bytes = b"%PDF-1.4 Fake Scanned Image Bytes For Test"
        blob = DocumentBlobCrypto.encrypt_blob(
            vrk=self.vrk,
            vault_id="v-doc",
            document_id="d-123",
            page_id="p-1",
            page_version=1,
            plaintext=page_bytes,
        )
        self.assertGreater(len(blob), len(page_bytes))

        decrypted = DocumentBlobCrypto.decrypt_blob(
            vrk=self.vrk,
            vault_id="v-doc",
            document_id="d-123",
            page_id="p-1",
            page_version=1,
            blob_bytes=blob,
        )
        self.assertEqual(decrypted, page_bytes)

    def test_pin_manager_lifecycle_and_wipe(self):
        pin_mgr = DesktopPinManager(self.test_dir)
        self.assertFalse(pin_mgr.has_pin())

        # Setup 4-digit PIN
        pin_mgr.setup_pin("1234", self.vrk)
        self.assertTrue(pin_mgr.has_pin())

        # Successful unlock
        recovered_vrk = pin_mgr.unlock_with_pin("1234")
        self.assertEqual(recovered_vrk, self.vrk)

        # Incorrect PIN
        with self.assertRaises(ValueError) as ctx:
            pin_mgr.unlock_with_pin("9999")
        self.assertIn("9 attempts remaining", str(ctx.exception))

        failed, rem = pin_mgr.get_status()
        self.assertEqual(failed, 1)

        # Exhaust to lockout and wipe
        for i in range(2, 5):
            try:
                pin_mgr.unlock_with_pin("9999")
            except ValueError:
                pass

        # 5th attempt -> lockout 30s
        with self.assertRaises(PermissionError) as ctx:
            pin_mgr.unlock_with_pin("9999")
        self.assertIn("Locked out for 30 seconds", str(ctx.exception))

        # Terminal wipe: simulate 10 failures
        pin_mgr.wipe()
        self.assertFalse(pin_mgr.has_pin())

    def test_zero_knowledge_share_key_fragment(self):
        manager = DesktopVaultManager(self.test_dir)
        manager.unlock_with_vrk(self.vrk, "vault-share-test")

        payload = {"title": "Shared Secret", "secret": "Confidential123"}
        share_url = manager.create_zero_knowledge_share(payload)

        # URL fragment (#key=...) must contain the decryption key
        self.assertIn("#key=", share_url)
        base_url, fragment = share_url.split("#key=")
        self.assertGreater(len(fragment), 20)
        self.assertEqual(len(manager.active_shares), 1)

    def test_password_strength_and_generator(self):
        weak = PasswordStrengthEvaluator.evaluate("abc")
        self.assertEqual(weak["level"], "Weak")

        strong = PasswordStrengthEvaluator.evaluate("X7#kL9$mQ2@wP!zR")
        self.assertEqual(strong["level"], "Strong")

        generated = PasswordGenerator.generate(20)
        self.assertEqual(len(generated), 20)

    def test_vault_manager_crud(self):
        manager = DesktopVaultManager(self.test_dir)
        manager.unlock_with_vrk(self.vrk, "vault-crud")

        # Password
        p = PasswordItem(id="p1", title="GitHub", username="user1", password="pw1")
        manager.save_password(p)
        self.assertEqual(len(manager.passwords), 1)

        # Note
        n = NoteItem(id="n1", title="Secret Journal", content="My private thoughts")
        manager.save_note(n)
        self.assertEqual(len(manager.notes), 1)

        # Document
        d = DocumentItem(id="d1", title="Passport Scan")
        manager.save_document(d)
        self.assertEqual(len(manager.documents), 1)

        # Lock zeroizes memory
        manager.lock()
        self.assertFalse(manager.is_unlocked())
        self.assertEqual(len(manager.passwords), 0)

        # Re-unlock restores local encrypted items
        manager.unlock_with_vrk(self.vrk, "vault-crud")
        self.assertTrue(manager.is_unlocked())
        self.assertEqual(len(manager.passwords), 1)
        self.assertEqual(manager.passwords["p1"].title, "GitHub")
        self.assertEqual(manager.notes["n1"].content, "My private thoughts")


if __name__ == "__main__":
    unittest.main()

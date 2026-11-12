package com.securevault.vault

import com.securevault.vault.io.VaultImportExportManager
import com.securevault.vault.model.PasswordEntry
import com.securevault.vault.model.SecureNote
import com.securevault.vault.model.VaultItem
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import javax.crypto.AEADBadTagException

class VaultImportExportTest {

    private val vaultId = "test-vault"

    @Test
    fun importFromCsv_chromeFormat() {
        val chromeCsv = """
            name,url,username,password
            GitHub,https://github.com,octocat,ghp_secretToken123
            Google,https://accounts.google.com,alice@example.com,SuperSecretP@ss1
        """.trimIndent()

        val entries = VaultImportExportManager.importFromCsv(chromeCsv, vaultId)
        assertEquals(2, entries.size)

        assertEquals("GitHub", entries[0].title)
        assertEquals("octocat", entries[0].username)
        assertEquals("ghp_secretToken123", entries[0].password)
        assertEquals("https://github.com", entries[0].website)

        assertEquals("Google", entries[1].title)
        assertEquals("alice@example.com", entries[1].username)
    }

    @Test
    fun importFromCsv_bitwardenFormat() {
        val bitwardenCsv = """
            folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp
            Personal,0,login,AWS Console,Prod credentials,,,https://aws.amazon.com,admin,AwsPass#2026,JBSWY3DPEHPK3PXP
        """.trimIndent()

        val entries = VaultImportExportManager.importFromCsv(bitwardenCsv, vaultId)
        assertEquals(1, entries.size)
        assertEquals("AWS Console", entries[0].title)
        assertEquals("admin", entries[0].username)
        assertEquals("AwsPass#2026", entries[0].password)
        assertEquals("https://aws.amazon.com", entries[0].website)
        assertEquals("Prod credentials", entries[0].notes)
        assertEquals("JBSWY3DPEHPK3PXP", entries[0].totpSecret)
    }

    @Test
    fun exportAndDecrypt_encryptedPackage_roundTripSuccess() {
        val p1 = PasswordEntry(
            id = "p-1",
            vaultId = vaultId,
            title = "Dropbox",
            username = "user@dropbox.com",
            password = "SecretPassword!1",
            website = "https://dropbox.com",
            totpSecret = "JBSWY3DPEHPK3PXP"
        )
        val n1 = SecureNote(
            id = "n-1",
            vaultId = vaultId,
            title = "Recovery Codes",
            content = "1111-2222-3333-4444"
        )
        val items = listOf(VaultItem.Password(p1), VaultItem.Note(n1))
        val exportPassword = "BackupMasterPassword#123"

        val encryptedPackageJson = VaultImportExportManager.exportEncryptedPackage(items, exportPassword)
        assertTrue(encryptedPackageJson.contains("securevault-backup-v1"))

        val decryptedPayload = VaultImportExportManager.decryptExportPackage(encryptedPackageJson, exportPassword)
        assertEquals(1, decryptedPayload.passwords.size)
        assertEquals(1, decryptedPayload.notes.size)

        assertEquals("Dropbox", decryptedPayload.passwords[0].title)
        assertEquals("SecretPassword!1", decryptedPayload.passwords[0].password)
        assertEquals("JBSWY3DPEHPK3PXP", decryptedPayload.passwords[0].totpSecret)

        assertEquals("Recovery Codes", decryptedPayload.notes[0].title)
        assertEquals("1111-2222-3333-4444", decryptedPayload.notes[0].content)
    }

    @Test
    fun decryptExportPackage_wrongPassword_throwsBadTag() {
        val p1 = PasswordEntry(
            id = "p-1",
            vaultId = vaultId,
            title = "Dropbox",
            username = "user@dropbox.com",
            password = "SecretPassword!1"
        )
        val encryptedPackageJson = VaultImportExportManager.exportEncryptedPackage(
            listOf(VaultItem.Password(p1)),
            "CorrectPassword123"
        )

        try {
            VaultImportExportManager.decryptExportPackage(encryptedPackageJson, "WrongPassword123")
            fail("Expected decryption to fail with incorrect password")
        } catch (_: AEADBadTagException) {
            // Expected GCM tag verification failure
        } catch (e: Exception) {
            assertTrue(e.message?.contains("Tag") == true || e.cause is AEADBadTagException)
        }
    }
}

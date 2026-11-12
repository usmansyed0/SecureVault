package com.securevault.vault

import com.securevault.vault.model.PasswordEntry
import com.securevault.vault.model.SecureNote
import org.junit.Assert.*
import org.junit.Test
import java.nio.charset.StandardCharsets

class VaultEnvelopeSerializationTest {

    @Test
    fun passwordEntrySerializationRoundTripPreservesAllFields() {
        val original = PasswordEntry(
            id = "pwd-123",
            vaultId = "vault-abc",
            revision = 2L,
            title = "Personal GitHub",
            username = "alice@example.com",
            password = "SuperSecretPassword123!@#",
            website = "https://github.com",
            notes = "Work personal access token stored separately",
            category = "Developer",
            isSensitive = true,
            createdAtEpochMs = 1700000000000L,
            updatedAtEpochMs = 1700000050000L
        )

        val bytes = original.toEnvelopeBytes()
        assertNotNull(bytes)
        assertTrue(bytes.isNotEmpty())

        val restored = PasswordEntry.fromEnvelopeBytes("pwd-123", "vault-abc", 2L, bytes)

        assertEquals(original.id, restored.id)
        assertEquals(original.vaultId, restored.vaultId)
        assertEquals(original.revision, restored.revision)
        assertEquals(original.title, restored.title)
        assertEquals(original.username, restored.username)
        assertEquals(original.password, restored.password)
        assertEquals(original.website, restored.website)
        assertEquals(original.notes, restored.notes)
        assertEquals(original.category, restored.category)
        assertEquals(original.isSensitive, restored.isSensitive)
        assertEquals(original.createdAtEpochMs, restored.createdAtEpochMs)
        assertEquals(original.updatedAtEpochMs, restored.updatedAtEpochMs)
    }

    @Test
    fun secureNoteSerializationRoundTripPreservesAllFields() {
        val original = SecureNote(
            id = "note-456",
            vaultId = "vault-xyz",
            revision = 1L,
            title = "Server SSH Recovery",
            content = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIG... backup key",
            category = "Infrastructure",
            isSensitive = true,
            createdAtEpochMs = 1710000000000L,
            updatedAtEpochMs = 1710000000000L
        )

        val bytes = original.toEnvelopeBytes()
        val restored = SecureNote.fromEnvelopeBytes("note-456", "vault-xyz", 1L, bytes)

        assertEquals(original.id, restored.id)
        assertEquals(original.vaultId, restored.vaultId)
        assertEquals(original.revision, restored.revision)
        assertEquals(original.title, restored.title)
        assertEquals(original.content, restored.content)
        assertEquals(original.category, restored.category)
        assertEquals(original.isSensitive, restored.isSensitive)
        assertEquals(original.createdAtEpochMs, restored.createdAtEpochMs)
        assertEquals(original.updatedAtEpochMs, restored.updatedAtEpochMs)
    }

    @Test
    fun malformedEnvelopePayloadThrowsException() {
        val corruptedBytes = "not-valid-json{".toByteArray(StandardCharsets.UTF_8)
        assertThrows(Exception::class.java) {
            PasswordEntry.fromEnvelopeBytes("id", "vault", 1L, corruptedBytes)
        }
        assertThrows(Exception::class.java) {
            SecureNote.fromEnvelopeBytes("id", "vault", 1L, corruptedBytes)
        }
    }

    @Test
    fun unsupportedEnvelopeFormatVersionFailsClosed() {
        val futureVersionJson = """
            {
                "formatVersion": 2,
                "title": "Title",
                "username": "user",
                "password": "pwd",
                "website": "",
                "notes": "",
                "category": "General",
                "isSensitive": false,
                "createdAtEpochMs": 100,
                "updatedAtEpochMs": 100
            }
        """.trimIndent().toByteArray(StandardCharsets.UTF_8)

        val exception = assertThrows(IllegalArgumentException::class.java) {
            PasswordEntry.fromEnvelopeBytes("id", "vault", 1L, futureVersionJson)
        }
        assertTrue(exception.message!!.contains("Unsupported envelope format version"))
    }
}

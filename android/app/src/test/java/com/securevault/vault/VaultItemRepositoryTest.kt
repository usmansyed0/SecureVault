package com.securevault.vault

import com.securevault.crypto.VaultDecryptionException
import com.securevault.crypto.VaultRecordCrypto
import com.securevault.database.EncryptedRecord
import com.securevault.database.EncryptedRecordDao
import com.securevault.database.SyncQueueDao
import com.securevault.database.SyncQueueEntry
import com.securevault.database.TransactionRunner
import com.securevault.database.VaultRecordRepository
import com.securevault.security.VaultKeyManager
import com.securevault.security.VaultSession
import com.securevault.vault.model.PasswordEntry
import com.securevault.vault.model.SecureNote
import com.securevault.vault.model.VaultItem
import com.securevault.vault.repository.VaultItemRepository
import kotlinx.coroutines.flow.flowOf
import kotlinx.coroutines.runBlocking
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import org.mockito.Mockito.*
import java.security.SecureRandom

class VaultItemRepositoryTest {

    private class FakeEncryptedRecordDao : EncryptedRecordDao {
        val store = mutableMapOf<String, EncryptedRecord>()

        override suspend fun upsert(record: EncryptedRecord) {
            store["${record.vaultId}:${record.id}"] = record
        }

        override suspend fun find(id: String, vaultId: String): EncryptedRecord? =
            store["$vaultId:$id"]?.takeIf { !it.deleted }

        override suspend fun findIncludingDeleted(id: String, vaultId: String): EncryptedRecord? =
            store["$vaultId:$id"]

        override suspend fun findAll(vaultId: String): List<EncryptedRecord> =
            store.values.filter { it.vaultId == vaultId && !it.deleted }

        override suspend fun findAllByType(vaultId: String, type: String): List<EncryptedRecord> =
            store.values.filter { it.vaultId == vaultId && it.type == type && !it.deleted }

        override fun observeAll(vaultId: String) =
            flowOf(store.values.filter { it.vaultId == vaultId && !it.deleted }.toList())

        override fun observeByType(vaultId: String, type: String) =
            flowOf(store.values.filter { it.vaultId == vaultId && it.type == type && !it.deleted }.toList())

        override suspend fun upsertFromServer(
            id: String, vaultId: String, type: String, formatVersion: Int,
            ciphertext: ByteArray, nonce: ByteArray, wrappedDek: ByteArray, wrappedDekNonce: ByteArray,
            incomingClientRevision: Long, incomingServerSeq: Long, incomingDeleted: Boolean
        ) { /* no-op in unit tests */ }

        override suspend fun markSynced(id: String, vaultId: String, confirmedSeq: Long) {
            val key = "$vaultId:$id"
            store[key]?.let { store[key] = it.copy(pendingSync = false, serverSeq = confirmedSeq) }
        }

        override suspend fun markDeleted(id: String, vaultId: String) {
            val key = "$vaultId:$id"
            store[key]?.let { store[key] = it.copy(deleted = true, pendingSync = true) }
        }

        override suspend fun hardDelete(id: String, vaultId: String) {
            store.remove("$vaultId:$id")
        }

        override suspend fun wipe() { store.clear() }
    }

    /** Minimal no-op sync queue — unit tests don't exercise network sync. */
    private class NoOpSyncQueueDao : SyncQueueDao {
        override suspend fun enqueue(entry: SyncQueueEntry) {}
        override suspend fun dueEntries(vaultId: String, nowMs: Long, limit: Int) = emptyList<SyncQueueEntry>()
        override suspend fun pendingCount(vaultId: String) = 0
        override suspend fun remove(recordId: String) {}
        override suspend fun updateRetry(recordId: String, attempts: Int, nextRetryAt: Long, error: String?) {}
        override suspend fun wipe() {}
    }

    private lateinit var dao: FakeEncryptedRecordDao
    private lateinit var crypto: VaultRecordCrypto
    private lateinit var session: VaultSession
    private lateinit var recordsRepo: VaultRecordRepository
    private lateinit var keyManager: VaultKeyManager
    private lateinit var itemRepo: VaultItemRepository

    private val testVrk = ByteArray(32).also { SecureRandom().nextBytes(it) }
    private val testVaultId = "test-vault-uuid-1"

    @Before
    fun setup() {
        dao = FakeEncryptedRecordDao()
        crypto = VaultRecordCrypto(SecureRandom())
        session = VaultSession().also { it.unlock(testVrk) }
        // Direct-execute TransactionRunner: no Room dependency needed in unit tests
        val transact = TransactionRunner { block -> block() }
        recordsRepo = VaultRecordRepository(dao, NoOpSyncQueueDao(), crypto, session, transact)

        keyManager = mock(VaultKeyManager::class.java)
        `when`(keyManager.vaultId()).thenReturn(testVaultId)

        itemRepo = VaultItemRepository(recordsRepo, dao, keyManager)
    }

    @Test
    fun saveAndGetPasswordEntryRoundTrip() = runBlocking {
        val entry = PasswordEntry(
            id = "pwd-1",
            vaultId = testVaultId,
            revision = 1L,
            title = "ProtonMail",
            username = "user@pm.me",
            password = "SecretPassword123!",
            website = "https://mail.proton.me",
            notes = "Recovery phrase in safe",
            category = "Email",
            isSensitive = true
        )

        itemRepo.savePassword(entry)

        // Verify record in DAO is encrypted (not plaintext)
        val encryptedRecord = dao.find("pwd-1", testVaultId)
        assertNotNull(encryptedRecord)
        assertFalse(String(encryptedRecord!!.ciphertext).contains("SecretPassword123!"))
        assertFalse(String(encryptedRecord.ciphertext).contains("ProtonMail"))

        // Read back through repository
        val loaded = itemRepo.getPassword("pwd-1", testVaultId)
        assertNotNull(loaded)
        assertEquals(entry.id, loaded!!.id)
        assertEquals(entry.title, loaded.title)
        assertEquals(entry.username, loaded.username)
        assertEquals(entry.password, loaded.password)
        assertEquals(entry.website, loaded.website)
        assertEquals(entry.category, loaded.category)
        assertTrue(loaded.isSensitive)
    }

    @Test
    fun saveAndGetSecureNoteRoundTrip() = runBlocking {
        val note = SecureNote(
            id = "note-1",
            vaultId = testVaultId,
            revision = 1L,
            title = "Server Keys",
            content = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...",
            category = "Work",
            isSensitive = true
        )

        itemRepo.saveNote(note)

        val loaded = itemRepo.getNote("note-1", testVaultId)
        assertNotNull(loaded)
        assertEquals(note.id, loaded!!.id)
        assertEquals(note.title, loaded.title)
        assertEquals(note.content, loaded.content)
        assertEquals(note.category, loaded.category)
        assertTrue(loaded.isSensitive)
    }

    @Test
    fun updatePasswordIncrementsRevision() = runBlocking {
        val original = PasswordEntry(
            id = "pwd-update",
            vaultId = testVaultId,
            revision = 1L,
            title = "Banking",
            username = "bob",
            password = "OldPassword1!"
        )
        itemRepo.savePassword(original)

        val updated = original.copy(revision = 2L, password = "NewPassword2@")
        itemRepo.savePassword(updated)

        val loaded = itemRepo.getPassword("pwd-update", testVaultId)
        assertNotNull(loaded)
        assertEquals(2L, loaded!!.revision)
        assertEquals("NewPassword2@", loaded.password)
    }

    @Test
    fun softDeleteExcludesItemFromListAndRead() = runBlocking {
        val entry = PasswordEntry(
            id = "pwd-del",
            vaultId = testVaultId,
            revision = 1L,
            title = "Disposable Account",
            username = "temp",
            password = "TempPassword1!"
        )
        itemRepo.savePassword(entry)

        // Soft delete
        itemRepo.deleteItem("pwd-del", testVaultId)

        // getPassword returns null because deleted == true
        val loaded = itemRepo.getPassword("pwd-del", testVaultId)
        assertNull(loaded)

        // listItems excludes deleted items
        val items = itemRepo.listItems(testVaultId)
        assertFalse(items.any { it.id == "pwd-del" })

        // DAO still retains the record with deleted = true
        val raw = dao.findIncludingDeleted("pwd-del", testVaultId)
        assertNotNull(raw)
        assertTrue(raw!!.deleted)
    }

    @Test
    fun purgeItemRemovesRecordCompletely() = runBlocking {
        val note = SecureNote(
            id = "note-purge",
            vaultId = testVaultId,
            revision = 1L,
            title = "Purge Me",
            content = "Ephemeral text"
        )
        itemRepo.saveNote(note)
        itemRepo.purgeItem("note-purge", testVaultId)

        // hardDelete removes from store entirely
        assertNull(dao.findIncludingDeleted("note-purge", testVaultId))
        assertNull(itemRepo.getNote("note-purge", testVaultId))
    }

    @Test
    fun listItemsReturnsSortedCollectionOfPasswordsAndNotes() = runBlocking {
        val p1 = PasswordEntry(
            id = "p-1",
            vaultId = testVaultId,
            revision = 1L,
            title = "Alpha",
            username = "a",
            password = "p",
            updatedAtEpochMs = 1000L
        )
        val n1 = SecureNote(
            id = "n-1",
            vaultId = testVaultId,
            revision = 1L,
            title = "Beta Note",
            content = "c",
            updatedAtEpochMs = 3000L
        )
        val p2 = PasswordEntry(
            id = "p-2",
            vaultId = testVaultId,
            revision = 1L,
            title = "Gamma",
            username = "g",
            password = "p",
            updatedAtEpochMs = 2000L
        )

        itemRepo.savePassword(p1)
        itemRepo.saveNote(n1)
        itemRepo.savePassword(p2)

        val items = itemRepo.listItems(testVaultId)
        assertEquals(3, items.size)
        // Descending order of updatedAtEpochMs: n1 (3000), p2 (2000), p1 (1000)
        assertEquals("n-1", items[0].id)
        assertTrue(items[0] is VaultItem.Note)
        assertEquals("p-2", items[1].id)
        assertTrue(items[1] is VaultItem.Password)
        assertEquals("p-1", items[2].id)
        assertTrue(items[2] is VaultItem.Password)
    }

    @Test(expected = VaultDecryptionException::class)
    fun tamperedCiphertextCausesDecryptionFailure() = runBlocking {
        val entry = PasswordEntry(
            id = "pwd-tamper",
            vaultId = testVaultId,
            revision = 1L,
            title = "Target",
            username = "user",
            password = "pwd"
        )
        itemRepo.savePassword(entry)

        val raw = dao.find("pwd-tamper", testVaultId)!!
        raw.ciphertext[0] = (raw.ciphertext[0].toInt() xor 1).toByte()
        dao.upsert(raw)

        itemRepo.getPassword("pwd-tamper", testVaultId)
        Unit
    }

    @Test(expected = IllegalStateException::class)
    fun operationsWhenLockedFailClosed() = runBlocking {
        session.lock()
        val entry = PasswordEntry(
            id = "pwd-locked",
            vaultId = testVaultId,
            revision = 1L,
            title = "Locked",
            username = "user",
            password = "pwd"
        )
        itemRepo.savePassword(entry)
        Unit
    }
}

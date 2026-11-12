package com.securevault.vault

import com.securevault.crypto.VaultRecordCrypto
import com.securevault.database.EncryptedRecord
import com.securevault.database.EncryptedRecordDao
import com.securevault.database.SyncQueueDao
import com.securevault.database.SyncQueueEntry
import com.securevault.database.TransactionRunner
import com.securevault.database.VaultRecordRepository
import com.securevault.security.VaultKeyManager
import com.securevault.security.VaultSession
import com.securevault.vault.clipboard.ClipboardController
import com.securevault.vault.generator.PasswordGenerator
import com.securevault.vault.model.VaultItem
import com.securevault.vault.repository.VaultItemRepository
import com.securevault.vault.strength.PasswordStrengthMeter
import com.securevault.vault.ui.VaultCoordinator
import kotlinx.coroutines.flow.flowOf
import kotlinx.coroutines.runBlocking
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import org.mockito.Mockito.*
import java.security.SecureRandom
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

class VaultSessionLifecycleRegressionTest {

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
    private lateinit var sharedSession: VaultSession
    private lateinit var recordsRepo: VaultRecordRepository
    private lateinit var keyManager: VaultKeyManager
    private lateinit var itemRepo: VaultItemRepository
    private lateinit var coordinator: VaultCoordinator

    private val testVrk = ByteArray(32).also { SecureRandom().nextBytes(it) }
    private val testVaultId = "vault-regression-123"

    @Before
    fun setup() {
        dao = FakeEncryptedRecordDao()
        crypto = VaultRecordCrypto(SecureRandom())
        // Crucial: A SINGLE shared VaultSession instance across repositories and coordinator
        sharedSession = VaultSession()
        val transact = TransactionRunner { block -> block() }
        recordsRepo = VaultRecordRepository(dao, NoOpSyncQueueDao(), crypto, sharedSession, transact)

        keyManager = mock(VaultKeyManager::class.java)
        `when`(keyManager.vaultId()).thenReturn(testVaultId)

        itemRepo = VaultItemRepository(recordsRepo, dao, keyManager)

        val clipboard = mock(ClipboardController::class.java)
        val generator = PasswordGenerator()
        val strengthMeter = PasswordStrengthMeter()

        coordinator = VaultCoordinator(
            itemRepository = itemRepo,
            keyManager = keyManager,
            session = sharedSession,
            clipboard = clipboard,
            generator = generator,
            strengthMeter = strengthMeter
        )
    }

    @Test
    fun successfulUnlockFollowedBySavePasswordSucceeds() {
        // Unlock the shared session
        sharedSession.unlock(testVrk)
        assertTrue(sharedSession.isUnlocked())

        val latch = CountDownLatch(1)
        var errorOccurred: String? = null

        coordinator.savePassword(
            existingId = null,
            existingRevision = null,
            title = "GitHub Account",
            username = "octocat",
            password = "SecurePassword123!",
            website = "https://github.com",
            notes = "Work account",
            category = "Dev",
            isSensitive = false,
            onError = { err -> errorOccurred = err; latch.countDown() },
            onComplete = { latch.countDown() }
        )

        assertTrue(latch.await(3, TimeUnit.SECONDS))
        assertNull("Saving password after unlock must not produce an error", errorOccurred)

        // Verify that the record was stored encrypted in the DAO
        assertEquals(1, dao.store.size)
        val record = dao.store.values.first()
        assertEquals(testVaultId, record.vaultId)
        assertFalse(String(record.ciphertext).contains("SecurePassword123!"))

        // Verify that loadItems() can decrypt and present the item in memory
        val loadLatch = CountDownLatch(1)
        coordinator.loadItems(onError = { loadLatch.countDown() })
        // Small delay or check items
        Thread.sleep(100)
        assertEquals(1, coordinator.items.value.size)
        val item = coordinator.items.value.first()
        assertTrue(item is VaultItem.Password)
        assertEquals("GitHub Account", (item as VaultItem.Password).entry.title)
    }

    @Test
    fun successfulUnlockFollowedBySaveNoteSucceeds() {
        sharedSession.unlock(testVrk)
        assertTrue(sharedSession.isUnlocked())

        val latch = CountDownLatch(1)
        var errorOccurred: String? = null

        coordinator.saveNote(
            existingId = null,
            existingRevision = null,
            title = "Recovery Codes",
            content = "1234-5678-9012",
            category = "Security",
            isSensitive = true,
            onError = { err -> errorOccurred = err; latch.countDown() },
            onComplete = { latch.countDown() }
        )

        assertTrue(latch.await(3, TimeUnit.SECONDS))
        assertNull("Saving note after unlock must not produce an error", errorOccurred)

        assertEquals(1, dao.store.size)
        val record = dao.store.values.first()
        assertEquals("note", record.type)
        assertFalse(String(record.ciphertext).contains("1234-5678-9012"))
    }

    @Test
    fun sessionBecomingLockedBeforeSaveFailsGracefullyWithoutCrashing() {
        // Shared session is NOT unlocked (or was locked)
        assertFalse(sharedSession.isUnlocked())

        var lockDetectedCalled = false
        coordinator.onLockDetected = { lockDetectedCalled = true }

        val latch = CountDownLatch(1)
        var receivedError: String? = null

        coordinator.savePassword(
            existingId = null,
            existingRevision = null,
            title = "Unsaved Password",
            username = "user",
            password = "password",
            website = "",
            notes = "",
            category = "General",
            isSensitive = false,
            onError = { err -> receivedError = err; latch.countDown() },
            onComplete = { fail("Should not complete when vault is locked") }
        )

        assertTrue(latch.await(3, TimeUnit.SECONDS))
        assertNotNull("Expected lock error message", receivedError)
        assertTrue(receivedError!!.contains("Vault is locked"))
        assertTrue("onLockDetected must be invoked when locked session is detected", lockDetectedCalled)
        assertTrue(coordinator.items.value.isEmpty())
    }

    @Test
    fun uiSessionStateStayingSynchronized() {
        var uiReportedLocked = false
        coordinator.onLockDetected = { uiReportedLocked = true }

        // Start locked
        assertFalse(sharedSession.isUnlocked())

        // Attempt load while locked
        coordinator.loadItems()
        assertTrue("Attempting to load items while locked must trigger onLockDetected", uiReportedLocked)
        assertTrue(coordinator.items.value.isEmpty())

        // Unlock
        uiReportedLocked = false
        sharedSession.unlock(testVrk)
        assertTrue(sharedSession.isUnlocked())

        val saveLatch = CountDownLatch(1)
        coordinator.savePassword(
            existingId = "pwd-sync",
            existingRevision = 1L,
            title = "Sync Test",
            username = "alice",
            password = "pwd",
            website = "",
            notes = "",
            category = "General",
            isSensitive = false,
            onComplete = { saveLatch.countDown() }
        )
        assertTrue(saveLatch.await(3, TimeUnit.SECONDS))
        assertFalse(uiReportedLocked)

        // Lock the session
        sharedSession.lock()
        assertFalse(sharedSession.isUnlocked())

        // Attempt delete while locked
        val deleteLatch = CountDownLatch(1)
        coordinator.deleteItem("pwd-sync", onError = { deleteLatch.countDown() })
        assertTrue(deleteLatch.await(3, TimeUnit.SECONDS))
        assertTrue("Delete attempt after lock must trigger onLockDetected", uiReportedLocked)
    }
}

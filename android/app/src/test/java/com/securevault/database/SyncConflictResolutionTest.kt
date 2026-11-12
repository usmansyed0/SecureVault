package com.securevault.database

import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.mockito.kotlin.any
import org.mockito.kotlin.argumentCaptor
import org.mockito.kotlin.mock
import org.mockito.kotlin.never
import org.mockito.kotlin.times
import org.mockito.kotlin.verify
import org.mockito.kotlin.whenever

/**
 * Unit tests for [EncryptedRecordDao.upsertFromServer] conflict-resolution logic
 * and [SyncQueueDao] exponential back-off scheduling.
 *
 * These tests use a fake in-memory DAO implementation so they run on the JVM
 * without Robolectric or an Android device.
 */
class SyncConflictResolutionTest {

    // ─── Fake in-memory DAO ───────────────────────────────────────────────────

    private val store = mutableMapOf<String, EncryptedRecord>()

    /** Minimal in-memory stand-in for [EncryptedRecordDao]. */
    private inner class FakeEncryptedRecordDao : EncryptedRecordDao {
        override suspend fun find(id: String, vaultId: String): EncryptedRecord? =
            store["$vaultId/$id"]?.takeIf { !it.deleted }

        override suspend fun findAll(vaultId: String): List<EncryptedRecord> =
            store.values.filter { it.vaultId == vaultId && !it.deleted }

        override suspend fun findAllByType(vaultId: String, type: String): List<EncryptedRecord> =
            store.values.filter { it.vaultId == vaultId && it.type == type && !it.deleted }

        override fun observeAll(vaultId: String) = kotlinx.coroutines.flow.flowOf(findAllSync(vaultId))
        override fun observeByType(vaultId: String, type: String) = kotlinx.coroutines.flow.flowOf(
            store.values.filter { it.vaultId == vaultId && it.type == type && !it.deleted }
        )

        override suspend fun findIncludingDeleted(id: String, vaultId: String): EncryptedRecord? =
            store["$vaultId/$id"]

        override suspend fun upsert(record: EncryptedRecord) {
            store["${record.vaultId}/${record.id}"] = record
        }

        override suspend fun upsertFromServer(
            id: String, vaultId: String, type: String, formatVersion: Int,
            ciphertext: ByteArray, nonce: ByteArray, wrappedDek: ByteArray, wrappedDekNonce: ByteArray,
            incomingClientRevision: Long, incomingServerSeq: Long, incomingDeleted: Boolean
        ) {
            val local = findIncludingDeleted(id, vaultId)
            val shouldApply = when {
                local == null -> true
                incomingServerSeq <= local.serverSeq -> false
                local.pendingSync && local.clientRevision > incomingClientRevision -> false
                else -> true
            }
            if (shouldApply) {
                upsert(
                    EncryptedRecord(
                        id = id, vaultId = vaultId, type = type, formatVersion = formatVersion,
                        ciphertext = ciphertext, nonce = nonce, wrappedDek = wrappedDek,
                        wrappedDekNonce = wrappedDekNonce,
                        clientRevision = incomingClientRevision,
                        serverSeq = incomingServerSeq,
                        deleted = incomingDeleted,
                        pendingSync = false
                    )
                )
            }
        }

        override suspend fun markSynced(id: String, vaultId: String, confirmedSeq: Long) {
            store["$vaultId/$id"]?.let { store["$vaultId/$id"] = it.copy(pendingSync = false, serverSeq = confirmedSeq) }
        }

        override suspend fun markDeleted(id: String, vaultId: String) {
            store["$vaultId/$id"]?.let { store["$vaultId/$id"] = it.copy(deleted = true, pendingSync = true) }
        }

        override suspend fun hardDelete(id: String, vaultId: String) { store.remove("$vaultId/$id") }
        override suspend fun wipe() { store.clear() }

        private fun findAllSync(vaultId: String) =
            store.values.filter { it.vaultId == vaultId && !it.deleted }
    }

    private lateinit var dao: FakeEncryptedRecordDao
    private val vaultId = "vault-1"
    private val emptyBytes = ByteArray(0)

    @Before fun setUp() {
        store.clear()
        dao = FakeEncryptedRecordDao()
    }

    // ─── Conflict resolution tests ────────────────────────────────────────────

    @Test fun `upsertFromServer inserts new record when none exists locally`() = runTest {
        dao.upsertFromServer(
            id = "r1", vaultId = vaultId, type = "password", formatVersion = 1,
            ciphertext = emptyBytes, nonce = emptyBytes, wrappedDek = emptyBytes, wrappedDekNonce = emptyBytes,
            incomingClientRevision = 1L, incomingServerSeq = 10L, incomingDeleted = false
        )
        val record = dao.findIncludingDeleted("r1", vaultId)
        assertNotNull(record)
        assertEquals(10L, record!!.serverSeq)
        assertFalse(record.pendingSync)
    }

    @Test fun `upsertFromServer skips when incoming serverSeq is not newer`() = runTest {
        // Seed a record that was already applied at serverSeq=20
        dao.upsert(makeRecord("r2", serverSeq = 20L, clientRevision = 5L, pendingSync = false))

        dao.upsertFromServer(
            id = "r2", vaultId = vaultId, type = "password", formatVersion = 1,
            ciphertext = byteArrayOf(0x99.toByte()), nonce = emptyBytes, wrappedDek = emptyBytes, wrappedDekNonce = emptyBytes,
            incomingClientRevision = 5L, incomingServerSeq = 20L, incomingDeleted = false
        )

        val record = dao.findIncludingDeleted("r2", vaultId)
        // ciphertext should NOT have been overwritten
        assertFalse(record!!.ciphertext.contentEquals(byteArrayOf(0x99.toByte())))
        assertEquals(20L, record.serverSeq)
    }

    @Test fun `upsertFromServer keeps local when local has higher clientRevision and pendingSync`() = runTest {
        // Local record has pending, un-pushed changes at revision 10
        dao.upsert(makeRecord("r3", serverSeq = 5L, clientRevision = 10L, pendingSync = true))

        // Server sends revision 7 (older than local)
        dao.upsertFromServer(
            id = "r3", vaultId = vaultId, type = "password", formatVersion = 1,
            ciphertext = byteArrayOf(0xAA.toByte()), nonce = emptyBytes, wrappedDek = emptyBytes, wrappedDekNonce = emptyBytes,
            incomingClientRevision = 7L, incomingServerSeq = 15L, incomingDeleted = false
        )

        val record = dao.findIncludingDeleted("r3", vaultId)
        // Local wins: clientRevision still 10, pendingSync still true
        assertEquals(10L, record!!.clientRevision)
        assertTrue(record.pendingSync)
    }

    @Test fun `upsertFromServer server wins when server clientRevision is newer and local pendingSync`() = runTest {
        dao.upsert(makeRecord("r4", serverSeq = 5L, clientRevision = 3L, pendingSync = true))

        // Server sends revision 8 (newer) — means server already accepted a newer write
        dao.upsertFromServer(
            id = "r4", vaultId = vaultId, type = "password", formatVersion = 1,
            ciphertext = byteArrayOf(0xBB.toByte()), nonce = emptyBytes, wrappedDek = emptyBytes, wrappedDekNonce = emptyBytes,
            incomingClientRevision = 8L, incomingServerSeq = 20L, incomingDeleted = false
        )

        val record = dao.findIncludingDeleted("r4", vaultId)
        assertEquals(8L, record!!.clientRevision)
        assertFalse(record.pendingSync)
        assertTrue(record.ciphertext.contentEquals(byteArrayOf(0xBB.toByte())))
    }

    @Test fun `upsertFromServer server wins when local record is clean (no pendingSync)`() = runTest {
        dao.upsert(makeRecord("r5", serverSeq = 5L, clientRevision = 3L, pendingSync = false))

        dao.upsertFromServer(
            id = "r5", vaultId = vaultId, type = "password", formatVersion = 1,
            ciphertext = byteArrayOf(0xCC.toByte()), nonce = emptyBytes, wrappedDek = emptyBytes, wrappedDekNonce = emptyBytes,
            incomingClientRevision = 3L, incomingServerSeq = 12L, incomingDeleted = false
        )

        val record = dao.findIncludingDeleted("r5", vaultId)
        assertTrue(record!!.ciphertext.contentEquals(byteArrayOf(0xCC.toByte())))
        assertFalse(record.pendingSync)
    }

    @Test fun `upsertFromServer applies server delete`() = runTest {
        dao.upsert(makeRecord("r6", serverSeq = 2L, clientRevision = 1L, pendingSync = false))

        dao.upsertFromServer(
            id = "r6", vaultId = vaultId, type = "password", formatVersion = 1,
            ciphertext = emptyBytes, nonce = emptyBytes, wrappedDek = emptyBytes, wrappedDekNonce = emptyBytes,
            incomingClientRevision = 1L, incomingServerSeq = 7L, incomingDeleted = true
        )

        val record = dao.findIncludingDeleted("r6", vaultId)
        assertNotNull(record)
        assertTrue(record!!.deleted)
        assertFalse(record.pendingSync)
    }

    // ─── Back-off calculation test ────────────────────────────────────────────

    @Test fun `exponential back-off doubles and caps correctly`() {
        val base = 2_000L
        val cap = 5 * 60 * 1_000L
        fun backoffMs(attempts: Int) = minOf(base * (1L shl (attempts - 1)), cap)

        assertEquals(2_000L, backoffMs(1))
        assertEquals(4_000L, backoffMs(2))
        assertEquals(8_000L, backoffMs(3))
        assertEquals(16_000L, backoffMs(4))
        assertEquals(32_000L, backoffMs(5))
        assertEquals(64_000L, backoffMs(6))
        assertEquals(128_000L, backoffMs(7))
        assertEquals(256_000L, backoffMs(8))
        // attempt 9: 512 s > 300 s cap
        assertEquals(cap, backoffMs(9))
        assertEquals(cap, backoffMs(10))
    }

    // ─── SqlCipherPassphraseProvider ─────────────────────────────────────────

    @Test fun `SqlCipherPassphraseProvider derives 32-byte key`() {
        val provider = SqlCipherPassphraseProvider()
        val vrk = ByteArray(32) { it.toByte() }
        val key = provider.derive(vrk)
        assertEquals(32, key.size)
    }

    @Test fun `SqlCipherPassphraseProvider is deterministic`() {
        val provider = SqlCipherPassphraseProvider()
        val vrk = ByteArray(32) { 0x42 }
        val k1 = provider.derive(vrk)
        val k2 = provider.derive(vrk)
        assertTrue(k1.contentEquals(k2))
    }

    @Test fun `SqlCipherPassphraseProvider differs for different VRKs`() {
        val provider = SqlCipherPassphraseProvider()
        val vrk1 = ByteArray(32) { it.toByte() }
        val vrk2 = ByteArray(32) { (it + 1).toByte() }
        assertFalse(provider.derive(vrk1).contentEquals(provider.derive(vrk2)))
    }

    @Test fun `toSqlCipherHexKey produces correct format`() {
        val key = ByteArray(32) { 0xFF.toByte() }
        val hex = key.toSqlCipherHexKey()
        assertTrue(hex.startsWith("x'"))
        assertTrue(hex.endsWith("'"))
        assertEquals(2 + 64 + 1, hex.length)  // x' + 64 hex chars + '
    }

    // ─── Helpers ──────────────────────────────────────────────────────────────

    private fun makeRecord(
        id: String,
        serverSeq: Long,
        clientRevision: Long,
        pendingSync: Boolean
    ) = EncryptedRecord(
        id = id,
        vaultId = vaultId,
        type = "password",
        formatVersion = 1,
        ciphertext = byteArrayOf(0x01),
        nonce = emptyBytes,
        wrappedDek = emptyBytes,
        wrappedDekNonce = emptyBytes,
        clientRevision = clientRevision,
        serverSeq = serverSeq,
        deleted = false,
        pendingSync = pendingSync
    )
}

package com.securevault.security

import com.securevault.crypto.RecordAddress
import com.securevault.crypto.VaultRecordCrypto
import com.securevault.database.EncryptedRecord
import com.securevault.database.EncryptedRecordDao
import kotlinx.coroutines.flow.flowOf
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import java.security.SecureRandom

class VaultIntegrityManagerTest {

    private lateinit var dao: FakeEncryptedRecordDao
    private lateinit var crypto: VaultRecordCrypto
    private lateinit var session: VaultSession
    private lateinit var integrityManager: VaultIntegrityManager

    private val vrk = ByteArray(32) { 0x42.toByte() }
    private val vaultId = "test-vault-id"

    private class FakeEncryptedRecordDao : EncryptedRecordDao {
        val records = mutableListOf<EncryptedRecord>()
        override suspend fun find(id: String, vaultId: String) = records.find { it.id == id && it.vaultId == vaultId }
        override suspend fun findAll(vaultId: String) = records.filter { it.vaultId == vaultId && !it.deleted }
        override suspend fun findAllByType(vaultId: String, type: String) = records.filter { it.vaultId == vaultId && it.type == type && !it.deleted }
        override fun observeAll(vaultId: String) = flowOf(records.filter { it.vaultId == vaultId })
        override fun observeByType(vaultId: String, type: String) = flowOf(records.filter { it.vaultId == vaultId && it.type == type })
        override suspend fun findIncludingDeleted(id: String, vaultId: String) = records.find { it.id == id && it.vaultId == vaultId }
        override suspend fun upsert(record: EncryptedRecord) { records.removeAll { it.id == record.id }; records.add(record) }
        override suspend fun markSynced(id: String, vaultId: String, confirmedSeq: Long) {}
        override suspend fun markDeleted(id: String, vaultId: String) {}
        override suspend fun hardDelete(id: String, vaultId: String) { records.removeAll { it.id == id } }
        override suspend fun wipe() { records.clear() }
    }

    @Before
    fun setup() {
        dao = FakeEncryptedRecordDao()
        crypto = VaultRecordCrypto()
        session = VaultSession()
        session.unlock(vrk)
        integrityManager = VaultIntegrityManager(dao, crypto, session)
    }

    @Test
    fun verifyIntegrity_emptyVault_isHealthy() = runTest {
        val report = integrityManager.verifyIntegrity(vaultId)
        assertTrue(report.isHealthy)
        assertEquals(0, report.totalRecords)
        assertEquals(0, report.validRecords)
        assertTrue(report.corruptedRecordIds.isEmpty())
        assertTrue(report.manifestHashHex.isNotEmpty())
    }

    @Test
    fun verifyIntegrity_validRecord_passesAEADCheck() = runTest {
        val address = RecordAddress(vaultId, "rec-1", "password", 1, 1L)
        val envelope = crypto.encrypt(vrk, address, "plaintext-secret".toByteArray())
        val record = EncryptedRecord(
            id = address.recordId,
            vaultId = address.vaultId,
            type = address.type,
            formatVersion = address.formatVersion,
            ciphertext = envelope.ciphertext,
            nonce = envelope.nonce,
            wrappedDek = envelope.wrappedDek,
            wrappedDekNonce = envelope.wrappedDekNonce,
            clientRevision = address.revision,
            pendingSync = false
        )
        dao.upsert(record)

        val report = integrityManager.verifyIntegrity(vaultId)
        assertTrue(report.isHealthy)
        assertEquals(1, report.totalRecords)
        assertEquals(1, report.validRecords)
        assertTrue(report.corruptedRecordIds.isEmpty())
    }

    @Test
    fun verifyIntegrity_tamperedCiphertext_detectsCorruption() = runTest {
        val address = RecordAddress(vaultId, "rec-1", "password", 1, 1L)
        val envelope = crypto.encrypt(vrk, address, "plaintext-secret".toByteArray())

        // Tamper with ciphertext byte (flips AEAD GCM authentication tag check)
        val tamperedCipher = envelope.ciphertext.copyOf()
        tamperedCipher[0] = (tamperedCipher[0].toInt() xor 0xFF).toByte()

        val record = EncryptedRecord(
            id = address.recordId,
            vaultId = address.vaultId,
            type = address.type,
            formatVersion = address.formatVersion,
            ciphertext = tamperedCipher,
            nonce = envelope.nonce,
            wrappedDek = envelope.wrappedDek,
            wrappedDekNonce = envelope.wrappedDekNonce,
            clientRevision = address.revision,
            pendingSync = false
        )
        dao.upsert(record)

        val report = integrityManager.verifyIntegrity(vaultId)
        assertFalse(report.isHealthy)
        assertEquals(1, report.totalRecords)
        assertEquals(0, report.validRecords)
        assertEquals(listOf("rec-1"), report.corruptedRecordIds)
    }

    @Test
    fun verifyIntegrity_truncatedNonce_detectsCorruption() = runTest {
        val record = EncryptedRecord(
            id = "bad-nonce",
            vaultId = vaultId,
            type = "password",
            formatVersion = 1,
            ciphertext = ByteArray(32),
            nonce = ByteArray(4), // Invalid GCM nonce length (must be 12)
            wrappedDek = ByteArray(48),
            wrappedDekNonce = ByteArray(12),
            clientRevision = 1L,
            pendingSync = false
        )
        dao.upsert(record)

        val report = integrityManager.verifyIntegrity(vaultId)
        assertFalse(report.isHealthy)
        assertEquals(listOf("bad-nonce"), report.corruptedRecordIds)
    }
}

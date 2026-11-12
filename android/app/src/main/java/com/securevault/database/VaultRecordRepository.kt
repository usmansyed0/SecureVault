package com.securevault.database

import com.securevault.crypto.EncryptedRecordEnvelope
import com.securevault.crypto.RecordAddress
import com.securevault.crypto.VaultRecordCrypto
import com.securevault.security.VaultSession
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.map
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Abstracts `RoomDatabase.withTransaction` so that [VaultRecordRepository] can be
 * tested without a real Room database instance.
 *
 * Production binding in [com.securevault.di.AppModule] uses `db.withTransaction`.
 * Test fakes use a direct-execute runner.
 */
fun interface TransactionRunner {
    suspend operator fun invoke(block: suspend () -> Unit)
}

/**
 * The only local persistence boundary for vault contents.
 *
 * Enforces zero-knowledge: plaintext is encrypted before touching Room and
 * decrypted immediately after retrieval, while the VRK is borrowed from the
 * in-memory [VaultSession] only for the duration of the operation.
 *
 * Every local write is paired with a [SyncQueueDao] enqueue inside a single
 * database transaction, so no mutation can be silently lost if the device goes
 * offline immediately after.
 */
@Singleton
class VaultRecordRepository @Inject constructor(
    private val dao: EncryptedRecordDao,
    private val syncQueueDao: SyncQueueDao,
    private val crypto: VaultRecordCrypto,
    private val session: VaultSession,
    private val transact: TransactionRunner
) {

    // ── Write path ───────────────────────────────────────────────────────────

    /**
     * Encrypts [plaintext] and writes the record plus its sync-queue entry
     * atomically.
     *
     * Callers must supply a [clientRevision] that is monotonically increasing
     * for the same [address].  The simplest strategy is to use
     * `System.currentTimeMillis()` or to read the current revision from Room
     * and increment by 1.
     */
    suspend fun store(address: RecordAddress, plaintext: ByteArray) {
        val envelope = session.withRootKey { vrk -> crypto.encrypt(vrk, address, plaintext) }
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
            pendingSync = true
        )
        val queueEntry = SyncQueueEntry(
            recordId = address.recordId,
            vaultId = address.vaultId,
            operation = "upsert",
            createdAt = System.currentTimeMillis()
        )
        transact {
            dao.upsert(record)
            syncQueueDao.enqueue(queueEntry)
        }
    }

    /**
     * Soft-deletes a record and enqueues the delete operation for server sync.
     * Hard deletion only happens after the server acknowledges the delete.
     */
    suspend fun delete(id: String, vaultId: String) {
        val queueEntry = SyncQueueEntry(
            recordId = id,
            vaultId = vaultId,
            operation = "delete",
            createdAt = System.currentTimeMillis()
        )
        transact {
            dao.markDeleted(id, vaultId)
            syncQueueDao.enqueue(queueEntry)
        }
    }

    // ── Read path ────────────────────────────────────────────────────────────

    /** Returns null if the record is missing or soft-deleted. */
    suspend fun load(address: RecordAddress): ByteArray? {
        val record = dao.find(address.recordId, address.vaultId) ?: return null
        if (record.deleted) return null
        assertMetadataMatch(record, address)
        return decryptRecord(record, address)
    }

    /** Loads any existing record by id+vaultId, reconstructing its [RecordAddress]. */
    suspend fun loadRecord(id: String, vaultId: String): Pair<RecordAddress, ByteArray>? {
        val record = dao.find(id, vaultId) ?: return null
        if (record.deleted) return null
        val address = record.toAddress()
        return address to decryptRecord(record, address)
    }

    /** Decrypts and returns all non-deleted records for a vault. */
    suspend fun loadAll(vaultId: String): List<Pair<RecordAddress, ByteArray>> {
        val records = dao.findAll(vaultId)
        return session.withRootKey { vrk ->
            records.mapNotNull { record ->
                val address = record.toAddress()
                val plaintext = try {
                    crypto.decrypt(vrk, address, record.toEnvelope())
                } catch (e: com.securevault.crypto.VaultDecryptionException) {
                    // Corrupt / tampered record — fail closed, log, skip.
                    android.util.Log.e("VaultRecordRepository", "Decryption failed for ${record.id}", e)
                    null
                }
                if (plaintext != null) address to plaintext else null
            }
        }
    }

    /** Reactive stream: emits list of (address, plaintext) whenever Room notifies a change. */
    fun observeAll(vaultId: String): Flow<List<Pair<RecordAddress, ByteArray>>> =
        dao.observeAll(vaultId).map { records ->
            session.withRootKey { vrk ->
                records.mapNotNull { record ->
                    val address = record.toAddress()
                    try {
                        address to crypto.decrypt(vrk, address, record.toEnvelope())
                    } catch (e: com.securevault.crypto.VaultDecryptionException) {
                        android.util.Log.e("VaultRecordRepository", "Decryption failed for ${record.id}", e)
                        null
                    }
                }
            }
        }

    // ── Wipe ─────────────────────────────────────────────────────────────────

    /** Full wipe on logout / vault destruction. */
    suspend fun wipe() {
        transact {
            dao.wipe()
            syncQueueDao.wipe()
        }
    }

    // ── Internal helpers ──────────────────────────────────────────────────────

    private fun assertMetadataMatch(record: EncryptedRecord, address: RecordAddress) {
        require(
            record.type == address.type &&
            record.formatVersion == address.formatVersion &&
            record.clientRevision == address.revision
        ) { "Vault record metadata mismatch for ${record.id}" }
    }

    private fun decryptRecord(record: EncryptedRecord, address: RecordAddress): ByteArray =
        session.withRootKey { vrk -> crypto.decrypt(vrk, address, record.toEnvelope()) }

    private fun EncryptedRecord.toAddress() =
        RecordAddress(vaultId, id, type, formatVersion, clientRevision)

    private fun EncryptedRecord.toEnvelope() =
        EncryptedRecordEnvelope(ciphertext, nonce, wrappedDek, wrappedDekNonce)
}

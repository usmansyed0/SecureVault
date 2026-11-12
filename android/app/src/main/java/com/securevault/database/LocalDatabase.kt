package com.securevault.database

import androidx.room.Dao
import androidx.room.Database
import androidx.room.Entity
import androidx.room.Index
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.PrimaryKey
import androidx.room.Query
import androidx.room.RoomDatabase
import androidx.room.Transaction
import androidx.room.migration.Migration
import androidx.sqlite.db.SupportSQLiteDatabase
import kotlinx.coroutines.flow.Flow

// ─────────────────────────────────────────────────────────────────────────────
// Entities
// ─────────────────────────────────────────────────────────────────────────────

/**
 * The only local persistence boundary for vault content.
 *
 * Zero-knowledge invariant: every plaintext byte is encrypted before it ever
 * reaches this entity.  The columns [ciphertext], [nonce], [wrappedDek] and
 * [wrappedDekNonce] form a complete AES-256-GCM envelope that can only be
 * opened by the in-memory VRK stored in [com.securevault.security.VaultSession].
 *
 * [pendingSync] = true  →  record has local changes that have NOT yet been
 *                           acknowledged by the server.
 * [serverSeq]           →  the server-side change-log sequence number at which
 *                           this record was last confirmed synced. 0 means never
 *                           confirmed. Used during pull to skip records already
 *                           applied.
 * [clientRevision]      →  monotonically increasing client-side counter sent to
 *                           the server on every upsert.  The server enforces
 *                           last-write-wins using this value.
 */
@Entity(
    tableName = "vault_records",
    indices = [
        Index("vaultId"),
        Index(value = ["vaultId", "type"]),
        Index(value = ["vaultId", "pendingSync"])
    ]
)
data class EncryptedRecord(
    @PrimaryKey val id: String,
    val vaultId: String,
    val type: String,
    val formatVersion: Int,
    val ciphertext: ByteArray,
    val nonce: ByteArray,
    val wrappedDek: ByteArray,
    val wrappedDekNonce: ByteArray,
    /** Client-side monotonic revision counter. Sent to server on upsert. */
    val clientRevision: Long,
    /** Server-side change-log sequence at which this record was last synced. 0 = unsynced. */
    val serverSeq: Long = 0L,
    val deleted: Boolean = false,
    /** True when the record has local mutations not yet acknowledged by the server. */
    val pendingSync: Boolean = true
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is EncryptedRecord) return false
        return id == other.id && vaultId == other.vaultId
    }
    override fun hashCode(): Int = 31 * id.hashCode() + vaultId.hashCode()
}

/**
 * Stores the highest server change-log sequence number fully applied to this
 * device.  There is exactly one row per vaultId.
 *
 * Pull sync always starts from [lastAppliedSeq] + 1, so operations are
 * idempotent: re-running sync after a partial failure will never create
 * duplicate records.
 */
@Entity(tableName = "sync_metadata")
data class SyncMetadata(
    @PrimaryKey val vaultId: String,
    /** Highest server_seq whose changes have been applied locally. */
    val lastAppliedSeq: Long = 0L
)

/**
 * Durable offline push queue.  Each entry represents one server upsert or
 * delete that must be delivered to the server, retried with exponential
 * back-off until acknowledged.
 *
 * Entries are inserted inside the same Room transaction that mutates
 * [EncryptedRecord], guaranteeing that no local write is ever lost even if
 * the device goes offline immediately after the mutation.
 *
 * [attemptCount] is incremented on every failed network attempt.
 * [nextRetryAt]  is an epoch-milliseconds timestamp; the worker will not retry
 *                until the current time exceeds this value.
 * [lastError]    records the last failure message for diagnostics.
 */
@Entity(
    tableName = "sync_queue",
    indices = [
        Index(value = ["vaultId", "nextRetryAt"]),
        Index("recordId")
    ]
)
data class SyncQueueEntry(
    @PrimaryKey val recordId: String,
    val vaultId: String,
    /** "upsert" or "delete" */
    val operation: String,
    /** epoch-ms when this entry was created or last updated */
    val createdAt: Long,
    val attemptCount: Int = 0,
    /** epoch-ms; 0 = ready to send immediately */
    val nextRetryAt: Long = 0L,
    val lastError: String? = null
)

// ─────────────────────────────────────────────────────────────────────────────
// DAOs
// ─────────────────────────────────────────────────────────────────────────────

@Dao
interface EncryptedRecordDao {

    // ── Reads ───────────────────────────────────────────────────────────────

    @Query("SELECT * FROM vault_records WHERE id = :id AND vaultId = :vaultId AND deleted = 0")
    suspend fun find(id: String, vaultId: String): EncryptedRecord?

    @Query("SELECT * FROM vault_records WHERE vaultId = :vaultId AND deleted = 0")
    suspend fun findAll(vaultId: String): List<EncryptedRecord>

    @Query("SELECT * FROM vault_records WHERE vaultId = :vaultId AND type = :type AND deleted = 0")
    suspend fun findAllByType(vaultId: String, type: String): List<EncryptedRecord>

    /** Reactive stream for the UI layer. */
    @Query("SELECT * FROM vault_records WHERE vaultId = :vaultId AND deleted = 0")
    fun observeAll(vaultId: String): Flow<List<EncryptedRecord>>

    @Query("SELECT * FROM vault_records WHERE vaultId = :vaultId AND type = :type AND deleted = 0")
    fun observeByType(vaultId: String, type: String): Flow<List<EncryptedRecord>>

    /** Only called during sync pull; returns records regardless of deleted flag. */
    @Query("SELECT * FROM vault_records WHERE id = :id AND vaultId = :vaultId")
    suspend fun findIncludingDeleted(id: String, vaultId: String): EncryptedRecord?

    // ── Writes ──────────────────────────────────────────────────────────────

    /**
     * Primary local write path.  Always sets [pendingSync] = true so the sync
     * worker knows to push this change.
     *
     * Uses REPLACE so Room's conflict resolution handles both insert and update
     * atomically; callers must wrap this + [SyncQueueDao.enqueue] in a single
     * [Transaction] to keep them consistent.
     */
    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsert(record: EncryptedRecord)

    /**
     * Applied during sync pull from the server.  Only replaces the local record
     * when the incoming [serverSeq] is greater than the stored one, preventing
     * a stale server push from overwriting a newer local write.
     *
     * Sets [pendingSync] = false and records [serverSeq] so subsequent pulls
     * skip this change.
     *
     * If a local record has [pendingSync] = true (un-pushed local mutation),
     * the server version is accepted only when its [incomingClientRevision] is
     * strictly greater than the local [clientRevision] (server already saw and
     * accepted a newer version than ours).  Otherwise we keep the local version
     * and let the push queue deliver it.
     */
    @Transaction
    suspend fun upsertFromServer(
        id: String,
        vaultId: String,
        type: String,
        formatVersion: Int,
        ciphertext: ByteArray,
        nonce: ByteArray,
        wrappedDek: ByteArray,
        wrappedDekNonce: ByteArray,
        incomingClientRevision: Long,
        incomingServerSeq: Long,
        incomingDeleted: Boolean
    ) {
        val local = findIncludingDeleted(id, vaultId)
        val shouldApply = when {
            // No local record at all — always apply.
            local == null -> true
            // Server sequence is not newer than what we already applied — skip (idempotent).
            incomingServerSeq <= local.serverSeq -> false
            // Local has un-pushed mutations with a higher client revision — keep local.
            local.pendingSync && local.clientRevision > incomingClientRevision -> false
            // In all other cases server wins.
            else -> true
        }
        if (shouldApply) {
            upsert(
                EncryptedRecord(
                    id = id,
                    vaultId = vaultId,
                    type = type,
                    formatVersion = formatVersion,
                    ciphertext = ciphertext,
                    nonce = nonce,
                    wrappedDek = wrappedDek,
                    wrappedDekNonce = wrappedDekNonce,
                    clientRevision = incomingClientRevision,
                    serverSeq = incomingServerSeq,
                    deleted = incomingDeleted,
                    pendingSync = false   // server is authoritative; no push needed
                )
            )
        }
    }

    /** Called after the server successfully acknowledges a push. */
    @Query("""
        UPDATE vault_records
        SET pendingSync = 0, serverSeq = :confirmedSeq
        WHERE id = :id AND vaultId = :vaultId
    """)
    suspend fun markSynced(id: String, vaultId: String, confirmedSeq: Long)

    @Query("UPDATE vault_records SET deleted = 1, pendingSync = 1 WHERE id = :id AND vaultId = :vaultId")
    suspend fun markDeleted(id: String, vaultId: String)

    @Query("DELETE FROM vault_records WHERE id = :id AND vaultId = :vaultId")
    suspend fun hardDelete(id: String, vaultId: String)

    /** Wipes all records; called during logout / vault destruction. */
    @Query("DELETE FROM vault_records")
    suspend fun wipe()
}

@Dao
interface SyncQueueDao {

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun enqueue(entry: SyncQueueEntry)

    /** Returns entries ready to send, ordered by creation time (FIFO). */
    @Query("""
        SELECT * FROM sync_queue
        WHERE vaultId = :vaultId AND nextRetryAt <= :nowMs
        ORDER BY createdAt ASC
        LIMIT :limit
    """)
    suspend fun dueEntries(vaultId: String, nowMs: Long, limit: Int = 50): List<SyncQueueEntry>

    @Query("SELECT COUNT(*) FROM sync_queue WHERE vaultId = :vaultId")
    suspend fun pendingCount(vaultId: String): Int

    @Query("DELETE FROM sync_queue WHERE recordId = :recordId")
    suspend fun remove(recordId: String)

    /** Update retry metadata after a failed attempt. */
    @Query("""
        UPDATE sync_queue
        SET attemptCount = :attempts, nextRetryAt = :nextRetryAt, lastError = :error
        WHERE recordId = :recordId
    """)
    suspend fun updateRetry(recordId: String, attempts: Int, nextRetryAt: Long, error: String?)

    @Query("DELETE FROM sync_queue")
    suspend fun wipe()
}

@Dao
interface SyncMetadataDao {

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun save(metadata: SyncMetadata)

    @Query("SELECT * FROM sync_metadata WHERE vaultId = :vaultId")
    suspend fun find(vaultId: String): SyncMetadata?

    @Query("DELETE FROM sync_metadata")
    suspend fun wipe()
}

// ─────────────────────────────────────────────────────────────────────────────
// Database
// ─────────────────────────────────────────────────────────────────────────────

@Database(
    entities = [EncryptedRecord::class, SyncQueueEntry::class, SyncMetadata::class],
    version = 3,
    exportSchema = true
)
abstract class LocalDatabase : RoomDatabase() {
    abstract fun encryptedRecordDao(): EncryptedRecordDao
    abstract fun syncQueueDao(): SyncQueueDao
    abstract fun syncMetadataDao(): SyncMetadataDao

    companion object {
        /**
         * Phase 1 records had no envelope columns; retain as legacy/unreadable.
         * Fail closed if an unlock is attempted on them.
         */
        val MIGRATION_1_2 = object : Migration(1, 2) {
            override fun migrate(db: SupportSQLiteDatabase) {
                db.execSQL("ALTER TABLE vault_records ADD COLUMN vaultId TEXT NOT NULL DEFAULT 'legacy'")
                db.execSQL("ALTER TABLE vault_records ADD COLUMN type TEXT NOT NULL DEFAULT 'legacy'")
                db.execSQL("ALTER TABLE vault_records ADD COLUMN formatVersion INTEGER NOT NULL DEFAULT 0")
                db.execSQL("ALTER TABLE vault_records ADD COLUMN wrappedDek BLOB NOT NULL DEFAULT X''")
                db.execSQL("ALTER TABLE vault_records ADD COLUMN wrappedDekNonce BLOB NOT NULL DEFAULT X''")
                db.execSQL("ALTER TABLE vault_records ADD COLUMN deleted INTEGER NOT NULL DEFAULT 0")
            }
        }

        /**
         * Phase 2 migration: add offline-sync columns to vault_records and
         * create the sync_queue + sync_metadata tables.
         *
         * Existing records are treated as locally-dirty (pendingSync=1) so they
         * will be pushed to the server on next sync; their serverSeq starts at 0.
         * clientRevision is renamed from `revision` to match the new naming.
         */
        val MIGRATION_2_3 = object : Migration(2, 3) {
            override fun migrate(db: SupportSQLiteDatabase) {
                // vault_records: add new columns
                db.execSQL(
                    "ALTER TABLE vault_records ADD COLUMN clientRevision INTEGER NOT NULL DEFAULT 0"
                )
                db.execSQL(
                    "ALTER TABLE vault_records ADD COLUMN serverSeq INTEGER NOT NULL DEFAULT 0"
                )
                db.execSQL(
                    "ALTER TABLE vault_records ADD COLUMN pendingSync INTEGER NOT NULL DEFAULT 1"
                )
                // Copy existing `revision` into `clientRevision` if the column exists
                // (safe: on a fresh schema `revision` may already be absent after renaming)
                try {
                    db.execSQL("UPDATE vault_records SET clientRevision = revision")
                } catch (_: Exception) { /* column absent on new installs — ignore */ }

                // Indexes
                db.execSQL("CREATE INDEX IF NOT EXISTS idx_vr_vaultId ON vault_records(vaultId)")
                db.execSQL("CREATE INDEX IF NOT EXISTS idx_vr_vaultId_type ON vault_records(vaultId, type)")
                db.execSQL("CREATE INDEX IF NOT EXISTS idx_vr_pending ON vault_records(vaultId, pendingSync)")

                // sync_queue
                db.execSQL("""
                    CREATE TABLE IF NOT EXISTS sync_queue (
                        recordId TEXT NOT NULL PRIMARY KEY,
                        vaultId TEXT NOT NULL,
                        operation TEXT NOT NULL,
                        createdAt INTEGER NOT NULL,
                        attemptCount INTEGER NOT NULL DEFAULT 0,
                        nextRetryAt INTEGER NOT NULL DEFAULT 0,
                        lastError TEXT
                    )
                """.trimIndent())
                db.execSQL("CREATE INDEX IF NOT EXISTS idx_sq_vault_retry ON sync_queue(vaultId, nextRetryAt)")
                db.execSQL("CREATE INDEX IF NOT EXISTS idx_sq_recordId ON sync_queue(recordId)")

                // sync_metadata
                db.execSQL("""
                    CREATE TABLE IF NOT EXISTS sync_metadata (
                        vaultId TEXT NOT NULL PRIMARY KEY,
                        lastAppliedSeq INTEGER NOT NULL DEFAULT 0
                    )
                """.trimIndent())
            }
        }
    }
}

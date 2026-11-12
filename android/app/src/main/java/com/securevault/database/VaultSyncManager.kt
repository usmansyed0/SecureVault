package com.securevault.database

import android.util.Log
import com.securevault.network.SecureVaultApi
import com.securevault.network.model.SyncRecordUpsertDto
import com.securevault.security.VaultSession
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import retrofit2.HttpException
import java.io.IOException
import java.util.Base64
import javax.inject.Inject
import javax.inject.Singleton

private const val TAG = "VaultSyncManager"

/** Maximum number of retries before giving up on an entry (it will retry on next app launch). */
private const val MAX_ATTEMPTS = 7

/** Base backoff in milliseconds; doubles on every failure up to [MAX_BACKOFF_MS]. */
private const val BASE_BACKOFF_MS = 2_000L
private const val MAX_BACKOFF_MS = 5 * 60 * 1_000L  // 5 minutes

/** How many queue entries to drain per sync pass (prevents unbounded batches). */
private const val PUSH_BATCH_SIZE = 50

/**
 * Orchestrates offline-first bidirectional sync between the local Room database
 * and the SecureVault backend.
 *
 * ### Sync protocol
 *
 * 1. **Pull** (`GET /v1/vault/changes?since_seq=N`): fetches every change since
 *    the cursor stored in [SyncMetadataDao].  Each change is applied via
 *    [EncryptedRecordDao.upsertFromServer], which resolves conflicts without
 *    silent data loss (see that method's KDoc).
 *
 * 2. **Push** ([SyncQueueDao.dueEntries]): drains the offline queue of locally-
 *    mutated records.  Every entry is sent to the server; on success the entry
 *    is removed and the record is marked synced.  On failure the entry is
 *    rescheduled with exponential back-off.
 *
 * ### Conflict resolution summary
 *
 * | Situation | Winner |
 * |---|---|
 * | Server seq ≤ last applied seq | Skip (idempotent) |
 * | Local `pendingSync=false` | Server wins |
 * | Local `pendingSync=true`, local `clientRevision` > server's | Local wins (push will deliver it) |
 * | Local `pendingSync=true`, local `clientRevision` ≤ server's | Server wins (server already applied a newer version) |
 *
 * ### Thread safety
 *
 * [sync] is safe to call concurrently from multiple coroutines; the
 * pull and push phases each use atomic Room transactions internally.
 * A [kotlinx.coroutines.sync.Mutex] guards the pull cursor update so two
 * concurrent pulls cannot apply the same server changes twice.
 *
 * ### Zero-knowledge guarantee
 *
 * This class handles only the *ciphertext* side of records.  It never calls
 * [VaultSession] directly and never sees plaintext.  The session is injected
 * only to check [VaultSession.isUnlocked] before proceeding.
 */
@Singleton
class VaultSyncManager @Inject constructor(
    private val api: SecureVaultApi,
    private val recordDao: EncryptedRecordDao,
    private val syncQueueDao: SyncQueueDao,
    private val syncMetadataDao: SyncMetadataDao,
    private val session: VaultSession
) {
    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    private val pullMutex = kotlinx.coroutines.sync.Mutex()

    // ── Public API ────────────────────────────────────────────────────────────

    /**
     * Runs a full pull-then-push sync for [vaultId].
     *
     * Suspends until both phases complete (or fail gracefully).  Call from a
     * WorkManager worker or a ViewModel launch.
     *
     * @return [SyncResult] summarising what happened.
     */
    suspend fun sync(vaultId: String): SyncResult = withContext(Dispatchers.IO) {
        if (!session.isUnlocked()) {
            Log.w(TAG, "Sync skipped: vault is locked")
            return@withContext SyncResult(skipped = true)
        }
        val pulled = pull(vaultId)
        val pushed = push(vaultId)
        SyncResult(pulledCount = pulled, pushedCount = pushed)
    }

    /**
     * Launches a background sync that does not block the caller.
     * Useful for triggering a sync on network reconnect or app resume.
     */
    fun syncAsync(vaultId: String): Job = scope.launch { sync(vaultId) }

    // ── Pull phase ────────────────────────────────────────────────────────────

    /**
     * Fetches changes from the server since the stored cursor and applies them.
     *
     * @return number of change items processed.
     */
    private suspend fun pull(vaultId: String): Int = pullMutex.withLock {
        val meta = syncMetadataDao.find(vaultId) ?: SyncMetadata(vaultId, lastAppliedSeq = 0L)
        var sinceSeq = meta.lastAppliedSeq
        var totalProcessed = 0

        try {
            // The server may paginate; keep fetching until the cursor stops advancing.
            while (true) {
                val response = api.getChanges(sinceSeq)
                val changes = response.changes
                if (changes.isEmpty()) break

                for (change in changes) {
                    val record = change.record
                    when (change.action) {
                        "upsert" -> if (record != null) {
                            recordDao.upsertFromServer(
                                id = record.id,
                                vaultId = record.vault_id,
                                type = record.type,
                                formatVersion = 1,           // current format version
                                ciphertext = record.ciphertext.decodeBase64(),
                                nonce = record.nonce.decodeBase64(),
                                wrappedDek = record.wrapped_dek.decodeBase64(),
                                wrappedDekNonce = record.wrapped_dek_nonce.decodeBase64(),
                                incomingClientRevision = record.client_revision,
                                incomingServerSeq = change.server_seq,
                                incomingDeleted = record.deleted
                            )
                        }
                        "delete" -> if (record != null) {
                            // Mark deleted from server; do NOT re-enqueue for push.
                            recordDao.upsertFromServer(
                                id = record.id,
                                vaultId = record.vault_id,
                                type = record.type,
                                formatVersion = 1,
                                ciphertext = record.ciphertext.decodeBase64(),
                                nonce = record.nonce.decodeBase64(),
                                wrappedDek = record.wrapped_dek.decodeBase64(),
                                wrappedDekNonce = record.wrapped_dek_nonce.decodeBase64(),
                                incomingClientRevision = record.client_revision,
                                incomingServerSeq = change.server_seq,
                                incomingDeleted = true
                            )
                        }
                        else -> Log.w(TAG, "Unknown sync action: ${change.action}")
                    }
                    if (change.server_seq > sinceSeq) {
                        sinceSeq = change.server_seq
                    }
                }

                // Advance the cursor atomically.
                syncMetadataDao.save(SyncMetadata(vaultId, lastAppliedSeq = sinceSeq))
                totalProcessed += changes.size

                // If the server returned fewer changes than a full page, we're done.
                if (changes.size < SERVER_PAGE_SIZE) break
            }
        } catch (e: CancellationException) {
            throw e
        } catch (e: IOException) {
            Log.w(TAG, "Pull failed (network): ${e.message}")
        } catch (e: HttpException) {
            Log.w(TAG, "Pull failed (HTTP ${e.code()}): ${e.message}")
        } catch (e: Exception) {
            Log.e(TAG, "Pull failed (unexpected): ${e.message}", e)
        }

        totalProcessed
    }

    // ── Push phase ────────────────────────────────────────────────────────────

    /**
     * Drains the offline sync queue, sending each entry to the server.
     *
     * Entries that fail are rescheduled with exponential back-off.  After
     * [MAX_ATTEMPTS] failures the entry is left in the queue for the next app
     * launch (prevents storm-retrying permanently-broken records).
     *
     * @return number of entries successfully pushed.
     */
    private suspend fun push(vaultId: String): Int {
        val nowMs = System.currentTimeMillis()
        val entries = syncQueueDao.dueEntries(vaultId, nowMs, PUSH_BATCH_SIZE)
        if (entries.isEmpty()) return 0

        var successCount = 0
        for (entry in entries) {
            if (entry.attemptCount >= MAX_ATTEMPTS) {
                Log.w(TAG, "Giving up on ${entry.recordId} after $MAX_ATTEMPTS attempts")
                continue
            }
            try {
                when (entry.operation) {
                    "upsert" -> pushUpsert(entry)
                    "delete" -> pushDelete(entry)
                    else -> {
                        Log.w(TAG, "Unknown queue operation: ${entry.operation}")
                        syncQueueDao.remove(entry.recordId)
                        continue
                    }
                }
                syncQueueDao.remove(entry.recordId)
                successCount++
            } catch (e: CancellationException) {
                throw e
            } catch (e: HttpException) {
                val newAttempts = entry.attemptCount + 1
                val backoff = backoffMs(newAttempts)
                Log.w(TAG, "Push HTTP ${e.code()} for ${entry.recordId}; retry in ${backoff}ms")
                syncQueueDao.updateRetry(
                    recordId = entry.recordId,
                    attempts = newAttempts,
                    nextRetryAt = nowMs + backoff,
                    error = "HTTP ${e.code()}: ${e.message()}"
                )
            } catch (e: IOException) {
                val newAttempts = entry.attemptCount + 1
                val backoff = backoffMs(newAttempts)
                Log.w(TAG, "Push IO error for ${entry.recordId}; retry in ${backoff}ms")
                syncQueueDao.updateRetry(
                    recordId = entry.recordId,
                    attempts = newAttempts,
                    nextRetryAt = nowMs + backoff,
                    error = e.message
                )
            } catch (e: Exception) {
                Log.e(TAG, "Push unexpected error for ${entry.recordId}", e)
                val newAttempts = entry.attemptCount + 1
                syncQueueDao.updateRetry(
                    recordId = entry.recordId,
                    attempts = newAttempts,
                    nextRetryAt = nowMs + backoffMs(newAttempts),
                    error = e.message
                )
            }
        }
        return successCount
    }

    private suspend fun pushUpsert(entry: SyncQueueEntry) {
        val record = recordDao.find(entry.recordId, entry.vaultId)
            ?: run {
                // Record was hard-deleted locally before we could push — treat as delete.
                api.deleteRecord(entry.recordId)
                return
            }
        val dto = SyncRecordUpsertDto(
            vault_id = record.vaultId,
            type = record.type,
            ciphertext = record.ciphertext.encodeBase64(),
            nonce = record.nonce.encodeBase64(),
            wrapped_dek = record.wrappedDek.encodeBase64(),
            wrapped_dek_nonce = record.wrappedDekNonce.encodeBase64(),
            client_revision = record.clientRevision
        )
        api.upsertRecord(entry.recordId, dto)
        // The server response does not include the new server_seq in the upsert response;
        // the confirmed serverSeq will arrive on the next pull.  Mark pendingSync=false now
        // so we stop re-sending it.
        recordDao.markSynced(entry.recordId, entry.vaultId, confirmedSeq = 0L)
    }

    private suspend fun pushDelete(entry: SyncQueueEntry) {
        try {
            api.deleteRecord(entry.recordId)
        } catch (e: HttpException) {
            // 404 means the server already deleted it — treat as success.
            if (e.code() != 404) throw e
        }
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    /** Exponential back-off with jitter: 2 s, 4 s, 8 s … capped at [MAX_BACKOFF_MS]. */
    private fun backoffMs(attempts: Int): Long {
        val base = minOf(BASE_BACKOFF_MS * (1L shl (attempts - 1)), MAX_BACKOFF_MS)
        val jitterMultiplier = java.util.concurrent.ThreadLocalRandom.current().nextDouble(0.8, 1.2)
        return minOf((base * jitterMultiplier).toLong(), MAX_BACKOFF_MS)
    }

    private fun String.decodeBase64(): ByteArray = Base64.getDecoder().decode(this)
    private fun ByteArray.encodeBase64(): String = Base64.getEncoder().encodeToString(this)

    private companion object {
        /** Assumed server page size; stop pulling when fewer items are returned. */
        const val SERVER_PAGE_SIZE = 500
    }
}

/** Summary returned by [VaultSyncManager.sync]. */
data class SyncResult(
    val skipped: Boolean = false,
    val pulledCount: Int = 0,
    val pushedCount: Int = 0
)

// Extension to allow idiomatic `mutex.withLock { }` without importing
private suspend fun <T> kotlinx.coroutines.sync.Mutex.withLock(block: suspend () -> T): T {
    lock()
    try {
        return block()
    } finally {
        unlock()
    }
}

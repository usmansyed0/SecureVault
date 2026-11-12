package com.securevault.security

import android.content.Context
import androidx.work.*
import java.util.concurrent.TimeUnit

/**
 * Background WorkManager worker that periodically verifies the dead-man switch threshold.
 * Runs even if the user has not opened the app, enforcing offline wipe guarantees.
 */
class DeadManSwitchWorker(
    appContext: Context,
    workerParams: WorkerParameters
) : CoroutineWorker(appContext, workerParams) {

    override suspend fun doWork(): Result {
        return try {
            val sessions = SecureSessionStore(applicationContext)
            val days = sessions.deadManSwitchDays()
            val lastContact = sessions.lastServerContact()
            if (lastContact > 0L) {
                val thresholdMs = days.toLong() * 24L * 60L * 60L * 1000L
                if (System.currentTimeMillis() - lastContact > thresholdMs) {
                    SafeSecurityLogger.event("dead_man_switch_worker_wipe")
                    val keyManager = VaultKeyManager(VaultMetadataStore(applicationContext))
                    keyManager.wipe()
                    try {
                        DeviceSigningKey(applicationContext).delete()
                    } catch (_: Exception) {}
                    sessions.clear()
                }
            }
            Result.success()
        } catch (e: Exception) {
            SafeSecurityLogger.event("dead_man_switch_worker_error")
            Result.failure()
        }
    }

    companion object {
        const val WORK_NAME = "securevault_dead_man_check"

        fun schedule(context: Context) {
            val request = PeriodicWorkRequestBuilder<DeadManSwitchWorker>(
                12, TimeUnit.HOURS
            ).build()

            WorkManager.getInstance(context).enqueueUniquePeriodicWork(
                WORK_NAME,
                ExistingPeriodicWorkPolicy.KEEP,
                request
            )
        }
    }
}

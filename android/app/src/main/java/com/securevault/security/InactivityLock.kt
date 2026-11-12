package com.securevault.security

interface DelayedTaskScheduler { fun schedule(delayMillis: Long, task: Runnable); fun cancel(task: Runnable) }

/** Testable inactivity policy. Every user interaction resets its one pending timeout. */
class InactivityLock(private val scheduler: DelayedTaskScheduler, private val timeoutMillis: Long = 300_000L) {
    @Volatile private var onTimeout: (() -> Unit)? = null
    @Volatile private var isPaused: Boolean = false
    private val timeout = Runnable {
        if (!isPaused) {
            onTimeout?.invoke()
        }
    }
    fun setOnTimeout(callback: () -> Unit) { onTimeout = callback }
    fun reset() {
        scheduler.cancel(timeout)
        if (!isPaused) {
            scheduler.schedule(timeoutMillis, timeout)
        }
    }
    fun pause() {
        isPaused = true
        scheduler.cancel(timeout)
    }
    fun resume() {
        isPaused = false
        reset()
    }
    fun cancel() = scheduler.cancel(timeout)
}

package com.securevault.security

import org.junit.Assert.assertEquals
import org.junit.Test

class InactivityLockTest {
    @Test fun activityResetsTimerAndTimeoutFiresOnce() {
        val scheduler = FakeScheduler(); var locks = 0
        val lock = InactivityLock(scheduler, 60_000); lock.setOnTimeout { locks++ }
        lock.reset(); lock.reset(); assertEquals(2, scheduler.cancelled)
        scheduler.runPending(); assertEquals(1, locks)
        lock.cancel(); scheduler.runPending(); assertEquals(1, locks)
    }
    private class FakeScheduler : DelayedTaskScheduler {
        var task: Runnable? = null; var cancelled = 0
        override fun schedule(delayMillis: Long, task: Runnable) { assertEquals(60_000, delayMillis); this.task = task }
        override fun cancel(task: Runnable) { cancelled++; if (this.task === task) this.task = null }
        fun runPending() { task?.also { task = null }?.run() }
    }
}

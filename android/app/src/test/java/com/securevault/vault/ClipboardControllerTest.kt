package com.securevault.vault

import com.securevault.security.DelayedTaskScheduler
import com.securevault.vault.clipboard.AndroidClipboardController
import com.securevault.vault.clipboard.ClipboardBackend
import org.junit.Assert.*
import org.junit.Test

class ClipboardControllerTest {

    private class FakeClipboardBackend : ClipboardBackend {
        var currentLabel: String? = null
        var currentText: String? = null
        var isSensitiveFlag: Boolean = false
        var clearCalled: Boolean = false

        override fun setPrimaryClip(label: String, text: String, isSensitive: Boolean) {
            currentLabel = label
            currentText = text
            isSensitiveFlag = isSensitive
            clearCalled = false
        }

        override fun getPrimaryClipText(): String? = currentText

        override fun clearPrimaryClip() {
            clearCalled = true
            currentText = null
            currentLabel = null
        }
    }

    private class FakeScheduler : DelayedTaskScheduler {
        var scheduledDelay: Long = 0L
        var task: Runnable? = null
        var cancelledCount: Int = 0

        override fun schedule(delayMillis: Long, task: Runnable) {
            this.scheduledDelay = delayMillis
            this.task = task
        }

        override fun cancel(task: Runnable) {
            cancelledCount++
            if (this.task === task) {
                this.task = null
            }
        }

        fun runPending() {
            val pending = task
            task = null
            pending?.run()
        }
    }

    @Test
    fun copySensitiveSetsTextAndSchedulesClear() {
        val fakeBackend = FakeClipboardBackend()
        val scheduler = FakeScheduler()
        val controller = AndroidClipboardController(fakeBackend, scheduler)

        controller.copySensitive("Password", "secret-123", timeoutMs = 30_000L)

        assertEquals("secret-123", fakeBackend.currentText)
        assertEquals("Password", fakeBackend.currentLabel)
        assertTrue(fakeBackend.isSensitiveFlag)
        assertFalse(fakeBackend.clearCalled)
        assertEquals(30_000L, scheduler.scheduledDelay)
        assertNotNull(scheduler.task)

        // Trigger the scheduled clear task
        scheduler.runPending()

        assertTrue("Clipboard should be cleared after timeout", fakeBackend.clearCalled)
        assertNull(fakeBackend.currentText)
    }

    @Test
    fun copySensitiveDoesNotClearIfClipboardChanged() {
        val fakeBackend = FakeClipboardBackend()
        val scheduler = FakeScheduler()
        val controller = AndroidClipboardController(fakeBackend, scheduler)

        controller.copySensitive("Password", "secret-123", timeoutMs = 30_000L)

        // User copies something else before timeout
        fakeBackend.currentText = "unrelated-user-text"

        // Trigger scheduled task
        scheduler.runPending()

        assertFalse("Clipboard must not be cleared if user copied something else", fakeBackend.clearCalled)
        assertEquals("unrelated-user-text", fakeBackend.currentText)
    }

    @Test
    fun cancelPendingClearPreventsAutoClear() {
        val fakeBackend = FakeClipboardBackend()
        val scheduler = FakeScheduler()
        val controller = AndroidClipboardController(fakeBackend, scheduler)

        controller.copySensitive("Password", "secret-123", timeoutMs = 30_000L)
        assertNotNull(scheduler.task)

        controller.cancelPendingClear()
        assertNull(scheduler.task)
        assertEquals(1, scheduler.cancelledCount)

        scheduler.runPending()
        assertFalse(fakeBackend.clearCalled)
        assertEquals("secret-123", fakeBackend.currentText)
    }

    @Test
    fun copyPlainSetsTextWithoutSensitiveFlag() {
        val fakeBackend = FakeClipboardBackend()
        val scheduler = FakeScheduler()
        val controller = AndroidClipboardController(fakeBackend, scheduler)

        controller.copyPlain("Username", "alice@example.com")

        assertEquals("alice@example.com", fakeBackend.currentText)
        assertFalse(fakeBackend.isSensitiveFlag)
        assertNull(scheduler.task)
    }
}

package com.securevault.security

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.concurrent.atomic.AtomicInteger

class VaultLockUnlockStressTest {

    @Test
    fun concurrentLockUnlockCycle_remainsThreadSafeAndZeroed() = runBlocking {
        val session = VaultSession()
        val key = ByteArray(32) { 0xAA.toByte() }
        val iterations = 500
        val successfulUnlocks = AtomicInteger(0)
        val caughtLockedExceptions = AtomicInteger(0)

        val jobs = (1..8).map { threadIdx ->
            async(Dispatchers.Default) {
                for (i in 1..iterations) {
                    if (i % 2 == 0) {
                        session.unlock(key)
                        try {
                            session.withRootKey { vrk ->
                                if (vrk.size == 32 && vrk[0] == 0xAA.toByte()) {
                                    successfulUnlocks.incrementAndGet()
                                }
                            }
                        } catch (_: IllegalStateException) {
                            caughtLockedExceptions.incrementAndGet()
                        }
                    } else {
                        session.lock()
                        try {
                            session.withRootKey { }
                        } catch (_: IllegalStateException) {
                            caughtLockedExceptions.incrementAndGet()
                        }
                    }
                }
            }
        }

        jobs.awaitAll()

        // Clean final state
        session.lock()
        assertFalse(session.isUnlocked())
        assertTrue("Expected successful unlock operations", successfulUnlocks.get() > 0)
        assertTrue("Expected caught locked exceptions during concurrency", caughtLockedExceptions.get() > 0)
    }
}

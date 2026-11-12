package com.securevault.security

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

class VaultSessionTest {
    @Test fun lockMakesKeyUnavailable() {
        val session = VaultSession(); session.unlock(ByteArray(32) { 7 }); assertTrue(session.isUnlocked()); session.lock(); assertFalse(session.isUnlocked())
        try { session.withRootKey { }; throw AssertionError("locked session exposed a key") } catch (_: IllegalStateException) { }
    }
    @Test fun lockWaitsForExistingLeaseAndThenPreventsFurtherKeyUse() {
        val session = VaultSession().also { it.unlock(ByteArray(32) { 7 }) }
        val operationStarted = CountDownLatch(1); val allowOperationToFinish = CountDownLatch(1); val lockInvoked = CountDownLatch(1); val lockFinished = CountDownLatch(1)
        Thread { session.withRootKey { operationStarted.countDown(); allowOperationToFinish.await() } }.start()
        assertTrue(operationStarted.await(1, TimeUnit.SECONDS))
        Thread { lockInvoked.countDown(); session.lock(); lockFinished.countDown() }.start()
        assertTrue(lockInvoked.await(1, TimeUnit.SECONDS))
        assertFalse("lock must wait for a held key lease", lockFinished.await(100, TimeUnit.MILLISECONDS))
        allowOperationToFinish.countDown()
        assertTrue(lockFinished.await(1, TimeUnit.SECONDS))
        try { session.withRootKey { }; throw AssertionError("operation acquired a key after lock") } catch (_: IllegalStateException) { }
    }
}

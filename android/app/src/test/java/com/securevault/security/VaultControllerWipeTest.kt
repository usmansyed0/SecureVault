package com.securevault.security

import com.securevault.database.VaultRecordRepository
import kotlinx.coroutines.runBlocking
import org.junit.Assert.*
import org.junit.Test
import org.mockito.Mockito.*
import java.security.Signature

class VaultControllerWipeTest {

    @Test
    fun wipeForRevokedDeviceDeletesDeviceSignerAndAllVaultState() = runBlocking {
        val keys = mock(VaultKeyManager::class.java)
        val session = VaultSession().also { it.unlock(ByteArray(32) { 1 }) }
        val records = mock(VaultRecordRepository::class.java)
        val sessions = mock(SecureSessionStore::class.java)
        val scheduler = object : DelayedTaskScheduler {
            override fun schedule(delayMillis: Long, task: Runnable) {}
            override fun cancel(task: Runnable) {}
        }
        val inactivity = InactivityLock(scheduler)
        val deviceSigner = FakeDeviceSigner()

        val controller = VaultController(keys, session, records, sessions, inactivity, deviceSigner)

        assertTrue(session.isUnlocked())
        controller.wipeForRevokedDevice()

        assertFalse("Session must be locked after wipe", session.isUnlocked())
        assertTrue("Device signing key must be deleted during revocation wipe", deviceSigner.deleteCalled)
        verify(keys, times(1)).wipe()
        verify(records, times(1)).wipe()
        verify(sessions, times(1)).clear()
    }

    @Test
    fun lockForAccountLogoutPreservesDeviceSignerAndVaultData() = runBlocking {
        val keys = mock(VaultKeyManager::class.java)
        val session = VaultSession().also { it.unlock(ByteArray(32) { 1 }) }
        val records = mock(VaultRecordRepository::class.java)
        val sessions = mock(SecureSessionStore::class.java)
        val scheduler = object : DelayedTaskScheduler {
            override fun schedule(delayMillis: Long, task: Runnable) {}
            override fun cancel(task: Runnable) {}
        }
        val inactivity = InactivityLock(scheduler)
        val deviceSigner = FakeDeviceSigner()

        val controller = VaultController(keys, session, records, sessions, inactivity, deviceSigner)

        assertTrue(session.isUnlocked())
        controller.lockForAccountLogout()

        assertFalse("Session must be locked on logout", session.isUnlocked())
        assertFalse("Device signing key must NOT be deleted during ordinary logout", deviceSigner.deleteCalled)
        verify(keys, never()).wipe()
        verify(records, never()).wipe()
        verify(sessions, never()).clear()
    }

    @Test
    fun wipeRemainsSafeIfSigningKeyDoesNotExist() = runBlocking {
        val keys = mock(VaultKeyManager::class.java)
        val session = VaultSession()
        val records = mock(VaultRecordRepository::class.java)
        val sessions = mock(SecureSessionStore::class.java)
        val scheduler = object : DelayedTaskScheduler {
            override fun schedule(delayMillis: Long, task: Runnable) {}
            override fun cancel(task: Runnable) {}
        }
        val inactivity = InactivityLock(scheduler)
        val deviceSigner = FakeDeviceSigner().apply { existsReturn = false }

        val controller = VaultController(keys, session, records, sessions, inactivity, deviceSigner)
        controller.wipeForRevokedDevice()

        assertTrue(deviceSigner.deleteCalled)
    }

    @Test
    fun checkDeadManSwitchDoesNotWipeWithinConfiguredDays() = runBlocking {
        val keys = mock(VaultKeyManager::class.java)
        val session = VaultSession()
        val records = mock(VaultRecordRepository::class.java)
        val sessions = mock(SecureSessionStore::class.java)
        val scheduler = object : DelayedTaskScheduler {
            override fun schedule(delayMillis: Long, task: Runnable) {}
            override fun cancel(task: Runnable) {}
        }
        val inactivity = InactivityLock(scheduler)
        val deviceSigner = FakeDeviceSigner()

        `when`(sessions.lastServerContact()).thenReturn(System.currentTimeMillis() - 2L * 24 * 3600 * 1000)
        `when`(sessions.deadManSwitchDays()).thenReturn(7)

        val controller = VaultController(keys, session, records, sessions, inactivity, deviceSigner)
        controller.checkDeadManSwitch()

        verify(keys, never()).wipe()
        verify(records, never()).wipe()
    }

    @Test(expected = IllegalStateException::class)
    fun checkDeadManSwitchWipesWhenExceedingConfiguredDays() {
        val keys = mock(VaultKeyManager::class.java)
        val session = VaultSession()
        val records = mock(VaultRecordRepository::class.java)
        val sessions = mock(SecureSessionStore::class.java)
        val scheduler = object : DelayedTaskScheduler {
            override fun schedule(delayMillis: Long, task: Runnable) {}
            override fun cancel(task: Runnable) {}
        }
        val inactivity = InactivityLock(scheduler)
        val deviceSigner = FakeDeviceSigner()

        // 8 days ago, with a 7-day threshold
        `when`(sessions.lastServerContact()).thenReturn(System.currentTimeMillis() - 8L * 24 * 3600 * 1000)
        `when`(sessions.deadManSwitchDays()).thenReturn(7)

        val controller = VaultController(keys, session, records, sessions, inactivity, deviceSigner)
        controller.checkDeadManSwitch()
    }

    private class FakeDeviceSigner : DeviceSigner {
        var deleteCalled = false
        var existsReturn = true

        override fun createIfMissing() {}
        override fun publicKeyDer(): ByteArray = byteArrayOf()
        override fun publicKeyBase64(): String = ""
        override fun exists(): Boolean = existsReturn
        override fun signatureForAuthentication(): Signature = throw UnsupportedOperationException()
        override fun signAuthenticated(signature: Signature, message: ByteArray): ByteArray = byteArrayOf()
        override fun sign(message: ByteArray): ByteArray = byteArrayOf()
        override fun delete() {
            deleteCalled = true
        }
    }
}

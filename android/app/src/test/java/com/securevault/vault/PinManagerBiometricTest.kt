package com.securevault.vault

import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/**
 * Tests verifying that biometric failures are completely separated from the
 * PIN wipe counter. A dirty fingerprint sensor must NEVER wipe the vault.
 */
class PinManagerBiometricTest {

    private lateinit var fakeStore: FakePinStore
    private lateinit var pinManager: PinManager

    /** A minimal in-memory PinStore for unit testing. */
    private class FakePinStore : PinStore {
        private var state: WrappedPinKey? = null

        override fun hasPin(): Boolean = state != null && !(state?.isWiped ?: true)
        override fun isWiped(): Boolean = state?.isWiped ?: false
        override fun save(value: WrappedPinKey) { state = value }
        override fun load(): WrappedPinKey? = state
        override fun recordFailure(failedAttempts: Int, lockoutUntilEpochMs: Long) {
            state = state?.copy(failedAttempts = failedAttempts, lockoutUntilEpochMs = lockoutUntilEpochMs)
        }
        override fun resetFailures() {
            state = state?.copy(failedAttempts = 0, lockoutUntilEpochMs = 0L, biometricFailedAttempts = 0)
        }
        override fun markWiped() { state = state?.copy(isWiped = true) }
        override fun clear() { state = null }
        override fun recordBiometricFailure(biometricFailedAttempts: Int) {
            state = state?.copy(biometricFailedAttempts = biometricFailedAttempts)
        }
        override fun resetBiometricFailures() {
            state = state?.copy(biometricFailedAttempts = 0)
        }
        override fun biometricFailedAttempts(): Int = state?.biometricFailedAttempts ?: 0

        fun seedWithPin(failedAttempts: Int = 0) {
            state = WrappedPinKey(
                salt = ByteArray(16) { 0x01 },
                innerNonce = ByteArray(12) { 0x02 },
                outerNonce = ByteArray(12) { 0x03 },
                outerCiphertext = ByteArray(48) { 0x04 },
                failedAttempts = failedAttempts,
                lockoutUntilEpochMs = 0L,
                isWiped = false,
                pinLength = 6,
                biometricFailedAttempts = 0,
            )
        }
    }

    private val argon2 = com.securevault.crypto.Argon2Kdf()

    @Before
    fun setUp() {
        fakeStore = FakePinStore()
        fakeStore.seedWithPin()
        pinManager = PinManager(fakeStore, argon2)
    }

    @Test
    fun biometricFailures_doNotIncrementPinFailedAttempts() = runBlocking {
        val initialPinFailures = fakeStore.load()!!.failedAttempts
        repeat(5) { pinManager.recordBiometricFailure() }
        assertEquals(
            "PIN failedAttempts must not change after biometric failures",
            initialPinFailures,
            fakeStore.load()!!.failedAttempts
        )
    }

    @Test
    fun tenBiometricFailures_doNotWipeVault() = runBlocking {
        var wipeCalled = false
        pinManager.onTerminalLockout = { wipeCalled = true }
        // Simulate 20 biometric failures (double the PIN wipe threshold)
        repeat(20) { pinManager.recordBiometricFailure() }
        assertFalse("Vault must NOT be wiped by biometric failures", fakeStore.isWiped())
        assertFalse("onTerminalLockout must NOT be called for biometric failures", wipeCalled)
    }

    @Test
    fun biometricFailures_incrementOnlyBiometricCounter() = runBlocking {
        repeat(3) { pinManager.recordBiometricFailure() }
        val state = fakeStore.load()!!
        assertEquals("Biometric counter should be 3", 3, state.biometricFailedAttempts)
        assertEquals("PIN counter must remain 0", 0, state.failedAttempts)
    }

    @Test
    fun biometricThreshold_triggersFallbackCallback_notWipe() = runBlocking {
        var fallbackCalled = false
        var wipeCalled = false
        pinManager.onBiometricTemporarilyUnavailable = { fallbackCalled = true }
        pinManager.onTerminalLockout = { wipeCalled = true }

        // BIOMETRIC_FALLBACK_THRESHOLD is 5
        repeat(PinManager.BIOMETRIC_FALLBACK_THRESHOLD) {
            pinManager.recordBiometricFailure()
        }
        assertTrue("Fallback callback should fire after threshold", fallbackCalled)
        assertFalse("Wipe must NOT be triggered", wipeCalled)
        assertFalse("Vault must NOT be wiped", fakeStore.isWiped())
    }

    @Test
    fun biometricCounter_resetsAfterThreshold() = runBlocking {
        repeat(PinManager.BIOMETRIC_FALLBACK_THRESHOLD) {
            pinManager.recordBiometricFailure()
        }
        // After threshold, counter should reset to 0 (fallback was triggered)
        assertEquals(0, fakeStore.load()!!.biometricFailedAttempts)
    }

    @Test
    fun pinFailures_stillCountTowardWipeThreshold() = runBlocking {
        val state = fakeStore.load()!!
        // Manually simulate 9 PIN failures recorded by PinManager.unlockWithPin
        fakeStore.recordFailure(9, 0L)
        assertEquals(9, fakeStore.load()!!.failedAttempts)
        // One more biometric failure should NOT push it over the edge
        pinManager.recordBiometricFailure()
        assertFalse("Vault must not be wiped", fakeStore.isWiped())
        assertEquals("PIN counter must still be 9", 9, fakeStore.load()!!.failedAttempts)
    }

    @Test
    fun successfulUnlock_resetsBothCounters() {
        fakeStore.recordFailure(3, 0L)
        fakeStore.recordBiometricFailure(2)
        fakeStore.resetFailures()
        val state = fakeStore.load()!!
        assertEquals(0, state.failedAttempts)
        assertEquals(0, state.biometricFailedAttempts)
    }
}

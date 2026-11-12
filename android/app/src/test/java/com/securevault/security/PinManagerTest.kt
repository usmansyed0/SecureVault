package com.securevault.security

import com.securevault.crypto.Argon2Kdf
import kotlinx.coroutines.runBlocking
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import java.security.SecureRandom
import com.securevault.vault.PinManager
import com.securevault.vault.PinStore
import com.securevault.vault.WrappedPinKey

class PinManagerTest {

    private class FakePinStore : PinStore {
        var stored: WrappedPinKey? = null
        var wiped: Boolean = false

        override fun hasPin(): Boolean = stored != null && !wiped
        override fun isWiped(): Boolean = wiped
        override fun save(value: WrappedPinKey) { stored = value; wiped = value.isWiped }
        override fun load(): WrappedPinKey? = if (wiped) null else stored
        override fun recordFailure(failedAttempts: Int, lockoutUntilEpochMs: Long) {
            stored = stored?.copy(failedAttempts = failedAttempts, lockoutUntilEpochMs = lockoutUntilEpochMs)
        }
        override fun resetFailures() {
            stored = stored?.copy(failedAttempts = 0, lockoutUntilEpochMs = 0L)
        }
        override fun markWiped() {
            stored = null
            wiped = true
        }
        override fun clear() {
            stored = null
            wiped = false
        }
        override fun recordBiometricFailure(biometricFailedAttempts: Int) {
            stored = stored?.copy(biometricFailedAttempts = biometricFailedAttempts)
        }
        override fun resetBiometricFailures() {
            stored = stored?.copy(biometricFailedAttempts = 0)
        }
        override fun biometricFailedAttempts(): Int = stored?.biometricFailedAttempts ?: 0
    }

    private lateinit var metadataStore: FakePinStore
    private lateinit var argon2: Argon2Kdf
    private lateinit var pinManager: PinManager
    private val testVrk = ByteArray(32).also { SecureRandom().nextBytes(it) }

    @Before
    fun setup() {
        metadataStore = FakePinStore()
        argon2 = Argon2Kdf()
        pinManager = PinManager(metadataStore, argon2)
    }

    @Test
    fun setupPinAndSuccessfulUnlockReturnsVrk() = runBlocking {
        val pin = "123456"
        pinManager.setupPin(pin, testVrk)

        assertTrue(pinManager.hasPin())
        val unlockedVrk = pinManager.unlockWithPin(pin)
        assertArrayEquals(testVrk, unlockedVrk)
        assertEquals(0, pinManager.failedAttempts())
    }

    @Test
    fun incorrectPinIncrementsFailureCountAndThrows() = runBlocking {
        val pin = "654321"
        pinManager.setupPin(pin, testVrk)

        try {
            pinManager.unlockWithPin("000000")
            fail("Expected SecurityException on wrong PIN")
        } catch (e: SecurityException) {
            assertTrue(e.message!!.contains("Incorrect PIN"))
        }

        assertEquals(1, pinManager.failedAttempts())
    }

    @Test
    fun multipleFailuresTriggerLockoutDelay() = runBlocking {
        val pin = "112233"
        pinManager.setupPin(pin, testVrk)

        for (i in 1..5) {
            try {
                pinManager.unlockWithPin("999999")
            } catch (_: SecurityException) {}
        }

        assertEquals(5, pinManager.failedAttempts())
        assertTrue("At 5 failures lockout delay must be active", pinManager.remainingLockoutSeconds() > 0)

        // Attempting to unlock while locked out should fail with lockout message
        try {
            pinManager.unlockWithPin(pin)
            fail("Should reject unlock during active lockout delay")
        } catch (e: SecurityException) {
            assertTrue(e.message!!.contains("Locked out"))
        }
    }

    @Test
    fun tenConsecutiveFailuresTriggersTerminalWipe() = runBlocking {
        val pin = "445566"
        pinManager.setupPin(pin, testVrk)

        var terminalLockoutTriggered = false
        pinManager.onTerminalLockout = {
            terminalLockoutTriggered = true
        }

        // Fast-forward 9 failures (bypassing delay in metadata store for test)
        metadataStore.recordFailure(9, 0L)

        // 10th failure
        try {
            pinManager.unlockWithPin("000000")
            fail("Expected terminal exception")
        } catch (e: SecurityException) {
            assertTrue(e.message!!.contains("Terminal attempt threshold reached"))
        }

        assertTrue("Terminal lockout callback must be invoked", terminalLockoutTriggered)
        assertTrue("Vault must be marked wiped", metadataStore.isWiped())
    }
}

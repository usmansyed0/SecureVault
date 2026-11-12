package com.securevault.crypto

import com.securevault.vault.strength.PasswordStrengthMeter
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import java.security.SecureRandom

class VaultPasswordManagerTest {

    private lateinit var manager: VaultPasswordManager

    @Before
    fun setUp() {
        manager = VaultPasswordManager(Argon2Kdf(), PasswordStrengthMeter())
    }

    @Test
    fun validatePasswordRejectsShortPassword() {
        val res = manager.validatePassword("Short1!abc") // 10 chars
        assertFalse(res.isValid)
        assertTrue(res.errorMessage!!.contains("at least 12 characters"))
    }

    @Test
    fun validatePasswordRejectsWeakLongPassword() {
        val res = manager.validatePassword("aaaaaaaaaaaa11") // 14 chars repeated
        assertFalse(res.isValid)
        assertTrue(res.errorMessage!!.contains("too weak"))
    }

    @Test
    fun validatePasswordAcceptsStrongPassword() {
        val res = manager.validatePassword("P@ssw0rd!Secure#2026")
        assertTrue(res.isValid)
        assertNull(res.errorMessage)
    }

    @Test
    fun wrapAndUnwrapVrkRoundTripsCorrectly() {
        val random = SecureRandom()
        val vrk = ByteArray(32).also(random::nextBytes)
        val password = "C0mpl3x&Str0ngVaultP@ssword2026!"

        val wrapped = manager.wrapVrk(vrk, password)
        assertEquals(16, wrapped.salt.size)
        assertEquals(12, wrapped.nonce.size)
        // 32 bytes + 16 bytes auth tag = 48 bytes
        assertEquals(48, wrapped.ciphertext.size)

        val unwrappedVrk = manager.unwrapVrk(
            password = password,
            salt = wrapped.salt,
            nonce = wrapped.nonce,
            ciphertext = wrapped.ciphertext
        )
        assertArrayEquals(vrk, unwrappedVrk)
    }

    @Test
    fun unwrapVrkFailsWithIncorrectPassword() {
        val random = SecureRandom()
        val vrk = ByteArray(32).also(random::nextBytes)
        val password = "C0mpl3x&Str0ngVaultP@ssword2026!"
        val wrongPassword = "WrongP@ssword12345!"

        val wrapped = manager.wrapVrk(vrk, password)

        try {
            manager.unwrapVrk(
                password = wrongPassword,
                salt = wrapped.salt,
                nonce = wrapped.nonce,
                ciphertext = wrapped.ciphertext
            )
            fail("Expected SecurityException when unwrapping with wrong password")
        } catch (e: SecurityException) {
            assertTrue(e.message!!.contains("Failed to unwrap"))
        }
    }
}

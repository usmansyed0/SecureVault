package com.securevault.vault

import com.securevault.vault.strength.PasswordStrength
import com.securevault.vault.strength.PasswordStrengthMeter
import org.junit.Assert.*
import org.junit.Test

class PasswordStrengthMeterTest {

    private val meter = PasswordStrengthMeter()

    @Test
    fun emptyPasswordIsVeryWeak() {
        val result = meter.evaluate("")
        assertEquals(PasswordStrength.VERY_WEAK, result.strength)
        assertEquals(0, result.score)
        assertEquals(0.0, result.entropyBits, 0.01)
        assertTrue(result.feedback.isNotEmpty())
    }

    @Test
    fun shortPasswordIsVeryWeak() {
        val result = meter.evaluate("abc")
        assertEquals(PasswordStrength.VERY_WEAK, result.strength)
        assertEquals(0, result.score)
        assertTrue(result.entropyBits < 30.0)
    }

    @Test
    fun simplePasswordIsWeak() {
        val result = meter.evaluate("password123")
        assertTrue(result.strength == PasswordStrength.WEAK || result.strength == PasswordStrength.VERY_WEAK)
        assertTrue(result.score <= 1)
    }

    @Test
    fun repetitiveCharactersIncurPenalty() {
        val repeating = meter.evaluate("aaaaaabbbbbb123456")
        assertTrue(repeating.feedback.any { it.contains("repeating") })
    }

    @Test
    fun sequentialCharactersIncurPenalty() {
        val sequential = meter.evaluate("abcdef123456!@#$")
        assertTrue(sequential.feedback.any { it.contains("sequential") })
    }

    @Test
    fun highEntropyComplexPasswordIsVeryStrong() {
        val strongPass = "kP9#vX2\$mQ8!zL4@wR7*"
        val result = meter.evaluate(strongPass)
        assertEquals(PasswordStrength.VERY_STRONG, result.strength)
        assertEquals(4, result.score)
        assertTrue(result.entropyBits >= 90.0)
        assertFalse(result.feedback.any { it.contains("repeating") })
        assertFalse(result.feedback.any { it.contains("sequential") })
    }
}

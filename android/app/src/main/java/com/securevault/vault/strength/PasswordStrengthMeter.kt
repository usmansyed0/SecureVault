package com.securevault.vault.strength

import javax.inject.Inject
import javax.inject.Singleton
import kotlin.math.ln

enum class PasswordStrength(val label: String, val score: Int) {
    VERY_WEAK("Very Weak", 0),
    WEAK("Weak", 1),
    FAIR("Fair", 2),
    STRONG("Strong", 3),
    VERY_STRONG("Very Strong", 4)
}

data class StrengthResult(
    val strength: PasswordStrength,
    val score: Int,
    val entropyBits: Double,
    val feedback: List<String>
)

@Singleton
class PasswordStrengthMeter @Inject constructor() {

    companion object {
        private val defaultInstance = PasswordStrengthMeter()
        fun estimate(password: String): StrengthResult = defaultInstance.evaluate(password)
        fun evaluate(password: String): StrengthResult = defaultInstance.evaluate(password)
    }

    fun evaluate(password: String): StrengthResult {
        if (password.isEmpty()) {
            return StrengthResult(
                strength = PasswordStrength.VERY_WEAK,
                score = 0,
                entropyBits = 0.0,
                feedback = listOf("Enter a password")
            )
        }

        var poolSize = 0
        val hasLower = password.any { it.isLowerCase() }
        val hasUpper = password.any { it.isUpperCase() }
        val hasDigit = password.any { it.isDigit() }
        val hasSymbol = password.any { !it.isLetterOrDigit() }

        if (hasLower) poolSize += 26
        if (hasUpper) poolSize += 26
        if (hasDigit) poolSize += 10
        if (hasSymbol) poolSize += 33

        val log2Pool = if (poolSize > 0) ln(poolSize.toDouble()) / ln(2.0) else 0.0
        var rawEntropy = password.length * log2Pool

        val feedback = mutableListOf<String>()

        if (!hasLower) feedback.add("Add lowercase letters")
        if (!hasUpper) feedback.add("Add uppercase letters")
        if (!hasDigit) feedback.add("Add numbers")
        if (!hasSymbol) feedback.add("Add symbols")
        if (password.length < 15) feedback.add("Increase length to at least 15 characters")

        // Penalize repeating characters (e.g., "aaa")
        var hasRepeat = false
        for (i in 0 until password.length - 2) {
            if (password[i] == password[i + 1] && password[i] == password[i + 2]) {
                hasRepeat = true
                break
            }
        }
        if (hasRepeat) {
            rawEntropy -= 15.0
            feedback.add("Avoid repeating characters")
        }

        // Penalize sequential sequences (e.g., "123", "abc")
        var hasSequence = false
        for (i in 0 until password.length - 2) {
            val c1 = password[i].code
            val c2 = password[i + 1].code
            val c3 = password[i + 2].code
            if ((c2 == c1 + 1 && c3 == c2 + 1) || (c2 == c1 - 1 && c3 == c2 - 1)) {
                hasSequence = true
                break
            }
        }
        if (hasSequence) {
            rawEntropy -= 15.0
            feedback.add("Avoid sequential characters")
        }

        val effectiveEntropy = rawEntropy.coerceAtLeast(0.0)
        val classCount = (if (hasLower) 1 else 0) + (if (hasUpper) 1 else 0) +
                (if (hasDigit) 1 else 0) + (if (hasSymbol) 1 else 0)

        val strength = when {
            password.length < 8 || effectiveEntropy < 30.0 -> PasswordStrength.VERY_WEAK
            password.length < 12 || effectiveEntropy < 50.0 || classCount < 2 -> PasswordStrength.WEAK
            effectiveEntropy < 70.0 || classCount < 3 -> PasswordStrength.FAIR
            password.length >= 15 && effectiveEntropy >= 90.0 && classCount >= 4 && !hasRepeat && !hasSequence -> PasswordStrength.VERY_STRONG
            effectiveEntropy >= 70.0 && classCount >= 3 -> PasswordStrength.STRONG
            else -> PasswordStrength.FAIR
        }

        return StrengthResult(
            strength = strength,
            score = strength.score,
            entropyBits = (effectiveEntropy * 10).toInt() / 10.0,
            feedback = feedback
        )
    }
}

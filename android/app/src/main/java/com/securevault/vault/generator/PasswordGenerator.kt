package com.securevault.vault.generator

import java.security.SecureRandom
import javax.inject.Inject
import javax.inject.Singleton

const val MIN_PASSWORD_LENGTH = 8
const val MAX_PASSWORD_LENGTH = 64
const val DEFAULT_PASSWORD_LENGTH = 20

data class PasswordGeneratorConfig(
    val length: Int = DEFAULT_PASSWORD_LENGTH,
    val includeUppercase: Boolean = true,
    val includeLowercase: Boolean = true,
    val includeDigits: Boolean = true,
    val includeSymbols: Boolean = true
)

@Singleton
class PasswordGenerator(
    private val random: SecureRandom
) {
    @Inject
    constructor() : this(SecureRandom())
    companion object {
        const val UPPERCASE = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        const val LOWERCASE = "abcdefghijklmnopqrstuvwxyz"
        const val DIGITS = "0123456789"
        const val SYMBOLS = "!@#$%^&*()_+-=[]{}|;:,.<>?"
    }

    fun generate(config: PasswordGeneratorConfig = PasswordGeneratorConfig()): String {
        require(config.length in MIN_PASSWORD_LENGTH..MAX_PASSWORD_LENGTH) {
            "Password length must be between $MIN_PASSWORD_LENGTH and $MAX_PASSWORD_LENGTH, requested: ${config.length}"
        }

        val requiredCharSets = mutableListOf<String>()
        if (config.includeUppercase) requiredCharSets.add(UPPERCASE)
        if (config.includeLowercase) requiredCharSets.add(LOWERCASE)
        if (config.includeDigits) requiredCharSets.add(DIGITS)
        if (config.includeSymbols) requiredCharSets.add(SYMBOLS)

        require(requiredCharSets.isNotEmpty()) {
            "At least one character class must be selected"
        }
        require(config.length >= requiredCharSets.size) {
            "Length ${config.length} cannot satisfy ${requiredCharSets.size} required character classes"
        }

        val passwordChars = CharArray(config.length)
        var index = 0

        // Guarantee at least one character from each selected class
        for (charset in requiredCharSets) {
            val charIndex = random.nextInt(charset.length)
            passwordChars[index++] = charset[charIndex]
        }

        // Build combined pool
        val combinedPool = requiredCharSets.joinToString("")

        // Fill remaining slots
        while (index < config.length) {
            val charIndex = random.nextInt(combinedPool.length)
            passwordChars[index++] = combinedPool[charIndex]
        }

        // Fisher-Yates shuffle using SecureRandom
        for (i in passwordChars.indices.reversed()) {
            val j = random.nextInt(i + 1)
            val temp = passwordChars[i]
            passwordChars[i] = passwordChars[j]
            passwordChars[j] = temp
        }

        return String(passwordChars)
    }
}

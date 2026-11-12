package com.securevault.crypto

import com.securevault.vault.strength.PasswordStrengthMeter
import java.security.SecureRandom
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import javax.inject.Inject
import javax.inject.Singleton

@Singleton
class VaultPasswordManager @Inject constructor(
    private val argon2Kdf: Argon2Kdf,
    private val strengthMeter: PasswordStrengthMeter
) {
    private val random = SecureRandom()

    companion object {
        const val MIN_PASSWORD_LENGTH = 12
        const val MIN_STRENGTH_SCORE = 3 // Minimum "Strong" score (0-4)
        const val SALT_BYTES = 16
        const val KEY_BYTES = 32
        const val GCM_IV_LENGTH = 12
        const val GCM_TAG_LENGTH_BITS = 128
        val AAD_VAULT_PASSWORD_WRAP = "vault_password_wrap_v1".toByteArray(Charsets.UTF_8)

        // Argon2id parameters
        const val ARGON2_ITERATIONS = 3
        const val ARGON2_MEMORY_KB = 65536 // 64 MB
        const val ARGON2_PARALLELISM = 2
    }

    data class ValidationResult(
        val isValid: Boolean,
        val errorMessage: String? = null
    )

    data class WrappedVaultPasswordVrk(
        val salt: ByteArray,
        val nonce: ByteArray,
        val ciphertext: ByteArray
    ) {
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other !is WrappedVaultPasswordVrk) return false
            return salt.contentEquals(other.salt) &&
                    nonce.contentEquals(other.nonce) &&
                    ciphertext.contentEquals(other.ciphertext)
        }

        override fun hashCode(): Int {
            var result = salt.contentHashCode()
            result = 31 * result + nonce.contentHashCode()
            result = 31 * result + ciphertext.contentHashCode()
            return result
        }
    }

    /**
     * Validates that the Vault Password meets minimum length (>= 12) and strength (score >= 3).
     */
    fun validatePassword(password: String): ValidationResult {
        if (password.length < MIN_PASSWORD_LENGTH) {
            return ValidationResult(
                isValid = false,
                errorMessage = "Vault Password must be at least $MIN_PASSWORD_LENGTH characters."
            )
        }
        val strength = strengthMeter.evaluate(password)
        if (strength.score < MIN_STRENGTH_SCORE) {
            val suggestions = if (strength.feedback.isNotEmpty()) ": " + strength.feedback.joinToString(", ") else "."
            return ValidationResult(
                isValid = false,
                errorMessage = "Vault Password is too weak (strength score ${strength.score}/4)$suggestions"
            )
        }
        return ValidationResult(isValid = true)
    }

    /**
     * Derives a 256-bit wrapping key using Argon2id.
     */
    fun deriveWrappingKey(password: CharArray, salt: ByteArray): ByteArray {
        require(salt.size >= SALT_BYTES) { "Salt must be at least $SALT_BYTES bytes" }
        return argon2Kdf.deriveKey(
            secretChars = password,
            salt = salt,
            iterations = ARGON2_ITERATIONS,
            memoryKb = ARGON2_MEMORY_KB,
            parallelism = ARGON2_PARALLELISM,
            outputLengthBytes = KEY_BYTES
        )
    }

    fun deriveWrappingKey(password: String, salt: ByteArray): ByteArray =
        deriveWrappingKey(password.toCharArray(), salt)

    /**
     * Generates a 16-byte random salt.
     */
    fun generateSalt(): ByteArray = argon2Kdf.generateSalt(SALT_BYTES)

    /**
     * Wraps the VRK using the Vault Password-derived key (AES-256-GCM with AAD).
     */
    fun wrapVrk(vrk: ByteArray, password: CharArray, salt: ByteArray = generateSalt()): WrappedVaultPasswordVrk {
        require(vrk.size == 32) { "VRK must be exactly 32 bytes" }
        val wrappingKey = deriveWrappingKey(password, salt)
        try {
            val iv = ByteArray(GCM_IV_LENGTH)
            random.nextBytes(iv)

            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            val keySpec = SecretKeySpec(wrappingKey, "AES")
            val gcmSpec = GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv)
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmSpec)
            cipher.updateAAD(AAD_VAULT_PASSWORD_WRAP)
            val ciphertext = cipher.doFinal(vrk)

            return WrappedVaultPasswordVrk(salt = salt, nonce = iv, ciphertext = ciphertext)
        } finally {
            wrappingKey.fill(0)
        }
    }

    fun wrapVrk(vrk: ByteArray, password: String, salt: ByteArray = generateSalt()): WrappedVaultPasswordVrk =
        wrapVrk(vrk, password.toCharArray(), salt)

    /**
     * Unwraps the VRK using the Vault Password and stored salt/nonce/ciphertext.
     */
    fun unwrapVrk(
        password: CharArray,
        salt: ByteArray,
        nonce: ByteArray,
        ciphertext: ByteArray
    ): ByteArray {
        val wrappingKey = deriveWrappingKey(password, salt)
        try {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            val keySpec = SecretKeySpec(wrappingKey, "AES")
            val gcmSpec = GCMParameterSpec(GCM_TAG_LENGTH_BITS, nonce)
            cipher.init(Cipher.DECRYPT_MODE, keySpec, gcmSpec)
            cipher.updateAAD(AAD_VAULT_PASSWORD_WRAP)
            val vrk = cipher.doFinal(ciphertext)
            if (vrk.size != 32) {
                throw SecurityException("Decrypted VRK has invalid length: ${vrk.size}")
            }
            return vrk
        } catch (e: Exception) {
            throw SecurityException("Failed to unwrap Vault Root Key with Vault Password", e)
        } finally {
            wrappingKey.fill(0)
        }
    }

    fun unwrapVrk(
        password: String,
        salt: ByteArray,
        nonce: ByteArray,
        ciphertext: ByteArray
    ): ByteArray = unwrapVrk(password.toCharArray(), salt, nonce, ciphertext)
}

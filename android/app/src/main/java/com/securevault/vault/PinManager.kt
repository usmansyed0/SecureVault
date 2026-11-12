package com.securevault.vault

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import com.securevault.crypto.Argon2Kdf
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.security.KeyStore
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import javax.inject.Inject
import javax.inject.Singleton

@Singleton
class PinManager @Inject constructor(
    private val metadataStore: PinStore,
    private val argon2: Argon2Kdf
) {
    private val random = SecureRandom()
    private val keyStore = try {
        KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
    } catch (_: Exception) {
        null
    }
    private var testOuterKey: SecretKey? = null

    var onTerminalLockout: (suspend () -> Unit)? = null
    /** Called when biometric failures exceed threshold; UI should fall back to PIN entry. */
    var onBiometricTemporarilyUnavailable: (() -> Unit)? = null

    fun hasPin(): Boolean = metadataStore.hasPin()

    fun pinLength(): Int = metadataStore.load()?.pinLength ?: 6

    fun failedAttempts(): Int = metadataStore.load()?.failedAttempts ?: 0

    fun biometricFailedAttempts(): Int = metadataStore.load()?.biometricFailedAttempts ?: 0

    fun remainingLockoutSeconds(): Long {
        val entry = metadataStore.load() ?: return 0L
        val diff = entry.lockoutUntilEpochMs - System.currentTimeMillis()
        return if (diff > 0) (diff + 999) / 1000 else 0L
    }

    private fun ensureOuterKey(): SecretKey {
        val ks = keyStore
        if (ks == null) {
            // JVM Unit test environment fallback
            val current = testOuterKey
            if (current != null) return current
            val kg = KeyGenerator.getInstance("AES")
            kg.init(256)
            val generated = kg.generateKey()
            testOuterKey = generated
            return generated
        }

        if (!ks.containsAlias(KEY_ALIAS)) {
            val builder = KeyGenParameterSpec.Builder(
                KEY_ALIAS,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
            )
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .setRandomizedEncryptionRequired(true)
                .setUserAuthenticationRequired(false) // Custom PIN handles authentication

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                builder.setUnlockedDeviceRequired(true)
            }

            val keyGen = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
            try {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                    builder.setIsStrongBoxBacked(true)
                    keyGen.init(builder.build())
                    keyGen.generateKey()
                } else {
                    keyGen.init(builder.build())
                    keyGen.generateKey()
                }
            } catch (_: Exception) {
                // StrongBox not available on device; fallback to TEE
                val fallbackBuilder = KeyGenParameterSpec.Builder(
                    KEY_ALIAS,
                    KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
                )
                    .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                    .setKeySize(256)
                    .setRandomizedEncryptionRequired(true)
                    .setUserAuthenticationRequired(false)

                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                    fallbackBuilder.setUnlockedDeviceRequired(true)
                }
                keyGen.init(fallbackBuilder.build())
                keyGen.generateKey()
            }
        }
        val entry = ks.getEntry(KEY_ALIAS, null) as? KeyStore.SecretKeyEntry
            ?: throw IllegalStateException("KeyStore entry $KEY_ALIAS is not a SecretKeyEntry")
        return entry.secretKey
    }

    /**
     * Configures the 6-digit SecureVault PIN by wrapping the VRK:
     * Inner: AES-256-GCM using Argon2id(pin, salt)
     * Outer: AES-256-GCM using Hardware Keystore key
     *
     * Minimum PIN length is 6 digits (raised from 4 in Phase 0).
     */
    fun setupPin(pin: String, vrk: ByteArray) {
        require(pin.length in 6..8 && pin.all { it.isDigit() }) {
            "PIN must be 6 to 8 digits"
        }
        require(vrk.size == 32) { "Invalid VRK size" }

        val salt = argon2.generateSalt(16)
        val pinSecret = argon2.deriveKey(pin, salt)
        val innerNonce = ByteArray(12).also(random::nextBytes)

        try {
            // 1. Inner encryption with PIN_Secret
            val innerCipher = Cipher.getInstance("AES/GCM/NoPadding")
            innerCipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(pinSecret, "AES"), GCMParameterSpec(128, innerNonce))
            innerCipher.updateAAD(salt)
            val innerCiphertext = innerCipher.doFinal(vrk)

            // 2. Outer encryption with Hardware Keystore key
            val outerKey = ensureOuterKey()
            val outerCipher = Cipher.getInstance("AES/GCM/NoPadding")
            outerCipher.init(Cipher.ENCRYPT_MODE, outerKey)
            outerCipher.updateAAD(salt + innerNonce)
            val outerCiphertext = outerCipher.doFinal(innerCiphertext)
            val outerNonce = outerCipher.iv

            metadataStore.save(
                WrappedPinKey(
                    salt = salt,
                    innerNonce = innerNonce,
                    outerNonce = outerNonce,
                    outerCiphertext = outerCiphertext,
                    failedAttempts = 0,
                    lockoutUntilEpochMs = 0L,
                    isWiped = false,
                    pinLength = pin.length
                )
            )
        } finally {
            pinSecret.fill(0)
        }
    }

    /**
     * Attempts to unlock the VRK with the provided PIN.
     * Enforces attempt throttling and triggers terminal wipe at 10 consecutive failures.
     */
    suspend fun unlockWithPin(pin: String): ByteArray = withContext(Dispatchers.Default) {
        val entry = metadataStore.load() ?: throw IllegalStateException("PIN is not configured")
        if (entry.isWiped) {
            throw SecurityException("Vault has been wiped due to excessive failed attempts")
        }

        val remaining = remainingLockoutSeconds()
        if (remaining > 0) {
            throw SecurityException("Too many failed attempts. Locked out for $remaining seconds.")
        }

        val outerKey = ensureOuterKey()

        // 1. Decrypt outer layer using Hardware Keystore
        val innerCiphertext = try {
            val outerCipher = Cipher.getInstance("AES/GCM/NoPadding")
            outerCipher.init(Cipher.DECRYPT_MODE, outerKey, GCMParameterSpec(128, entry.outerNonce))
            outerCipher.updateAAD(entry.salt + entry.innerNonce)
            outerCipher.doFinal(entry.outerCiphertext)
        } catch (e: Exception) {
            throw SecurityException("Hardware decryption layer failed", e)
        }

        // 2. Derive PIN_Secret and decrypt inner layer
        val pinSecret = argon2.deriveKey(pin, entry.salt)
        try {
            val innerCipher = Cipher.getInstance("AES/GCM/NoPadding")
            innerCipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(pinSecret, "AES"), GCMParameterSpec(128, entry.innerNonce))
            innerCipher.updateAAD(entry.salt)
            val vrk = innerCipher.doFinal(innerCiphertext)

            // Success! Reset failure count
            metadataStore.resetFailures()
            vrk
        } catch (_: Exception) {
            // Decryption failed -> incorrect PIN
            val newAttempts = entry.failedAttempts + 1
            if (newAttempts >= TERMINAL_ATTEMPTS) {
                testOuterKey = null
                keyStore?.let { ks ->
                    if (ks.containsAlias(KEY_ALIAS)) {
                        ks.deleteEntry(KEY_ALIAS)
                    }
                }
                metadataStore.markWiped()
                onTerminalLockout?.invoke()
                throw SecurityException("Terminal attempt threshold reached ($newAttempts/$TERMINAL_ATTEMPTS). Local vault wiped.")
            } else {
                val delayMs = computeLockoutDelayMs(newAttempts)
                val lockoutUntil = if (delayMs > 0) System.currentTimeMillis() + delayMs else 0L
                metadataStore.recordFailure(newAttempts, lockoutUntil)
                val remainingAttempts = TERMINAL_ATTEMPTS - newAttempts
                throw SecurityException("Incorrect PIN. $remainingAttempts attempt(s) remaining before vault wipe.")
            }
        } finally {
            pinSecret.fill(0)
        }
    }

    /**
     * Records a biometric authentication failure.
     *
     * IMPORTANT: Biometric failures NEVER increment the PIN wipe counter (failedAttempts).
     * They only increment a separate biometricFailedAttempts counter used purely to
     * trigger UI fallback to PIN entry after repeated sensor failures.
     *
     * The vault wipe threshold (TERMINAL_ATTEMPTS) is only reachable through wrong PINs.
     * A dirty fingerprint sensor cannot wipe the vault.
     */
    suspend fun recordBiometricFailure() {
        val entry = metadataStore.load() ?: return
        val newBioAttempts = entry.biometricFailedAttempts + 1
        metadataStore.recordBiometricFailure(newBioAttempts)
        // After BIOMETRIC_FALLBACK_THRESHOLD consecutive biometric failures,
        // signal the UI to fall back to PIN entry.
        if (newBioAttempts >= BIOMETRIC_FALLBACK_THRESHOLD) {
            metadataStore.resetBiometricFailures()
            onBiometricTemporarilyUnavailable?.invoke()
        }
        // NOTE: No wipe logic here. No keyStore deletion. No onTerminalLockout invocation.
        // failedAttempts is intentionally NOT touched.
    }

    fun wipeHardwareKey() {
        keyStore?.let { ks ->
            if (ks.containsAlias(KEY_ALIAS)) {
                ks.deleteEntry(KEY_ALIAS)
            }
        }
        testOuterKey = null
        metadataStore.clear()
    }

    private fun computeLockoutDelayMs(failedAttempts: Int): Long = when (failedAttempts) {
        in 1..4 -> 0L
        5 -> 30_000L
        6 -> 60_000L
        7 -> 300_000L      // 5 minutes
        8 -> 900_000L      // 15 minutes
        9 -> 3600_000L     // 1 hour
        else -> 0L
    }

    companion object {
        const val KEY_ALIAS = "securevault.pin.wrap.v1"
        const val TERMINAL_ATTEMPTS = 10
        /**
         * Number of consecutive biometric failures before the UI falls back to PIN entry.
         * This does NOT wipe the vault — it only triggers the PIN fallback screen.
         */
        const val BIOMETRIC_FALLBACK_THRESHOLD = 5
    }
}

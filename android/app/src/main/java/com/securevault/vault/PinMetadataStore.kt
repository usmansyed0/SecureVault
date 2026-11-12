package com.securevault.vault

import android.content.Context
import android.util.Base64
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import dagger.hilt.android.qualifiers.ApplicationContext
import javax.inject.Inject
import javax.inject.Singleton

data class WrappedPinKey(
    val salt: ByteArray,
    val innerNonce: ByteArray,
    val outerNonce: ByteArray,
    val outerCiphertext: ByteArray,
    val failedAttempts: Int = 0,
    val lockoutUntilEpochMs: Long = 0L,
    val isWiped: Boolean = false,
    val pinLength: Int = 4,
    /** Biometric-only failure count. Never contributes to the vault-wipe threshold. */
    val biometricFailedAttempts: Int = 0,
)

interface PinStore {
    fun hasPin(): Boolean
    fun isWiped(): Boolean
    fun save(value: WrappedPinKey)
    fun load(): WrappedPinKey?
    fun recordFailure(failedAttempts: Int, lockoutUntilEpochMs: Long)
    fun resetFailures()
    fun markWiped()
    fun clear()
    /** Increment the biometric-only failure counter. Does NOT affect PIN wipe counter. */
    fun recordBiometricFailure(biometricFailedAttempts: Int)
    /** Reset the biometric failure counter (called on successful PIN or biometric unlock). */
    fun resetBiometricFailures()
    fun biometricFailedAttempts(): Int
}

@Singleton
open class PinMetadataStore @Inject constructor(@ApplicationContext context: Context) : PinStore {
    private val prefs by lazy {
        EncryptedSharedPreferences.create(
            context,
            "pin-metadata.enc",
            MasterKey.Builder(context).setKeyScheme(MasterKey.KeyScheme.AES256_GCM).build(),
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
        )
    }

    override fun hasPin(): Boolean =
        prefs.contains(KEY_SALT) && prefs.contains(KEY_OUTER_CIPHERTEXT) && !isWiped()

    override fun isWiped(): Boolean = prefs.getBoolean(KEY_IS_WIPED, false)

    override fun save(value: WrappedPinKey) {
        prefs.edit()
            .putString(KEY_SALT, encode(value.salt))
            .putString(KEY_INNER_NONCE, encode(value.innerNonce))
            .putString(KEY_OUTER_NONCE, encode(value.outerNonce))
            .putString(KEY_OUTER_CIPHERTEXT, encode(value.outerCiphertext))
            .putInt(KEY_FAILED_ATTEMPTS, value.failedAttempts)
            .putLong(KEY_LOCKOUT_UNTIL, value.lockoutUntilEpochMs)
            .putBoolean(KEY_IS_WIPED, value.isWiped)
            .putInt(KEY_PIN_LENGTH, value.pinLength)
            .apply()
    }

    override fun load(): WrappedPinKey? {
        val salt = prefs.getString(KEY_SALT, null)?.let(::decode) ?: return null
        val innerNonce = prefs.getString(KEY_INNER_NONCE, null)?.let(::decode) ?: return null
        val outerNonce = prefs.getString(KEY_OUTER_NONCE, null)?.let(::decode) ?: return null
        val outerCiphertext = prefs.getString(KEY_OUTER_CIPHERTEXT, null)?.let(::decode) ?: return null
        val failed = prefs.getInt(KEY_FAILED_ATTEMPTS, 0)
        val lockout = prefs.getLong(KEY_LOCKOUT_UNTIL, 0L)
        val isWiped = prefs.getBoolean(KEY_IS_WIPED, false)
        val pinLength = prefs.getInt(KEY_PIN_LENGTH, 4)
        val bioFailed = prefs.getInt(KEY_BIOMETRIC_FAILED_ATTEMPTS, 0)
        return WrappedPinKey(salt, innerNonce, outerNonce, outerCiphertext, failed, lockout, isWiped, pinLength, bioFailed)
    }

    override fun recordFailure(failedAttempts: Int, lockoutUntilEpochMs: Long) {
        prefs.edit()
            .putInt(KEY_FAILED_ATTEMPTS, failedAttempts)
            .putLong(KEY_LOCKOUT_UNTIL, lockoutUntilEpochMs)
            .apply()
    }

    override fun resetFailures() {
        prefs.edit()
            .putInt(KEY_FAILED_ATTEMPTS, 0)
            .putLong(KEY_LOCKOUT_UNTIL, 0L)
            .putInt(KEY_BIOMETRIC_FAILED_ATTEMPTS, 0)
            .apply()
    }

    override fun recordBiometricFailure(biometricFailedAttempts: Int) {
        prefs.edit()
            .putInt(KEY_BIOMETRIC_FAILED_ATTEMPTS, biometricFailedAttempts)
            .apply()
    }

    override fun resetBiometricFailures() {
        prefs.edit()
            .putInt(KEY_BIOMETRIC_FAILED_ATTEMPTS, 0)
            .apply()
    }

    override fun biometricFailedAttempts(): Int =
        prefs.getInt(KEY_BIOMETRIC_FAILED_ATTEMPTS, 0)

    override fun markWiped() {
        prefs.edit()
            .clear()
            .putBoolean(KEY_IS_WIPED, true)
            .apply()
    }

    override fun clear() = prefs.edit().clear().apply()

    private fun encode(value: ByteArray) = Base64.encodeToString(value, Base64.NO_WRAP)
    private fun decode(value: String): ByteArray = Base64.decode(value, Base64.NO_WRAP)

    private companion object {
        const val KEY_SALT = "pin_salt"
        const val KEY_INNER_NONCE = "pin_inner_nonce"
        const val KEY_OUTER_NONCE = "pin_outer_nonce"
        const val KEY_OUTER_CIPHERTEXT = "pin_outer_ciphertext"
        const val KEY_FAILED_ATTEMPTS = "pin_failed_attempts"
        const val KEY_LOCKOUT_UNTIL = "pin_lockout_until"
        const val KEY_IS_WIPED = "pin_is_wiped"
        const val KEY_PIN_LENGTH = "pin_length"
        /** Separate from KEY_FAILED_ATTEMPTS; biometric failures NEVER trigger the wipe. */
        const val KEY_BIOMETRIC_FAILED_ATTEMPTS = "pin_biometric_failed_attempts"
    }
}

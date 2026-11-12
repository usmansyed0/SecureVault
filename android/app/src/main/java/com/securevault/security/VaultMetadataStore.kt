package com.securevault.security

import android.content.Context
import android.util.Base64
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import dagger.hilt.android.qualifiers.ApplicationContext
import javax.inject.Inject
import javax.inject.Singleton

data class WrappedVaultKey(val vaultId: String, val nonce: ByteArray, val ciphertext: ByteArray)
data class WrappedPasswordVrkRecord(val salt: ByteArray, val nonce: ByteArray, val ciphertext: ByteArray)

/** Persists an already Keystore-wrapped VRK and encrypted fallback envelopes; never receives raw VRK bytes. */
@Singleton
class VaultMetadataStore @Inject constructor(@ApplicationContext context: Context) {
    private val prefs = EncryptedSharedPreferences.create(
        context,
        "vault-metadata.enc",
        MasterKey.Builder(context).setKeyScheme(MasterKey.KeyScheme.AES256_GCM).build(),
        EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
        EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
    )

    fun hasVault(): Boolean = prefs.contains(KEY_VAULT_ID) && prefs.contains(KEY_CIPHERTEXT) && prefs.contains(KEY_NONCE)
    fun save(value: WrappedVaultKey) {
        prefs.edit()
            .putString(KEY_VAULT_ID, value.vaultId)
            .putString(KEY_NONCE, encode(value.nonce))
            .putString(KEY_CIPHERTEXT, encode(value.ciphertext))
            .apply()
    }
    fun load(): WrappedVaultKey? {
        val id = prefs.getString(KEY_VAULT_ID, null) ?: return null
        val nonce = prefs.getString(KEY_NONCE, null)?.let(::decode) ?: return null
        val ciphertext = prefs.getString(KEY_CIPHERTEXT, null)?.let(::decode) ?: return null
        return WrappedVaultKey(id, nonce, ciphertext)
    }

    fun saveVaultPasswordWrappedVrk(salt: ByteArray, nonce: ByteArray, ciphertext: ByteArray) {
        prefs.edit()
            .putString(KEY_VP_SALT, encode(salt))
            .putString(KEY_VP_NONCE, encode(nonce))
            .putString(KEY_VP_CIPHERTEXT, encode(ciphertext))
            .apply()
    }

    fun loadVaultPasswordWrappedVrk(): WrappedPasswordVrkRecord? {
        val salt = prefs.getString(KEY_VP_SALT, null)?.let(::decode) ?: return null
        val nonce = prefs.getString(KEY_VP_NONCE, null)?.let(::decode) ?: return null
        val ciphertext = prefs.getString(KEY_VP_CIPHERTEXT, null)?.let(::decode) ?: return null
        return WrappedPasswordVrkRecord(salt, nonce, ciphertext)
    }

    fun hasVaultPasswordWrappedVrk(): Boolean =
        prefs.contains(KEY_VP_SALT) && prefs.contains(KEY_VP_NONCE) && prefs.contains(KEY_VP_CIPHERTEXT)

    fun saveRecoveryWrappedVrk(blob: ByteArray) {
        prefs.edit().putString(KEY_RECOVERY_BLOB, encode(blob)).apply()
    }

    fun loadRecoveryWrappedVrk(): ByteArray? =
        prefs.getString(KEY_RECOVERY_BLOB, null)?.let(::decode)

    fun hasRecoveryWrappedVrk(): Boolean = prefs.contains(KEY_RECOVERY_BLOB)

    fun clear() = prefs.edit().clear().apply()
    private fun encode(value: ByteArray) = Base64.encodeToString(value, Base64.NO_WRAP)
    private fun decode(value: String): ByteArray = Base64.decode(value, Base64.NO_WRAP)
    private companion object {
        const val KEY_VAULT_ID = "vault_id"
        const val KEY_NONCE = "wrapped_vrk_nonce"
        const val KEY_CIPHERTEXT = "wrapped_vrk_ciphertext"
        const val KEY_VP_SALT = "vp_salt"
        const val KEY_VP_NONCE = "vp_nonce"
        const val KEY_VP_CIPHERTEXT = "vp_ciphertext"
        const val KEY_RECOVERY_BLOB = "recovery_wrapped_blob"
    }
}

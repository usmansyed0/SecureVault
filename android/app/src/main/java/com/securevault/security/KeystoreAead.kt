package com.securevault.security

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.os.Build
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/** Only cryptographic primitives supplied by Android's provider are used. Keys are non-exportable. */
class KeystoreAead(private val alias: String) {
    private val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
    fun createIfMissing(requireUserAuth: Boolean = true) { if (keyStore.containsAlias(alias)) return
        val spec = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM).setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256).setRandomizedEncryptionRequired(true)
            .setUserAuthenticationRequired(requireUserAuth).apply {
                // CryptoObject + DEVICE_CREDENTIAL is not consistently supported by BiometricPrompt.
                // Keep the Keystore and prompt policies identical; never replace this with UI-only auth.
                if (requireUserAuth && Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)
                else if (requireUserAuth) setUserAuthenticationValidityDurationSeconds(-1)
            }.build()
        KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore").apply { init(spec); generateKey() }
    }
    private fun key(): SecretKey {
        val entry = keyStore.getEntry(alias, null) as? KeyStore.SecretKeyEntry
            ?: throw IllegalStateException("KeyStore entry $alias is not a SecretKeyEntry")
        return entry.secretKey
    }
    fun exists(): Boolean = keyStore.containsAlias(alias)
    /** The returned cipher must be passed to BiometricPrompt and completed only on success. */
    fun cipherForAuthenticatedEncryption(): Cipher = Cipher.getInstance("AES/GCM/NoPadding").also { it.init(Cipher.ENCRYPT_MODE, key()) }
    fun cipherForAuthenticatedDecryption(nonce: ByteArray): Cipher {
        require(nonce.size == 12) { "Unexpected GCM nonce length" }
        return Cipher.getInstance("AES/GCM/NoPadding").also { it.init(Cipher.DECRYPT_MODE, key(), GCMParameterSpec(128, nonce)) }
    }
    fun encrypt(plaintext: ByteArray, aad: ByteArray): EncryptedBlob { val cipher = Cipher.getInstance("AES/GCM/NoPadding"); cipher.init(Cipher.ENCRYPT_MODE, key()); cipher.updateAAD(aad); return EncryptedBlob(cipher.iv, cipher.doFinal(plaintext)) }
    fun decrypt(blob: EncryptedBlob, aad: ByteArray): ByteArray { require(blob.nonce.size == 12) { "Unexpected GCM nonce length" }; val cipher = Cipher.getInstance("AES/GCM/NoPadding"); cipher.init(Cipher.DECRYPT_MODE, key(), GCMParameterSpec(128, blob.nonce)); cipher.updateAAD(aad); return cipher.doFinal(blob.ciphertext) }
    fun delete() { keyStore.deleteEntry(alias) }
}
data class EncryptedBlob(val nonce: ByteArray, val ciphertext: ByteArray)

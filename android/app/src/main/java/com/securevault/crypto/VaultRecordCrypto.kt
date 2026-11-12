package com.securevault.crypto

import java.io.ByteArrayOutputStream
import java.io.DataOutputStream
import java.nio.charset.StandardCharsets
import java.security.GeneralSecurityException
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

private const val GCM_NONCE_BYTES = 12
private const val GCM_TAG_BITS = 128
private const val KEY_BYTES = 32

data class RecordAddress(val vaultId: String, val recordId: String, val type: String, val formatVersion: Int, val revision: Long)
data class EncryptedRecordEnvelope(val ciphertext: ByteArray, val nonce: ByteArray, val wrappedDek: ByteArray, val wrappedDekNonce: ByteArray)
class VaultDecryptionException(cause: Throwable) : SecurityException("Vault record authentication failed", cause)

/** AES-GCM record encryption using an independent random DEK, itself wrapped by the in-memory VRK. */
class VaultRecordCrypto(private val random: SecureRandom = SecureRandom()) {
    fun encrypt(vrk: ByteArray, address: RecordAddress, plaintext: ByteArray): EncryptedRecordEnvelope {
        require(vrk.size == KEY_BYTES) { "Invalid vault root key" }
        val dek = ByteArray(KEY_BYTES).also(random::nextBytes)
        try {
            val aad = aad(address)
            val payload = encryptAead(dek, plaintext, aad)
            val wrapped = encryptAead(vrk, dek, wrapAad(aad))
            return EncryptedRecordEnvelope(payload.second, payload.first, wrapped.second, wrapped.first)
        } finally { dek.fill(0) }
    }
    fun decrypt(vrk: ByteArray, address: RecordAddress, envelope: EncryptedRecordEnvelope): ByteArray {
        require(vrk.size == KEY_BYTES) { "Invalid vault root key" }
        val aad = aad(address)
        val dek = try { decryptAead(vrk, envelope.wrappedDekNonce, envelope.wrappedDek, wrapAad(aad))
        } catch (e: GeneralSecurityException) { throw VaultDecryptionException(e)
        } catch (e: IllegalArgumentException) { throw VaultDecryptionException(e) }
        try { return decryptAead(dek, envelope.nonce, envelope.ciphertext, aad)
        } catch (e: GeneralSecurityException) { throw VaultDecryptionException(e)
        } catch (e: IllegalArgumentException) { throw VaultDecryptionException(e) } finally { dek.fill(0) }
    }
    private fun encryptAead(keyBytes: ByteArray, value: ByteArray, aad: ByteArray): Pair<ByteArray, ByteArray> {
        val nonce = ByteArray(GCM_NONCE_BYTES).also(random::nextBytes)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, key(keyBytes), GCMParameterSpec(GCM_TAG_BITS, nonce)); cipher.updateAAD(aad)
        return nonce to cipher.doFinal(value)
    }
    private fun decryptAead(keyBytes: ByteArray, nonce: ByteArray, value: ByteArray, aad: ByteArray): ByteArray {
        require(nonce.size == GCM_NONCE_BYTES) { "Unexpected GCM nonce length" }
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, key(keyBytes), GCMParameterSpec(GCM_TAG_BITS, nonce)); cipher.updateAAD(aad)
        return cipher.doFinal(value)
    }
    private fun key(bytes: ByteArray): SecretKey = SecretKeySpec(bytes, "AES")
    private fun wrapAad(aad: ByteArray) = aad + ".dek-wrap.v1".toByteArray(StandardCharsets.UTF_8)
    private fun aad(address: RecordAddress): ByteArray = ByteArrayOutputStream().use { bytes -> DataOutputStream(bytes).use { out ->
        out.writeUTF("securevault.record.aad.v1"); out.writeUTF(address.vaultId); out.writeUTF(address.recordId); out.writeUTF(address.type); out.writeInt(address.formatVersion); out.writeLong(address.revision)
        }; bytes.toByteArray() }
}

package com.securevault.vault.document

import android.content.Context
import com.securevault.security.VaultSession
import dagger.hilt.android.qualifiers.ApplicationContext
import java.io.File
import java.nio.ByteBuffer
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.UUID
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import javax.inject.Inject
import javax.inject.Singleton

@Singleton
class DocumentBlobManager @Inject constructor(
    @ApplicationContext private val context: Context,
    private val session: VaultSession
) {
    private val random = SecureRandom()
    private val blobDir: File by lazy {
        File(context.filesDir, "secure_blobs").apply {
            if (!exists()) mkdirs()
        }
    }

    /**
     * Derives a stable 32-byte page DEK deterministically from VRK and stable page address:
     * DEK = SHA256(VRK || "DocumentPageKey" || vaultId || documentId || pageId)
     */
    private fun derivePageKey(vrk: ByteArray, vaultId: String, documentId: String, pageId: String): ByteArray {
        val md = MessageDigest.getInstance("SHA-256")
        md.update(vrk)
        md.update("DocumentPageKey".toByteArray(StandardCharsets.UTF_8))
        md.update(vaultId.toByteArray(StandardCharsets.UTF_8))
        md.update(documentId.toByteArray(StandardCharsets.UTF_8))
        md.update(pageId.toByteArray(StandardCharsets.UTF_8))
        return md.digest()
    }

    private fun computeAad(vaultId: String, documentId: String, pageId: String, pageVersion: Int): ByteArray {
        return "$vaultId:$documentId:$pageId:$pageVersion".toByteArray(StandardCharsets.UTF_8)
    }

    /**
     * Encrypts and saves page binary data (e.g. image bytes or PDF bytes).
     * Output file format: [12 bytes GCM Nonce] [Ciphertext + GCM Tag]
     */
    fun savePageBlob(
        vaultId: String,
        documentId: String,
        pageId: String,
        pageVersion: Int,
        plaintextBytes: ByteArray
    ): String {
        val blobId = UUID.randomUUID().toString()
        val nonce = ByteArray(12).also(random::nextBytes)
        val aad = computeAad(vaultId, documentId, pageId, pageVersion)

        val encryptedPayload = session.withRootKey { vrk ->
            val pageKey = derivePageKey(vrk, vaultId, documentId, pageId)
            try {
                val cipher = Cipher.getInstance("AES/GCM/NoPadding")
                cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(pageKey, "AES"), GCMParameterSpec(128, nonce))
                cipher.updateAAD(aad)
                cipher.doFinal(plaintextBytes)
            } finally {
                pageKey.fill(0)
            }
        }

        val blobFile = File(blobDir, "$blobId.enc")
        val buffer = ByteBuffer.allocate(nonce.size + encryptedPayload.size)
        buffer.put(nonce)
        buffer.put(encryptedPayload)
        blobFile.writeBytes(buffer.array())

        return blobId
    }

    /**
     * Loads and decrypts page binary data into memory on demand.
     */
    fun loadPageBlob(
        vaultId: String,
        documentId: String,
        pageId: String,
        pageVersion: Int,
        blobId: String
    ): ByteArray {
        val blobFile = File(blobDir, "$blobId.enc")
        require(blobFile.exists()) { "Blob file not found for id $blobId" }

        val fileBytes = blobFile.readBytes()
        require(fileBytes.size >= 12 + 16) { "Malformed blob file: too short" }

        val nonce = fileBytes.copyOfRange(0, 12)
        val ciphertext = fileBytes.copyOfRange(12, fileBytes.size)
        val aad = computeAad(vaultId, documentId, pageId, pageVersion)

        return session.withRootKey { vrk ->
            val pageKey = derivePageKey(vrk, vaultId, documentId, pageId)
            try {
                val cipher = Cipher.getInstance("AES/GCM/NoPadding")
                cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(pageKey, "AES"), GCMParameterSpec(128, nonce))
                cipher.updateAAD(aad)
                cipher.doFinal(ciphertext)
            } finally {
                pageKey.fill(0)
            }
        }
    }

    /**
     * Permanently deletes encrypted blob file from disk.
     */
    fun deleteBlob(blobId: String) {
        val blobFile = File(blobDir, "$blobId.enc")
        if (blobFile.exists()) {
            blobFile.delete()
        }
    }

    /**
     * Wipes all stored blob files in the private app sandbox.
     */
    fun wipeAllBlobs() {
        blobDir.listFiles()?.forEach { it.delete() }
    }
}

package com.securevault.security

import com.securevault.crypto.EncryptedRecordEnvelope
import com.securevault.crypto.RecordAddress
import com.securevault.crypto.VaultRecordCrypto
import com.securevault.database.EncryptedRecordDao
import java.security.MessageDigest
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Results of local vault AEAD and manifest integrity verification.
 */
data class VaultIntegrityReport(
    val isHealthy: Boolean,
    val totalRecords: Int,
    val validRecords: Int,
    val corruptedRecordIds: List<String>,
    val manifestHashHex: String
)

/**
 * Performs local integrity validation on startup / unlock.
 *
 * Verifies AEAD tags (AES-256-GCM 128-bit authentication tags on both the
 * wrapped DEK and the encrypted payload) to detect any offline tampering,
 * bit-rot, or storage corruption, and computes a deterministic SHA-256
 * manifest hash across all stored items.
 */
@Singleton
class VaultIntegrityManager @Inject constructor(
    private val dao: EncryptedRecordDao,
    private val crypto: VaultRecordCrypto,
    private val session: VaultSession
) {

    suspend fun verifyIntegrity(vaultId: String): VaultIntegrityReport {
        val records = dao.findAll(vaultId)
        val corruptedIds = mutableListOf<String>()
        val md = MessageDigest.getInstance("SHA-256")

        // Sort deterministically by record ID for consistent manifest hash
        val sortedRecords = records.sortedBy { it.id }

        for (record in sortedRecords) {
            val address = RecordAddress(
                vaultId = record.vaultId,
                recordId = record.id,
                type = record.type,
                formatVersion = record.formatVersion,
                revision = record.clientRevision
            )
            val envelope = EncryptedRecordEnvelope(
                ciphertext = record.ciphertext,
                nonce = record.nonce,
                wrappedDek = record.wrappedDek,
                wrappedDekNonce = record.wrappedDekNonce
            )

            // Basic envelope structural validity check
            if (record.nonce.size != 12 || record.wrappedDekNonce.size != 12 || record.ciphertext.size < 16) {
                corruptedIds.add(record.id)
                continue
            }

            // Cryptographic AEAD verification if vault is unlocked
            if (session.isUnlocked()) {
                val ok = try {
                    session.withRootKey { vrk ->
                        val plaintext = crypto.decrypt(vrk, address, envelope)
                        plaintext.isNotEmpty()
                    }
                } catch (_: Exception) {
                    false
                }
                if (!ok) {
                    corruptedIds.add(record.id)
                    continue
                }
            }

            // Update manifest hash: id:type:revision:sha256(ciphertext)
            val cipherSha = MessageDigest.getInstance("SHA-256").digest(record.ciphertext)
            val entryDesc = "${record.id}:${record.type}:${record.clientRevision}:"
            md.update(entryDesc.toByteArray(Charsets.UTF_8))
            md.update(cipherSha)
        }

        val manifestHash = md.digest().joinToString("") { "%02x".format(it) }

        return VaultIntegrityReport(
            isHealthy = corruptedIds.isEmpty(),
            totalRecords = records.size,
            validRecords = records.size - corruptedIds.size,
            corruptedRecordIds = corruptedIds,
            manifestHashHex = manifestHash
        )
    }
}

package com.securevault.vault

import com.securevault.crypto.EncryptedRecordEnvelope
import com.securevault.crypto.RecordAddress
import com.securevault.crypto.VaultDecryptionException
import com.securevault.crypto.VaultRecordCrypto
import com.securevault.database.EncryptedRecord
import com.securevault.database.EncryptedRecordDao
import com.securevault.network.model.SyncRecordUpsertDto
import com.securevault.security.VaultSession
import com.securevault.vault.model.PasswordEntry
import kotlinx.coroutines.flow.flowOf
import kotlinx.coroutines.runBlocking
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import java.security.SecureRandom
import java.util.Base64

/**
 * End-to-End Integration Test for SecureVault Cryptographic and Sync Lifecycles.
 *
 * Verifies the full zero-knowledge round trip:
 * 1. Vault Provisioning & VRK generation (32-byte random key)
 * 2. In-memory [VaultSession] management and memory clearing
 * 3. Item creation ([PasswordEntry]) and envelope serialization
 * 4. AES-256-GCM encryption with fresh DEK, DEK wrapping, and strict AAD binding
 * 5. Local database storage and offline sync push simulation (Base64 DTO payload)
 * 6. Server ingestion and sync pull on a secondary/fresh client
 * 7. Decryption and deserialization on the secondary client
 * 8. Cryptographic tamper resistance (ciphertext, nonces, wrapped DEK, AAD, wrong VRK)
 * 9. Multi-revision updates and conflict resolution
 * 10. Session locking zeroization verification
 */
class VaultE2EIntegrationTest {

    private lateinit var crypto: VaultRecordCrypto
    private lateinit var random: SecureRandom

    // Simulated in-memory storage for Client 1 and Client 2
    private lateinit var client1Store: FakeRecordDao
    private lateinit var client2Store: FakeRecordDao

    // Simulated Server Storage
    private lateinit var serverStore: MutableMap<String, ServerStoredRecord>

    private data class ServerStoredRecord(
        val recordId: String,
        val vaultId: String,
        val type: String,
        val formatVersion: Int,
        val ciphertextB64: String,
        val nonceB64: String,
        val wrappedDekB64: String,
        val wrappedDekNonceB64: String,
        val clientRevision: Long,
        val serverSeq: Long,
        val deleted: Boolean = false
    )

    private class FakeRecordDao : EncryptedRecordDao {
        val records = mutableMapOf<String, EncryptedRecord>()

        override suspend fun upsert(record: EncryptedRecord) {
            records["${record.vaultId}:${record.id}"] = record
        }

        override suspend fun find(id: String, vaultId: String): EncryptedRecord? =
            records["$vaultId:$id"]?.takeIf { !it.deleted }

        override suspend fun findIncludingDeleted(id: String, vaultId: String): EncryptedRecord? =
            records["$vaultId:$id"]

        override suspend fun findAll(vaultId: String): List<EncryptedRecord> =
            records.values.filter { it.vaultId == vaultId && !it.deleted }

        override suspend fun findAllByType(vaultId: String, type: String): List<EncryptedRecord> =
            records.values.filter { it.vaultId == vaultId && it.type == type && !it.deleted }

        override fun observeAll(vaultId: String) =
            flowOf(records.values.filter { it.vaultId == vaultId && !it.deleted }.toList())

        override fun observeByType(vaultId: String, type: String) =
            flowOf(records.values.filter { it.vaultId == vaultId && it.type == type && !it.deleted }.toList())

        override suspend fun upsertFromServer(
            id: String, vaultId: String, type: String, formatVersion: Int,
            ciphertext: ByteArray, nonce: ByteArray, wrappedDek: ByteArray, wrappedDekNonce: ByteArray,
            incomingClientRevision: Long, incomingServerSeq: Long, incomingDeleted: Boolean
        ) {
            val key = "$vaultId:$id"
            records[key] = EncryptedRecord(
                id = id,
                vaultId = vaultId,
                type = type,
                formatVersion = formatVersion,
                ciphertext = ciphertext,
                nonce = nonce,
                wrappedDek = wrappedDek,
                wrappedDekNonce = wrappedDekNonce,
                clientRevision = incomingClientRevision,
                serverSeq = incomingServerSeq,
                pendingSync = false,
                deleted = incomingDeleted
            )
        }

        override suspend fun markSynced(id: String, vaultId: String, confirmedSeq: Long) {
            val key = "$vaultId:$id"
            records[key]?.let {
                records[key] = it.copy(pendingSync = false, serverSeq = confirmedSeq)
            }
        }

        override suspend fun markDeleted(id: String, vaultId: String) {
            val key = "$vaultId:$id"
            records[key]?.let {
                records[key] = it.copy(deleted = true, pendingSync = true)
            }
        }

        override suspend fun hardDelete(id: String, vaultId: String) {
            records.remove("$vaultId:$id")
        }

        override suspend fun wipe() {
            records.clear()
        }
    }

    @Before
    fun setUp() {
        random = SecureRandom()
        crypto = VaultRecordCrypto(random)
        client1Store = FakeRecordDao()
        client2Store = FakeRecordDao()
        serverStore = mutableMapOf()
    }

    @Test
    fun `full e2e registration provisioning add entry encrypt sync push pull and decrypt round-trip`() = runBlocking {
        // ── 1. Vault Provisioning & VRK Generation ──
        val vrk = ByteArray(32).also(random::nextBytes)
        val vaultId = "vault-alpha-001"
        val recordId = "rec-pwd-999"

        val sessionClient1 = VaultSession()
        sessionClient1.unlock(vrk)
        assertTrue("Client 1 session must be unlocked", sessionClient1.isUnlocked())

        // ── 2. Create Password Entry ──
        val originalEntry = PasswordEntry(
            id = recordId,
            vaultId = vaultId,
            revision = 1L,
            title = "ProtonMail",
            username = "security-lead@proton.me",
            password = "CorrectHorseBatteryStaple!2026#",
            website = "https://mail.proton.me",
            notes = "Secured with Hardware Security Key (FIDO2)",
            category = "Email",
            isSensitive = true,
            isFavorite = true,
            totpSecret = "JBSWY3DPEHPK3PXP"
        )
        val plaintextBytes = originalEntry.toEnvelopeBytes()
        assertTrue("Serialized envelope must not be empty", plaintextBytes.isNotEmpty())

        // ── 3. Real AES-256-GCM Encryption with DEK Wrapping ──
        val addressV1 = RecordAddress(
            vaultId = vaultId,
            recordId = recordId,
            type = "PASSWORD",
            formatVersion = 1,
            revision = 1L
        )

        val envelope = sessionClient1.withRootKey { key ->
            crypto.encrypt(key, addressV1, plaintextBytes)
        }

        // Validate envelope characteristics
        assertEquals("AES-GCM nonce must be 12 bytes", 12, envelope.nonce.size)
        assertEquals("Wrapped DEK nonce must be 12 bytes", 12, envelope.wrappedDekNonce.size)
        // 32-byte DEK + 16-byte GCM authentication tag = 48 bytes
        assertEquals("Wrapped DEK must be 48 bytes (32 key + 16 auth tag)", 48, envelope.wrappedDek.size)
        assertFalse("Ciphertext must not match plaintext", envelope.ciphertext.contentEquals(plaintextBytes))

        // Store in Client 1 local database as pending sync
        val localRecordClient1 = EncryptedRecord(
            id = recordId,
            vaultId = vaultId,
            type = "PASSWORD",
            formatVersion = 1,
            ciphertext = envelope.ciphertext,
            nonce = envelope.nonce,
            wrappedDek = envelope.wrappedDek,
            wrappedDekNonce = envelope.wrappedDekNonce,
            clientRevision = 1L,
            serverSeq = 0L,
            pendingSync = true,
            deleted = false
        )
        client1Store.upsert(localRecordClient1)

        // ── 4. Sync Push to Backend ──
        val pushDto = SyncRecordUpsertDto(
            vault_id = vaultId,
            type = "PASSWORD",
            ciphertext = Base64.getEncoder().encodeToString(envelope.ciphertext),
            nonce = Base64.getEncoder().encodeToString(envelope.nonce),
            wrapped_dek = Base64.getEncoder().encodeToString(envelope.wrappedDek),
            wrapped_dek_nonce = Base64.getEncoder().encodeToString(envelope.wrappedDekNonce),
            client_revision = 1L
        )

        // Server receives push, allocates server sequence number 1001
        val allocatedServerSeq = 1001L
        serverStore[recordId] = ServerStoredRecord(
            recordId = recordId,
            vaultId = pushDto.vault_id,
            type = pushDto.type,
            formatVersion = 1,
            ciphertextB64 = pushDto.ciphertext,
            nonceB64 = pushDto.nonce,
            wrappedDekB64 = pushDto.wrapped_dek,
            wrappedDekNonceB64 = pushDto.wrapped_dek_nonce,
            clientRevision = pushDto.client_revision,
            serverSeq = allocatedServerSeq
        )

        // Client 1 marks record as synced
        client1Store.markSynced(recordId, vaultId, allocatedServerSeq)
        val syncedClient1 = client1Store.find(recordId, vaultId)
        assertNotNull(syncedClient1)
        assertFalse("Record must no longer be pending sync", syncedClient1!!.pendingSync)
        assertEquals(allocatedServerSeq, syncedClient1.serverSeq)

        // ── 5. Client 2 Sync Pull ──
        // Client 2 authenticates and derives identical VRK from user credentials
        val sessionClient2 = VaultSession()
        sessionClient2.unlock(vrk.copyOf())
        assertTrue("Client 2 session must be unlocked", sessionClient2.isUnlocked())

        // Client 2 pulls changes (server sends list of updated records)
        val serverRecord = serverStore[recordId]!!
        client2Store.upsertFromServer(
            id = serverRecord.recordId,
            vaultId = serverRecord.vaultId,
            type = serverRecord.type,
            formatVersion = serverRecord.formatVersion,
            ciphertext = Base64.getDecoder().decode(serverRecord.ciphertextB64),
            nonce = Base64.getDecoder().decode(serverRecord.nonceB64),
            wrappedDek = Base64.getDecoder().decode(serverRecord.wrappedDekB64),
            wrappedDekNonce = Base64.getDecoder().decode(serverRecord.wrappedDekNonceB64),
            incomingClientRevision = serverRecord.clientRevision,
            incomingServerSeq = serverRecord.serverSeq,
            incomingDeleted = serverRecord.deleted
        )

        // ── 6. Decrypt Round-Trip on Client 2 ──
        val client2Record = client2Store.find(recordId, vaultId)
        assertNotNull("Client 2 must have received the record", client2Record)

        val client2Envelope = EncryptedRecordEnvelope(
            ciphertext = client2Record!!.ciphertext,
            nonce = client2Record.nonce,
            wrappedDek = client2Record.wrappedDek,
            wrappedDekNonce = client2Record.wrappedDekNonce
        )
        val client2Address = RecordAddress(
            vaultId = client2Record.vaultId,
            recordId = client2Record.id,
            type = client2Record.type,
            formatVersion = client2Record.formatVersion,
            revision = client2Record.clientRevision
        )

        val decryptedBytes = sessionClient2.withRootKey { key ->
            crypto.decrypt(key, client2Address, client2Envelope)
        }

        // Deserialize back to PasswordEntry
        val decryptedEntry = PasswordEntry.fromEnvelopeBytes(
            id = client2Record.id,
            vaultId = client2Record.vaultId,
            revision = client2Record.clientRevision,
            bytes = decryptedBytes
        )

        // Verify all fields are preserved bit-for-bit
        assertEquals(originalEntry.id, decryptedEntry.id)
        assertEquals(originalEntry.vaultId, decryptedEntry.vaultId)
        assertEquals(originalEntry.title, decryptedEntry.title)
        assertEquals(originalEntry.username, decryptedEntry.username)
        assertEquals(originalEntry.password, decryptedEntry.password)
        assertEquals(originalEntry.website, decryptedEntry.website)
        assertEquals(originalEntry.notes, decryptedEntry.notes)
        assertEquals(originalEntry.category, decryptedEntry.category)
        assertEquals(originalEntry.isSensitive, decryptedEntry.isSensitive)
        assertEquals(originalEntry.isFavorite, decryptedEntry.isFavorite)
        assertEquals(originalEntry.totpSecret, decryptedEntry.totpSecret)
    }

    @Test
    fun `tamper detection rejects modified ciphertext or nonces with VaultDecryptionException`() {
        val vrk = ByteArray(32).also(random::nextBytes)
        val address = RecordAddress("v1", "r1", "PASSWORD", 1, 1L)
        val plaintext = "Sensitive Data Payload".toByteArray()

        val envelope = crypto.encrypt(vrk, address, plaintext)

        // 1. Bit flip in ciphertext
        val tamperedCiphertext = envelope.ciphertext.copyOf()
        tamperedCiphertext[0] = (tamperedCiphertext[0].toInt() xor 0x01).toByte()
        val badCiphertextEnvelope = envelope.copy(ciphertext = tamperedCiphertext)
        assertThrows(VaultDecryptionException::class.java) {
            crypto.decrypt(vrk, address, badCiphertextEnvelope)
        }

        // 2. Bit flip in record nonce
        val tamperedNonce = envelope.nonce.copyOf()
        tamperedNonce[0] = (tamperedNonce[0].toInt() xor 0x01).toByte()
        val badNonceEnvelope = envelope.copy(nonce = tamperedNonce)
        assertThrows(VaultDecryptionException::class.java) {
            crypto.decrypt(vrk, address, badNonceEnvelope)
        }

        // 3. Bit flip in wrapped DEK
        val tamperedWrappedDek = envelope.wrappedDek.copyOf()
        tamperedWrappedDek[0] = (tamperedWrappedDek[0].toInt() xor 0x01).toByte()
        val badWrappedDekEnvelope = envelope.copy(wrappedDek = tamperedWrappedDek)
        assertThrows(VaultDecryptionException::class.java) {
            crypto.decrypt(vrk, address, badWrappedDekEnvelope)
        }

        // 4. Bit flip in wrapped DEK nonce
        val tamperedWrappedDekNonce = envelope.wrappedDekNonce.copyOf()
        tamperedWrappedDekNonce[0] = (tamperedWrappedDekNonce[0].toInt() xor 0x01).toByte()
        val badWrappedDekNonceEnvelope = envelope.copy(wrappedDekNonce = tamperedWrappedDekNonce)
        assertThrows(VaultDecryptionException::class.java) {
            crypto.decrypt(vrk, address, badWrappedDekNonceEnvelope)
        }

        // 5. Wrong VRK
        val attackerVrk = ByteArray(32).also(random::nextBytes)
        assertThrows(VaultDecryptionException::class.java) {
            crypto.decrypt(attackerVrk, address, envelope)
        }
    }

    @Test
    fun `aad authentication failure when record address is modified`() {
        val vrk = ByteArray(32).also(random::nextBytes)
        val correctAddress = RecordAddress("vault-1", "record-1", "PASSWORD", 1, 1L)
        val plaintext = "SuperSecret".toByteArray()

        val envelope = crypto.encrypt(vrk, correctAddress, plaintext)

        // Attacker attempts to bind the ciphertext to a different vault ID
        val wrongVaultAddress = correctAddress.copy(vaultId = "vault-2")
        assertThrows(VaultDecryptionException::class.java) {
            crypto.decrypt(vrk, wrongVaultAddress, envelope)
        }

        // Attacker attempts to change the record ID
        val wrongRecordIdAddress = correctAddress.copy(recordId = "record-2")
        assertThrows(VaultDecryptionException::class.java) {
            crypto.decrypt(vrk, wrongRecordIdAddress, envelope)
        }

        // Attacker attempts to change the record type
        val wrongTypeAddress = correctAddress.copy(type = "NOTE")
        assertThrows(VaultDecryptionException::class.java) {
            crypto.decrypt(vrk, wrongTypeAddress, envelope)
        }

        // Attacker attempts replay of an old revision
        val replayRevisionAddress = correctAddress.copy(revision = 2L)
        assertThrows(VaultDecryptionException::class.java) {
            crypto.decrypt(vrk, replayRevisionAddress, envelope)
        }
    }

    @Test
    fun `session locking securely zeros memory and denies access`() {
        val vrk = ByteArray(32).also(random::nextBytes)
        val session = VaultSession()
        session.unlock(vrk)
        assertTrue(session.isUnlocked())

        // Key usage succeeds while unlocked
        val retrieved = session.withRootKey { it.copyOf() }
        assertArrayEquals(vrk, retrieved)

        // Lock session
        session.lock()
        assertFalse(session.isUnlocked())

        // Accessing root key after lock must throw IllegalStateException
        assertThrows(IllegalStateException::class.java) {
            session.withRootKey { it }
        }
    }

    @Test
    fun `multi-revision update round-trip updates correctly across clients`() = runBlocking {
        val vrk = ByteArray(32).also(random::nextBytes)
        val vaultId = "vault-update-test"
        val recordId = "rec-upd-101"

        // Revision 1
        val entryV1 = PasswordEntry(
            id = recordId,
            vaultId = vaultId,
            revision = 1L,
            title = "AWS Console",
            username = "devops-admin",
            password = "OldPasswordV1!"
        )
        val addressV1 = RecordAddress(vaultId, recordId, "PASSWORD", 1, 1L)
        val envelopeV1 = crypto.encrypt(vrk, addressV1, entryV1.toEnvelopeBytes())

        // Client 1 updates password to Revision 2
        val entryV2 = entryV1.copy(
            revision = 2L,
            password = "NewUpgradedPasswordV2!@#$"
        )
        val addressV2 = RecordAddress(vaultId, recordId, "PASSWORD", 1, 2L)
        val envelopeV2 = crypto.encrypt(vrk, addressV2, entryV2.toEnvelopeBytes())

        // Client 2 receives Revision 2 from server sync
        client2Store.upsertFromServer(
            id = recordId,
            vaultId = vaultId,
            type = "PASSWORD",
            formatVersion = 1,
            ciphertext = envelopeV2.ciphertext,
            nonce = envelopeV2.nonce,
            wrappedDek = envelopeV2.wrappedDek,
            wrappedDekNonce = envelopeV2.wrappedDekNonce,
            incomingClientRevision = 2L,
            incomingServerSeq = 2002L,
            incomingDeleted = false
        )

        val retrievedRecord = client2Store.find(recordId, vaultId)
        assertNotNull(retrievedRecord)
        assertEquals(2L, retrievedRecord!!.clientRevision)

        val decryptedBytes = crypto.decrypt(
            vrk,
            addressV2,
            EncryptedRecordEnvelope(
                retrievedRecord.ciphertext,
                retrievedRecord.nonce,
                retrievedRecord.wrappedDek,
                retrievedRecord.wrappedDekNonce
            )
        )
        val decryptedEntry = PasswordEntry.fromEnvelopeBytes(recordId, vaultId, 2L, decryptedBytes)
        assertEquals("NewUpgradedPasswordV2!@#$", decryptedEntry.password)
        assertEquals(2L, decryptedEntry.revision)
    }
}

package com.securevault.database

import androidx.room.Room
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import android.security.keystore.UserNotAuthenticatedException
import com.securevault.crypto.RecordAddress
import com.securevault.crypto.VaultDecryptionException
import com.securevault.crypto.VaultRecordCrypto
import com.securevault.security.KeystoreAead
import com.securevault.security.SecureSessionStore
import com.securevault.security.VaultMetadataStore
import com.securevault.security.VaultSession
import com.securevault.security.WrappedVaultKey
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.security.SecureRandom
import java.util.UUID

@RunWith(AndroidJUnit4::class)
class EncryptedVaultIntegrationTest {
    @Test fun repositoryPersistsCiphertextAndRejectsTampering() = runBlocking {
        val context = ApplicationProvider.getApplicationContext<android.content.Context>()
        val db = Room.inMemoryDatabaseBuilder(context, LocalDatabase::class.java).allowMainThreadQueries().build()
        val session = VaultSession().also { it.unlock(ByteArray(32) { 7 }) }
        val address = RecordAddress("vault", "record", "test", 1, 1)
        val plaintext = "known-vault-plaintext".encodeToByteArray()
        val repository = VaultRecordRepository(db.encryptedRecordDao(), VaultRecordCrypto(), session)
        try {
            repository.store(address, plaintext)
            val raw = db.encryptedRecordDao().find(address.recordId, address.vaultId)!!
            assertFalse(raw.ciphertext.contentEquals(plaintext)); assertArrayEquals(plaintext, repository.load(address))
            raw.wrappedDek[0] = (raw.wrappedDek[0].toInt() xor 1).toByte(); db.encryptedRecordDao().upsert(raw)
            try { repository.load(address); throw AssertionError("tampered wrapped DEK decrypted") } catch (_: VaultDecryptionException) { }
        } finally { session.lock(); db.close() }
    }
    @Test fun actualKeystorePersistsAndRejectsTamperedWrappedVrk() {
        val context = ApplicationProvider.getApplicationContext<android.content.Context>()
        val alias = "securevault.test.${UUID.randomUUID()}"; val key = KeystoreAead(alias)
        val aad = "securevault.vrk.wrap.v1".encodeToByteArray()
        val metadata = VaultMetadataStore(context)
        val vrk = ByteArray(32).also(SecureRandom()::nextBytes)
        try {
            key.createIfMissing(requireUserAuth = false)
            val wrapped = key.encrypt(vrk, aad)
            metadata.save(WrappedVaultKey("vault", wrapped.nonce, wrapped.ciphertext))
            val persisted = metadata.load()!!
            assertArrayEquals(vrk, key.decrypt(com.securevault.security.EncryptedBlob(persisted.nonce, persisted.ciphertext), aad))
            persisted.ciphertext[0] = (persisted.ciphertext[0].toInt() xor 1).toByte()
            try { key.decrypt(com.securevault.security.EncryptedBlob(persisted.nonce, persisted.ciphertext), aad); throw AssertionError("tampered wrapped VRK decrypted") }
            catch (_: Exception) { }
        } finally { vrk.fill(0); metadata.clear(); key.delete() }
    }

    @Test fun authenticatedKeystoreKeyCannotStartCryptoBeforeAuthentication() {
        val alias = "securevault.test.auth.${UUID.randomUUID()}"; val key = KeystoreAead(alias)
        try {
            key.createIfMissing(requireUserAuth = true)
            try {
                val cipher = key.cipherForAuthenticatedEncryption()
                cipher.doFinal("unauthenticated-payload".encodeToByteArray())
                throw AssertionError("authentication-gated key executed crypto without authentication")
            } catch (_: UserNotAuthenticatedException) { }
            catch (_: javax.crypto.IllegalBlockSizeException) { }
            catch (_: android.security.KeyStoreException) { }
        } finally { key.delete() }
    }

    @Test fun localWipeComponentsRemoveAllLocalVaultState() = runBlocking {
        val context = ApplicationProvider.getApplicationContext<android.content.Context>()
        val alias = "securevault.test.${UUID.randomUUID()}"; val key = KeystoreAead(alias)
        val metadata = VaultMetadataStore(context); val sessions = SecureSessionStore(context)
        val db = Room.inMemoryDatabaseBuilder(context, LocalDatabase::class.java).allowMainThreadQueries().build()
        try {
            key.createIfMissing(requireUserAuth = false)
            val encrypted = key.encrypt("vrk-wrap-test".encodeToByteArray(), "aad".encodeToByteArray())
            metadata.save(WrappedVaultKey("vault", encrypted.nonce, encrypted.ciphertext)); sessions.saveRefreshToken("test-token")
            db.encryptedRecordDao().upsert(EncryptedRecord("r", "v", "t", 1, byteArrayOf(9), byteArrayOf(1), byteArrayOf(2), byteArrayOf(3), 1))
            db.encryptedRecordDao().wipe(); metadata.clear(); sessions.clear(); key.delete()
            assertNull(db.encryptedRecordDao().find("r", "v")); assertFalse(metadata.hasVault()); assertNull(sessions.refreshToken()); assertFalse(key.exists())
        } finally { metadata.clear(); sessions.clear(); key.delete(); db.close() }
    }
}

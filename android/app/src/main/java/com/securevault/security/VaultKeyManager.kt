package com.securevault.security

import java.security.SecureRandom
import java.util.UUID
import javax.crypto.Cipher
import javax.inject.Inject
import com.securevault.vault.PinManager
import javax.inject.Singleton

/** Owns VRK provisioning and Keystore wrapping. Raw VRKs only transit this class and VaultSession. */
@Singleton
class VaultKeyManager @Inject constructor(private val metadata: VaultMetadataStore) {
    private val aead = KeystoreAead(KEY_ALIAS)
    private val random = SecureRandom()
    fun hasVault() = metadata.hasVault()
    fun prepareCreate(): Cipher { check(!hasVault()) { "Vault already exists" }; aead.createIfMissing(); return aead.cipherForAuthenticatedEncryption() }
    fun completeCreate(authenticatedCipher: Cipher, session: VaultSession? = null): String {
        check(!hasVault()) { "Vault already exists" }
        val vrk = ByteArray(32).also(random::nextBytes)
        try {
            val ciphertext = authenticatedCipher.doFinal(vrk)
            val nonce = authenticatedCipher.iv
            require(nonce.size == 12) { "Unexpected Keystore GCM nonce length" }
            val vaultId = UUID.randomUUID().toString()
            metadata.save(WrappedVaultKey(vaultId, nonce, ciphertext))
            session?.unlock(vrk)
            return vaultId
        } finally { vrk.fill(0) }
    }

    fun completeCreateWithPin(pin: String, session: VaultSession, pinManager: PinManager): String {
        check(!hasVault()) { "Vault already exists" }
        val vrk = ByteArray(32).also(random::nextBytes)
        try {
            aead.createIfMissing(requireUserAuth = false)
            val cipher = aead.cipherForAuthenticatedEncryption()
            val ciphertext = cipher.doFinal(vrk)
            val nonce = cipher.iv
            require(nonce.size == 12) { "Unexpected Keystore GCM nonce length" }
            val vaultId = UUID.randomUUID().toString()
            metadata.save(WrappedVaultKey(vaultId, nonce, ciphertext))
            session.unlock(vrk)
            pinManager.setupPin(pin, vrk)
            return vaultId
        } finally { vrk.fill(0) }
    }

    fun completeCreateWithVaultPassword(
        vaultPassword: CharArray,
        pin: String,
        recoveryKey: ByteArray,
        session: VaultSession,
        pinManager: PinManager,
        vaultPasswordManager: com.securevault.crypto.VaultPasswordManager,
        recoveryKeyManager: com.securevault.crypto.RecoveryKeyManager
    ): Triple<String, ByteArray, ByteArray> {
        check(!hasVault()) { "Vault already exists" }
        val vrk = ByteArray(32).also(random::nextBytes)
        try {
            aead.createIfMissing(requireUserAuth = false)
            val cipher = aead.cipherForAuthenticatedEncryption()
            val ciphertext = cipher.doFinal(vrk)
            val nonce = cipher.iv
            require(nonce.size == 12) { "Unexpected Keystore GCM nonce length" }
            val vaultId = UUID.randomUUID().toString()
            metadata.save(WrappedVaultKey(vaultId, nonce, ciphertext))

            // Wrap VRK with Vault Password (Argon2id + AES-256-GCM)
            val vpSalt = vaultPasswordManager.generateSalt()
            val vpWrapped = vaultPasswordManager.wrapVrk(vrk, vaultPassword, vpSalt)
            metadata.saveVaultPasswordWrappedVrk(vpWrapped.salt, vpWrapped.nonce, vpWrapped.ciphertext)

            // Wrap VRK with Recovery Key (BIP-39 256-bit entropy + AES-256-GCM)
            val recWrapped = recoveryKeyManager.wrapVrk(vrk, recoveryKey)
            metadata.saveRecoveryWrappedVrk(recWrapped)

            session.unlock(vrk)
            pinManager.setupPin(pin, vrk)
            return Triple(vaultId, recWrapped, vpSalt)
        } finally {
            vrk.fill(0)
        }
    }

    fun unlockWithVaultPassword(
        vaultPassword: CharArray,
        session: VaultSession,
        vaultPasswordManager: com.securevault.crypto.VaultPasswordManager
    ): Boolean {
        val record = metadata.loadVaultPasswordWrappedVrk() ?: return false
        val vrk = vaultPasswordManager.unwrapVrk(
            password = vaultPassword,
            salt = record.salt,
            nonce = record.nonce,
            ciphertext = record.ciphertext
        )
        try {
            session.unlock(vrk)
            if (!aead.exists() || !metadata.hasVault()) {
                aead.createIfMissing(requireUserAuth = false)
                val cipher = aead.cipherForAuthenticatedEncryption()
                val ciphertext = cipher.doFinal(vrk)
                val vaultId = metadata.load()?.vaultId ?: UUID.randomUUID().toString()
                metadata.save(WrappedVaultKey(vaultId, cipher.iv, ciphertext))
            }
            return true
        } finally {
            vrk.fill(0)
        }
    }

    fun unlockWithRecoveryKey(
        recoveryKey: ByteArray,
        session: VaultSession,
        recoveryKeyManager: com.securevault.crypto.RecoveryKeyManager
    ): Boolean {
        val blob = metadata.loadRecoveryWrappedVrk() ?: return false
        val vrk = recoveryKeyManager.unwrapVrk(blob, recoveryKey)
        try {
            session.unlock(vrk)
            if (!aead.exists() || !metadata.hasVault()) {
                aead.createIfMissing(requireUserAuth = false)
                val cipher = aead.cipherForAuthenticatedEncryption()
                val ciphertext = cipher.doFinal(vrk)
                val vaultId = metadata.load()?.vaultId ?: UUID.randomUUID().toString()
                metadata.save(WrappedVaultKey(vaultId, cipher.iv, ciphertext))
            }
            return true
        } finally {
            vrk.fill(0)
        }
    }

    fun resetVaultPassword(
        newPassword: CharArray,
        session: VaultSession,
        vaultPasswordManager: com.securevault.crypto.VaultPasswordManager
    ) {
        session.withRootKey { vrk ->
            val salt = vaultPasswordManager.generateSalt()
            val wrapped = vaultPasswordManager.wrapVrk(vrk, newPassword, salt)
            metadata.saveVaultPasswordWrappedVrk(wrapped.salt, wrapped.nonce, wrapped.ciphertext)
        }
    }

    fun hasVaultPassword(): Boolean = metadata.hasVaultPasswordWrappedVrk()
    fun hasRecoveryKey(): Boolean = metadata.hasRecoveryWrappedVrk()
    fun loadRecoveryWrappedVrk(): ByteArray? = metadata.loadRecoveryWrappedVrk()

    fun importVrkFromRecovery(
        vrk: ByteArray,
        vaultId: String,
        newPassword: CharArray,
        newPin: String,
        newRecoveryKey: ByteArray,
        session: VaultSession,
        pinManager: PinManager,
        vaultPasswordManager: com.securevault.crypto.VaultPasswordManager,
        recoveryKeyManager: com.securevault.crypto.RecoveryKeyManager
    ) {
        require(vrk.size == 32) { "Invalid VRK length" }
        aead.createIfMissing(requireUserAuth = false)
        val cipher = aead.cipherForAuthenticatedEncryption()
        val ciphertext = cipher.doFinal(vrk)
        metadata.save(WrappedVaultKey(vaultId, cipher.iv, ciphertext))

        val salt = vaultPasswordManager.generateSalt()
        val vpWrapped = vaultPasswordManager.wrapVrk(vrk, newPassword, salt)
        metadata.saveVaultPasswordWrappedVrk(vpWrapped.salt, vpWrapped.nonce, vpWrapped.ciphertext)

        val recWrapped = recoveryKeyManager.wrapVrk(vrk, newRecoveryKey)
        metadata.saveRecoveryWrappedVrk(recWrapped)

        session.unlock(vrk)
        pinManager.setupPin(newPin, vrk)
    }

    fun importVrkIntoSession(vrk: ByteArray, session: VaultSession, vaultId: String, authenticatedCipher: Cipher) {
        require(vrk.size == 32) { "Invalid VRK length" }
        val ciphertext = authenticatedCipher.doFinal(vrk)
        val nonce = authenticatedCipher.iv
        require(nonce.size == 12) { "Unexpected Keystore GCM nonce length" }
        metadata.save(WrappedVaultKey(vaultId, nonce, ciphertext))
        session.unlock(vrk)
    }
    fun prepareUnlock(): Cipher {
        val wrapped = metadata.load() ?: throw IllegalStateException("Vault has not been created")
        return aead.cipherForAuthenticatedDecryption(wrapped.nonce)
    }
    /** Completes the Keystore-gated unwrap without exposing VRK bytes to callers. */
    fun unlockIntoSession(authenticatedCipher: Cipher, session: VaultSession) {
        val wrapped = metadata.load() ?: throw IllegalStateException("Vault has not been created")
        val vrk = try { authenticatedCipher.doFinal(wrapped.ciphertext) } catch (e: Exception) { throw SecurityException("Vault key authentication failed", e) }
        try {
            if (vrk.size != 32) throw SecurityException("Invalid vault root key")
            session.unlock(vrk)
        } finally { vrk.fill(0) }
    }
    fun vaultId(): String? = metadata.load()?.vaultId
    fun wipe() { metadata.clear(); aead.delete() }
    fun hasWrappingKey() = aead.exists()
    private companion object { const val KEY_ALIAS = "securevault.vrk.wrap.v1" }
}

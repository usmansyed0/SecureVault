package com.securevault.security

import com.securevault.database.VaultRecordRepository
import com.securevault.auth.VaultAccountLifecycle
import com.securevault.vault.PinManager
import javax.crypto.Cipher
import javax.inject.Inject
import javax.inject.Singleton

enum class VaultState { SETUP_REQUIRED, LOCKED, UNLOCKED }

/** Central lock policy. UI state never unlocks data; only completeUnlock installs VRK bytes into VaultSession. */
@Singleton
class VaultController @Inject constructor(
    private val keys: VaultKeyManager,
    private val session: VaultSession,
    private val records: VaultRecordRepository,
    private val sessions: SecureSessionStore,
    private val inactivity: InactivityLock,
    private val deviceSigner: DeviceSigner,
    private val pinManager: PinManager? = null
) : VaultAccountLifecycle {
    init {
        inactivity.setOnTimeout { lock() }
        pinManager?.onTerminalLockout = { logoutAndWipeLocalVault() }
    }
    fun state(): VaultState = when { !keys.hasVault() -> VaultState.SETUP_REQUIRED; session.isUnlocked() -> VaultState.UNLOCKED; else -> VaultState.LOCKED }
    fun prepareCreate(): Cipher = keys.prepareCreate()
    fun completeCreate(cipher: Cipher) { keys.completeCreate(cipher, session); touch() }
    fun createVaultWithPin(pin: String): String {
        val pm = pinManager ?: throw IllegalStateException("PIN manager not available")
        val vaultId = keys.completeCreateWithPin(pin, session, pm)
        touch()
        return vaultId
    }

    fun createVaultWithVaultPassword(
        vaultPassword: CharArray,
        pin: String,
        recoveryKey: ByteArray,
        vaultPasswordManager: com.securevault.crypto.VaultPasswordManager,
        recoveryKeyManager: com.securevault.crypto.RecoveryKeyManager
    ): Triple<String, ByteArray, ByteArray> {
        val pm = pinManager ?: throw IllegalStateException("PIN manager not available")
        val res = keys.completeCreateWithVaultPassword(
            vaultPassword = vaultPassword,
            pin = pin,
            recoveryKey = recoveryKey,
            session = session,
            pinManager = pm,
            vaultPasswordManager = vaultPasswordManager,
            recoveryKeyManager = recoveryKeyManager
        )
        touch()
        return res
    }

    fun unlockWithVaultPassword(
        vaultPassword: CharArray,
        vaultPasswordManager: com.securevault.crypto.VaultPasswordManager
    ): Boolean {
        checkDeadManSwitch()
        val success = keys.unlockWithVaultPassword(vaultPassword, session, vaultPasswordManager)
        if (success) {
            touch()
        }
        return success
    }

    fun unlockWithRecoveryKey(
        recoveryKey: ByteArray,
        recoveryKeyManager: com.securevault.crypto.RecoveryKeyManager
    ): Boolean {
        checkDeadManSwitch()
        val success = keys.unlockWithRecoveryKey(recoveryKey, session, recoveryKeyManager)
        if (success) {
            touch()
        }
        return success
    }

    fun resetVaultPassword(
        newPassword: CharArray,
        vaultPasswordManager: com.securevault.crypto.VaultPasswordManager
    ) {
        keys.resetVaultPassword(newPassword, session, vaultPasswordManager)
    }

    fun hasVaultPassword(): Boolean = keys.hasVaultPassword()
    fun hasRecoveryKey(): Boolean = keys.hasRecoveryKey()
    fun completeImport(vrk: ByteArray, vaultId: String, cipher: Cipher) { keys.importVrkIntoSession(vrk, session, vaultId, cipher); touch() }
    fun prepareUnlock(): Cipher = keys.prepareUnlock()
    fun completeUnlock(cipher: Cipher) { checkDeadManSwitch(); keys.unlockIntoSession(cipher, session); touch() }
    fun hasVault(): Boolean = keys.hasVault() || (pinManager?.hasPin() ?: false) || keys.hasVaultPassword() || keys.hasRecoveryKey()
    fun hasPin(): Boolean = pinManager?.hasPin() ?: false
    fun pinLength(): Int = pinManager?.pinLength() ?: 4
    fun setupPin(pin: String) {
        check(session.isUnlocked()) { "Vault must be unlocked to set up PIN" }
        session.withRootKey { vrk -> pinManager?.setupPin(pin, vrk) }
    }
    suspend fun unlockWithPin(pin: String) {
        checkDeadManSwitch()
        val pm = pinManager ?: throw IllegalStateException("PIN manager not available")
        val vrk = pm.unlockWithPin(pin)
        try {
            session.unlock(vrk)
            touch()
        } finally {
            vrk.fill(0)
        }
    }

    fun checkDeadManSwitch() {
        val lastContact = sessions.lastServerContact()
        if (lastContact == 0L) {
            sessions.saveLastServerContact(System.currentTimeMillis())
            return
        }
        val days = sessions.deadManSwitchDays()
        val threshold = days.toLong() * 24 * 3600 * 1000
        if (System.currentTimeMillis() - lastContact > threshold) {
            kotlinx.coroutines.runBlocking { logoutAndWipeLocalVault() }
            throw IllegalStateException("Vault wiped: $days days of offline inactivity exceeded dead-man switch threshold. This protects your data if the device is lost.")
        }
    }
    fun deadManSwitchDays(): Int = sessions.deadManSwitchDays()
    fun setDeadManSwitchDays(days: Int) = sessions.saveDeadManSwitchDays(days)
    fun remainingLockoutSeconds(): Long = pinManager?.remainingLockoutSeconds() ?: 0L
    fun failedPinAttempts(): Int = pinManager?.failedAttempts() ?: 0
    suspend fun recordBiometricFailure() { pinManager?.recordBiometricFailure() }
    fun touch() { if (session.isUnlocked()) inactivity.reset() }
    fun pauseInactivity() { inactivity.pause() }
    fun resumeInactivity() { if (session.isUnlocked()) inactivity.resume() }
    fun lock() { inactivity.cancel(); session.lock() }
    suspend fun logoutAndWipeLocalVault() {
        lock()
        records.wipe()
        keys.wipe()
        pinManager?.wipeHardwareKey()
        deviceSigner.delete()
        sessions.clear()
    }
    override fun lockForAccountLogout() { lock() }
    override suspend fun wipeForRevokedDevice() { logoutAndWipeLocalVault() }
}

package com.securevault.ui.viewmodels

import android.util.Log
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.securevault.security.VaultController
import com.securevault.security.VaultState
import com.securevault.util.AppError
import com.securevault.vault.ui.VaultCoordinator
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import javax.inject.Inject

/**
 * Immutable snapshot of local vault state for the UI.
 *
 * @property vaultState         Current vault lock state.
 * @property isLoading          True while an unlock / setup operation is in progress.
 * @property errorMessage       Localised, non-sensitive error string for display.
 * @property failedPinAttempts  Number of consecutive failed PIN attempts since last unlock.
 * @property lockoutSecondsLeft Remaining lockout duration in seconds (0 = no lockout).
 * @property deadManSwitchDays  Currently configured dead-man switch threshold in days.
 * @property hasBiometrics      True when the device has a biometric key provisioned in the vault.
 * @property hasPin             True when a PIN is enrolled in the vault.
 */
data class VaultUiState(
    val vaultState: VaultState = VaultState.SETUP_REQUIRED,
    val isLoading: Boolean = false,
    val errorMessage: String? = null,
    val failedPinAttempts: Int = 0,
    val lockoutSecondsLeft: Long = 0L,
    val deadManSwitchDays: Int = 30,
    val hasBiometrics: Boolean = false,
    val hasPin: Boolean = false
)

/** One-shot events emitted by [VaultViewModel] to drive navigation. */
sealed class VaultEvent {
    /** Vault was successfully unlocked — navigate to Home. */
    object Unlocked : VaultEvent()
    /** Vault setup completed — navigate to Home. */
    object SetupComplete : VaultEvent()
    /** Vault became locked due to inactivity or explicit action — navigate to Lock screen. */
    object Locked : VaultEvent()
    /** Dead-man switch triggered — vault wiped, navigate to Login. */
    data class DeadManSwitchWiped(val reason: String) : VaultEvent()
}

/**
 * Lifecycle-aware ViewModel that owns all local vault state and unlock logic,
 * previously scattered across [MainActivity].
 *
 * - All blocking crypto is dispatched to [Dispatchers.Default].
 * - Exceptions are always caught and converted to [AppError].
 * - Sensitive byte arrays (PINs after encoding, VRKs) are never held in fields.
 */
@HiltViewModel
class VaultViewModel @Inject constructor(
    private val vault: VaultController,
    private val vaultCoordinator: VaultCoordinator
) : ViewModel() {

    private val _uiState = MutableStateFlow(buildState())
    val uiState: StateFlow<VaultUiState> = _uiState.asStateFlow()

    private val _events = MutableSharedFlow<VaultEvent>(extraBufferCapacity = 1)
    val events: SharedFlow<VaultEvent> = _events.asSharedFlow()

    // ──────────────────────────────────────────────────────────────────────────
    // Startup integrity check
    // ──────────────────────────────────────────────────────────────────────────

    init {
        runStartupChecks()
    }

    private fun runStartupChecks() {
        viewModelScope.launch {
            try {
                vault.checkDeadManSwitch()
            } catch (e: Exception) {
                // Dead-man switch triggered — vault already wiped inside VaultController
                Log.w("SecureVault", "Dead-man switch triggered on startup", e)
                _uiState.value = buildState().copy(errorMessage = "Vault wiped: offline threshold exceeded")
                _events.emit(VaultEvent.DeadManSwitchWiped("Offline threshold exceeded"))
                return@launch
            }
            _uiState.value = buildState()
            if (vault.state() == VaultState.UNLOCKED) {
                vaultCoordinator.loadItems()
            }
        }
    }

    // ──────────────────────────────────────────────────────────────────────────
    // Unlock operations
    // ──────────────────────────────────────────────────────────────────────────

    /**
     * Unlock the vault using a 4-digit PIN.
     * The PIN string is never stored; the byte-level copy inside [VaultController.unlockWithPin]
     * is zeroed by that call.
     */
    fun unlockWithPin(pin: String) {
        viewModelScope.launch {
            _uiState.value = _uiState.value.copy(isLoading = true, errorMessage = null)
            try {
                withContext(Dispatchers.Default) {
                    vault.unlockWithPin(pin)
                }
                vaultCoordinator.loadItems()
                refreshState()
                _events.emit(VaultEvent.Unlocked)
            } catch (t: Throwable) {
                val err = AppError.fromThrowable(t, "Incorrect PIN")
                refreshState(errorMessage = err.userMessage)
            }
        }
    }

    /**
     * Called by [MainActivity] after the BiometricPrompt succeeds and provides
     * an authenticated [javax.crypto.Cipher].
     */
    fun completeUnlockWithBiometric(cipher: javax.crypto.Cipher) {
        viewModelScope.launch {
            _uiState.value = _uiState.value.copy(isLoading = true, errorMessage = null)
            try {
                vault.completeUnlock(cipher)
                vaultCoordinator.loadItems()
                refreshState()
                _events.emit(VaultEvent.Unlocked)
            } catch (t: Throwable) {
                val err = AppError.fromThrowable(t, "Biometric unlock failed")
                refreshState(errorMessage = err.userMessage)
            }
        }
    }

    /** Notify the ViewModel that biometric auth produced an error from the OS prompt. */
    fun onBiometricError(message: String) {
        _uiState.value = _uiState.value.copy(isLoading = false, errorMessage = message)
    }

    /**
     * Records a consecutive biometric failure, potentially triggering lockout
     * if [com.securevault.vault.PinManager] reaches its threshold.
     */
    fun recordBiometricFailure() {
        viewModelScope.launch {
            try {
                vault.recordBiometricFailure()
                refreshState(errorMessage = "Biometric authentication failed")
            } catch (e: SecurityException) {
                // Terminal lockout reached
                refreshState(errorMessage = "Too many failed attempts. Vault locked.")
            }
        }
    }

    // ──────────────────────────────────────────────────────────────────────────
    // Vault setup (first-time creation)
    // ──────────────────────────────────────────────────────────────────────────

    /** Complete vault creation after biometric enrolment succeeded. */
    fun completeCreateWithBiometric(cipher: javax.crypto.Cipher, pin: String) {
        viewModelScope.launch {
            _uiState.value = _uiState.value.copy(isLoading = true, errorMessage = null)
            try {
                vault.completeCreate(cipher)
                vault.setupPin(pin)
                vaultCoordinator.loadItems()
                refreshState()
                _events.emit(VaultEvent.SetupComplete)
            } catch (t: Throwable) {
                val err = AppError.fromThrowable(t, "Vault setup failed")
                refreshState(errorMessage = err.userMessage)
            }
        }
    }

    /** Create a PIN-only vault (no biometric key). */
    fun createVaultWithPin(pin: String) {
        viewModelScope.launch {
            _uiState.value = _uiState.value.copy(isLoading = true, errorMessage = null)
            try {
                withContext(Dispatchers.Default) {
                    vault.createVaultWithPin(pin)
                }
                vaultCoordinator.loadItems()
                refreshState()
                _events.emit(VaultEvent.SetupComplete)
            } catch (t: Throwable) {
                val err = AppError.fromThrowable(t, "Vault creation failed")
                refreshState(errorMessage = err.userMessage)
            }
        }
    }

    /** Set or update the PIN when the vault is already unlocked. */
    fun setupPin(pin: String) {
        viewModelScope.launch {
            try {
                vault.setupPin(pin)
                refreshState()
            } catch (t: Throwable) {
                val err = AppError.fromThrowable(t, "Failed to configure PIN")
                _uiState.value = _uiState.value.copy(errorMessage = err.userMessage)
            }
        }
    }

    // ──────────────────────────────────────────────────────────────────────────
    // Lock / lifecycle
    // ──────────────────────────────────────────────────────────────────────────

    /** Lock the vault and clear decrypted in-memory state. */
    fun lock() {
        vault.lock()
        vaultCoordinator.clearDecryptedState()
        refreshState()
        viewModelScope.launch { _events.emit(VaultEvent.Locked) }
    }

    /** Called from [MainActivity.onStop] — always lock when app goes to background. */
    fun lockOnBackground() {
        if (vault.hasVault()) {
            lock()
        }
    }

    /** Resume inactivity timer when the app returns to the foreground. */
    fun onResume() {
        viewModelScope.launch {
            try {
                vault.checkDeadManSwitch()
            } catch (e: Exception) {
                val msg = "Vault wiped: offline threshold exceeded"
                refreshState(errorMessage = msg)
                _events.emit(VaultEvent.DeadManSwitchWiped(msg))
                return@launch
            }
            vault.resumeInactivity()
            vault.touch()
            refreshState()
        }
    }

    /** Signal user interaction so the inactivity timer is reset. */
    fun onTouch() {
        vault.touch()
    }

    // ──────────────────────────────────────────────────────────────────────────
    // Dead-man switch configuration
    // ──────────────────────────────────────────────────────────────────────────

    fun setDeadManSwitchDays(days: Int) {
        vault.setDeadManSwitchDays(days)
        _uiState.value = _uiState.value.copy(deadManSwitchDays = days)
    }

    // ──────────────────────────────────────────────────────────────────────────
    // Biometric cipher preparation (returns cipher for BiometricPrompt)
    // ──────────────────────────────────────────────────────────────────────────

    /** Returns the [javax.crypto.Cipher] to pass to BiometricPrompt for unlock. */
    fun prepareUnlockCipher(): javax.crypto.Cipher = vault.prepareUnlock()

    /** Returns the [javax.crypto.Cipher] to pass to BiometricPrompt for first-time create. */
    fun prepareCreateCipher(): javax.crypto.Cipher = vault.prepareCreate()

    // ──────────────────────────────────────────────────────────────────────────
    // Convenience accessors used by screens
    // ──────────────────────────────────────────────────────────────────────────

    fun hasVault(): Boolean = vault.hasVault()
    fun hasPin(): Boolean = vault.hasPin()
    fun pinLength(): Int = vault.pinLength()
    fun vaultState(): VaultState = vault.state()

    // ──────────────────────────────────────────────────────────────────────────
    // Internal helpers
    // ──────────────────────────────────────────────────────────────────────────

    private fun buildState(errorMessage: String? = null) = VaultUiState(
        vaultState = vault.state(),
        isLoading = false,
        errorMessage = errorMessage,
        failedPinAttempts = vault.failedPinAttempts(),
        lockoutSecondsLeft = vault.remainingLockoutSeconds(),
        deadManSwitchDays = vault.deadManSwitchDays(),
        hasPin = vault.hasPin(),
        hasBiometrics = false // updated by MainActivity via BiometricManager
    )

    private fun refreshState(errorMessage: String? = null) {
        _uiState.value = buildState(errorMessage)
    }

    fun clearError() {
        _uiState.value = _uiState.value.copy(errorMessage = null)
    }
}

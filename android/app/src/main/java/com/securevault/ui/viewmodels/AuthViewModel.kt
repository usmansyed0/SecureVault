package com.securevault.ui.viewmodels

import android.util.Log
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.securevault.auth.SessionCoordinator
import com.securevault.auth.SessionTokens
import com.securevault.crypto.Argon2Kdf
import com.securevault.crypto.AuthSecretKdf
import com.securevault.network.SecureVaultApi
import com.securevault.network.model.GoogleAuthRequestDto
import com.securevault.network.model.LoginRequestDto
import com.securevault.network.model.RegisterRequestDto
import com.securevault.security.DeviceSigningKey
import com.securevault.security.SecureSessionStore
import com.securevault.util.AppError
import com.securevault.util.SecureBuffer.useAndWipe
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
 * Immutable snapshot of the authentication / session layer.
 *
 * @property isLoggedIn     True when a valid access token is held.
 * @property deviceStatus   Raw device status string from the server (e.g. "active", "stolen").
 * @property isLoading      True while a network operation is in progress.
 * @property errorMessage   Non-null when the last operation produced a user-visible error.
 */
data class AuthUiState(
    val isLoggedIn: Boolean = false,
    val deviceStatus: String? = null,
    val isLoading: Boolean = false,
    val errorMessage: String? = null
)

/** One-shot navigation / UI events fired from [AuthViewModel]. */
sealed class AuthEvent {
    /** Login/registration succeeded and the vault is ready. */
    object NavigateToHome : AuthEvent()
    /** Login succeeded but the local vault does not exist yet. */
    object NavigateToSetupVault : AuthEvent()
    /** Login succeeded but the local vault is locked. */
    object NavigateToLock : AuthEvent()
    /** User explicitly signed out. */
    object NavigateToLogin : AuthEvent()
    /** Google Sign-In was cancelled — no error should be shown. */
    object GoogleSignInCancelled : AuthEvent()
}

/**
 * Lifecycle-aware ViewModel that owns all authentication and session logic
 * previously scattered across [MainActivity].
 *
 * All coroutine launches are guarded by try/catch with typed [AppError]
 * mapping to prevent raw exception messages from reaching the UI.
 * Heavy Argon2 KDF work is dispatched to [Dispatchers.Default].
 */
@HiltViewModel
class AuthViewModel @Inject constructor(
    private val api: SecureVaultApi,
    private val session: SessionCoordinator,
    private val sessionStore: SecureSessionStore,
    private val deviceSigningKey: DeviceSigningKey
) : ViewModel() {

    private val _uiState = MutableStateFlow(AuthUiState())
    val uiState: StateFlow<AuthUiState> = _uiState.asStateFlow()

    private val _events = MutableSharedFlow<AuthEvent>(extraBufferCapacity = 1)
    val events: SharedFlow<AuthEvent> = _events.asSharedFlow()

    // ──────────────────────────────────────────────────────────────────────────
    // Initialisation
    // ──────────────────────────────────────────────────────────────────────────

    init {
        _uiState.value = AuthUiState(
            isLoggedIn = session.accessToken() != null,
            deviceStatus = session.deviceStatus
        )
    }

    // ──────────────────────────────────────────────────────────────────────────
    // Public API
    // ──────────────────────────────────────────────────────────────────────────

    /**
     * Derive [auth_secret] from [email] + [masterPassword] via Argon2id,
     * then call the register endpoint.  Emits [AuthEvent.NavigateToHome]
     * (via an intermediate onSuccess callback) on success.
     */
    fun register(
        email: String,
        masterPassword: String,
        onSuccess: () -> Unit
    ) {
        viewModelScope.launch {
            _uiState.value = _uiState.value.copy(isLoading = true, errorMessage = null)
            try {
                val (authSecret, saltStr) = withContext(Dispatchers.Default) {
                    val salt = ByteArray(16).also { java.security.SecureRandom().nextBytes(it) }
                    val vrk = Argon2Kdf().deriveKey(masterPassword, salt)
                    val secret = AuthSecretKdf.derive(vrk)
                    val saltB64 = android.util.Base64.encodeToString(salt, android.util.Base64.NO_WRAP)
                    // Zero the VRK immediately after deriving authSecret
                    vrk.useAndWipe { /* vrk used inline inside deriveKey; secret already derived */ }
                    Pair(secret, saltB64)
                }
                api.register(RegisterRequestDto(email, authSecret, saltStr))
                _uiState.value = _uiState.value.copy(isLoading = false)
                onSuccess()
            } catch (t: Throwable) {
                val err = AppError.fromThrowable(t, "Registration failed")
                _uiState.value = _uiState.value.copy(isLoading = false, errorMessage = err.userMessage)
            }
        }
    }

    /**
     * Full onboarding flow: derives auth key, registers (or silently ignores
     * 409), logs in, and emits an event so [MainActivity] can set up the local vault.
     *
     * Returns the raw [SessionTokens] through [onTokens] so [MainActivity] can
     * pass them to the vault-creation flow (biometric or PIN).
     */
    fun completeOnboarding(
        displayName: String,
        email: String,
        masterPassword: String,
        onTokens: (SessionTokens?) -> Unit
    ) {
        viewModelScope.launch {
            _uiState.value = _uiState.value.copy(isLoading = true, errorMessage = null)
            try {
                sessionStore.saveDisplayName(displayName)
                sessionStore.saveUserEmail(email)

                val tokens = withContext(Dispatchers.Default) {
                    try {
                        val saltRes = try { api.getSalt(email) } catch (_: Exception) { null }
                        val saltBytes = if (saltRes?.master_salt != null) {
                            android.util.Base64.decode(saltRes.master_salt, android.util.Base64.NO_WRAP)
                        } else {
                            ByteArray(16).also { java.security.SecureRandom().nextBytes(it) }
                        }
                        val vrk = Argon2Kdf().deriveKey(masterPassword, saltBytes)
                        val authSecret = AuthSecretKdf.derive(vrk)
                        val saltStr = android.util.Base64.encodeToString(saltBytes, android.util.Base64.NO_WRAP)
                        vrk.useAndWipe {}

                        try {
                            api.register(RegisterRequestDto(email, authSecret, saltStr))
                        } catch (e: retrofit2.HttpException) {
                            if (e.code() != 400 && e.code() != 409) throw e
                        }

                        deviceSigningKey.createIfMissing()
                        val pubKey = deviceSigningKey.publicKeyBase64()
                        api.login(
                            LoginRequestDto(
                                login = email,
                                auth_secret = authSecret,
                                device_name = "Android " + android.os.Build.MODEL,
                                platform = "android",
                                public_key = pubKey
                            )
                        )
                    } catch (e: Exception) {
                        Log.w("SecureVault", "Backend unavailable during onboarding, proceeding offline", e)
                        null
                    }
                }

                if (tokens != null) {
                    val st = SessionTokens(
                        tokens.access_token, tokens.refresh_token, tokens.user_id,
                        tokens.device_id, tokens.session_id, tokens.device_status
                    )
                    session.install(st)
                    _uiState.value = _uiState.value.copy(
                        isLoggedIn = true,
                        deviceStatus = tokens.device_status
                    )
                }

                _uiState.value = _uiState.value.copy(isLoading = false)
                onTokens(
                    if (tokens != null) SessionTokens(
                        tokens.access_token, tokens.refresh_token, tokens.user_id,
                        tokens.device_id, tokens.session_id, tokens.device_status
                    ) else null
                )
            } catch (t: Throwable) {
                val err = AppError.fromThrowable(t, "Account setup failed")
                _uiState.value = _uiState.value.copy(isLoading = false, errorMessage = err.userMessage)
            }
        }
    }

    /**
     * Derives Argon2id auth key for [email] and calls the login endpoint.
     * Fires a navigation event based on the local vault state provided by [vaultStateProvider].
     */
    fun login(
        email: String,
        masterPassword: String,
        vaultStateProvider: () -> com.securevault.security.VaultState,
        onSuccess: () -> Unit
    ) {
        viewModelScope.launch {
            _uiState.value = _uiState.value.copy(isLoading = true, errorMessage = null)
            try {
                deviceSigningKey.createIfMissing()
                val pubKey = deviceSigningKey.publicKeyBase64()

                val saltRes = try { api.getSalt(email) } catch (_: Exception) { null }
                val masterSalt = saltRes?.master_salt
                val saltBytes = if (!masterSalt.isNullOrBlank()) {
                    android.util.Base64.decode(masterSalt, android.util.Base64.NO_WRAP)
                } else {
                    "securevault_default_salt".toByteArray()
                }

                val authSecret = withContext(Dispatchers.Default) {
                    val vrk = Argon2Kdf().deriveKey(masterPassword, saltBytes)
                    val secret = AuthSecretKdf.derive(vrk)
                    vrk.useAndWipe {}
                    secret
                }

                val tokens = api.login(
                    LoginRequestDto(
                        login = email,
                        auth_secret = authSecret,
                        device_name = "Android " + android.os.Build.MODEL,
                        platform = "android",
                        public_key = pubKey
                    )
                )

                session.install(
                    SessionTokens(
                        tokens.access_token, tokens.refresh_token, tokens.user_id,
                        tokens.device_id, tokens.session_id, tokens.device_status
                    )
                )
                sessionStore.saveUserEmail(email)

                _uiState.value = _uiState.value.copy(
                    isLoggedIn = true,
                    deviceStatus = tokens.device_status,
                    isLoading = false,
                    errorMessage = null
                )

                onSuccess()
            } catch (t: Throwable) {
                val err = AppError.fromThrowable(t, "Login failed")
                _uiState.value = _uiState.value.copy(isLoading = false, errorMessage = err.userMessage)
            }
        }
    }

    /**
     * Initiates Google credential flow. The caller is responsible for the
     * CredentialManager interaction (which requires an Activity context);
     * this method handles only the backend token exchange.
     */
    fun completeGoogleSignIn(
        idToken: String,
        nonce: String,
        onSuccess: () -> Unit
    ) {
        viewModelScope.launch {
            _uiState.value = _uiState.value.copy(isLoading = true, errorMessage = null)
            try {
                deviceSigningKey.createIfMissing()
                val pubKey = deviceSigningKey.publicKeyBase64()
                val tokens = api.googleAuth(
                    GoogleAuthRequestDto(
                        id_token = idToken,
                        device_name = "Android " + android.os.Build.MODEL,
                        public_key = pubKey,
                        nonce = nonce
                    )
                )
                session.install(
                    SessionTokens(
                        tokens.access_token, tokens.refresh_token, tokens.user_id,
                        tokens.device_id, tokens.session_id, tokens.device_status
                    )
                )
                _uiState.value = _uiState.value.copy(
                    isLoggedIn = true,
                    deviceStatus = tokens.device_status,
                    isLoading = false,
                    errorMessage = null
                )
                onSuccess()
            } catch (t: Throwable) {
                val err = AppError.fromThrowable(t, "Google Sign-In failed")
                _uiState.value = _uiState.value.copy(isLoading = false, errorMessage = err.userMessage)
            }
        }
    }

    /** Fetches the server nonce for Google Sign-In replay protection. */
    suspend fun fetchGoogleNonce(): String? = try {
        api.getGoogleNonce().nonce
    } catch (_: Exception) {
        null
    }

    /** Emits [AuthEvent.GoogleSignInCancelled] and clears loading state. */
    fun onGoogleSignInCancelled() {
        viewModelScope.launch {
            _uiState.value = _uiState.value.copy(isLoading = false, errorMessage = null)
            _events.emit(AuthEvent.GoogleSignInCancelled)
        }
    }

    /**
     * Clears session, locks vault state, and emits [AuthEvent.NavigateToLogin].
     */
    fun logout(onVaultLock: () -> Unit) {
        viewModelScope.launch {
            onVaultLock()
            session.logout()
            _uiState.value = AuthUiState(isLoggedIn = false, deviceStatus = null)
            _events.emit(AuthEvent.NavigateToLogin)
        }
    }

    /** Sync current session state from [SessionCoordinator] (call after process death restore). */
    fun syncFromSession() {
        _uiState.value = _uiState.value.copy(
            isLoggedIn = session.accessToken() != null,
            deviceStatus = session.deviceStatus
        )
    }

    /** Mark an error as acknowledged so it is not redisplayed. */
    fun clearError() {
        _uiState.value = _uiState.value.copy(errorMessage = null)
    }
}

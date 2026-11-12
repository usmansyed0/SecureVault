package com.securevault

import android.content.Intent
import android.os.Bundle
import android.view.MotionEvent
import android.view.WindowManager
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.viewModels
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.lifecycleScope
import com.securevault.auth.SessionCoordinator
import com.securevault.auth.StepUpCoordinator
import com.securevault.network.SecureVaultApi
import com.securevault.network.model.StepUpGrantRequestDto
import com.securevault.security.DeviceSigningKey
import com.securevault.security.SafeSecurityLogger
import com.securevault.security.VaultController
import com.securevault.security.VaultState
import com.securevault.ui.viewmodels.AuthEvent
import com.securevault.ui.viewmodels.AuthViewModel
import com.securevault.ui.viewmodels.DevicesViewModel
import com.securevault.ui.viewmodels.VaultEvent
import com.securevault.ui.viewmodels.VaultViewModel
import com.securevault.vault.ui.VaultCoordinator
import com.securevault.vault.ui.screens.*
import com.securevault.vault.ui.theme.SecureVaultTheme
import com.securevault.vault.ui.theme.VaultThemeOption
import dagger.hilt.android.AndroidEntryPoint
import kotlinx.coroutines.launch
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.rememberNavController
import javax.inject.Inject

@AndroidEntryPoint
class MainActivity : FragmentActivity() {

    // ──────────────────────────────────────────────────────────────────────────
    // Injected singletons (still needed for BiometricPrompt, StepUp, NavHost)
    // ──────────────────────────────────────────────────────────────────────────
    @Inject lateinit var vault: VaultController
    @Inject lateinit var session: SessionCoordinator
    @Inject lateinit var stepUp: StepUpCoordinator
    @Inject lateinit var deviceSigningKey: DeviceSigningKey
    @Inject lateinit var api: SecureVaultApi
    @Inject lateinit var vaultCoordinator: VaultCoordinator
    @Inject lateinit var sessionStore: com.securevault.security.SecureSessionStore
    @Inject lateinit var vaultPasswordManager: com.securevault.crypto.VaultPasswordManager
    @Inject lateinit var recoveryKeyManager: com.securevault.crypto.RecoveryKeyManager

    // ──────────────────────────────────────────────────────────────────────────
    // ViewModels
    // ──────────────────────────────────────────────────────────────────────────
    private val authViewModel: AuthViewModel by viewModels()
    private val vaultViewModel: VaultViewModel by viewModels()
    private val devicesViewModel: DevicesViewModel by viewModels()

    // ──────────────────────────────────────────────────────────────────────────
    // Minimal Activity-level UI state (theme, PIN dialog, step-up prompt)
    // ──────────────────────────────────────────────────────────────────────────
    private val selectedTheme = mutableStateOf(VaultThemeOption.CYBER_DARK)
    private val showSetupPin = mutableStateOf(false)
    private val statusMessage = mutableStateOf("")

    // ──────────────────────────────────────────────────────────────────────────
    // Lifecycle
    // ──────────────────────────────────────────────────────────────────────────

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        if (!BuildConfig.DEBUG) {
            window.setFlags(
                WindowManager.LayoutParams.FLAG_SECURE,
                WindowManager.LayoutParams.FLAG_SECURE
            )
        }

        setContent {
            SecureVaultTheme(selectedTheme = selectedTheme.value) {
                Surface(
                    modifier = Modifier.fillMaxSize(),
                    color = MaterialTheme.colorScheme.background
                ) {
                    SecureVaultApp()
                }
            }
        }
    }

    override fun dispatchTouchEvent(event: MotionEvent): Boolean {
        vaultViewModel.onTouch()
        return super.dispatchTouchEvent(event)
    }

    override fun onResume() {
        super.onResume()
        vaultViewModel.onResume()
    }

    override fun onStop() {
        super.onStop()
        vaultViewModel.lockOnBackground()
    }

    // ──────────────────────────────────────────────────────────────────────────
    // Biometric helpers (require Activity context — stay in Activity)
    // ──────────────────────────────────────────────────────────────────────────

    fun unlockWithBiometrics(onSuccess: () -> Unit, onError: (String) -> Unit) {
        val canAuth = BiometricManager.from(this)
            .canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG)
        if (canAuth != BiometricManager.BIOMETRIC_SUCCESS) {
            onError("Fingerprint is not enrolled or unavailable. Please use your 4-digit PIN.")
            return
        }
        try {
            val cipher = vaultViewModel.prepareUnlockCipher()
            val prompt = BiometricPrompt(this, ContextCompat.getMainExecutor(this),
                object : BiometricPrompt.AuthenticationCallback() {
                    override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                        val authCipher = result.cryptoObject?.cipher
                        if (authCipher != null) {
                            vaultViewModel.completeUnlockWithBiometric(authCipher)
                            onSuccess()
                        } else {
                            onError("Biometric cipher missing")
                        }
                    }
                    override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                        onError(errString.toString())
                    }
                    override fun onAuthenticationFailed() {
                        vaultViewModel.recordBiometricFailure()
                        onError("Biometric authentication failed")
                    }
                })
            prompt.authenticate(
                buildPromptInfo("Unlock SecureVault", negativeButtonText = "Cancel"),
                BiometricPrompt.CryptoObject(cipher)
            )
        } catch (e: Exception) {
            onError(com.securevault.util.AppError.fromThrowable(e, "Biometric unlock unavailable").userMessage)
        }
    }

    fun createVaultWithBiometrics(pin: String, onSuccess: () -> Unit, onError: (String) -> Unit) {
        val canAuth = BiometricManager.from(this)
            .canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG)
        if (canAuth != BiometricManager.BIOMETRIC_SUCCESS) {
            onError("Biometrics not enrolled on device.")
            return
        }
        try {
            val cipher = vaultViewModel.prepareCreateCipher()
            val prompt = BiometricPrompt(this, ContextCompat.getMainExecutor(this),
                object : BiometricPrompt.AuthenticationCallback() {
                    override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                        val authCipher = result.cryptoObject?.cipher ?: return
                        vaultViewModel.completeCreateWithBiometric(authCipher, pin)
                        onSuccess()
                    }
                    override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                        onError(errString.toString())
                    }
                })
            prompt.authenticate(
                buildPromptInfo("Initialize Secure Vault", negativeButtonText = "Cancel"),
                BiometricPrompt.CryptoObject(cipher)
            )
        } catch (e: Exception) {
            onError(com.securevault.util.AppError.fromThrowable(e, "Failed to initialize vault").userMessage)
        }
    }

    // ──────────────────────────────────────────────────────────────────────────
    // Step-up authentication (requires Activity for BiometricPrompt)
    // ──────────────────────────────────────────────────────────────────────────

    fun authenticateStepUp(
        action: String,
        password: String,
        onGrant: (String) -> Unit,
        onError: (String) -> Unit
    ) {
        lifecycleScope.launch {
            try {
                val challenge = stepUp.requestChallenge(action)
                val message = stepUp.buildCanonicalMessage(
                    challenge.challenge_id, action, challenge.challenge
                )
                val signature = stepUp.prepareSignature()
                val prompt = BiometricPrompt(
                    this@MainActivity,
                    ContextCompat.getMainExecutor(this@MainActivity),
                    object : BiometricPrompt.AuthenticationCallback() {
                        override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                            val authSig = result.cryptoObject?.signature ?: return
                            lifecycleScope.launch {
                                try {
                                    val sigBase64 = stepUp.signMessage(authSig, message)
                                    val grant = stepUp.complete(
                                        challenge.challenge_id, challenge.challenge,
                                        sigBase64, password
                                    )
                                    onGrant(grant)
                                } catch (e: Exception) {
                                    onError(com.securevault.util.AppError.fromThrowable(e, "Step-up authorization failed").userMessage)
                                }
                            }
                        }
                        override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                            onError(errString.toString())
                        }
                    }
                )
                prompt.authenticate(
                    buildPromptInfo(
                        title = "Step-Up Authentication",
                        subtitle = "Confirm: $action",
                        negativeButtonText = "Cancel"
                    ),
                    BiometricPrompt.CryptoObject(signature)
                )
            } catch (e: Exception) {
                onError(com.securevault.util.AppError.fromThrowable(e, "Step-up challenge request failed").userMessage)
            }
        }
    }

    // ──────────────────────────────────────────────────────────────────────────
    // Composable NavHost
    // ──────────────────────────────────────────────────────────────────────────

    @Composable
    private fun SecureVaultApp() {
        val navController = rememberNavController()
        var passwordPromptAction by remember { mutableStateOf<((String) -> Unit)?>(null) }
        var passwordPromptInput by remember { mutableStateOf("") }

        // Collect ViewModel state
        val authState by authViewModel.uiState.collectAsState()
        val vaultState by vaultViewModel.uiState.collectAsState()

        // ── Auth events ──────────────────────────────────────────────────────
        LaunchedEffect(Unit) {
            authViewModel.events.collect { event ->
                when (event) {
                    is AuthEvent.NavigateToLogin -> navController.navigate("login") {
                        popUpTo(0) { inclusive = true }
                        launchSingleTop = true
                    }
                    is AuthEvent.NavigateToHome -> navController.navigate("home") {
                        popUpTo(0) { inclusive = true }
                    }
                    is AuthEvent.NavigateToSetupVault -> { /* handled inline during onboarding */ }
                    is AuthEvent.NavigateToLock -> navController.navigate("lock") {
                        popUpTo("login") { inclusive = true }
                    }
                    is AuthEvent.GoogleSignInCancelled -> { /* no-op */ }
                }
            }
        }

        // ── Vault events ─────────────────────────────────────────────────────
        LaunchedEffect(Unit) {
            vaultViewModel.events.collect { event ->
                when (event) {
                    is VaultEvent.Unlocked -> navController.navigate("home") {
                        popUpTo("lock") { inclusive = true }
                    }
                    is VaultEvent.SetupComplete -> navController.navigate("home") {
                        popUpTo(0) { inclusive = true }
                    }
                    is VaultEvent.Locked -> {
                        val current = navController.currentBackStackEntry?.destination?.route
                        if (current != null && current != "lock" && current != "login" && current != "register") {
                            navController.navigate("lock") {
                                popUpTo("home") { inclusive = true }
                            }
                        }
                    }
                    is VaultEvent.DeadManSwitchWiped -> {
                        statusMessage.value = event.reason
                        navController.navigate("login") { popUpTo(0) { inclusive = true } }
                    }
                }
            }
        }

        // Hook VaultCoordinator callbacks
        vaultCoordinator.onUserActivity = { vaultViewModel.onTouch() }
        vaultCoordinator.onLockDetected = {
            runOnUiThread {
                val current = navController.currentBackStackEntry?.destination?.route
                if (current != null && current != "lock" && current != "login" && current != "register") {
                    navController.navigate("lock") {
                        popUpTo("home") { inclusive = true }
                    }
                }
            }
        }

        // ── Step-up password prompt dialog ───────────────────────────────────
        if (passwordPromptAction != null) {
            AlertDialog(
                onDismissRequest = { passwordPromptAction = null; passwordPromptInput = "" },
                title = { Text("Confirm Account Password") },
                text = {
                    OutlinedTextField(
                        value = passwordPromptInput,
                        onValueChange = { passwordPromptInput = it },
                        label = { Text("Account Password") },
                        singleLine = true
                    )
                },
                confirmButton = {
                    Button(onClick = {
                        val act = passwordPromptAction
                        val pass = passwordPromptInput
                        passwordPromptAction = null
                        passwordPromptInput = ""
                        act?.invoke(pass)
                    }) { Text("Authenticate") }
                },
                dismissButton = {
                    TextButton(onClick = { passwordPromptAction = null; passwordPromptInput = "" }) {
                        Text("Cancel")
                    }
                }
            )
        }

        // ── PIN setup dialog ─────────────────────────────────────────────────
        if (showSetupPin.value) {
            SetupPinDialog(
                onDismiss = { showSetupPin.value = false },
                onPinConfirmed = { pin ->
                    vaultViewModel.setupPin(pin)
                    showSetupPin.value = false
                }
            )
        }

        // ── Start destination logic ──────────────────────────────────────────
        val hasLocalAccount = vault.hasVault() || vault.hasPin()
        val startDest = when {
            !authState.isLoggedIn && !hasLocalAccount -> "login"
            vault.state() == VaultState.UNLOCKED -> "home"
            hasLocalAccount -> "lock"
            else -> "login"
        }

        NavHost(
            navController = navController,
            startDestination = startDest
        ) {
            composable("login") {
                LoginScreen(
                    onLogin = { email, pass ->
                        authViewModel.login(email, pass, vaultStateProvider = { vault.state() }) {
                            statusMessage.value = ""
                            when (vault.state()) {
                                VaultState.UNLOCKED -> navController.navigate("home") {
                                    popUpTo("login") { inclusive = true }
                                }
                                VaultState.SETUP_REQUIRED -> createVaultWithBiometrics(
                                    pin = "",
                                    onSuccess = {
                                        navController.navigate("home") { popUpTo("login") { inclusive = true } }
                                    },
                                    onError = { statusMessage.value = it }
                                )
                                VaultState.LOCKED -> navController.navigate("lock") {
                                    popUpTo("login") { inclusive = true }
                                }
                            }
                        }
                    },
                    onGoogleSignIn = {
                        performGoogleSignIn {
                            statusMessage.value = ""
                            if (vault.state() == VaultState.UNLOCKED) {
                                navController.navigate("home") { popUpTo("login") { inclusive = true } }
                            } else if (vault.state() == VaultState.SETUP_REQUIRED) {
                                createVaultWithBiometrics("",
                                    onSuccess = { navController.navigate("home") { popUpTo("login") { inclusive = true } } },
                                    onError = { statusMessage.value = it }
                                )
                            } else {
                                navController.navigate("lock") { popUpTo("login") { inclusive = true } }
                            }
                        }
                    },
                    onNavigateToRegister = {
                        statusMessage.value = ""
                        navController.navigate("register")
                    },
                    onNavigateToRecovery = {
                        statusMessage.value = ""
                        navController.navigate("device_recovery")
                    },
                    errorMessage = (authState.errorMessage ?: statusMessage.value).takeIf { it.isNotEmpty() }
                )
            }

            composable("register") {
                val bioManager = BiometricManager.from(this@MainActivity)
                val canAuth = bioManager.canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG)
                val isBiometricAvailable = canAuth != BiometricManager.BIOMETRIC_ERROR_NO_HARDWARE &&
                        canAuth != BiometricManager.BIOMETRIC_ERROR_HW_UNAVAILABLE
                val isBiometricEnrolled = canAuth == BiometricManager.BIOMETRIC_SUCCESS

                OnboardingFlowScreen(
                    isBiometricAvailable = isBiometricAvailable,
                    isBiometricEnrolled = isBiometricEnrolled,
                    onOpenBiometricSettings = {
                        try {
                            if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.R) {
                                startActivity(Intent(android.provider.Settings.ACTION_BIOMETRIC_ENROLL).apply {
                                    putExtra(
                                        android.provider.Settings.EXTRA_BIOMETRIC_AUTHENTICATORS_ALLOWED,
                                        BiometricManager.Authenticators.BIOMETRIC_STRONG
                                    )
                                })
                            } else {
                                startActivity(Intent(android.provider.Settings.ACTION_SECURITY_SETTINGS))
                            }
                        } catch (_: Exception) {
                            try { startActivity(Intent(android.provider.Settings.ACTION_SECURITY_SETTINGS)) } catch (_: Exception) {}
                        }
                    },
                    onComplete = { dispName, email, pass, pin, bio ->
                        authViewModel.completeOnboarding(dispName, email, pass) { _ ->
                            // After account setup, provision the local vault
                            val bioCanAuth = BiometricManager.from(this@MainActivity)
                                .canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG)
                            if (bio && bioCanAuth == BiometricManager.BIOMETRIC_SUCCESS) {
                                createVaultWithBiometrics(pin,
                                    onSuccess = { navController.navigate("home") { popUpTo(0) { inclusive = true } } },
                                    onError = {
                                        vaultViewModel.createVaultWithPin(pin)
                                    }
                                )
                            } else {
                                vaultViewModel.createVaultWithPin(pin)
                            }
                        }
                    },
                    onNavigateToLogin = {
                        statusMessage.value = ""
                        navController.popBackStack()
                    },
                    errorMessage = (authState.errorMessage ?: statusMessage.value).takeIf { it.isNotEmpty() }
                )
            }

            composable("lock") {
                LockScreen(
                    hasPin = vaultState.hasPin,
                    lockoutSecondsRemaining = vaultState.lockoutSecondsLeft,
                    failedAttempts = vaultState.failedPinAttempts,
                    errorMessage = (vaultState.errorMessage ?: statusMessage.value).takeIf { it.isNotEmpty() },
                    pinLength = vault.pinLength(),
                    onUnlockWithPin = { pin ->
                        vaultViewModel.unlockWithPin(pin)
                        statusMessage.value = ""
                    },
                    onUnlockWithBiometric = {
                        unlockWithBiometrics(
                            onSuccess = { statusMessage.value = "" },
                            onError = { err -> statusMessage.value = err }
                        )
                    },
                    onLogout = {
                        statusMessage.value = ""
                        authViewModel.logout {
                            vaultCoordinator.clearDecryptedState()
                            vault.lock()
                        }
                    },
                    onNavigateToRecovery = {
                        statusMessage.value = ""
                        navController.navigate("device_recovery")
                    }
                )
            }

            composable("home") {
                HomeScreen(
                    userName = sessionStore.displayName()?.takeIf { it.isNotBlank() }
                        ?: sessionStore.userEmail()?.substringBefore("@") ?: "User",
                    coordinator = vaultCoordinator,
                    onNavigateToPasswords = { navController.navigate("passwords") },
                    onNavigateToDocuments = { navController.navigate("documents") },
                    onNavigateToNotes = { navController.navigate("notes") },
                    onNavigateToImageToPdf = { navController.navigate("imagetopdf") },
                    onNavigateToShare = { navController.navigate("share") },
                    onNavigateToSettings = { navController.navigate("settings") },
                    onLockVault = {
                        vaultViewModel.lock()
                    }
                )
            }

            composable("passwords") {
                PasswordsScreen(
                    coordinator = vaultCoordinator,
                    onBack = { navController.popBackStack() }
                )
            }

            composable("documents") {
                DocumentsScreen(
                    coordinator = vaultCoordinator,
                    onNavigateToScanner = { navController.navigate("imagetopdf") },
                    onBack = { navController.popBackStack() }
                )
            }

            composable("notes") {
                NotesScreen(
                    coordinator = vaultCoordinator,
                    onBack = { navController.popBackStack() }
                )
            }

            composable("imagetopdf") {
                ImageToPdfScreen(
                    coordinator = vaultCoordinator,
                    onBack = { navController.popBackStack() },
                    onSavedToDocuments = {
                        navController.navigate("documents") {
                            popUpTo("imagetopdf") { inclusive = true }
                        }
                    }
                )
            }

            composable("share") {
                ShareCenterScreen(
                    coordinator = vaultCoordinator,
                    onBack = { navController.popBackStack() }
                )
            }

            composable("devices") {
                val devicesState by devicesViewModel.uiState.collectAsState()
                DeviceManagementScreen(
                    devices = devicesState.devices,
                    currentDeviceId = session.deviceId,
                    onRevokeDevice = { id ->
                        passwordPromptAction = { pass ->
                            authenticateStepUp("device_revoke", pass,
                                onGrant = { grant -> devicesViewModel.revokeDevice(id, grant) },
                                onError = { err -> statusMessage.value = err }
                            )
                        }
                    },
                    onMarkDeviceStolen = { id ->
                        passwordPromptAction = { pass ->
                            authenticateStepUp("device_mark_stolen", pass,
                                onGrant = { grant -> devicesViewModel.markDeviceStolen(id, grant) },
                                onError = { err -> statusMessage.value = err }
                            )
                        }
                    },
                    onEndDeviceSessions = { id ->
                        passwordPromptAction = { pass ->
                            authenticateStepUp("device_end_sessions", pass,
                                onGrant = { grant -> devicesViewModel.endDeviceSessions(id, grant) },
                                onError = { err -> statusMessage.value = err }
                            )
                        }
                    },
                    onSignOutAllOthers = {
                        passwordPromptAction = { pass ->
                            authenticateStepUp("device_end_sessions", pass,
                                onGrant = { grant -> devicesViewModel.signOutOtherDevices(grant) },
                                onError = { err -> statusMessage.value = err }
                            )
                        }
                    },
                    onBack = { navController.popBackStack() }
                )
            }

            composable("settings") {
                SettingsScreen(
                    currentTheme = selectedTheme.value,
                    onThemeSelected = { selectedTheme.value = it },
                    coordinator = vaultCoordinator,
                    onNavigateToDevices = {
                        devicesViewModel.refreshDevices()
                        navController.navigate("devices")
                    },
                    onNavigateToShares = { navController.navigate("share") },
                    onNavigateToStatistics = { navController.navigate("statistics") },
                    onSetupPin = { showSetupPin.value = true },
                    onLockVault = { vaultViewModel.lock() },
                    onLogout = {
                        authViewModel.logout {
                            vaultCoordinator.clearDecryptedState()
                            vault.lock()
                        }
                    },
                    deadManDays = vaultState.deadManSwitchDays,
                    onDeadManDaysChanged = { vaultViewModel.setDeadManSwitchDays(it) },
                    onBack = { navController.popBackStack() }
                )
            }

            composable("statistics") {
                StatisticsScreen(
                    coordinator = vaultCoordinator,
                    onBack = { navController.popBackStack() }
                )
            }

            composable("device_recovery") {
                DeviceLossRecoveryScreen(
                    onUnlockWithPassword = { password ->
                        val success = vault.unlockWithVaultPassword(password.toCharArray(), vaultPasswordManager)
                        if (success) {
                            statusMessage.value = ""
                        }
                        success
                    },
                    onUnlockWithRecoveryKey = { phraseOrHex ->
                        try {
                            val s = phraseOrHex.trim()
                            val entropy = if (s.contains(" ")) {
                                recoveryKeyManager.phraseToRecoveryKey(s)
                            } else {
                                val len = s.length
                                val data = ByteArray(len / 2)
                                for (i in 0 until len step 2) {
                                    data[i / 2] = ((Character.digit(s[i], 16) shl 4) + Character.digit(s[i + 1], 16)).toByte()
                                }
                                data
                            }
                            val success = vault.unlockWithRecoveryKey(entropy, recoveryKeyManager)
                            if (success) {
                                statusMessage.value = ""
                            }
                            success
                        } catch (e: Exception) {
                            false
                        }
                    },
                    onSetupNewPin = { pin ->
                        vault.setupPin(pin)
                    },
                    onRecoveryComplete = {
                        navController.navigate("home") {
                            popUpTo(0) { inclusive = true }
                        }
                    },
                    onCancel = {
                        navController.popBackStack()
                    }
                )
            }
        }
    }

    // ──────────────────────────────────────────────────────────────────────────
    // Google Sign-In (requires Activity context for CredentialManager)
    // ──────────────────────────────────────────────────────────────────────────

    private fun performGoogleSignIn(onSuccess: () -> Unit) {
        lifecycleScope.launch {
            val serverClientId = try {
                getString(R.string.google_web_client_id)
            } catch (_: Exception) { "" }

            if (serverClientId.isBlank()) {
                statusMessage.value = "Google Sign-In requires configuring a Google OAuth 2.0 Web Client ID in strings.xml (google_web_client_id)."
                return@launch
            }

            try {
                val nonce = authViewModel.fetchGoogleNonce()
                if (nonce == null) {
                    statusMessage.value = "Can't reach the server. Check your connection and try again."
                    return@launch
                }

                val credentialManager = androidx.credentials.CredentialManager.create(this@MainActivity)
                val googleIdOptionBuilder = com.google.android.libraries.identity.googleid.GetGoogleIdOption.Builder()
                    .setFilterByAuthorizedAccounts(false)
                    .setServerClientId(serverClientId)
                    .setAutoSelectEnabled(false)
                    .setNonce(nonce)

                val request = androidx.credentials.GetCredentialRequest.Builder()
                    .addCredentialOption(googleIdOptionBuilder.build())
                    .build()

                val result = credentialManager.getCredential(request = request, context = this@MainActivity)
                val credential = result.credential

                if (credential is androidx.credentials.CustomCredential &&
                    credential.type == com.google.android.libraries.identity.googleid.GoogleIdTokenCredential.TYPE_GOOGLE_ID_TOKEN_CREDENTIAL
                ) {
                    val googleIdToken = com.google.android.libraries.identity.googleid.GoogleIdTokenCredential.createFrom(credential.data)
                    authViewModel.completeGoogleSignIn(googleIdToken.idToken, nonce) {
                        onSuccess()
                    }
                } else {
                    statusMessage.value = "Unsupported credential received from Google."
                }
            } catch (e: androidx.credentials.exceptions.GetCredentialCancellationException) {
                // User cancelled — notify ViewModel to reset loading state
                authViewModel.onGoogleSignInCancelled()
            } catch (e: androidx.credentials.exceptions.NoCredentialException) {
                statusMessage.value = "No Google account found on device. Please add a Google account in Settings and try again."
            } catch (e: java.net.SocketTimeoutException) {
                statusMessage.value = "Connection timed out. Check your internet connection and try again."
            } catch (e: java.io.IOException) {
                statusMessage.value = "Network error. Check your connection and try again."
            } catch (e: Throwable) {
                SafeSecurityLogger.event("google_signin_error")
                statusMessage.value = com.securevault.util.AppError.fromThrowable(e, "Google Sign-In failed").userMessage
            }
        }
    }

    // ──────────────────────────────────────────────────────────────────────────
    // Utilities
    // ──────────────────────────────────────────────────────────────────────────

    companion object {
        fun buildPromptInfo(
            title: String,
            subtitle: String? = null,
            negativeButtonText: String = "Cancel"
        ): BiometricPrompt.PromptInfo {
            require(negativeButtonText.isNotBlank()) { "Negative button text must be set and non-empty" }
            val builder = BiometricPrompt.PromptInfo.Builder()
                .setTitle(title)
                .setNegativeButtonText(negativeButtonText)
                .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
            if (subtitle != null) builder.setSubtitle(subtitle)
            return builder.build()
        }
    }
}

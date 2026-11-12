package com.securevault.vault.ui.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.ui.graphics.Color
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.securevault.vault.ui.CyberShieldAnimation

@Composable
fun LoginScreen(
    onLogin: (email: String, masterPass: String) -> Unit,
    onGoogleSignIn: () -> Unit,
    onNavigateToRegister: () -> Unit,
    errorMessage: String?,
    onNavigateToRecovery: (() -> Unit)? = null
) {
    var email by remember { mutableStateOf("") }
    var masterPassword by remember { mutableStateOf("") }
    var passwordVisible by remember { mutableStateOf(false) }
    val scrollState = rememberScrollState()

    Column(
        modifier = Modifier
            .fillMaxSize()
            .background(MaterialTheme.colorScheme.background)
            .verticalScroll(scrollState)
            .padding(24.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center
    ) {
        CyberShieldAnimation()
        Spacer(modifier = Modifier.height(12.dp))

        Text(
            text = "SECURE VAULT",
            style = MaterialTheme.typography.headlineMedium,
            fontWeight = FontWeight.Black,
            letterSpacing = 2.sp
        )
        Text(
            text = "Zero-Knowledge Personal Encrypted Safe",
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )

        Spacer(modifier = Modifier.height(28.dp))

        OutlinedTextField(
            value = email,
            onValueChange = { email = it },
            label = { Text("Account Email") },
            placeholder = { Text("user@example.com") },
            modifier = Modifier.fillMaxWidth(),
            singleLine = true,
            shape = RoundedCornerShape(12.dp)
        )

        Spacer(modifier = Modifier.height(12.dp))

        OutlinedTextField(
            value = masterPassword,
            onValueChange = { masterPassword = it },
            label = { Text("Master Password") },
            modifier = Modifier.fillMaxWidth(),
            singleLine = true,
            visualTransformation = if (passwordVisible) androidx.compose.ui.text.input.VisualTransformation.None else PasswordVisualTransformation(),
            trailingIcon = {
                IconButton(onClick = { passwordVisible = !passwordVisible }) {
                    Text(
                        text = if (passwordVisible) "👁️" else "🔒",
                        fontSize = 16.sp
                    )
                }
            },
            shape = RoundedCornerShape(12.dp)
        )

        if (!errorMessage.isNullOrEmpty()) {
            Spacer(modifier = Modifier.height(10.dp))
            Surface(
                shape = RoundedCornerShape(8.dp),
                color = MaterialTheme.colorScheme.error.copy(alpha = 0.15f),
                modifier = Modifier.fillMaxWidth()
            ) {
                Text(
                    text = errorMessage,
                    color = MaterialTheme.colorScheme.error,
                    style = MaterialTheme.typography.bodySmall,
                    modifier = Modifier.padding(10.dp)
                )
            }
        }

        Spacer(modifier = Modifier.height(20.dp))

        Button(
            onClick = { onLogin(email.trim(), masterPassword) },
            modifier = Modifier.fillMaxWidth().height(50.dp),
            shape = RoundedCornerShape(12.dp),
            enabled = email.isNotBlank() && masterPassword.length >= 9
        ) {
            Text("Unlock Account", fontWeight = FontWeight.Bold)
        }

        Spacer(modifier = Modifier.height(12.dp))

        OutlinedButton(
            onClick = onGoogleSignIn,
            modifier = Modifier.fillMaxWidth().height(50.dp),
            shape = RoundedCornerShape(12.dp)
        ) {
            Text("Sign In with Google")
        }

        Spacer(modifier = Modifier.height(16.dp))

        TextButton(onClick = onNavigateToRegister) {
            Text("Don't have a vault yet? Create Account")
        }

        if (onNavigateToRecovery != null) {
            TextButton(onClick = onNavigateToRecovery) {
                Text(
                    text = "Lost Your Device? Recover Vault",
                    color = MaterialTheme.colorScheme.primary,
                    fontWeight = FontWeight.SemiBold
                )
            }
        }
    }
}

enum class OnboardingStage(val stepNumber: Int, val title: String) {
    CREATE_ACCOUNT(1, "Create Account"),
    DISPLAY_NAME(2, "Your Name"),
    EMAIL(3, "Account Email"),
    MASTER_PASSWORD(4, "Master Password"),
    CONFIRM_MASTER_PASSWORD(5, "Confirm Password"),
    CREATE_PIN(6, "Create 4-Digit PIN"),
    CONFIRM_PIN(7, "Confirm 4-Digit PIN"),
    BIOMETRIC_SETUP(8, "Fingerprint Setup"),
    VAULT_CREATED(9, "Vault Created"),
    ENTER_VAULT(10, "Enter SecureVault")
}

@Composable
fun OnboardingFlowScreen(
    isBiometricAvailable: Boolean,
    isBiometricEnrolled: Boolean,
    onOpenBiometricSettings: () -> Unit,
    onComplete: (displayName: String, email: String, masterPass: String, pin: String, enableBiometric: Boolean) -> Unit,
    onNavigateToLogin: () -> Unit,
    errorMessage: String?
) {
    var stage by remember { mutableStateOf(OnboardingStage.CREATE_ACCOUNT) }
    var displayName by remember { mutableStateOf("") }
    var email by remember { mutableStateOf("") }
    var masterPassword by remember { mutableStateOf("") }
    var confirmPassword by remember { mutableStateOf("") }
    var pin by remember { mutableStateOf("") }
    var confirmPin by remember { mutableStateOf("") }
    var enableBiometric by remember { mutableStateOf(false) }

    var passwordVisible by remember { mutableStateOf(false) }
    var confirmPasswordVisible by remember { mutableStateOf(false) }
    var pinVisible by remember { mutableStateOf(false) }
    var confirmPinVisible by remember { mutableStateOf(false) }

    val scrollState = rememberScrollState()

    Column(
        modifier = Modifier
            .fillMaxSize()
            .background(MaterialTheme.colorScheme.background)
            .verticalScroll(scrollState)
            .padding(24.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center
    ) {
        CyberShieldAnimation()
        Spacer(modifier = Modifier.height(12.dp))

        // Stage indicator: Step X of 10
        Surface(
            shape = RoundedCornerShape(16.dp),
            color = MaterialTheme.colorScheme.primary.copy(alpha = 0.12f),
            modifier = Modifier.padding(bottom = 8.dp)
        ) {
            Text(
                text = "STAGE ${stage.stepNumber} OF 10: ${stage.title.uppercase()}",
                style = MaterialTheme.typography.labelMedium,
                fontWeight = FontWeight.Bold,
                letterSpacing = 1.2.sp,
                color = MaterialTheme.colorScheme.primary,
                modifier = Modifier.padding(horizontal = 12.dp, vertical = 6.dp)
            )
        }

        LinearProgressIndicator(
            progress = { stage.stepNumber / 10f },
            modifier = Modifier.fillMaxWidth().height(4.dp).padding(vertical = 4.dp),
            color = MaterialTheme.colorScheme.primary,
            trackColor = MaterialTheme.colorScheme.surfaceVariant
        )

        Spacer(modifier = Modifier.height(16.dp))

        when (stage) {
            OnboardingStage.CREATE_ACCOUNT -> {
                Text(
                    text = "Create Secure Vault",
                    style = MaterialTheme.typography.headlineMedium,
                    fontWeight = FontWeight.Black
                )
                Text(
                    text = "Your personal encrypted digital safe for credentials, documents, and private diary notes.",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.padding(vertical = 8.dp)
                )

                Spacer(modifier = Modifier.height(24.dp))

                Button(
                    onClick = { stage = OnboardingStage.DISPLAY_NAME },
                    modifier = Modifier.fillMaxWidth().height(50.dp),
                    shape = RoundedCornerShape(12.dp)
                ) {
                    Text("Get Started", fontWeight = FontWeight.Bold)
                }

                Spacer(modifier = Modifier.height(12.dp))

                TextButton(onClick = onNavigateToLogin) {
                    Text("Already have a vault? Log In")
                }
            }

            OnboardingStage.DISPLAY_NAME -> {
                Text(
                    text = "What should we call you?",
                    style = MaterialTheme.typography.headlineSmall,
                    fontWeight = FontWeight.Bold
                )
                Text(
                    text = "Your display name personalizes your vault greeting.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.padding(vertical = 6.dp)
                )

                Spacer(modifier = Modifier.height(16.dp))

                OutlinedTextField(
                    value = displayName,
                    onValueChange = { displayName = it },
                    label = { Text("Display Name") },
                    placeholder = { Text("e.g. Alex Vance") },
                    modifier = Modifier.fillMaxWidth(),
                    singleLine = true,
                    shape = RoundedCornerShape(12.dp)
                )

                Spacer(modifier = Modifier.height(24.dp))

                Button(
                    onClick = { stage = OnboardingStage.EMAIL },
                    modifier = Modifier.fillMaxWidth().height(50.dp),
                    shape = RoundedCornerShape(12.dp),
                    enabled = displayName.trim().isNotBlank()
                ) {
                    Text("Continue", fontWeight = FontWeight.Bold)
                }

                Spacer(modifier = Modifier.height(8.dp))
                TextButton(onClick = { stage = OnboardingStage.CREATE_ACCOUNT }) { Text("Back") }
            }

            OnboardingStage.EMAIL -> {
                Text(
                    text = "Enter your email",
                    style = MaterialTheme.typography.headlineSmall,
                    fontWeight = FontWeight.Bold
                )
                Text(
                    text = "Used for account authentication and multi-device sync.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.padding(vertical = 6.dp)
                )

                Spacer(modifier = Modifier.height(16.dp))

                OutlinedTextField(
                    value = email,
                    onValueChange = { email = it },
                    label = { Text("Email Address") },
                    placeholder = { Text("user@example.com") },
                    modifier = Modifier.fillMaxWidth(),
                    singleLine = true,
                    shape = RoundedCornerShape(12.dp)
                )

                Spacer(modifier = Modifier.height(24.dp))

                Button(
                    onClick = { stage = OnboardingStage.MASTER_PASSWORD },
                    modifier = Modifier.fillMaxWidth().height(50.dp),
                    shape = RoundedCornerShape(12.dp),
                    enabled = email.trim().contains("@") && email.trim().contains(".")
                ) {
                    Text("Continue", fontWeight = FontWeight.Bold)
                }

                Spacer(modifier = Modifier.height(8.dp))
                TextButton(onClick = { stage = OnboardingStage.DISPLAY_NAME }) { Text("Back") }
            }

            OnboardingStage.MASTER_PASSWORD -> {
                Text(
                    text = "Create Master Password",
                    style = MaterialTheme.typography.headlineSmall,
                    fontWeight = FontWeight.Bold
                )
                Surface(
                    shape = RoundedCornerShape(10.dp),
                    color = Color(0xFFFFB300).copy(alpha = 0.12f),
                    modifier = Modifier.fillMaxWidth().padding(vertical = 10.dp)
                ) {
                    Text(
                        text = "⚠️ The Master Password is non-recoverable. It encrypts your account and is NOT used for daily unlock.",
                        style = MaterialTheme.typography.bodySmall,
                        color = Color(0xFFFFD54F),
                        modifier = Modifier.padding(10.dp)
                    )
                }

                OutlinedTextField(
                    value = masterPassword,
                    onValueChange = { masterPassword = it },
                    label = { Text("Master Password (min 9 chars)") },
                    modifier = Modifier.fillMaxWidth(),
                    singleLine = true,
                    visualTransformation = if (passwordVisible) androidx.compose.ui.text.input.VisualTransformation.None else PasswordVisualTransformation(),
                    trailingIcon = {
                        IconButton(onClick = { passwordVisible = !passwordVisible }) {
                            Text(text = if (passwordVisible) "👁️" else "🔒", fontSize = 16.sp)
                        }
                    },
                    shape = RoundedCornerShape(12.dp)
                )

                if (masterPassword.isNotEmpty() && masterPassword.length < 9) {
                    Text(
                        text = "Must be at least 9 characters (${masterPassword.length}/9)",
                        color = Color(0xFFFFB300),
                        style = MaterialTheme.typography.bodySmall,
                        modifier = Modifier.align(Alignment.Start).padding(start = 4.dp, top = 4.dp)
                    )
                }

                Spacer(modifier = Modifier.height(24.dp))

                Button(
                    onClick = { stage = OnboardingStage.CONFIRM_MASTER_PASSWORD },
                    modifier = Modifier.fillMaxWidth().height(50.dp),
                    shape = RoundedCornerShape(12.dp),
                    enabled = masterPassword.length >= 9
                ) {
                    Text("Continue", fontWeight = FontWeight.Bold)
                }

                Spacer(modifier = Modifier.height(8.dp))
                TextButton(onClick = { stage = OnboardingStage.EMAIL }) { Text("Back") }
            }

            OnboardingStage.CONFIRM_MASTER_PASSWORD -> {
                Text(
                    text = "Confirm Master Password",
                    style = MaterialTheme.typography.headlineSmall,
                    fontWeight = FontWeight.Bold
                )
                Text(
                    text = "Please re-type your Master Password exactly.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.padding(vertical = 6.dp)
                )

                Spacer(modifier = Modifier.height(16.dp))

                OutlinedTextField(
                    value = confirmPassword,
                    onValueChange = { confirmPassword = it },
                    label = { Text("Re-enter Master Password") },
                    modifier = Modifier.fillMaxWidth(),
                    singleLine = true,
                    visualTransformation = if (confirmPasswordVisible) androidx.compose.ui.text.input.VisualTransformation.None else PasswordVisualTransformation(),
                    trailingIcon = {
                        IconButton(onClick = { confirmPasswordVisible = !confirmPasswordVisible }) {
                            Text(text = if (confirmPasswordVisible) "👁️" else "🔒", fontSize = 16.sp)
                        }
                    },
                    shape = RoundedCornerShape(12.dp)
                )

                if (confirmPassword.isNotEmpty() && confirmPassword != masterPassword) {
                    Text(
                        text = "Passwords do not match",
                        color = MaterialTheme.colorScheme.error,
                        style = MaterialTheme.typography.bodySmall,
                        modifier = Modifier.align(Alignment.Start).padding(start = 4.dp, top = 4.dp)
                    )
                }

                Spacer(modifier = Modifier.height(24.dp))

                Button(
                    onClick = { stage = OnboardingStage.CREATE_PIN },
                    modifier = Modifier.fillMaxWidth().height(50.dp),
                    shape = RoundedCornerShape(12.dp),
                    enabled = confirmPassword.isNotEmpty() && confirmPassword == masterPassword
                ) {
                    Text("Confirm Password", fontWeight = FontWeight.Bold)
                }

                Spacer(modifier = Modifier.height(8.dp))
                TextButton(onClick = { stage = OnboardingStage.MASTER_PASSWORD }) { Text("Back") }
            }

            OnboardingStage.CREATE_PIN -> {
                Text(
                    text = "Create SecureVault PIN",
                    style = MaterialTheme.typography.headlineSmall,
                    fontWeight = FontWeight.Bold
                )
                Text(
                    text = "This 4-digit PIN is your primary daily unlock method. It is verified securely on this device.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.padding(vertical = 6.dp)
                )

                Spacer(modifier = Modifier.height(16.dp))

                OutlinedTextField(
                    value = pin,
                    onValueChange = { if (it.length <= 4 && it.all { c -> c.isDigit() }) pin = it },
                    label = { Text("4-Digit PIN") },
                    modifier = Modifier.fillMaxWidth(),
                    singleLine = true,
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.NumberPassword),
                    visualTransformation = if (pinVisible) androidx.compose.ui.text.input.VisualTransformation.None else PasswordVisualTransformation(),
                    trailingIcon = {
                        IconButton(onClick = { pinVisible = !pinVisible }) {
                            Text(text = if (pinVisible) "👁️" else "🔒", fontSize = 16.sp)
                        }
                    },
                    shape = RoundedCornerShape(12.dp)
                )

                Spacer(modifier = Modifier.height(24.dp))

                Button(
                    onClick = { stage = OnboardingStage.CONFIRM_PIN },
                    modifier = Modifier.fillMaxWidth().height(50.dp),
                    shape = RoundedCornerShape(12.dp),
                    enabled = pin.length == 4
                ) {
                    Text("Continue", fontWeight = FontWeight.Bold)
                }

                Spacer(modifier = Modifier.height(8.dp))
                TextButton(onClick = { stage = OnboardingStage.CONFIRM_MASTER_PASSWORD }) { Text("Back") }
            }

            OnboardingStage.CONFIRM_PIN -> {
                Text(
                    text = "Confirm 4-Digit PIN",
                    style = MaterialTheme.typography.headlineSmall,
                    fontWeight = FontWeight.Bold
                )
                Text(
                    text = "Re-enter your 4-digit PIN to confirm.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.padding(vertical = 6.dp)
                )

                Spacer(modifier = Modifier.height(16.dp))

                OutlinedTextField(
                    value = confirmPin,
                    onValueChange = { if (it.length <= 4 && it.all { c -> c.isDigit() }) confirmPin = it },
                    label = { Text("Re-enter 4-Digit PIN") },
                    modifier = Modifier.fillMaxWidth(),
                    singleLine = true,
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.NumberPassword),
                    visualTransformation = if (confirmPinVisible) androidx.compose.ui.text.input.VisualTransformation.None else PasswordVisualTransformation(),
                    trailingIcon = {
                        IconButton(onClick = { confirmPinVisible = !confirmPinVisible }) {
                            Text(text = if (confirmPinVisible) "👁️" else "🔒", fontSize = 16.sp)
                        }
                    },
                    shape = RoundedCornerShape(12.dp)
                )

                if (confirmPin.isNotEmpty() && confirmPin != pin) {
                    Text(
                        text = "PINs do not match",
                        color = MaterialTheme.colorScheme.error,
                        style = MaterialTheme.typography.bodySmall,
                        modifier = Modifier.align(Alignment.Start).padding(start = 4.dp, top = 4.dp)
                    )
                }

                Spacer(modifier = Modifier.height(24.dp))

                Button(
                    onClick = { stage = OnboardingStage.BIOMETRIC_SETUP },
                    modifier = Modifier.fillMaxWidth().height(50.dp),
                    shape = RoundedCornerShape(12.dp),
                    enabled = confirmPin.length == 4 && confirmPin == pin
                ) {
                    Text("Confirm PIN", fontWeight = FontWeight.Bold)
                }

                Spacer(modifier = Modifier.height(8.dp))
                TextButton(onClick = { stage = OnboardingStage.CREATE_PIN }) { Text("Back") }
            }

            OnboardingStage.BIOMETRIC_SETUP -> {
                Text(
                    text = "Fingerprint / Biometric",
                    style = MaterialTheme.typography.headlineSmall,
                    fontWeight = FontWeight.Bold
                )

                Surface(
                    shape = RoundedCornerShape(12.dp),
                    color = MaterialTheme.colorScheme.surfaceVariant,
                    modifier = Modifier.fillMaxWidth().padding(vertical = 12.dp)
                ) {
                    Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                        Text(
                            text = "🔐 Android Biometric Integration",
                            style = MaterialTheme.typography.labelLarge,
                            fontWeight = FontWeight.Bold
                        )
                        Text(
                            text = "Fingerprint enrollment is managed directly by Android OS security. SecureVault uses your enrolled biometric for fast daily unlock alongside your 4-digit PIN.",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                        if (!isBiometricEnrolled) {
                            Text(
                                text = "Notice: No fingerprint is currently enrolled in Android system settings on this device.",
                                style = MaterialTheme.typography.bodySmall,
                                color = Color(0xFFFFB300),
                                fontWeight = FontWeight.SemiBold
                            )
                        } else {
                            Text(
                                text = "✓ Fingerprint is available and enrolled on this device.",
                                style = MaterialTheme.typography.bodySmall,
                                color = Color(0xFF00E676),
                                fontWeight = FontWeight.SemiBold
                            )
                        }
                    }
                }

                Spacer(modifier = Modifier.height(16.dp))

                if (isBiometricEnrolled) {
                    Button(
                        onClick = {
                            enableBiometric = true
                            stage = OnboardingStage.VAULT_CREATED
                        },
                        modifier = Modifier.fillMaxWidth().height(50.dp),
                        shape = RoundedCornerShape(12.dp)
                    ) {
                        Text("Enable Fingerprint Unlock", fontWeight = FontWeight.Bold)
                    }

                    Spacer(modifier = Modifier.height(10.dp))

                    OutlinedButton(
                        onClick = {
                            enableBiometric = false
                            stage = OnboardingStage.VAULT_CREATED
                        },
                        modifier = Modifier.fillMaxWidth().height(50.dp),
                        shape = RoundedCornerShape(12.dp)
                    ) {
                        Text("Skip for now (Use PIN Only)")
                    }
                } else {
                    Button(
                        onClick = onOpenBiometricSettings,
                        modifier = Modifier.fillMaxWidth().height(50.dp),
                        shape = RoundedCornerShape(12.dp)
                    ) {
                        Text("Set up fingerprint in Android Settings")
                    }

                    Spacer(modifier = Modifier.height(10.dp))

                    OutlinedButton(
                        onClick = {
                            enableBiometric = false
                            stage = OnboardingStage.VAULT_CREATED
                        },
                        modifier = Modifier.fillMaxWidth().height(50.dp),
                        shape = RoundedCornerShape(12.dp)
                    ) {
                        Text("Skip for now (Use PIN Only)")
                    }
                }

                Spacer(modifier = Modifier.height(8.dp))
                TextButton(onClick = { stage = OnboardingStage.CONFIRM_PIN }) { Text("Back") }
            }

            OnboardingStage.VAULT_CREATED -> {
                Text(
                    text = "Vault Ready!",
                    style = MaterialTheme.typography.headlineMedium,
                    fontWeight = FontWeight.Black,
                    color = Color(0xFF00E676)
                )

                Surface(
                    shape = RoundedCornerShape(16.dp),
                    color = MaterialTheme.colorScheme.surfaceVariant,
                    modifier = Modifier.fillMaxWidth().padding(vertical = 16.dp)
                ) {
                    Column(
                        modifier = Modifier.padding(18.dp),
                        verticalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        Text("✓ 256-bit Vault Root Key Generated", fontWeight = FontWeight.Bold, color = Color(0xFF00E676))
                        Text("✓ Argon2id + Keystore Dual-Protected PIN", fontWeight = FontWeight.Bold, color = Color(0xFF00E676))
                        if (enableBiometric) {
                            Text("✓ Android Biometric Unlock Configured", fontWeight = FontWeight.Bold, color = Color(0xFF00E676))
                        } else {
                            Text("✓ Daily Unlock: 4-Digit SecureVault PIN", fontWeight = FontWeight.Bold, color = Color(0xFF00E5FF))
                        }
                        Text("✓ Master Password Encrypted for Safe Recovery", fontWeight = FontWeight.Bold, color = Color(0xFF00E676))
                    }
                }

                Spacer(modifier = Modifier.height(24.dp))

                Button(
                    onClick = { stage = OnboardingStage.ENTER_VAULT },
                    modifier = Modifier.fillMaxWidth().height(50.dp),
                    shape = RoundedCornerShape(12.dp)
                ) {
                    Text("Proceed", fontWeight = FontWeight.Bold)
                }
            }

            OnboardingStage.ENTER_VAULT -> {
                var isLoading by remember { mutableStateOf(false) }

                Text(
                    text = "Welcome, $displayName! 🎉",
                    style = MaterialTheme.typography.headlineSmall,
                    fontWeight = FontWeight.Black
                )
                Text(
                    text = "Your digital safe is sealed and ready for daily use.",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.padding(vertical = 8.dp)
                )

                Surface(
                    shape = RoundedCornerShape(16.dp),
                    color = Color(0xFF00E676).copy(alpha = 0.10f),
                    modifier = Modifier.fillMaxWidth().padding(vertical = 12.dp)
                ) {
                    Column(
                        modifier = Modifier.padding(16.dp),
                        verticalArrangement = Arrangement.spacedBy(6.dp)
                    ) {
                        Text("✓ Master Password configured", fontWeight = FontWeight.SemiBold, color = Color(0xFF00E676), style = MaterialTheme.typography.bodyMedium)
                        Text("✓ 4-Digit Daily PIN set up", fontWeight = FontWeight.SemiBold, color = Color(0xFF00E676), style = MaterialTheme.typography.bodyMedium)
                        if (enableBiometric) {
                            Text("✓ Biometric unlock enabled", fontWeight = FontWeight.SemiBold, color = Color(0xFF00E676), style = MaterialTheme.typography.bodyMedium)
                        }
                        Text("✓ Setup complete — ready to enter", fontWeight = FontWeight.SemiBold, color = Color(0xFF00E676), style = MaterialTheme.typography.bodyMedium)
                    }
                }

                if (!errorMessage.isNullOrEmpty()) {
                    Spacer(modifier = Modifier.height(6.dp))
                    Surface(
                        shape = RoundedCornerShape(8.dp),
                        color = Color(0xFFFFB300).copy(alpha = 0.12f),
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Text(
                            text = errorMessage,
                            color = Color(0xFFFFB300),
                            style = MaterialTheme.typography.bodySmall,
                            modifier = Modifier.padding(10.dp)
                        )
                    }
                }

                Spacer(modifier = Modifier.height(24.dp))

                Button(
                    onClick = {
                        if (!isLoading) {
                            isLoading = true
                            onComplete(displayName.trim(), email.trim(), masterPassword, pin, enableBiometric)
                        }
                    },
                    modifier = Modifier.fillMaxWidth().height(50.dp),
                    shape = RoundedCornerShape(12.dp),
                    enabled = !isLoading
                ) {
                    if (isLoading) {
                        CircularProgressIndicator(
                            modifier = Modifier.size(22.dp),
                            color = MaterialTheme.colorScheme.onPrimary,
                            strokeWidth = 2.dp
                        )
                        Spacer(modifier = Modifier.width(10.dp))
                        Text("Setting up your vault…", fontWeight = FontWeight.Bold)
                    } else {
                        Text("Enter SecureVault", fontWeight = FontWeight.Bold)
                    }
                }
            }
        }
    }
}

@Composable
fun SetupPinDialog(
    onDismiss: () -> Unit,
    onPinConfirmed: (String) -> Unit
) {
    var pin by remember { mutableStateOf("") }
    var confirmPin by remember { mutableStateOf("") }
    var error by remember { mutableStateOf<String?>(null) }

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Set 4-Digit Daily PIN", fontWeight = FontWeight.Bold) },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                Text(
                    text = "Your 4-digit PIN unlocks the vault on this device without retyping your Master Password.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )

                OutlinedTextField(
                    value = pin,
                    onValueChange = { if (it.length <= 4 && it.all { c -> c.isDigit() }) pin = it },
                    label = { Text("Enter 4-Digit PIN") },
                    visualTransformation = PasswordVisualTransformation(),
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.NumberPassword),
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth()
                )

                OutlinedTextField(
                    value = confirmPin,
                    onValueChange = { if (it.length <= 4 && it.all { c -> c.isDigit() }) confirmPin = it },
                    label = { Text("Confirm PIN") },
                    visualTransformation = PasswordVisualTransformation(),
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.NumberPassword),
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth()
                )

                val currentError = error
                if (currentError != null) {
                    Text(currentError, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall)
                }
            }
        },
        confirmButton = {
            Button(
                onClick = {
                    if (pin != confirmPin) {
                        error = "PINs do not match"
                    } else if (pin.length != 4) {
                        error = "PIN must be exactly 4 digits"
                    } else {
                        onPinConfirmed(pin)
                    }
                },
                enabled = pin.length == 4
            ) {
                Text("Set PIN")
            }
        },
        dismissButton = {
            OutlinedButton(onClick = onDismiss) { Text("Cancel") }
        }
    )
}

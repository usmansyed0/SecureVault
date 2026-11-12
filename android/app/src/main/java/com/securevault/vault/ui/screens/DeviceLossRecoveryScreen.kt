package com.securevault.vault.ui.screens

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.core.tween
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.outlined.ArrowBack
import androidx.compose.material.icons.outlined.CheckCircle
import androidx.compose.material.icons.outlined.Key
import androidx.compose.material.icons.outlined.Lock
import androidx.compose.material.icons.outlined.Shield
import androidx.compose.material.icons.outlined.Warning
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.securevault.vault.ui.theme.VaultRadius
import com.securevault.vault.ui.theme.VaultSpacing

enum class RecoveryMethod {
    VAULT_PASSWORD,
    RECOVERY_PHRASE
}

enum class RecoveryStep {
    ENTER_CREDENTIALS,
    VERIFYING,
    SETUP_NEW_PIN,
    COMPLETE
}

/**
 * Guided 3-step wizard for recovering a vault when a user has lost their device.
 *
 * Step 1: User chooses to authenticate with Vault Password OR 24-Word Recovery Phrase
 * Step 2: Key derivation and VRK unwrapping with zero-knowledge guarantees
 * Step 3: Re-establish local hardware PIN / biometrics for the new device
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun DeviceLossRecoveryScreen(
    onUnlockWithPassword: (password: String) -> Boolean,
    onUnlockWithRecoveryKey: (phraseOrHex: String) -> Boolean,
    onSetupNewPin: (pin: String) -> Unit,
    onRecoveryComplete: () -> Unit,
    onCancel: () -> Unit
) {
    var step by remember { mutableStateOf(RecoveryStep.ENTER_CREDENTIALS) }
    var method by remember { mutableStateOf(RecoveryMethod.VAULT_PASSWORD) }

    var vaultPassword by remember { mutableStateOf("") }
    var passwordVisible by remember { mutableStateOf(false) }

    var recoveryPhrase by remember { mutableStateOf("") }

    var newPin by remember { mutableStateOf("") }
    var confirmPin by remember { mutableStateOf("") }

    var errorMessage by remember { mutableStateOf<String?>(null) }
    var isProcessing by remember { mutableStateOf(false) }

    val scrollState = rememberScrollState()

    Scaffold(
        topBar = {
            TopAppBar(
                title = {
                    Text(
                        text = "Device Loss Recovery",
                        style = MaterialTheme.typography.titleLarge,
                        fontWeight = FontWeight.Bold
                    )
                },
                navigationIcon = {
                    IconButton(
                        onClick = onCancel,
                        modifier = Modifier.semantics { contentDescription = "Cancel recovery" }
                    ) {
                        Icon(Icons.AutoMirrored.Outlined.ArrowBack, contentDescription = null)
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = MaterialTheme.colorScheme.background
                )
            )
        }
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(horizontal = VaultSpacing.lg)
                .verticalScroll(scrollState),
            verticalArrangement = Arrangement.spacedBy(VaultSpacing.lg),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            Spacer(modifier = Modifier.height(VaultSpacing.xs))

            // ── Step indicator ───────────────────────────────────────────────
            StepIndicatorRow(currentStep = step)

            // ── Error notice ─────────────────────────────────────────────────
            errorMessage?.let { error ->
                Surface(
                    shape = RoundedCornerShape(VaultRadius.md),
                    color = MaterialTheme.colorScheme.errorContainer,
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Row(
                        modifier = Modifier.padding(VaultSpacing.md),
                        horizontalArrangement = Arrangement.spacedBy(VaultSpacing.sm),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Icon(
                            imageVector = Icons.Outlined.Warning,
                            contentDescription = "Error",
                            tint = MaterialTheme.colorScheme.error
                        )
                        Text(
                            text = error,
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onErrorContainer
                        )
                    }
                }
            }

            when (step) {
                RecoveryStep.ENTER_CREDENTIALS, RecoveryStep.VERIFYING -> {
                    // Header Card with zero-knowledge reassurance
                    Surface(
                        shape = RoundedCornerShape(VaultRadius.lg),
                        color = MaterialTheme.colorScheme.surfaceVariant,
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Column(
                            modifier = Modifier.padding(VaultSpacing.lg),
                            verticalArrangement = Arrangement.spacedBy(VaultSpacing.xs + 2.dp)
                        ) {
                            Row(
                                verticalAlignment = Alignment.CenterVertically,
                                horizontalArrangement = Arrangement.spacedBy(VaultSpacing.sm)
                            ) {
                                Icon(
                                    imageVector = Icons.Outlined.Shield,
                                    contentDescription = null,
                                    tint = MaterialTheme.colorScheme.primary,
                                    modifier = Modifier.size(24.dp)
                                )
                                Text(
                                    text = "Zero-Knowledge Safe Recovery",
                                    style = MaterialTheme.typography.titleMedium,
                                    fontWeight = FontWeight.Bold
                                )
                            }
                            Text(
                                text = "Recover your vault on this new device using either your Vault Password or your 24-word Recovery Key. Neither is ever stored in plaintext.",
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                        }
                    }

                    // Method selector tabs
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(VaultSpacing.sm)
                    ) {
                        FilterChip(
                            selected = method == RecoveryMethod.VAULT_PASSWORD,
                            onClick = { method = RecoveryMethod.VAULT_PASSWORD; errorMessage = null },
                            label = { Text("Vault Password") },
                            modifier = Modifier
                                .weight(1f)
                                .semantics { contentDescription = "Recover using Vault Password" }
                        )
                        FilterChip(
                            selected = method == RecoveryMethod.RECOVERY_PHRASE,
                            onClick = { method = RecoveryMethod.RECOVERY_PHRASE; errorMessage = null },
                            label = { Text("24-Word Recovery Key") },
                            modifier = Modifier
                                .weight(1f)
                                .semantics { contentDescription = "Recover using 24-Word Phrase" }
                        )
                    }

                    if (method == RecoveryMethod.VAULT_PASSWORD) {
                        OutlinedTextField(
                            value = vaultPassword,
                            onValueChange = { vaultPassword = it; errorMessage = null },
                            label = { Text("Vault Password") },
                            placeholder = { Text("Enter your master vault password") },
                            modifier = Modifier
                                .fillMaxWidth()
                                .semantics { contentDescription = "Vault password input" },
                            singleLine = true,
                            visualTransformation = if (passwordVisible) VisualTransformation.None else PasswordVisualTransformation(),
                            trailingIcon = {
                                IconButton(
                                    onClick = { passwordVisible = !passwordVisible },
                                    modifier = Modifier.semantics {
                                        contentDescription = if (passwordVisible) "Hide password" else "Show password"
                                    }
                                ) {
                                    Text(if (passwordVisible) "👁️" else "🔒", fontSize = 16.sp)
                                }
                            },
                            shape = RoundedCornerShape(VaultRadius.md)
                        )
                    } else {
                        OutlinedTextField(
                            value = recoveryPhrase,
                            onValueChange = { recoveryPhrase = it; errorMessage = null },
                            label = { Text("24-Word Recovery Phrase") },
                            placeholder = { Text("e.g. apple banana cherry dog elephant...") },
                            modifier = Modifier
                                .fillMaxWidth()
                                .height(130.dp)
                                .semantics { contentDescription = "24-word recovery phrase input" },
                            maxLines = 5,
                            shape = RoundedCornerShape(VaultRadius.md)
                        )

                        val wordCount = recoveryPhrase.trim().split(Regex("\\s+")).filter { it.isNotBlank() }.size
                        Text(
                            text = "Words entered: $wordCount / 24",
                            style = MaterialTheme.typography.labelSmall,
                            color = if (wordCount == 24) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurfaceVariant,
                            modifier = Modifier.fillMaxWidth()
                        )
                    }

                    Button(
                        onClick = {
                            errorMessage = null
                            isProcessing = true
                            step = RecoveryStep.VERIFYING

                            val success = if (method == RecoveryMethod.VAULT_PASSWORD) {
                                onUnlockWithPassword(vaultPassword)
                            } else {
                                onUnlockWithRecoveryKey(recoveryPhrase)
                            }

                            isProcessing = false
                            if (success) {
                                step = RecoveryStep.SETUP_NEW_PIN
                            } else {
                                step = RecoveryStep.ENTER_CREDENTIALS
                                errorMessage = if (method == RecoveryMethod.VAULT_PASSWORD) {
                                    "Invalid vault password. Please verify and try again."
                                } else {
                                    "Invalid recovery key. Check word spelling and phrase checksum."
                                }
                            }
                        },
                        modifier = Modifier
                            .fillMaxWidth()
                            .height(52.dp)
                            .semantics { contentDescription = "Verify and restore vault credentials" },
                        enabled = !isProcessing && (
                            (method == RecoveryMethod.VAULT_PASSWORD && vaultPassword.length >= 8) ||
                            (method == RecoveryMethod.RECOVERY_PHRASE && recoveryPhrase.trim().isNotBlank())
                        ),
                        shape = RoundedCornerShape(VaultRadius.md)
                    ) {
                        if (isProcessing) {
                            CircularProgressIndicator(
                                color = MaterialTheme.colorScheme.onPrimary,
                                modifier = Modifier.size(24.dp),
                                strokeWidth = 2.dp
                            )
                        } else {
                            Icon(Icons.Outlined.Key, contentDescription = null, modifier = Modifier.size(20.dp))
                            Spacer(Modifier.width(8.dp))
                            Text("Verify & Unlock Vault", fontWeight = FontWeight.Bold)
                        }
                    }
                }

                RecoveryStep.SETUP_NEW_PIN -> {
                    Surface(
                        shape = RoundedCornerShape(VaultRadius.lg),
                        color = MaterialTheme.colorScheme.primaryContainer.copy(alpha = 0.5f),
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Row(
                            modifier = Modifier.padding(VaultSpacing.lg),
                            horizontalArrangement = Arrangement.spacedBy(VaultSpacing.md),
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Icon(
                                imageVector = Icons.Outlined.CheckCircle,
                                contentDescription = null,
                                tint = MaterialTheme.colorScheme.primary,
                                modifier = Modifier.size(28.dp)
                            )
                            Column {
                                Text(
                                    text = "Vault Decrypted Successfully!",
                                    style = MaterialTheme.typography.titleMedium,
                                    fontWeight = FontWeight.Bold
                                )
                                Text(
                                    text = "Now establish a new PIN and enroll biometrics for quick access on this device.",
                                    style = MaterialTheme.typography.bodySmall,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant
                                )
                            }
                        }
                    }

                    OutlinedTextField(
                        value = newPin,
                        onValueChange = { if (it.length <= 6 && it.all { char -> char.isDigit() }) newPin = it },
                        label = { Text("New Device PIN (4 to 6 digits)") },
                        modifier = Modifier
                            .fillMaxWidth()
                            .semantics { contentDescription = "Enter new device PIN" },
                        singleLine = true,
                        visualTransformation = PasswordVisualTransformation(),
                        shape = RoundedCornerShape(VaultRadius.md)
                    )

                    OutlinedTextField(
                        value = confirmPin,
                        onValueChange = { if (it.length <= 6 && it.all { char -> char.isDigit() }) confirmPin = it },
                        label = { Text("Confirm New Device PIN") },
                        modifier = Modifier
                            .fillMaxWidth()
                            .semantics { contentDescription = "Confirm new device PIN" },
                        singleLine = true,
                        visualTransformation = PasswordVisualTransformation(),
                        shape = RoundedCornerShape(VaultRadius.md)
                    )

                    Button(
                        onClick = {
                            if (newPin != confirmPin) {
                                errorMessage = "PINs do not match. Please re-enter."
                                return@Button
                            }
                            if (newPin.length < 4) {
                                errorMessage = "PIN must be at least 4 digits."
                                return@Button
                            }
                            onSetupNewPin(newPin)
                            step = RecoveryStep.COMPLETE
                        },
                        modifier = Modifier
                            .fillMaxWidth()
                            .height(52.dp)
                            .semantics { contentDescription = "Save new PIN and complete recovery" },
                        enabled = newPin.length >= 4 && confirmPin.length >= 4,
                        shape = RoundedCornerShape(VaultRadius.md)
                    ) {
                        Icon(Icons.Outlined.Lock, contentDescription = null, modifier = Modifier.size(20.dp))
                        Spacer(Modifier.width(8.dp))
                        Text("Save PIN & Complete Setup", fontWeight = FontWeight.Bold)
                    }
                }

                RecoveryStep.COMPLETE -> {
                    Surface(
                        shape = RoundedCornerShape(VaultRadius.lg),
                        color = MaterialTheme.colorScheme.primaryContainer,
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Column(
                            modifier = Modifier.padding(VaultSpacing.xl),
                            horizontalAlignment = Alignment.CenterHorizontally,
                            verticalArrangement = Arrangement.spacedBy(VaultSpacing.md)
                        ) {
                            Icon(
                                imageVector = Icons.Outlined.CheckCircle,
                                contentDescription = null,
                                tint = MaterialTheme.colorScheme.primary,
                                modifier = Modifier.size(56.dp)
                            )
                            Text(
                                text = "Device Recovery Complete!",
                                style = MaterialTheme.typography.titleLarge,
                                fontWeight = FontWeight.Bold,
                                textAlign = TextAlign.Center
                            )
                            Text(
                                text = "This device is now securely paired with your encrypted vault. You can now access your passwords, notes, and documents.",
                                style = MaterialTheme.typography.bodyMedium,
                                textAlign = TextAlign.Center,
                                color = MaterialTheme.colorScheme.onPrimaryContainer.copy(alpha = 0.8f)
                            )

                            Spacer(modifier = Modifier.height(VaultSpacing.sm))

                            Button(
                                onClick = onRecoveryComplete,
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .height(52.dp)
                                    .semantics { contentDescription = "Enter vault" },
                                shape = RoundedCornerShape(VaultRadius.md)
                            ) {
                                Text("Enter Vault", fontWeight = FontWeight.Bold)
                            }
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun StepIndicatorRow(currentStep: RecoveryStep) {
    val steps = listOf("1. Authenticate", "2. Set PIN", "3. Complete")
    val currentIndex = when (currentStep) {
        RecoveryStep.ENTER_CREDENTIALS, RecoveryStep.VERIFYING -> 0
        RecoveryStep.SETUP_NEW_PIN -> 1
        RecoveryStep.COMPLETE -> 2
    }

    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically
    ) {
        steps.forEachIndexed { index, label ->
            val isActive = index == currentIndex
            val isDone = index < currentIndex

            Surface(
                shape = RoundedCornerShape(VaultRadius.sm),
                color = when {
                    isDone -> MaterialTheme.colorScheme.primaryContainer
                    isActive -> MaterialTheme.colorScheme.primary
                    else -> MaterialTheme.colorScheme.surfaceVariant
                },
                modifier = Modifier.weight(1f).padding(horizontal = 2.dp)
            ) {
                Text(
                    text = label,
                    style = MaterialTheme.typography.labelSmall,
                    fontWeight = if (isActive) FontWeight.Bold else FontWeight.Normal,
                    color = when {
                        isActive -> MaterialTheme.colorScheme.onPrimary
                        isDone -> MaterialTheme.colorScheme.onPrimaryContainer
                        else -> MaterialTheme.colorScheme.onSurfaceVariant
                    },
                    textAlign = TextAlign.Center,
                    modifier = Modifier.padding(vertical = 6.dp)
                )
            }
        }
    }
}

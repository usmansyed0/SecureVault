package com.securevault.vault.ui.screens

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.outlined.ArrowBack
import androidx.compose.material.icons.outlined.Shield
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.net.toUri
import com.securevault.vault.ui.PasswordGeneratorDialog
import com.securevault.vault.ui.VaultCoordinator
import com.securevault.vault.ui.theme.VaultRadius
import com.securevault.vault.ui.theme.VaultSpacing
import com.securevault.vault.ui.theme.VaultThemeOption

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SettingsScreen(
    currentTheme: VaultThemeOption,
    onThemeSelected: (VaultThemeOption) -> Unit,
    coordinator: VaultCoordinator,
    onNavigateToDevices: () -> Unit,
    onNavigateToShares: () -> Unit,
    onNavigateToStatistics: () -> Unit,
    onSetupPin: () -> Unit,
    onLockVault: () -> Unit,
    onLogout: () -> Unit,
    onDeleteAccount: () -> Unit = {},
    deadManDays: Int = 7,
    onDeadManDaysChanged: (Int) -> Unit = {},
    onBack: () -> Unit
) {
    val context = LocalContext.current
    val scrollState = rememberScrollState()
    var showThemeDialog by remember { mutableStateOf(false) }
    var showGeneratorDialog by remember { mutableStateOf(false) }
    var showStrengthDialog by remember { mutableStateOf(false) }
    var showDeadManDialog by remember { mutableStateOf(false) }
    var currentDeadManDays by remember(deadManDays) { mutableStateOf(deadManDays) }
    var backupStatusMsg by remember { mutableStateOf<String?>(null) }

    Scaffold(
        topBar = {
            TopAppBar(
                title = {
                    Text(
                        text = "Settings",
                        style = MaterialTheme.typography.titleLarge,
                        fontWeight = FontWeight.Bold
                    )
                },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Outlined.ArrowBack, contentDescription = "Back")
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
                .verticalScroll(scrollState)
                .padding(horizontal = VaultSpacing.lg, vertical = VaultSpacing.sm),
            verticalArrangement = Arrangement.spacedBy(VaultSpacing.lg)
        ) {
            // Backup status snackbar/banner
            backupStatusMsg?.let { msg ->
                Surface(
                    shape = RoundedCornerShape(10.dp),
                    color = MaterialTheme.colorScheme.primaryContainer,
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Text(
                        text = msg,
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onPrimaryContainer,
                        modifier = Modifier.padding(12.dp)
                    )
                }
            }

            // Security Group
            SettingsGroup(title = "SECURITY & UNLOCK") {
                SettingsItem(
                    icon = "🔢",
                    title = "Change 4-Digit PIN",
                    subtitle = "Argon2id + Keystore dual-protected daily unlock",
                    onClick = onSetupPin
                )
                SettingsItem(
                    icon = "👆",
                    title = "Biometric Unlock",
                    subtitle = "Android Keystore hardware-bound fingerprint/face",
                    onClick = {}
                )
                SettingsItem(
                    icon = "⏱️",
                    title = "Auto-Lock Policy",
                    subtitle = "Inactivity lock after 60 seconds of idle time",
                    onClick = {}
                )
                SettingsItem(
                    icon = "💀",
                    title = "Offline Dead-Man Switch",
                    subtitle = "Wipe vault if offline for more than $currentDeadManDays days",
                    onClick = { showDeadManDialog = true }
                )
            }

            // Sync & Backup Group
            SettingsGroup(title = "BACKUP & MULTI-DEVICE") {
                SettingsItem(
                    icon = "☁️",
                    title = "Create Encrypted Cloud Backup",
                    subtitle = "End-to-end encrypted backup manifest",
                    onClick = {
                        coordinator.createCloudBackup(
                            onSuccess = { backupStatusMsg = "Encrypted cloud backup created successfully!" },
                            onError = { backupStatusMsg = "Backup error: $it" }
                        )
                    }
                )
                SettingsItem(
                    icon = "📱",
                    title = "Connected Devices",
                    subtitle = "Manage enrolled phones, tablets, and desktops",
                    onClick = onNavigateToDevices
                )
                SettingsItem(
                    icon = "🔗",
                    title = "Active Shared Links",
                    subtitle = "Manage expiring links and view count",
                    onClick = onNavigateToShares
                )
            }

            // Emergency Access & Device Loss Group
            SettingsGroup(title = "EMERGENCY ACCESS & DEVICE LOSS") {
                Surface(
                    shape = RoundedCornerShape(12.dp),
                    color = MaterialTheme.colorScheme.primaryContainer.copy(alpha = 0.35f),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Column(
                        modifier = Modifier.padding(14.dp),
                        verticalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        Row(
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.spacedBy(8.dp)
                        ) {
                            Icon(
                                imageVector = Icons.Outlined.Shield,
                                contentDescription = null,
                                tint = MaterialTheme.colorScheme.primary,
                                modifier = Modifier.size(22.dp)
                            )
                            Text(
                                text = "Device-Loss Preparation Guide",
                                style = MaterialTheme.typography.titleSmall,
                                fontWeight = FontWeight.Bold
                            )
                        }
                        Text(
                            text = "If your phone is lost, stolen, or damaged, you can restore your vault on another device using your 24-Word Recovery Key or your Vault Password.\n\n" +
                                "1. Write down your 24-Word Recovery Key and store it in a secure physical location (fireproof safe).\n" +
                                "2. Never store your recovery key unencrypted on cloud drives or screenshots.\n" +
                                "3. If a device is lost, use Connected Devices to revoke access immediately.",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                }
            }

            // Customization & Tools Group
            SettingsGroup(title = "PREFERENCES & UTILITIES") {
                SettingsItem(
                    icon = "🎨",
                    title = "Appearance & Themes",
                    subtitle = currentTheme.displayName,
                    onClick = { showThemeDialog = true }
                )
                SettingsItem(
                    icon = "📊",
                    title = "Vault Statistics",
                    subtitle = "Item counts and storage insights",
                    onClick = onNavigateToStatistics
                )
                SettingsItem(
                    icon = "⚙️",
                    title = "Password Generator",
                    subtitle = "Generate high-entropy cryptographic keys",
                    onClick = { showGeneratorDialog = true }
                )
                SettingsItem(
                    icon = "🛡️",
                    title = "Password Strength Meter",
                    subtitle = "Analyze credential entropy and estimated crack times",
                    onClick = { showStrengthDialog = true }
                )
            }

            // Legal & Privacy Group (Play Store requirement — Phase 6)
            SettingsGroup(title = "LEGAL & PRIVACY") {
                SettingsItem(
                    icon = "\uD83D\uDCC4",
                    title = "Privacy Policy",
                    subtitle = "How your data is collected, used, and deleted",
                    onClick = {
                        val intent = android.content.Intent(
                            android.content.Intent.ACTION_VIEW,
                            "https://securevault.app/privacy".toUri()
                        )
                        context.startActivity(intent)
                    }
                )
                SettingsItem(
                    icon = "\uD83D\uDCCB",
                    title = "Terms of Service",
                    subtitle = "Usage terms and conditions",
                    onClick = {
                        val intent = android.content.Intent(
                            android.content.Intent.ACTION_VIEW,
                            "https://securevault.app/terms".toUri()
                        )
                        context.startActivity(intent)
                    }
                )
                SettingsItem(
                    icon = "\uD83D\uDDD1\uFE0F",
                    title = "Request Account Deletion",
                    subtitle = "Submit a deletion request via the web portal",
                    onClick = {
                        val intent = android.content.Intent(
                            android.content.Intent.ACTION_VIEW,
                            "https://securevault.app/account-deletion".toUri()
                        )
                        context.startActivity(intent)
                    }
                )
            }

            // Lock vs Logout
            SettingsGroup(title = "SESSION MANAGEMENT") {
                SettingsItem(
                    icon = "\uD83D\uDD12",
                    title = "Lock Vault",
                    subtitle = "Daily protection — PIN/biometric unlock remains available",
                    onClick = onLockVault
                )
                SettingsItem(
                    icon = "\uD83D\uDEAA",
                    title = "Account Logout",
                    subtitle = "Terminates account session — Master Password required next time",
                    titleColor = MaterialTheme.colorScheme.error,
                    onClick = onLogout
                )
                SettingsItem(
                    icon = "\u26A0\uFE0F",
                    title = "Delete Account",
                    subtitle = "Permanently delete vault, all records, and account data",
                    titleColor = MaterialTheme.colorScheme.error,
                    onClick = onDeleteAccount
                )
            }
        }
    }

    // Theme Picker Dialog
    if (showThemeDialog) {
        AlertDialog(
            onDismissRequest = { showThemeDialog = false },
            title = { Text("Select Vault Theme", fontWeight = FontWeight.Bold) },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    VaultThemeOption.entries.forEach { theme ->
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .clip(RoundedCornerShape(10.dp))
                                .clickable {
                                    onThemeSelected(theme)
                                    showThemeDialog = false
                                }
                                .padding(12.dp),
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            RadioButton(
                                selected = currentTheme == theme,
                                onClick = {
                                    onThemeSelected(theme)
                                    showThemeDialog = false
                                }
                            )
                            Spacer(modifier = Modifier.width(8.dp))
                            Text(theme.displayName, style = MaterialTheme.typography.bodyMedium)
                        }
                    }
                }
            },
            confirmButton = {
                TextButton(onClick = { showThemeDialog = false }) { Text("Close") }
            }
        )
    }

    // Offline Dead-Man Switch Dialog
    if (showDeadManDialog) {
        AlertDialog(
            onDismissRequest = { showDeadManDialog = false },
            title = { Text("Offline Dead-Man Switch", fontWeight = FontWeight.Bold) },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(VaultSpacing.sm)) {
                    Text(
                        "If this device remains offline with no connection to the server for longer than the selected threshold, the local vault will automatically wipe itself to protect against hardware extraction.",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                    Spacer(modifier = Modifier.height(8.dp))
                    listOf(1, 3, 7, 14, 30).forEach { days ->
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .clickable {
                                    currentDeadManDays = days
                                    onDeadManDaysChanged(days)
                                    showDeadManDialog = false
                                }
                                .padding(vertical = 8.dp),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Text(
                                text = "$days days" + if (days == 7) " (Default)" else "",
                                fontWeight = if (days == currentDeadManDays) FontWeight.Bold else FontWeight.Normal,
                                color = if (days == currentDeadManDays) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurface
                            )
                            if (days == currentDeadManDays) {
                                Text("✓", color = MaterialTheme.colorScheme.primary, fontWeight = FontWeight.Bold)
                            }
                        }
                    }
                }
            },
            confirmButton = {
                TextButton(onClick = { showDeadManDialog = false }) {
                    Text("Close")
                }
            }
        )
    }

    // Standalone Password Generator Dialog
    if (showGeneratorDialog) {
        PasswordGeneratorDialog(
            generator = coordinator.generator,
            strengthMeter = coordinator.strengthMeter,
            onDismiss = { showGeneratorDialog = false },
            onPasswordSelected = { pwd ->
                coordinator.copyToClipboard(pwd, "Generated Password", isSensitive = true)
                showGeneratorDialog = false
            }
        )
    }

    if (showStrengthDialog) {
        var testPassword by remember { mutableStateOf("") }
        val strengthResult = remember(testPassword) { coordinator.strengthMeter.evaluate(testPassword) }
        AlertDialog(
            onDismissRequest = { showStrengthDialog = false },
            title = { Text("Password Strength Meter", fontWeight = FontWeight.Bold) },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                    Text(
                        text = "Test credential entropy and estimated cracking time:",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                    OutlinedTextField(
                        value = testPassword,
                        onValueChange = { testPassword = it },
                        label = { Text("Test Password") },
                        modifier = Modifier.fillMaxWidth(),
                        singleLine = true
                    )
                    if (testPassword.isNotEmpty()) {
                        com.securevault.vault.ui.PasswordStrengthBar(result = strengthResult)
                    }
                }
            },
            confirmButton = {
                Button(onClick = { showStrengthDialog = false }) {
                    Text("Done")
                }
            }
        )
    }
}

@Composable
fun SettingsGroup(
    title: String,
    content: @Composable ColumnScope.() -> Unit
) {
    Column(verticalArrangement = Arrangement.spacedBy(VaultSpacing.xs + 2.dp)) {
        Text(
            text = title,
            style = MaterialTheme.typography.labelSmall,
            fontWeight = FontWeight.Bold,
            letterSpacing = 1.sp,
            color = MaterialTheme.colorScheme.primary,
            modifier = Modifier.padding(start = VaultSpacing.xs)
        )
        Surface(
            shape = RoundedCornerShape(VaultRadius.lg),
            color = MaterialTheme.colorScheme.surfaceVariant,
            modifier = Modifier.fillMaxWidth()
        ) {
            Column(
                modifier = Modifier.padding(VaultSpacing.sm),
                verticalArrangement = Arrangement.spacedBy(2.dp),
                content = content
            )
        }
    }
}

@Composable
fun SettingsItem(
    icon: String,
    title: String,
    subtitle: String,
    titleColor: Color = Color.Unspecified,
    onClick: () -> Unit
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(VaultRadius.md))
            .clickable(onClick = onClick)
            .padding(VaultSpacing.md),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.SpaceBetween
    ) {
        Row(
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(VaultSpacing.md),
            modifier = Modifier.weight(1f)
        ) {
            Text(icon, style = MaterialTheme.typography.titleMedium)
            Column {
                Text(
                    text = title,
                    style = MaterialTheme.typography.bodyMedium,
                    fontWeight = FontWeight.SemiBold,
                    color = if (titleColor != Color.Unspecified) titleColor
                            else MaterialTheme.colorScheme.onSurface
                )
                Text(
                    text = subtitle,
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        }
        Text(
            text = "›",
            style = MaterialTheme.typography.titleLarge,
            color = MaterialTheme.colorScheme.outline
        )
    }
}

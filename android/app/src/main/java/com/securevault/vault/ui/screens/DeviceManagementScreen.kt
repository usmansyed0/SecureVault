package com.securevault.vault.ui.screens

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.core.tween
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.slideInVertically
import androidx.compose.animation.slideOutVertically
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.outlined.ArrowBack
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalUriHandler
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.securevault.network.model.DeviceDto
import com.securevault.vault.ui.theme.VaultRadius
import com.securevault.vault.ui.theme.VaultSpacing

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun DeviceManagementScreen(
    devices: List<DeviceDto>,
    currentDeviceId: String?,
    onRevokeDevice: (String) -> Unit,
    onMarkDeviceStolen: (String) -> Unit,
    onEndDeviceSessions: (String) -> Unit,
    onSignOutAllOthers: () -> Unit,
    onBack: () -> Unit
) {
    val uriHandler = LocalUriHandler.current
    var deviceToMarkStolen by remember { mutableStateOf<DeviceDto?>(null) }
    var deviceToRevoke by remember { mutableStateOf<DeviceDto?>(null) }
    var showSignOutOthersDialog by remember { mutableStateOf(false) }
    var showRotationAdviceDialog by remember { mutableStateOf(false) }

    // Dialog: Confirm Report Stolen
    deviceToMarkStolen?.let { dev ->
        AlertDialog(
            onDismissRequest = { deviceToMarkStolen = null },
            title = {
                Text(
                    text = "⚠️ Report Device as Stolen?",
                    fontWeight = FontWeight.Bold,
                    color = MaterialTheme.colorScheme.error
                )
            },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(VaultSpacing.sm)) {
                    Text("Device: ${dev.name} (${dev.platform})")
                    Text(
                        "Reporting this device as STOLEN immediately:\n" +
                        "• Terminates all active sessions\n" +
                        "• Deletes cloud session credentials\n" +
                        "• Commands the phone to wipe all cryptographic keys and local databases on next contact\n" +
                        "• Bumps your account revocation generation",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
            },
            confirmButton = {
                Button(
                    onClick = {
                        val id = dev.id
                        deviceToMarkStolen = null
                        onMarkDeviceStolen(id)
                        showRotationAdviceDialog = true
                    },
                    colors = ButtonDefaults.buttonColors(containerColor = MaterialTheme.colorScheme.error)
                ) {
                    Text("Confirm Stolen & Wipe")
                }
            },
            dismissButton = {
                TextButton(onClick = { deviceToMarkStolen = null }) {
                    Text("Cancel")
                }
            }
        )
    }

    // Dialog: Post-Theft Key Rotation Recommendation
    if (showRotationAdviceDialog) {
        AlertDialog(
            onDismissRequest = { showRotationAdviceDialog = false },
            title = {
                Text("🛡️ Recommended: Rotate Vault Key", fontWeight = FontWeight.Bold)
            },
            text = {
                Text(
                    "The device has been reported stolen. To ensure total zero-knowledge security against memory extraction or stolen hardware, we strongly recommend:\n\n" +
                    "1. Changing your Vault Password in Settings\n" +
                    "2. Rotating passwords on sensitive accounts stored in your vault\n" +
                    "3. Using Google Find Hub to lock or erase the phone hardware",
                    style = MaterialTheme.typography.bodyMedium
                )
            },
            confirmButton = {
                Button(onClick = {
                    showRotationAdviceDialog = false
                    uriHandler.openUri("https://www.google.com/android/find")
                }) {
                    Text("Open Google Find Hub")
                }
            },
            dismissButton = {
                TextButton(onClick = { showRotationAdviceDialog = false }) {
                    Text("Done")
                }
            }
        )
    }

    // Dialog: Confirm Revoke
    deviceToRevoke?.let { dev ->
        AlertDialog(
            onDismissRequest = { deviceToRevoke = null },
            title = { Text("Revoke Device Access?") },
            text = {
                Text("Are you sure you want to revoke '${dev.name}'? It will no longer be able to sync or access vault records.")
            },
            confirmButton = {
                Button(onClick = {
                    val id = dev.id
                    deviceToRevoke = null
                    onRevokeDevice(id)
                }) {
                    Text("Revoke Access")
                }
            },
            dismissButton = {
                TextButton(onClick = { deviceToRevoke = null }) {
                    Text("Cancel")
                }
            }
        )
    }

    // Dialog: Confirm Sign Out All Others
    if (showSignOutOthersDialog) {
        AlertDialog(
            onDismissRequest = { showSignOutOthersDialog = false },
            title = { Text("Sign Out All Other Devices?") },
            text = {
                Text("All active sessions on all enrolled devices except this one will be terminated immediately.")
            },
            confirmButton = {
                Button(onClick = {
                    showSignOutOthersDialog = false
                    onSignOutAllOthers()
                }) {
                    Text("Sign Out Others")
                }
            },
            dismissButton = {
                TextButton(onClick = { showSignOutOthersDialog = false }) {
                    Text("Cancel")
                }
            }
        )
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = {
                    Text(
                        text = "Device Management",
                        style = MaterialTheme.typography.titleLarge,
                        fontWeight = FontWeight.Bold
                    )
                },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Outlined.ArrowBack, contentDescription = "Back")
                    }
                },
                actions = {
                    if (devices.size > 1) {
                        TextButton(onClick = { showSignOutOthersDialog = true }) {
                            Text("Sign Out Others", color = MaterialTheme.colorScheme.primary)
                        }
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
                .padding(horizontal = VaultSpacing.lg),
            verticalArrangement = Arrangement.spacedBy(VaultSpacing.md)
        ) {
            // Security Info Banner
            Surface(
                shape = RoundedCornerShape(VaultRadius.lg),
                color = MaterialTheme.colorScheme.surfaceVariant,
                modifier = Modifier.fillMaxWidth()
            ) {
                Row(
                    modifier = Modifier.padding(VaultSpacing.lg),
                    horizontalArrangement = Arrangement.spacedBy(VaultSpacing.md),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Text("📱", style = MaterialTheme.typography.headlineSmall)
                    Column {
                        Text(
                            text = "Active Device Security",
                            style = MaterialTheme.typography.titleSmall,
                            fontWeight = FontWeight.Bold
                        )
                        Text(
                            text = "If a device is marked stolen, local cryptographic access is destroyed immediately upon sync.",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                }
            }

            // Google Find Hub Banner
            Surface(
                shape = RoundedCornerShape(VaultRadius.md),
                color = MaterialTheme.colorScheme.primaryContainer.copy(alpha = 0.4f),
                modifier = Modifier
                    .fillMaxWidth()
                    .clickable { uriHandler.openUri("https://www.google.com/android/find") }
            ) {
                Row(
                    modifier = Modifier.padding(horizontal = VaultSpacing.md, vertical = VaultSpacing.sm),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Row(
                        horizontalArrangement = Arrangement.spacedBy(VaultSpacing.sm),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Text("📍", fontSize = 16.sp)
                        Text(
                            text = "Lock or erase phone via Google Find Hub",
                            style = MaterialTheme.typography.labelMedium,
                            fontWeight = FontWeight.SemiBold,
                            color = MaterialTheme.colorScheme.primary
                        )
                    }
                    Text("↗", color = MaterialTheme.colorScheme.primary, fontWeight = FontWeight.Bold)
                }
            }

            Text(
                text = "ENROLLED DEVICES (${devices.size})",
                style = MaterialTheme.typography.labelMedium,
                fontWeight = FontWeight.Bold,
                letterSpacing = 1.sp,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )

            AnimatedVisibility(
                visible = devices.isEmpty(),
                enter = fadeIn(tween(200)),
                exit  = fadeOut(tween(150))
            ) {
                Box(
                    modifier = Modifier.fillMaxSize().weight(1f),
                    contentAlignment = Alignment.Center
                ) {
                    Text(
                        text = "No devices connected",
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
            }

            AnimatedVisibility(
                visible = devices.isNotEmpty(),
                enter = fadeIn(tween(200)) + slideInVertically(tween(220)) { it / 8 },
                exit  = fadeOut(tween(150))
            ) {
                LazyColumn(
                    modifier = Modifier.fillMaxSize().weight(1f),
                    verticalArrangement = Arrangement.spacedBy(VaultSpacing.md)
                ) {
                    items(devices, key = { it.id }) { dev ->
                        val isCurrent = dev.id == currentDeviceId
                        val isStolen = dev.status.lowercase() == "stolen"

                        Card(
                            modifier = Modifier.fillMaxWidth(),
                            shape = RoundedCornerShape(VaultRadius.lg),
                            colors = CardDefaults.cardColors(
                                containerColor = if (isStolen)
                                    MaterialTheme.colorScheme.errorContainer.copy(alpha = 0.2f)
                                else
                                    MaterialTheme.colorScheme.surfaceVariant
                            )
                        ) {
                            Column(
                                modifier = Modifier.padding(VaultSpacing.lg),
                                verticalArrangement = Arrangement.spacedBy(VaultSpacing.sm + 2.dp)
                            ) {
                                Row(
                                    modifier = Modifier.fillMaxWidth(),
                                    horizontalArrangement = Arrangement.SpaceBetween,
                                    verticalAlignment = Alignment.CenterVertically
                                ) {
                                    Row(
                                        verticalAlignment = Alignment.CenterVertically,
                                        horizontalArrangement = Arrangement.spacedBy(VaultSpacing.sm + 2.dp)
                                    ) {
                                        Text(
                                            text = when (dev.platform.lowercase()) {
                                                "android" -> "🤖"
                                                "windows" -> "💻"
                                                "macos"   -> "🍎"
                                                else      -> "🐧"
                                            },
                                            style = MaterialTheme.typography.headlineSmall
                                        )
                                        Column {
                                            Row(
                                                verticalAlignment = Alignment.CenterVertically,
                                                horizontalArrangement = Arrangement.spacedBy(VaultSpacing.xs + 2.dp)
                                            ) {
                                                Text(
                                                    text = dev.name,
                                                    style = MaterialTheme.typography.titleMedium,
                                                    fontWeight = FontWeight.Bold
                                                )
                                                if (isCurrent) {
                                                    Surface(
                                                        shape = RoundedCornerShape(VaultRadius.xs),
                                                        color = MaterialTheme.colorScheme.primary.copy(alpha = 0.2f)
                                                    ) {
                                                        Text(
                                                            text = "THIS DEVICE",
                                                            style = MaterialTheme.typography.labelSmall,
                                                            color = MaterialTheme.colorScheme.primary,
                                                            modifier = Modifier.padding(
                                                                horizontal = VaultSpacing.xs + 2.dp,
                                                                vertical = 2.dp
                                                            ),
                                                            fontWeight = FontWeight.Bold
                                                        )
                                                    }
                                                }
                                            }
                                            Text(
                                                text = "Platform: ${dev.platform.replaceFirstChar { it.uppercase() }}",
                                                style = MaterialTheme.typography.bodySmall,
                                                color = MaterialTheme.colorScheme.onSurfaceVariant
                                            )
                                            val lastSeen = dev.last_seen_at ?: dev.last_active
                                            Text(
                                                text = if (lastSeen != null) "Last active: $lastSeen" else "Last active: Just now",
                                                style = MaterialTheme.typography.labelSmall,
                                                color = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.8f)
                                            )
                                        }
                                    }

                                    // Status Badge
                                    val statusColor = when (dev.status.lowercase()) {
                                        "trusted" -> Color(0xFF00E676)
                                        "stolen"  -> Color(0xFFFF3366)
                                        "revoked" -> Color(0xFFFFB300)
                                        else      -> Color(0xFF4E80EE)
                                    }
                                    Surface(
                                        shape = RoundedCornerShape(VaultRadius.sm),
                                        color = statusColor.copy(alpha = 0.15f)
                                    ) {
                                        Text(
                                            text = dev.status.uppercase(),
                                            color = statusColor,
                                            fontWeight = FontWeight.Bold,
                                            style = MaterialTheme.typography.labelSmall,
                                            modifier = Modifier.padding(
                                                horizontal = VaultSpacing.sm,
                                                vertical = VaultSpacing.xs
                                            )
                                        )
                                    }
                                }

                                if (!isCurrent && !isStolen) {
                                    Row(
                                        modifier = Modifier.fillMaxWidth(),
                                        horizontalArrangement = Arrangement.End,
                                        verticalAlignment = Alignment.CenterVertically
                                    ) {
                                        TextButton(onClick = { onEndDeviceSessions(dev.id) }) {
                                            Text("Sign Out")
                                        }
                                        TextButton(onClick = { deviceToRevoke = dev }) {
                                            Text("Revoke", color = Color(0xFFFFB300))
                                        }
                                        TextButton(onClick = { deviceToMarkStolen = dev }) {
                                            Text("Report Stolen", color = MaterialTheme.colorScheme.error)
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

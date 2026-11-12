package com.securevault.vault.ui.screens

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.core.tween
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.slideInVertically
import androidx.compose.animation.slideOutVertically
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.outlined.ArrowBack
import androidx.compose.material.icons.outlined.Link
import androidx.compose.material.icons.outlined.Shield
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.securevault.vault.ui.VaultCoordinator
import com.securevault.vault.ui.theme.VaultRadius
import com.securevault.vault.ui.theme.VaultSpacing

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ShareCenterScreen(
    coordinator: VaultCoordinator,
    onBack: () -> Unit
) {
    LaunchedEffect(Unit) {
        coordinator.loadShares()
    }

    val activeShares = coordinator.activeShares.value

    Scaffold(
        topBar = {
            TopAppBar(
                title = {
                    Text(
                        text = "Secure Share Center",
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
                    Icon(
                        imageVector = Icons.Outlined.Shield,
                        contentDescription = null,
                        modifier = Modifier.size(28.dp),
                        tint = MaterialTheme.colorScheme.primary
                    )
                    Column {
                        Text(
                            text = "Zero-Knowledge Sharing",
                            style = MaterialTheme.typography.titleSmall,
                            fontWeight = FontWeight.Bold
                        )
                        Text(
                            text = "Item decryption keys are placed strictly into the URL fragment (#key=…). The server never sees the plaintext or key.",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                }
            }

            Text(
                text = "ACTIVE SHARED LINKS (${activeShares.size})",
                style = MaterialTheme.typography.labelMedium,
                fontWeight = FontWeight.Bold,
                letterSpacing = 1.sp,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )

            AnimatedVisibility(
                visible = activeShares.isEmpty(),
                enter = fadeIn(tween(200)),
                exit  = fadeOut(tween(150))
            ) {
                Box(
                    modifier = Modifier.fillMaxSize().weight(1f),
                    contentAlignment = Alignment.Center
                ) {
                    Column(
                        horizontalAlignment = Alignment.CenterHorizontally,
                        verticalArrangement = Arrangement.spacedBy(VaultSpacing.sm)
                    ) {
                        Icon(
                            imageVector = Icons.Outlined.Link,
                            contentDescription = null,
                            modifier = Modifier.size(64.dp),
                            tint = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.5f)
                        )
                        Text(
                            text = "No Active Shared Links",
                            style = MaterialTheme.typography.titleMedium,
                            fontWeight = FontWeight.Bold
                        )
                        Text(
                            text = "Share individual passwords, documents, or notes using their 3-dot menus.",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                }
            }

            AnimatedVisibility(
                visible = activeShares.isNotEmpty(),
                enter = fadeIn(tween(200)) + slideInVertically(tween(220)) { it / 8 },
                exit  = fadeOut(tween(150))
            ) {
                LazyColumn(
                    modifier = Modifier.fillMaxSize().weight(1f),
                    verticalArrangement = Arrangement.spacedBy(VaultSpacing.sm + 2.dp)
                ) {
                    items(activeShares, key = { it.id }) { share ->
                        AnimatedVisibility(
                            visible = true,
                            enter = fadeIn(tween(180)) + slideInVertically(tween(200)) { it / 6 },
                            exit  = fadeOut(tween(150)) + slideOutVertically(tween(160)) { it / 6 }
                        ) {
                            Card(
                                modifier = Modifier.fillMaxWidth(),
                                shape = RoundedCornerShape(VaultRadius.lg),
                                colors = CardDefaults.cardColors(
                                    containerColor = MaterialTheme.colorScheme.surfaceVariant
                                )
                            ) {
                                Column(
                                    modifier = Modifier.padding(VaultSpacing.lg),
                                    verticalArrangement = Arrangement.spacedBy(VaultSpacing.xs + 2.dp)
                                ) {
                                    Row(
                                        modifier = Modifier.fillMaxWidth(),
                                        horizontalArrangement = Arrangement.SpaceBetween,
                                        verticalAlignment = Alignment.CenterVertically
                                    ) {
                                        Column {
                                            Text(
                                                text = "Shared ${share.item_type.replaceFirstChar { it.uppercase() }}",
                                                style = MaterialTheme.typography.titleMedium,
                                                fontWeight = FontWeight.Bold
                                            )
                                            Text(
                                                text = "Views: ${share.view_count} / ${if (share.max_views >= 1000) "Unlimited" else share.max_views.toString()}",
                                                style = MaterialTheme.typography.bodySmall,
                                                color = MaterialTheme.colorScheme.primary
                                            )
                                        }

                                        Button(
                                            onClick = { coordinator.revokeShare(share.id) {} },
                                            colors = ButtonDefaults.buttonColors(
                                                containerColor = MaterialTheme.colorScheme.error
                                            )
                                        ) {
                                            Text("Revoke")
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

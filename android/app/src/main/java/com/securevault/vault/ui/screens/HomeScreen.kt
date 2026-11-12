package com.securevault.vault.ui.screens

import androidx.activity.compose.BackHandler
import androidx.compose.animation.core.*
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.securevault.vault.ui.CyberShieldAnimation
import com.securevault.vault.ui.VaultCoordinator
import com.securevault.vault.ui.VaultGlassSurface
import com.securevault.vault.ui.theme.LocalVaultThemeStyle
import com.securevault.vault.ui.theme.VaultRadius
import com.securevault.vault.ui.theme.VaultSpacing

@Composable
fun HomeScreen(
    userName: String,
    coordinator: VaultCoordinator,
    onNavigateToPasswords: () -> Unit,
    onNavigateToDocuments: () -> Unit,
    onNavigateToNotes: () -> Unit,
    onNavigateToImageToPdf: () -> Unit,
    onNavigateToShare: () -> Unit,
    onNavigateToSettings: () -> Unit,
    onLockVault: () -> Unit
) {
    // When the user presses the system Back button on HomeScreen, lock the vault!
    BackHandler {
        onLockVault()
    }

    val scrollState = rememberScrollState()
    val theme = LocalVaultThemeStyle.current

    // Ambient motion behind header (slow, looping, breathing variance)
    val infiniteTransition = rememberInfiniteTransition(label = "ambientMotion")
    val ambientPulse by infiniteTransition.animateFloat(
        initialValue = 0.70f,
        targetValue = 1.0f,
        animationSpec = infiniteRepeatable(
            animation = tween(5000, easing = FastOutSlowInEasing),
            repeatMode = RepeatMode.Reverse
        ),
        label = "ambientPulse"
    )
    val ambientShift by infiniteTransition.animateFloat(
        initialValue = -50f,
        targetValue = 50f,
        animationSpec = infiniteRepeatable(
            animation = tween(10000, easing = LinearEasing),
            repeatMode = RepeatMode.Reverse
        ),
        label = "ambientShift"
    )

    Box(
        modifier = Modifier
            .fillMaxSize()
            .background(MaterialTheme.colorScheme.background)
    ) {
        // Ambient background glow layer behind dashboard top
        if (!theme.isLight) {
            Box(
                modifier = Modifier
                    .fillMaxWidth()
                    .height(300.dp)
                    .background(
                        Brush.radialGradient(
                            colors = theme.headerGlowColors.map { it.copy(alpha = it.alpha * ambientPulse) },
                            center = Offset(250f + ambientShift * 2f, 150f),
                            radius = 450f * ambientPulse
                        )
                    )
            )
        }

        Column(
            modifier = Modifier
                .fillMaxSize()
                .verticalScroll(scrollState)
                .padding(horizontal = VaultSpacing.xl, vertical = VaultSpacing.lg),
            verticalArrangement = Arrangement.spacedBy(VaultSpacing.xl - 2.dp)
        ) {
            // Top Bar: SECURE VAULT + Lock Action + Settings Icon
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(VaultSpacing.sm)) {
                    Surface(
                        shape = CircleShape,
                        color = MaterialTheme.colorScheme.primary.copy(alpha = 0.2f),
                        modifier = Modifier.size(32.dp)
                    ) {
                        Box(contentAlignment = Alignment.Center) {
                            Text("🛡️", style = MaterialTheme.typography.bodyLarge)
                        }
                    }
                    Text(
                        text = "SECURE VAULT",
                        style = MaterialTheme.typography.titleMedium,
                        fontWeight = FontWeight.Black,
                        letterSpacing = 2.sp,
                        color = MaterialTheme.colorScheme.onBackground
                    )
                }

                Row(horizontalArrangement = Arrangement.spacedBy(VaultSpacing.xs), verticalAlignment = Alignment.CenterVertically) {
                    IconButton(onClick = onLockVault) {
                        Text("🔒", style = MaterialTheme.typography.titleMedium)
                    }
                    IconButton(onClick = onNavigateToSettings) {
                        Text("⚙️", style = MaterialTheme.typography.titleLarge)
                    }
                }
            }

            // Personalized Greeting & Status Header
            Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                val hour = remember { java.util.Calendar.getInstance().get(java.util.Calendar.HOUR_OF_DAY) }
                val greeting = when {
                    hour < 12 -> "Good morning"
                    hour < 17 -> "Good afternoon"
                    else -> "Good evening"
                }
                Text(
                    text = "$greeting,",
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.SemiBold,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                Text(
                    text = userName,
                    style = MaterialTheme.typography.headlineMedium,
                    fontWeight = FontWeight.Black,
                    color = MaterialTheme.colorScheme.onBackground,
                    maxLines = 1,
                    overflow = androidx.compose.ui.text.style.TextOverflow.Ellipsis
                )
                Text(
                    text = "Everything in one secure place.",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }

            // Search Bar
            OutlinedTextField(
                value = coordinator.searchQuery.value,
                onValueChange = { coordinator.setSearchQuery(it) },
                placeholder = { Text("Search passwords, documents, notes…") },
                leadingIcon = { Text("🔍", style = MaterialTheme.typography.bodyLarge) },
                shape = RoundedCornerShape(VaultRadius.lg),
                modifier = Modifier.fillMaxWidth(),
                singleLine = true
            )

            // 4 Primary Feature Cards
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(VaultSpacing.md)
            ) {
                PrimaryCard(
                    title = "Passwords",
                    subtitle = "${coordinator.passwordCount()} items",
                    icon = "🔑",
                    gradient = theme.passwordsGradient,
                    modifier = Modifier.weight(1f),
                    onClick = onNavigateToPasswords
                )
                PrimaryCard(
                    title = "Documents",
                    subtitle = "${coordinator.documentCount()} items",
                    icon = "📄",
                    gradient = theme.documentsGradient,
                    modifier = Modifier.weight(1f),
                    onClick = onNavigateToDocuments
                )
            }

            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(VaultSpacing.md)
            ) {
                PrimaryCard(
                    title = "Notes",
                    subtitle = "${coordinator.noteCount()} items",
                    icon = "📒",
                    gradient = theme.notesGradient,
                    modifier = Modifier.weight(1f),
                    onClick = onNavigateToNotes
                )
                PrimaryCard(
                    title = "Image to PDF",
                    subtitle = "Convert & save",
                    icon = "🖼️",
                    gradient = theme.imageToPdfGradient,
                    modifier = Modifier.weight(1f),
                    onClick = onNavigateToImageToPdf
                )
            }

            // Quick Actions Section
            Text(
                text = "QUICK ACTIONS",
                style = MaterialTheme.typography.labelMedium,
                fontWeight = FontWeight.Bold,
                letterSpacing = 1.2.sp,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )

            // Full-width Share card with theme styling
            VaultGlassSurface(
                modifier = Modifier
                    .fillMaxWidth()
                    .clickable(onClick = onNavigateToShare)
            ) {
                Box(
                    modifier = Modifier
                        .fillMaxWidth()
                        .background(theme.shareGradient, alpha = if (theme.isLight) 0.10f else 0.22f)
                ) {
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(VaultSpacing.xl - 2.dp),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.SpaceBetween
                    ) {
                        Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(VaultSpacing.md)) {
                            Surface(
                                shape = RoundedCornerShape(12.dp),
                                color = MaterialTheme.colorScheme.primary.copy(alpha = 0.25f),
                                modifier = Modifier.size(44.dp)
                            ) {
                                Box(contentAlignment = Alignment.Center) {
                                    Text("✈️", style = MaterialTheme.typography.titleMedium)
                                }
                            }
                            Column {
                                Text(text = "Share", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold)
                                Text(
                                    text = "Share securely with anyone",
                                    style = MaterialTheme.typography.bodySmall,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant
                                )
                            }
                        }
                        Text(
                            text = "›",
                            style = MaterialTheme.typography.headlineMedium,
                            fontWeight = FontWeight.Bold,
                            color = MaterialTheme.colorScheme.primary
                        )
                    }
                }
            }
        }
    }
}

@Composable
fun PrimaryCard(
    title: String,
    subtitle: String,
    icon: String,
    gradient: Brush,
    modifier: Modifier = Modifier,
    onClick: () -> Unit
) {
    val theme = LocalVaultThemeStyle.current

    VaultGlassSurface(
        modifier = modifier
            .height(130.dp)
            .clickable(onClick = onClick)
    ) {
        Box(
            modifier = Modifier
                .fillMaxSize()
                .background(gradient, alpha = if (theme.isLight) 0.12f else 0.28f)
                .padding(VaultSpacing.lg)
        ) {
            Column(
                modifier = Modifier.fillMaxSize(),
                verticalArrangement = Arrangement.SpaceBetween
            ) {
                Surface(
                    shape = RoundedCornerShape(12.dp),
                    color = MaterialTheme.colorScheme.surface.copy(alpha = 0.7f),
                    modifier = Modifier.size(42.dp)
                ) {
                    Box(contentAlignment = Alignment.Center) {
                        Text(icon, style = MaterialTheme.typography.titleLarge)
                    }
                }
                Column {
                    Text(
                        text = title,
                        style = MaterialTheme.typography.titleMedium,
                        fontWeight = FontWeight.Bold
                    )
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Text(
                            text = subtitle,
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                        Text(
                            text = "›",
                            style = MaterialTheme.typography.bodyLarge,
                            fontWeight = FontWeight.Bold,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                }
            }
        }
    }
}

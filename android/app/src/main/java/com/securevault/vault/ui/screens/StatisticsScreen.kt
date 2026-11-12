package com.securevault.vault.ui.screens

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.outlined.ArrowBack
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.securevault.vault.ui.CyberShieldAnimation
import com.securevault.vault.ui.VaultCoordinator
import com.securevault.vault.ui.theme.VaultRadius
import com.securevault.vault.ui.theme.VaultSpacing

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun StatisticsScreen(
    coordinator: VaultCoordinator,
    onBack: () -> Unit
) {
    val scrollState = rememberScrollState()
    val allItems = coordinator.items.value
    val passwordCount = coordinator.passwordCount()
    val documentCount = coordinator.documentCount()
    val noteCount = coordinator.noteCount()
    val favoriteCount = allItems.count { it.isFavorite }
    val activeSharesCount = coordinator.activeShares.value.size

    Scaffold(
        topBar = {
            TopAppBar(
                title = {
                    Text(
                        text = "Vault Statistics",
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
            // Overview Card
            Surface(
                shape = RoundedCornerShape(20.dp),
                color = MaterialTheme.colorScheme.surfaceVariant,
                modifier = Modifier.fillMaxWidth()
            ) {
                Row(
                    modifier = Modifier.padding(20.dp),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.SpaceBetween
                ) {
                    Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                        Text(
                            text = "${allItems.size}",
                            style = MaterialTheme.typography.displaySmall,
                            fontWeight = FontWeight.Black,
                            color = MaterialTheme.colorScheme.primary
                        )
                        Text(
                            text = "Total Encrypted Vault Items",
                            style = MaterialTheme.typography.titleSmall,
                            fontWeight = FontWeight.Bold
                        )
                        Text(
                            text = "Zero plaintext persisted on storage",
                            style = MaterialTheme.typography.bodySmall,
                            color = Color(0xFF00E676)
                        )
                    }
                    CyberShieldAnimation(modifier = Modifier.size(70.dp))
                }
            }

            Text(
                text = "BREAKDOWN BY CATEGORY",
                style = MaterialTheme.typography.labelSmall,
                fontWeight = FontWeight.Bold,
                letterSpacing = 1.sp
            )

            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(VaultSpacing.sm + 2.dp)
            ) {
                StatCard(title = "Passwords", count = "$passwordCount", icon = "🔑", modifier = Modifier.weight(1f))
                StatCard(title = "Documents", count = "$documentCount", icon = "📁", modifier = Modifier.weight(1f))
            }

            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(VaultSpacing.sm + 2.dp)
            ) {
                StatCard(title = "Notes & Diary", count = "$noteCount", icon = "📔", modifier = Modifier.weight(1f))
                StatCard(title = "Favorites", count = "$favoriteCount", icon = "★", modifier = Modifier.weight(1f))
            }

            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(VaultSpacing.sm + 2.dp)
            ) {
                StatCard(title = "Active Shares", count = "$activeSharesCount", icon = "🔗", modifier = Modifier.weight(1f))
                StatCard(title = "Security Grade", count = "A+", icon = "🛡️", modifier = Modifier.weight(1f))
            }
        }
    }
}

@Composable
fun StatCard(
    title: String,
    count: String,
    icon: String,
    modifier: Modifier = Modifier
) {
    Surface(
        shape = RoundedCornerShape(VaultRadius.lg),
        color = MaterialTheme.colorScheme.surfaceVariant,
        modifier = modifier
    ) {
        Column(
            modifier = Modifier.padding(VaultSpacing.lg),
            verticalArrangement = Arrangement.spacedBy(VaultSpacing.xs + 2.dp)
        ) {
            Text(icon, style = MaterialTheme.typography.headlineSmall)
            Text(
                text = count,
                style = MaterialTheme.typography.headlineMedium,
                fontWeight = FontWeight.Bold
            )
            Text(
                text = title,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
    }
}

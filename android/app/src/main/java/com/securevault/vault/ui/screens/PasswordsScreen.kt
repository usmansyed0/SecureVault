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
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Add
import androidx.compose.material.icons.automirrored.outlined.ArrowBack
import androidx.compose.material.icons.outlined.Lock
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.securevault.vault.model.PasswordEntry
import com.securevault.vault.model.VaultItem
import com.securevault.vault.ui.AddEditPasswordDialog
import com.securevault.vault.ui.ShareItemType
import com.securevault.vault.ui.ShareSuccessBanner
import com.securevault.vault.ui.ShareWarningDialog
import com.securevault.vault.ui.VaultCoordinator
import com.securevault.vault.ui.VaultPasswordCard
import com.securevault.vault.ui.theme.VaultRadius
import com.securevault.vault.ui.theme.VaultSpacing

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun PasswordsScreen(
    coordinator: VaultCoordinator,
    onBack: () -> Unit
) {
    val context = LocalContext.current
    var showAddDialog by remember { mutableStateOf(false) }
    var editingEntry by remember { mutableStateOf<PasswordEntry?>(null) }
    var shareItem by remember { mutableStateOf<PasswordEntry?>(null) }
    var strengthEntry by remember { mutableStateOf<PasswordEntry?>(null) }
    var createdShareLink by remember { mutableStateOf<String?>(null) }

    val items = coordinator.filteredItems().filterIsInstance<VaultItem.Password>()
    val categories = listOf("All", "Website", "App", "Favorites")
    var selectedCat by remember { mutableStateOf("All") }

    Scaffold(
        topBar = {
            TopAppBar(
                title = {
                    Text(
                        text = "Passwords Vault",
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
        },
        floatingActionButton = {
            FloatingActionButton(
                onClick = { showAddDialog = true },
                shape = CircleShape,
                containerColor = MaterialTheme.colorScheme.primary
            ) {
                Icon(Icons.Outlined.Add, contentDescription = "Add Password")
            }
        }
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(horizontal = VaultSpacing.lg),
            verticalArrangement = Arrangement.spacedBy(VaultSpacing.md)
        ) {
            // Success Banner for Share
            createdShareLink?.let { link ->
                ShareSuccessBanner(
                    shareLink = link,
                    onCopyLink = {
                        coordinator.copyToClipboard(link, "Secure Share Link", isSensitive = false)
                    },
                    onDismiss = { createdShareLink = null }
                )
            }

            // Search Input
            OutlinedTextField(
                value = coordinator.searchQuery.value,
                onValueChange = { coordinator.setSearchQuery(it) },
                placeholder = { Text("Search passwords…") },
                shape = RoundedCornerShape(VaultRadius.md),
                modifier = Modifier.fillMaxWidth(),
                singleLine = true
            )

            // Category Filter Chips
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(VaultSpacing.sm)
            ) {
                categories.forEach { cat ->
                    FilterChip(
                        selected = selectedCat == cat,
                        onClick = { selectedCat = cat },
                        label = { Text(cat) }
                    )
                }
            }

            // Clipboard Notice Banner
            coordinator.clipboardNotice.value?.let { notice ->
                Surface(
                    shape = RoundedCornerShape(VaultRadius.sm),
                    color = MaterialTheme.colorScheme.primaryContainer,
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Text(
                        text = notice,
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onPrimaryContainer,
                        modifier = Modifier.padding(VaultSpacing.sm + 2.dp)
                    )
                }
            }

            // Passwords List
            val displayed = items.filter { item ->
                when (selectedCat) {
                    "All" -> true
                    "Favorites" -> item.isFavorite
                    else -> item.category.equals(selectedCat, ignoreCase = true)
                }
            }

            // ── Empty State ─────────────────────────────────────────────────
            AnimatedVisibility(
                visible = displayed.isEmpty(),
                enter = fadeIn(tween(200)),
                exit  = fadeOut(tween(150))
            ) {
                Box(
                    modifier = Modifier
                        .fillMaxSize()
                        .weight(1f),
                    contentAlignment = Alignment.Center
                ) {
                    Column(
                        horizontalAlignment = Alignment.CenterHorizontally,
                        verticalArrangement = Arrangement.spacedBy(VaultSpacing.sm)
                    ) {
                        Icon(
                            imageVector = Icons.Outlined.Lock,
                            contentDescription = null,
                            modifier = Modifier.size(64.dp),
                            tint = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.5f)
                        )
                        Text(
                            text = "No Passwords Found",
                            style = MaterialTheme.typography.titleMedium,
                            fontWeight = FontWeight.Bold
                        )
                        Text(
                            text = "Tap + below to add your first password.",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                        Spacer(Modifier.height(VaultSpacing.sm))
                        FilledTonalButton(onClick = { showAddDialog = true }) {
                            Icon(
                                Icons.Outlined.Add,
                                contentDescription = null,
                                modifier = Modifier.size(ButtonDefaults.IconSize)
                            )
                            Spacer(Modifier.width(ButtonDefaults.IconSpacing))
                            Text("Add Password")
                        }
                    }
                }
            }

            // ── Passwords List ──────────────────────────────────────────────
            AnimatedVisibility(
                visible = displayed.isNotEmpty(),
                enter = fadeIn(tween(200)) + slideInVertically(tween(220)) { it / 8 },
                exit  = fadeOut(tween(150))
            ) {
                LazyColumn(
                    modifier = Modifier.fillMaxSize().weight(1f),
                    verticalArrangement = Arrangement.spacedBy(VaultSpacing.sm + 2.dp),
                    contentPadding = PaddingValues(bottom = 80.dp)
                ) {
                    items(displayed, key = { it.id }) { item ->
                        val entry = item.entry
                        AnimatedVisibility(
                            visible = true,
                            enter = fadeIn(tween(180)) + slideInVertically(tween(200)) { it / 6 },
                            exit  = fadeOut(tween(150)) + slideOutVertically(tween(160)) { it / 6 }
                        ) {
                            VaultPasswordCard(
                                entry = entry,
                                isRevealed = coordinator.revealedPasswordIds.value.contains(entry.id),
                                onToggleReveal = { coordinator.togglePasswordVisibility(entry.id) },
                                onCopyPassword = { coordinator.copyToClipboard(entry.password, "Password") },
                                onCopyUsername = { coordinator.copyToClipboard(entry.username, "Username", isSensitive = false) },
                                onEdit = { editingEntry = entry },
                                onDelete = { coordinator.deleteItem(entry.id) },
                                onFavorite = { coordinator.toggleFavorite(item) },
                                onStrength = { strengthEntry = entry },
                                onShare = { shareItem = entry }
                            )
                        }
                    }
                }
            }
        }
    }

    // Add / Edit Dialog
    if (showAddDialog || editingEntry != null) {
        AddEditPasswordDialog(
            initialEntry = editingEntry,
            generator = coordinator.generator,
            strengthMeter = coordinator.strengthMeter,
            onDismiss = {
                showAddDialog = false
                editingEntry = null
            },
            onSave = { title, user, pass, web, notes, cat, sens, fav, icon ->
                coordinator.savePassword(
                    existingId = editingEntry?.id,
                    existingRevision = editingEntry?.revision,
                    title = title,
                    username = user,
                    password = pass,
                    website = web,
                    notes = notes,
                    category = cat,
                    isSensitive = sens,
                    isFavorite = fav,
                    iconUri = icon,
                    onComplete = {
                        showAddDialog = false
                        editingEntry = null
                    }
                )
            }
        )
    }

    // Share Item Dialog
    shareItem?.let { entry ->
        ShareWarningDialog(
            itemTitle = entry.title,
            itemType = ShareItemType.PASSWORD,
            onDismiss = { shareItem = null },
            onConfirmShare = { expires, views, includePassword ->
                coordinator.createShare(
                    item = VaultItem.Password(entry),
                    expiresInSeconds = expires,
                    maxViews = views,
                    includePassword = includePassword,
                    onSuccess = { link ->
                        coordinator.copyToClipboard(link, "Secure Share Link", isSensitive = false)
                        createdShareLink = link
                        shareItem = null
                    },
                    onError = { shareItem = null }
                )
            },
            onShareViaSystem = { includePassword ->
                coordinator.shareViaSystemSheet(
                    context = context,
                    item = VaultItem.Password(entry),
                    includePassword = includePassword
                )
                shareItem = null
            }
        )
    }
}

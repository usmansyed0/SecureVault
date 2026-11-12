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
import androidx.compose.material.icons.outlined.BookmarkBorder
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.securevault.vault.model.SecureNote
import com.securevault.vault.model.VaultItem
import com.securevault.vault.ui.AddEditNoteDialog
import com.securevault.vault.ui.ShareItemType
import com.securevault.vault.ui.ShareSuccessBanner
import com.securevault.vault.ui.ShareWarningDialog
import com.securevault.vault.ui.VaultCoordinator
import com.securevault.vault.ui.VaultNoteCard
import com.securevault.vault.ui.theme.VaultRadius
import com.securevault.vault.ui.theme.VaultSpacing

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun NotesScreen(
    coordinator: VaultCoordinator,
    onBack: () -> Unit
) {
    val context = LocalContext.current
    var isCreatingNote by remember { mutableStateOf(false) }
    var editingNote by remember { mutableStateOf<SecureNote?>(null) }
    var shareItem by remember { mutableStateOf<SecureNote?>(null) }
    var createdShareLink by remember { mutableStateOf<String?>(null) }

    if (isCreatingNote || editingNote != null) {
        NoteEditorScreen(
            initialNote = editingNote,
            coordinator = coordinator,
            onBack = {
                isCreatingNote = false
                editingNote = null
            }
        )
        return
    }

    val allNotes = coordinator.filteredItems().filterIsInstance<VaultItem.Note>()
    val categories = listOf("All", "Personal", "Diary", "Work", "Favorites")
    var selectedCat by remember { mutableStateOf("All") }

    Scaffold(
        topBar = {
            TopAppBar(
                title = {
                    Text(
                        text = "Private Diary & Notes",
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
                onClick = { isCreatingNote = true },
                shape = CircleShape,
                containerColor = MaterialTheme.colorScheme.primary
            ) {
                Icon(Icons.Outlined.Add, contentDescription = "New Note / Diary Entry")
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
                placeholder = { Text("Search private notes & diary…") },
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

            val displayed = allNotes.filter { item ->
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
                    modifier = Modifier.fillMaxSize().weight(1f),
                    contentAlignment = Alignment.Center
                ) {
                    Column(
                        horizontalAlignment = Alignment.CenterHorizontally,
                        verticalArrangement = Arrangement.spacedBy(VaultSpacing.sm)
                    ) {
                        Icon(
                            imageVector = Icons.Outlined.BookmarkBorder,
                            contentDescription = null,
                            modifier = Modifier.size(64.dp),
                            tint = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.5f)
                        )
                        Text(
                            text = "No Notes Yet",
                            style = MaterialTheme.typography.titleMedium,
                            fontWeight = FontWeight.Bold
                        )
                        Text(
                            text = "Write your private thoughts freely. Tap + to create an entry.",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                        Spacer(Modifier.height(VaultSpacing.sm))
                        FilledTonalButton(onClick = { isCreatingNote = true }) {
                            Icon(
                                Icons.Outlined.Add,
                                contentDescription = null,
                                modifier = Modifier.size(ButtonDefaults.IconSize)
                            )
                            Spacer(Modifier.width(ButtonDefaults.IconSpacing))
                            Text("New Note")
                        }
                    }
                }
            }

            // ── Notes List ────────────────────────────────────────────────────
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
                        val note = item.note
                        AnimatedVisibility(
                            visible = true,
                            enter = fadeIn(tween(180)) + slideInVertically(tween(200)) { it / 6 },
                            exit  = fadeOut(tween(150)) + slideOutVertically(tween(160)) { it / 6 }
                        ) {
                            VaultNoteCard(
                                note = note,
                                onCopyContent = { coordinator.copyToClipboard(note.content, "Note Content") },
                                onEdit = { editingNote = note },
                                onDelete = { coordinator.deleteItem(note.id) },
                                onFavorite = { coordinator.toggleFavorite(item) },
                                onShare = { shareItem = note }
                            )
                        }
                    }
                }
            }
        }
    }



    // Share Item Dialog
    shareItem?.let { note ->
        ShareWarningDialog(
            itemTitle = note.title,
            itemType = ShareItemType.NOTE,
            onDismiss = { shareItem = null },
            onConfirmShare = { expires, views, _ ->
                coordinator.createShare(
                    item = VaultItem.Note(note),
                    expiresInSeconds = expires,
                    maxViews = views,
                    onSuccess = { link ->
                        coordinator.copyToClipboard(link, "Secure Note Link", isSensitive = false)
                        createdShareLink = link
                        shareItem = null
                    },
                    onError = { shareItem = null }
                )
            },
            onShareViaSystem = {
                coordinator.shareViaSystemSheet(
                    context = context,
                    item = VaultItem.Note(note)
                )
                shareItem = null
            }
        )
    }
}

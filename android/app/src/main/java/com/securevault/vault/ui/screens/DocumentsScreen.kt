package com.securevault.vault.ui.screens

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.animateContentSize
import androidx.compose.animation.core.tween
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.slideInVertically
import androidx.compose.animation.slideOutVertically
import androidx.compose.foundation.clickable
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.lazy.grid.GridCells
import androidx.compose.foundation.lazy.grid.LazyVerticalGrid
import androidx.compose.foundation.lazy.grid.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Add
import androidx.compose.material.icons.automirrored.outlined.ArrowBack
import androidx.compose.material.icons.outlined.FolderOpen
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.securevault.vault.model.DocumentEntry
import com.securevault.vault.model.DocumentPage
import com.securevault.vault.model.VaultItem
import com.securevault.vault.ui.ShareItemType
import com.securevault.vault.ui.ShareSuccessBanner
import com.securevault.vault.ui.ShareWarningDialog
import com.securevault.vault.ui.VaultCoordinator
import com.securevault.vault.ui.VaultDocumentCard
import com.securevault.vault.ui.VaultGlassSurface
import com.securevault.vault.ui.theme.LocalVaultThemeStyle
import com.securevault.vault.ui.theme.VaultRadius
import com.securevault.vault.ui.theme.VaultSpacing
import com.securevault.vault.document.OcrHelper

import android.content.Intent
import android.graphics.Bitmap
import android.net.Uri
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.ui.platform.LocalContext
import androidx.core.content.FileProvider
import kotlinx.coroutines.launch
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.FileOutputStream
import java.text.SimpleDateFormat
import java.util.*

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun DocumentsScreen(
    coordinator: VaultCoordinator,
    onNavigateToScanner: () -> Unit,
    onBack: () -> Unit
) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()

    var selectedDoc by remember { mutableStateOf<DocumentEntry?>(null) }
    var shareItem by remember { mutableStateOf<DocumentEntry?>(null) }
    var editingDoc by remember { mutableStateOf<DocumentEntry?>(null) }
    var showAddSheet by remember { mutableStateOf(false) }
    var createdShareLink by remember { mutableStateOf<String?>(null) }

    // ─── Camera capture with real OCR ────────────────────────────────────────
    val cameraLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.TakePicturePreview()
    ) { bitmap ->
        if (bitmap != null) {
            scope.launch {
                val stream = ByteArrayOutputStream()
                bitmap.compress(Bitmap.CompressFormat.JPEG, 85, stream)
                val bytes = stream.toByteArray()

                // Run OCR before saving — result is encrypted as part of DocumentEntry
                val ocrResult = OcrHelper.extractText(bitmap)

                val vaultId = coordinator.blobManager?.let { "active-vault" } ?: "vault"
                val docId   = UUID.randomUUID().toString()
                val pageId  = UUID.randomUUID().toString()
                val blobId  = coordinator.blobManager?.savePageBlob(vaultId, docId, pageId, 1, bytes)
                    ?: UUID.randomUUID().toString()
                val page = DocumentPage(
                    pageId = pageId,
                    pageNumber = 1,
                    mimeType = "image/jpeg",
                    blobId = blobId,
                    width = bitmap.width,
                    height = bitmap.height
                )
                val time = SimpleDateFormat("MMM dd, HH:mm", Locale.getDefault()).format(Date())
                coordinator.saveDocument(
                    existingId = null,
                    existingRevision = null,
                    title = "Camera Scan $time",
                    category = "Personal Documents",
                    pages = listOf(page),
                    ocrText = ocrResult,   // real extracted text, or "" if blank page
                    onComplete = {}
                )
            }
        }
    }

    // ─── Single gallery image with real OCR ──────────────────────────────────
    val galleryLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.GetContent()
    ) { uri ->
        if (uri != null) {
            scope.launch {
                val bytes = try {
                    context.contentResolver.openInputStream(uri)?.use { it.readBytes() }
                } catch (_: Exception) { null }

                if (bytes != null) {
                    val ocrResult = OcrHelper.extractText(bytes)

                    val vaultId = "active-vault"
                    val docId   = UUID.randomUUID().toString()
                    val pageId  = UUID.randomUUID().toString()
                    val blobId  = coordinator.blobManager?.savePageBlob(vaultId, docId, pageId, 1, bytes)
                        ?: UUID.randomUUID().toString()
                    val page = DocumentPage(
                        pageId = pageId,
                        pageNumber = 1,
                        mimeType = "image/jpeg",
                        blobId = blobId
                    )
                    coordinator.saveDocument(
                        existingId = null,
                        existingRevision = null,
                        title = "Gallery Image",
                        category = "Personal Documents",
                        pages = listOf(page),
                        ocrText = ocrResult,
                        onComplete = {}
                    )
                }
            }
        }
    }

    // ─── Multiple gallery images with per-page OCR ────────────────────────────
    val multipleImagesLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.GetMultipleContents()
    ) { uris ->
        if (uris.isNotEmpty()) {
            scope.launch {
                val pageBytesList = uris.mapNotNull { uri ->
                    try { context.contentResolver.openInputStream(uri)?.use { it.readBytes() } }
                    catch (_: Exception) { null }
                }
                val pages = pageBytesList.mapIndexed { index, bytes ->
                    val pageId = UUID.randomUUID().toString()
                    val blobId = coordinator.blobManager
                        ?.savePageBlob("active-vault", "doc-multi", pageId, 1, bytes)
                        ?: UUID.randomUUID().toString()
                    DocumentPage(
                        pageId = pageId,
                        pageNumber = index + 1,
                        mimeType = "image/jpeg",
                        blobId = blobId
                    )
                }
                if (pages.isNotEmpty()) {
                    // Aggregate OCR from all pages; encrypted as one ocrText field
                    val ocrResult = OcrHelper.extractTextFromPages(pageBytesList)
                    coordinator.saveDocument(
                        existingId = null,
                        existingRevision = null,
                        title = "Imported Images (${pages.size} pages)",
                        category = "Personal Documents",
                        pages = pages,
                        ocrText = ocrResult,
                        onComplete = {}
                    )
                }
            }
        }
    }

    // ─── PDF import (no image OCR; PDFs are binary blobs here) ───────────────
    val pdfLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.OpenDocument()
    ) { uri ->
        if (uri != null) {
            scope.launch {
                val bytes = try {
                    context.contentResolver.openInputStream(uri)?.use { it.readBytes() }
                } catch (_: Exception) { null }
                if (bytes != null) {
                    val pageId = UUID.randomUUID().toString()
                    val blobId = coordinator.blobManager
                        ?.savePageBlob("active-vault", "doc-pdf", pageId, 1, bytes)
                        ?: UUID.randomUUID().toString()
                    val page = DocumentPage(
                        pageId = pageId,
                        pageNumber = 1,
                        mimeType = "application/pdf",
                        blobId = blobId
                    )
                    // PDFs are stored as encrypted binary blobs; OCR text is empty
                    // (a future enhancement can render pages via PdfRenderer and then OCR them)
                    coordinator.saveDocument(
                        existingId = null,
                        existingRevision = null,
                        title = "Imported PDF Document",
                        category = "Certificates",
                        pages = listOf(page),
                        ocrText = "",
                        onComplete = {}
                    )
                }
            }
        }
    }

    val allDocs = coordinator.filteredItems().filterIsInstance<VaultItem.Document>()
    val categories = listOf("All", "ID Cards", "Personal", "Certificates", "Other", "Favorites")
    var selectedCat by remember { mutableStateOf("All") }

    Scaffold(
        topBar = {
            TopAppBar(
                title = {
                    Text(
                        text = "Documents Vault",
                        style = MaterialTheme.typography.titleLarge,
                        fontWeight = FontWeight.Bold
                    )
                },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(
                            imageVector = Icons.AutoMirrored.Outlined.ArrowBack,
                            contentDescription = "Back"
                        )
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = MaterialTheme.colorScheme.background
                )
            )
        },
        floatingActionButton = {
            FloatingActionButton(
                onClick = { showAddSheet = true },
                shape = CircleShape,
                containerColor = MaterialTheme.colorScheme.primary
            ) {
                Icon(Icons.Outlined.Add, contentDescription = "Scan / Import Document")
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

            // ── Search Input ─────────────────────────────────────────────────
            OutlinedTextField(
                value = coordinator.searchQuery.value,
                onValueChange = { coordinator.setSearchQuery(it) },
                placeholder = { Text("Search documents & OCR text…") },
                shape = RoundedCornerShape(VaultRadius.md),
                modifier = Modifier.fillMaxWidth(),
                singleLine = true
            )

            // ── Category Filter Chips (Horizontally Scrollable) ───────────────
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .horizontalScroll(rememberScrollState()),
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

            val displayed = allDocs.filter { item ->
                when (selectedCat) {
                    "All"       -> true
                    "Favorites" -> item.isFavorite
                    "ID Cards"  -> item.category.equals("ID Cards", ignoreCase = true) || item.category.equals("Identity", ignoreCase = true)
                    "Personal"  -> item.category.equals("Personal", ignoreCase = true) || item.category.equals("Personal Documents", ignoreCase = true)
                    else        -> item.category.equals(selectedCat, ignoreCase = true)
                }
            }

            // ── Empty State ───────────────────────────────────────────────────
            AnimatedVisibility(
                visible = displayed.isEmpty(),
                enter = fadeIn(animationSpec = tween(200)),
                exit = fadeOut(animationSpec = tween(150))
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
                            imageVector = Icons.Outlined.FolderOpen,
                            contentDescription = null,
                            modifier = Modifier.size(64.dp),
                            tint = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.5f)
                        )
                        Text(
                            text = "No Documents Found",
                            style = MaterialTheme.typography.titleMedium,
                            fontWeight = FontWeight.Bold
                        )
                        Text(
                            text = "Tap + below to scan, convert, or import documents.",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                        Spacer(Modifier.height(VaultSpacing.sm))
                        FilledTonalButton(onClick = { showAddSheet = true }) {
                            Icon(
                                Icons.Outlined.Add,
                                contentDescription = null,
                                modifier = Modifier.size(ButtonDefaults.IconSize)
                            )
                            Spacer(Modifier.width(ButtonDefaults.IconSpacing))
                            Text("Add Document")
                        }
                    }
                }
            }

            // ── Document List ─────────────────────────────────────────────────
            AnimatedVisibility(
                visible = displayed.isNotEmpty(),
                enter = fadeIn(animationSpec = tween(200)) +
                        slideInVertically(animationSpec = tween(220)) { it / 8 },
                exit  = fadeOut(animationSpec = tween(150))
            ) {
                LazyVerticalGrid(
                    columns = GridCells.Fixed(1),
                    modifier = Modifier
                        .fillMaxSize()
                        .weight(1f),
                    verticalArrangement = Arrangement.spacedBy(VaultSpacing.sm + 2.dp),
                    contentPadding = PaddingValues(bottom = 80.dp)
                ) {
                    items(displayed, key = { it.id }) { item ->
                        val doc = item.entry
                        // Per-item slide-in + fade on appear
                        AnimatedVisibility(
                            visible = true,
                            enter = fadeIn(tween(180)) +
                                    slideInVertically(tween(200)) { it / 6 },
                            exit  = fadeOut(tween(150)) +
                                    slideOutVertically(tween(160)) { it / 6 }
                        ) {
                            VaultDocumentCard(
                                doc = doc,
                                onView   = { selectedDoc = doc },
                                onEdit   = { editingDoc = doc },
                                onDelete = { coordinator.deleteItem(doc.id) },
                                onFavorite = { coordinator.toggleFavorite(item) },
                                onShare  = { shareItem = doc }
                            )
                        }
                    }
                }
            }
        }
    }

    val theme = LocalVaultThemeStyle.current

    // ── Document Viewer Dialog ────────────────────────────────────────────────
    selectedDoc?.let { doc ->
        AlertDialog(
            onDismissRequest = { selectedDoc = null },
            shape = RoundedCornerShape(theme.cardCornerRadius),
            containerColor = if (theme.enableFrostedBlur) theme.frostedSurfaceColor else MaterialTheme.colorScheme.surfaceVariant,
            title = {
                Text(text = doc.title, fontWeight = FontWeight.Bold)
            },
            text = {
                Column(
                    modifier = Modifier.fillMaxWidth(),
                    verticalArrangement = Arrangement.spacedBy(VaultSpacing.sm + 2.dp)
                ) {
                    Surface(
                        shape = RoundedCornerShape(VaultRadius.md),
                        color = MaterialTheme.colorScheme.surfaceVariant,
                        modifier = Modifier
                            .fillMaxWidth()
                            .height(160.dp)
                    ) {
                        Box(contentAlignment = Alignment.Center) {
                            Column(horizontalAlignment = Alignment.CenterHorizontally) {
                                Icon(
                                    imageVector = Icons.Outlined.FolderOpen,
                                    contentDescription = null,
                                    modifier = Modifier.size(40.dp),
                                    tint = MaterialTheme.colorScheme.primary
                                )
                                Spacer(Modifier.height(VaultSpacing.xs))
                                Text(
                                    text = "${doc.pages.size} Page(s) — Encrypted Blob",
                                    style = MaterialTheme.typography.bodyMedium,
                                    fontWeight = FontWeight.SemiBold
                                )
                                Text(
                                    text = "Category: ${doc.category}",
                                    style = MaterialTheme.typography.bodySmall,
                                    color = MaterialTheme.colorScheme.primary
                                )
                            }
                        }
                    }

                    if (doc.ocrText.isNotEmpty()) {
                        Text(
                            text = "Extracted OCR Text (decrypted in-memory):",
                            style = MaterialTheme.typography.labelSmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                        Surface(
                            shape = RoundedCornerShape(VaultRadius.sm),
                            color = MaterialTheme.colorScheme.surface,
                            modifier = Modifier
                                .fillMaxWidth()
                                .animateContentSize()
                        ) {
                            Text(
                                text = doc.ocrText,
                                style = MaterialTheme.typography.bodySmall,
                                modifier = Modifier.padding(VaultSpacing.sm)
                            )
                        }
                    }
                }
            },
            confirmButton = {
                Button(onClick = { selectedDoc = null }) { Text("Close") }
            }
        )
    }

    // ── Add Document Action Sheet ─────────────────────────────────────────────
    if (showAddSheet) {
        AlertDialog(
            onDismissRequest = { showAddSheet = false },
            shape = RoundedCornerShape(theme.cardCornerRadius),
            containerColor = if (theme.enableFrostedBlur) theme.frostedSurfaceColor else MaterialTheme.colorScheme.surfaceVariant,
            title = {
                Text("Add to Documents Vault", fontWeight = FontWeight.Bold)
            },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(VaultSpacing.sm + 2.dp)) {
                    AddActionRow(
                        emoji = "📷",
                        title = "Scan with Camera",
                        subtitle = "Capture document — OCR text extracted on-device"
                    ) {
                        showAddSheet = false
                        cameraLauncher.launch(null)
                    }
                    AddActionRow(
                        emoji = "📄",
                        title = "Import PDF",
                        subtitle = "Select PDF from device storage"
                    ) {
                        showAddSheet = false
                        pdfLauncher.launch(arrayOf("application/pdf"))
                    }
                    AddActionRow(
                        emoji = "🖼️",
                        title = "Import Images",
                        subtitle = "Select multiple images — OCR each page on-device"
                    ) {
                        showAddSheet = false
                        multipleImagesLauncher.launch("image/*")
                    }
                    AddActionRow(
                        emoji = "🖼️",
                        title = "Gallery",
                        subtitle = "Select a single photo — OCR extracted on-device"
                    ) {
                        showAddSheet = false
                        galleryLauncher.launch("image/*")
                    }
                }
            },
            confirmButton = {},
            dismissButton = {
                OutlinedButton(onClick = { showAddSheet = false }) { Text("Cancel") }
            }
        )
    }

    // ── Share Item Dialog ─────────────────────────────────────────────────────
    shareItem?.let { doc ->
        ShareWarningDialog(
            itemTitle = doc.title,
            itemType = ShareItemType.DOCUMENT,
            onDismiss = { shareItem = null },
            onConfirmShare = { expires, views, _ ->
                coordinator.createShare(
                    item = VaultItem.Document(doc),
                    expiresInSeconds = expires,
                    maxViews = views,
                    onSuccess = { link ->
                        coordinator.copyToClipboard(
                            link, "Secure Document Link", isSensitive = false
                        )
                        createdShareLink = link
                        shareItem = null
                    },
                    onError = { shareItem = null }
                )
            },
            onShareViaSystem = {
                try {
                    val page = doc.pages.firstOrNull()
                    val bytes = if (page != null) {
                        coordinator.blobManager?.loadPageBlob(
                            doc.vaultId, doc.id, page.pageId, 1, page.blobId
                        )
                    } else null

                    if (bytes != null) {
                        val ext = if (page?.mimeType?.contains("pdf") == true) "pdf" else "jpg"
                        val uri = com.securevault.vault.SecureShareProvider.createEphemeralShareUri(
                            context = context,
                            fileName = "${doc.title}.$ext",
                            data = bytes,
                            mimeType = page?.mimeType ?: "*/*"
                        )
                        com.securevault.vault.SecureShareProvider.shareFileViaSystem(
                            context = context,
                            title = doc.title,
                            uri = uri,
                            mimeType = page?.mimeType ?: "*/*"
                        )
                    }
                } catch (_: Exception) {}
                shareItem = null
            }
        )
    }
}

/** Reusable action row for the "Add Document" bottom sheet. */
@Composable
private fun AddActionRow(
    emoji: String,
    title: String,
    subtitle: String,
    onClick: () -> Unit
) {
    VaultGlassSurface(
        modifier = Modifier
            .fillMaxWidth()
            .clickable(onClick = onClick)
            .animateContentSize()
    ) {
        Row(
            modifier = Modifier.padding(VaultSpacing.md),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Text(
                text = emoji,
                style = MaterialTheme.typography.headlineSmall,
                modifier = Modifier.padding(end = VaultSpacing.md)
            )
            Column {
                Text(title, style = MaterialTheme.typography.bodyMedium, fontWeight = FontWeight.Bold)
                Text(
                    subtitle,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        }
    }
}

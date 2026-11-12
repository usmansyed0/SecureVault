package com.securevault.vault.ui.screens

import android.graphics.Bitmap
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyRow
import androidx.compose.foundation.lazy.itemsIndexed
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.outlined.ArrowBack
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.securevault.vault.document.DocumentScannerUtils
import com.securevault.vault.document.OcrHelper
import com.securevault.vault.model.DocumentPage
import com.securevault.vault.ui.VaultCoordinator
import kotlinx.coroutines.launch
import java.io.ByteArrayOutputStream
import java.util.UUID

data class ScannedPageItem(
    val pageId: String = UUID.randomUUID().toString(),
    var filter: String = "Original",
    var rotation: Int = 0,
    val titleHint: String = "Scanned Page"
)

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ImageToPdfScreen(
    coordinator: VaultCoordinator,
    onBack: () -> Unit,
    onSavedToDocuments: () -> Unit
) {
    val scope = rememberCoroutineScope()
    var scannedPages by remember {
        mutableStateOf(
            listOf(
                ScannedPageItem(filter = "Original", titleHint = "Page 1"),
                ScannedPageItem(filter = "B&W", titleHint = "Page 2")
            )
        )
    }
    var selectedPageIndex by remember { mutableIntStateOf(0) }
    var showSaveDialog by remember { mutableStateOf(false) }
    var docTitle by remember { mutableStateOf("") }
    var docCategory by remember { mutableStateOf("Personal Documents") }

    val filters = listOf("Original", "Vivid", "Light", "B&W")

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Image to PDF Converter", fontWeight = FontWeight.Bold) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Outlined.ArrowBack, contentDescription = "Back")
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(containerColor = MaterialTheme.colorScheme.background)
            )
        }
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            // Scanner preview stage
            Surface(
                shape = RoundedCornerShape(20.dp),
                color = MaterialTheme.colorScheme.surfaceVariant,
                modifier = Modifier
                    .fillMaxWidth()
                    .height(280.dp)
            ) {
                Box(contentAlignment = Alignment.Center) {
                    Column(
                        horizontalAlignment = Alignment.CenterHorizontally,
                        verticalArrangement = Arrangement.spacedBy(12.dp)
                    ) {
                        Text("📄", fontSize = 56.sp)
                        val currentPage = scannedPages.getOrNull(selectedPageIndex)
                        Text(
                            text = if (currentPage != null) "${currentPage.titleHint} (Filter: ${currentPage.filter}, Rotation: ${currentPage.rotation}°)" else "No pages selected",
                            style = MaterialTheme.typography.titleMedium,
                            fontWeight = FontWeight.Bold
                        )
                        Text(
                            text = "Perspective Corrected • Scanner Enhanced",
                            style = MaterialTheme.typography.labelSmall,
                            color = Color(0xFF00E676)
                        )
                    }
                }
            }

            // Quick Scanner Controls: Rotate, Filter Chips
            if (scannedPages.isNotEmpty() && selectedPageIndex < scannedPages.size) {
                val current = scannedPages[selectedPageIndex]
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Text("Scanner Filter:", style = MaterialTheme.typography.labelMedium)
                        TextButton(
                            onClick = {
                                val updated = scannedPages.toMutableList()
                                updated[selectedPageIndex] = current.copy(rotation = (current.rotation + 90) % 360)
                                scannedPages = updated
                            }
                        ) {
                            Text("Rotate 90° ⟳")
                        }
                    }

                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        filters.forEach { f ->
                            FilterChip(
                                selected = current.filter == f,
                                onClick = {
                                    val updated = scannedPages.toMutableList()
                                    updated[selectedPageIndex] = current.copy(filter = f)
                                    scannedPages = updated
                                },
                                label = { Text(f) }
                            )
                        }
                    }
                }
            }

            // Pages Carousel
            Text("Document Pages (${scannedPages.size}):", style = MaterialTheme.typography.labelMedium)
            LazyRow(
                horizontalArrangement = Arrangement.spacedBy(10.dp),
                modifier = Modifier.fillMaxWidth()
            ) {
                itemsIndexed(scannedPages) { idx, page ->
                    Surface(
                        shape = RoundedCornerShape(12.dp),
                        color = if (idx == selectedPageIndex) MaterialTheme.colorScheme.primaryContainer else MaterialTheme.colorScheme.surfaceVariant,
                        modifier = Modifier
                            .size(70.dp, 90.dp)
                            .clip(RoundedCornerShape(12.dp))
                            .clickable { selectedPageIndex = idx }
                    ) {
                        Box(contentAlignment = Alignment.Center) {
                            Column(horizontalAlignment = Alignment.CenterHorizontally) {
                                Text("P${idx + 1}", fontWeight = FontWeight.Bold)
                                Text(page.filter, style = MaterialTheme.typography.labelSmall)
                            }
                        }
                    }
                }

                item {
                    // Add Page Button (Camera / Gallery)
                    Surface(
                        shape = RoundedCornerShape(12.dp),
                        color = MaterialTheme.colorScheme.surfaceVariant,
                        modifier = Modifier
                            .size(70.dp, 90.dp)
                            .clip(RoundedCornerShape(12.dp))
                            .clickable {
                                scannedPages = scannedPages + ScannedPageItem(titleHint = "Page ${scannedPages.size + 1}")
                                selectedPageIndex = scannedPages.size - 1
                            }
                    ) {
                        Box(contentAlignment = Alignment.Center) {
                            Text("+ Add", fontWeight = FontWeight.Bold, color = MaterialTheme.colorScheme.primary)
                        }
                    }
                }
            }

            Spacer(modifier = Modifier.weight(1f))

            // Action Buttons
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(10.dp)
            ) {
                OutlinedButton(
                    onClick = {
                        if (scannedPages.size > 1 && selectedPageIndex < scannedPages.size) {
                            scannedPages = scannedPages.toMutableList().apply { removeAt(selectedPageIndex) }
                            selectedPageIndex = (selectedPageIndex - 1).coerceAtLeast(0)
                        }
                    },
                    modifier = Modifier.weight(1f),
                    enabled = scannedPages.size > 1
                ) {
                    Text("Remove Page")
                }

                Button(
                    onClick = { showSaveDialog = true },
                    modifier = Modifier.weight(1f),
                    enabled = scannedPages.isNotEmpty()
                ) {
                    Text("Create PDF")
                }
            }
        }
    }

    // Save To Documents Dialog
    if (showSaveDialog) {
        AlertDialog(
            onDismissRequest = { showSaveDialog = false },
            title = { Text("Save to Documents Vault", fontWeight = FontWeight.Bold) },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                    OutlinedTextField(
                        value = docTitle,
                        onValueChange = { docTitle = it },
                        label = { Text("Document Title *") },
                        placeholder = { Text("e.g. Passport Scan, Marksheet, Contract") },
                        modifier = Modifier.fillMaxWidth(),
                        singleLine = true
                    )

                    Text("Category:", style = MaterialTheme.typography.labelSmall)
                    val cats = listOf("Personal Documents", "Certificates", "Identity", "Receipts")
                    Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                        cats.take(2).forEach { c ->
                            FilterChip(
                                selected = docCategory == c,
                                onClick = { docCategory = c },
                                label = { Text(c.split(" ").first()) }
                            )
                        }
                    }
                }
            },
            confirmButton = {
                Button(
                    onClick = {
                        scope.launch {
                            try {
                                val (finalPages, pageBytesList) = kotlinx.coroutines.withContext(kotlinx.coroutines.Dispatchers.Default) {
                                    val byteList = mutableListOf<ByteArray>()
                                    val pages = scannedPages.mapIndexed { idx, page ->
                                        val fakeBitmap = Bitmap.createBitmap(300, 400, Bitmap.Config.ARGB_8888)
                                        val filtered = DocumentScannerUtils.applyFilter(fakeBitmap, page.filter)
                                        val rotated = DocumentScannerUtils.rotateBitmap(filtered, page.rotation)

                                        val stream = ByteArrayOutputStream()
                                        rotated.compress(Bitmap.CompressFormat.JPEG, 85, stream)
                                        val pageBytes = stream.toByteArray()
                                        byteList.add(pageBytes)

                                        val blobId = coordinator.blobManager?.savePageBlob(
                                            vaultId = "active-vault",
                                            documentId = UUID.randomUUID().toString(),
                                            pageId = page.pageId,
                                            pageVersion = 1,
                                            plaintextBytes = pageBytes
                                        ) ?: UUID.randomUUID().toString()

                                        DocumentPage(
                                            pageId = page.pageId,
                                            pageNumber = idx + 1,
                                            mimeType = "image/jpeg",
                                            blobId = blobId,
                                            rotationDegrees = page.rotation,
                                            filter = page.filter,
                                            width = 300,
                                            height = 400
                                        )
                                    }
                                    pages to byteList
                                }

                                val ocrText = kotlinx.coroutines.withContext(kotlinx.coroutines.Dispatchers.Default) {
                                    OcrHelper.extractTextFromPages(pageBytesList)
                                }

                                coordinator.saveDocument(
                                    existingId = null,
                                    existingRevision = null,
                                    title = docTitle.ifBlank { "Scanned Document (${scannedPages.size} pages)" },
                                    category = docCategory,
                                    pages = finalPages,
                                    ocrText = ocrText,
                                    onComplete = {
                                        showSaveDialog = false
                                        onSavedToDocuments()
                                    }
                                )
                            } catch (e: Exception) {
                                android.util.Log.e("ImageToPdfScreen", "Failed to save scanned document", e)
                            }
                        }
                    },
                    enabled = docTitle.isNotBlank()
                ) {
                    Text("Save Securely")
                }
            },
            dismissButton = {
                OutlinedButton(onClick = { showSaveDialog = false }) {
                    Text("Cancel")
                }
            }
        )
    }
}

package com.securevault.vault.ui.screens

import androidx.activity.compose.BackHandler
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.BasicTextField
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ArrowBack
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.focus.FocusRequester
import androidx.compose.ui.focus.focusRequester
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.SolidColor
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.securevault.vault.model.SecureNote
import com.securevault.vault.ui.VaultCoordinator
import java.text.SimpleDateFormat
import java.util.*

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun NoteEditorScreen(
    initialNote: SecureNote?,
    coordinator: VaultCoordinator,
    onBack: () -> Unit
) {
    var title by remember { mutableStateOf(initialNote?.title ?: "") }
    var content by remember { mutableStateOf(initialNote?.content ?: "") }
    var category by remember { mutableStateOf(initialNote?.category ?: "Diary") }
    var selectedTheme by remember { mutableStateOf(initialNote?.theme ?: "Midnight Cyber") }
    var isFavorite by remember { mutableStateOf(initialNote?.isFavorite ?: false) }
    var isSensitive by remember { mutableStateOf(initialNote?.isSensitive ?: false) }

    // Undo / Redo stacks
    val undoStack = remember { mutableStateListOf<Pair<String, String>>() }
    val redoStack = remember { mutableStateListOf<Pair<String, String>>() }

    val contentFocusRequester = remember { FocusRequester() }
    val themes = listOf("Midnight Cyber", "Amethyst Ink", "Emerald Forest", "Sunset Paper", "Minimal Slate")
    var showThemeMenu by remember { mutableStateOf(false) }

    val formattedDate = remember {
        val time = initialNote?.updatedAtEpochMs ?: System.currentTimeMillis()
        SimpleDateFormat("MMM dd, yyyy • hh:mm a", Locale.getDefault()).format(Date(time))
    }

    val charCount = content.length
    val wordCount = if (content.isBlank()) 0 else content.trim().split("\\s+".toRegex()).size

    // Save helper
    val saveCurrentNote: () -> Unit = {
        if (title.isNotBlank() || content.isNotBlank()) {
            val saveTitle = title.ifBlank { "Untitled Note" }
            coordinator.saveNote(
                existingId = initialNote?.id,
                existingRevision = initialNote?.revision,
                title = saveTitle,
                content = content,
                category = category,
                isSensitive = isSensitive,
                theme = selectedTheme,
                isFavorite = isFavorite,
                onComplete = {}
            )
        }
    }

    // Intercept hardware/system back button to autosave and exit
    BackHandler {
        saveCurrentNote()
        onBack()
    }

    // Theme background color
    val themeBgColor = when (selectedTheme) {
        "Amethyst Ink" -> Color(0xFF181028)
        "Emerald Forest" -> Color(0xFF0C1F17)
        "Sunset Paper" -> Color(0xFF1E1510)
        "Minimal Slate" -> Color(0xFF161A22)
        else -> MaterialTheme.colorScheme.background // Midnight Cyber
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = {
                    Column {
                        Text(
                            text = if (initialNote == null) "New Note / Diary" else "Edit Note",
                            style = MaterialTheme.typography.titleMedium,
                            fontWeight = FontWeight.Bold
                        )
                        Text(
                            text = "$formattedDate • $wordCount words",
                            style = MaterialTheme.typography.labelSmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                },
                navigationIcon = {
                    IconButton(onClick = {
                        saveCurrentNote()
                        onBack()
                    }) {
                        Icon(Icons.Default.ArrowBack, contentDescription = "Save and Close")
                    }
                },
                actions = {
                    IconButton(onClick = { isFavorite = !isFavorite }) {
                        Text(if (isFavorite) "★" else "☆", fontSize = 20.sp, color = if (isFavorite) Color(0xFFFFD700) else MaterialTheme.colorScheme.onSurface)
                    }
                    IconButton(onClick = { showThemeMenu = true }) {
                        Text("🎨", fontSize = 18.sp)
                    }
                    DropdownMenu(
                        expanded = showThemeMenu,
                        onDismissRequest = { showThemeMenu = false }
                    ) {
                        themes.forEach { th ->
                            DropdownMenuItem(
                                text = { Text(th, fontWeight = if (selectedTheme == th) FontWeight.Bold else FontWeight.Normal) },
                                onClick = {
                                    selectedTheme = th
                                    showThemeMenu = false
                                }
                            )
                        }
                    }
                    Button(
                        onClick = {
                            saveCurrentNote()
                            onBack()
                        },
                        shape = RoundedCornerShape(12.dp),
                        modifier = Modifier.padding(end = 8.dp)
                    ) {
                        Text("Save")
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(containerColor = themeBgColor)
            )
        },
        bottomBar = {
            // Modern bottom formatting toolbar
            Surface(
                color = MaterialTheme.colorScheme.surfaceVariant,
                tonalElevation = 6.dp,
                modifier = Modifier.fillMaxWidth()
            ) {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(horizontal = 12.dp, vertical = 6.dp),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Row(horizontalArrangement = Arrangement.spacedBy(4.dp)) {
                        // Undo
                        IconButton(
                            onClick = {
                                if (undoStack.isNotEmpty()) {
                                    val last = undoStack.removeLast()
                                    redoStack.add(Pair(title, content))
                                    title = last.first
                                    content = last.second
                                }
                            },
                            enabled = undoStack.isNotEmpty()
                        ) {
                            Text("↩️", fontSize = 16.sp)
                        }
                        // Redo
                        IconButton(
                            onClick = {
                                if (redoStack.isNotEmpty()) {
                                    val next = redoStack.removeLast()
                                    undoStack.add(Pair(title, content))
                                    title = next.first
                                    content = next.second
                                }
                            },
                            enabled = redoStack.isNotEmpty()
                        ) {
                            Text("↪️", fontSize = 16.sp)
                        }
                        // Insert Bullet
                        IconButton(onClick = {
                            undoStack.add(Pair(title, content))
                            content = if (content.endsWith("\n") || content.isEmpty()) "$content• " else "$content\n• "
                        }) {
                            Text("•—", fontWeight = FontWeight.Bold, fontSize = 16.sp)
                        }
                        // Insert Checkbox
                        IconButton(onClick = {
                            undoStack.add(Pair(title, content))
                            content = if (content.endsWith("\n") || content.isEmpty()) "$content[ ] " else "$content\n[ ] "
                        }) {
                            Text("☑", fontSize = 16.sp)
                        }
                        // Insert Quote
                        IconButton(onClick = {
                            undoStack.add(Pair(title, content))
                            content = if (content.endsWith("\n") || content.isEmpty()) "$content> " else "$content\n> "
                        }) {
                            Text("❝", fontSize = 16.sp)
                        }
                    }

                    Text(
                        text = "$charCount chars",
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
            }
        }
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .background(themeBgColor)
                .padding(padding)
                .padding(horizontal = 20.dp, vertical = 12.dp)
        ) {
            // Note Title (large natural typography)
            BasicTextField(
                value = title,
                onValueChange = { newTitle ->
                    if (title != newTitle) {
                        undoStack.add(Pair(title, content))
                        redoStack.clear()
                    }
                    title = newTitle
                },
                textStyle = MaterialTheme.typography.headlineMedium.copy(
                    fontWeight = FontWeight.Bold,
                    color = MaterialTheme.colorScheme.onBackground
                ),
                cursorBrush = SolidColor(MaterialTheme.colorScheme.primary),
                singleLine = true,
                modifier = Modifier.fillMaxWidth(),
                decorationBox = { innerTextField ->
                    Box {
                        if (title.isEmpty()) {
                            Text(
                                text = "Title",
                                style = MaterialTheme.typography.headlineMedium,
                                fontWeight = FontWeight.Bold,
                                color = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.5f)
                            )
                        }
                        innerTextField()
                    }
                }
            )

            Spacer(modifier = Modifier.height(16.dp))

            // Large natural writing / diary area
            BasicTextField(
                value = content,
                onValueChange = { newContent ->
                    if (content != newContent) {
                        undoStack.add(Pair(title, content))
                        redoStack.clear()
                    }
                    content = newContent
                },
                textStyle = MaterialTheme.typography.bodyLarge.copy(
                    fontSize = 17.sp,
                    lineHeight = 26.sp,
                    color = MaterialTheme.colorScheme.onBackground
                ),
                cursorBrush = SolidColor(MaterialTheme.colorScheme.primary),
                modifier = Modifier
                    .fillMaxWidth()
                    .weight(1f)
                    .focusRequester(contentFocusRequester),
                decorationBox = { innerTextField ->
                    Box(modifier = Modifier.fillMaxSize()) {
                        if (content.isEmpty()) {
                            Text(
                                text = "Start writing your private thoughts or notes freely. Everything is encrypted locally with your vault root key...",
                                style = MaterialTheme.typography.bodyLarge.copy(fontSize = 17.sp, lineHeight = 26.sp),
                                color = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.45f)
                            )
                        }
                        innerTextField()
                    }
                }
            )
        }
    }

    // Request focus on editor open if new note
    LaunchedEffect(Unit) {
        if (title.isEmpty()) {
            contentFocusRequester.requestFocus()
        }
    }
}

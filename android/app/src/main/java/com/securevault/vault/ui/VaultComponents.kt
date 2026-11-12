package com.securevault.vault.ui

import androidx.compose.animation.core.*
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.ui.res.painterResource
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.shadow
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.*
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.lazy.LazyRow
import androidx.compose.foundation.lazy.items
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.securevault.vault.generator.PasswordGenerator
import com.securevault.vault.generator.PasswordGeneratorConfig
import com.securevault.vault.model.DocumentEntry
import com.securevault.vault.model.DocumentPage
import com.securevault.vault.model.PasswordEntry
import com.securevault.vault.model.SecureNote
import com.securevault.vault.strength.PasswordStrength
import com.securevault.vault.strength.PasswordStrengthMeter
import com.securevault.vault.strength.StrengthResult
import com.securevault.vault.ui.theme.LocalVaultThemeStyle
import com.securevault.vault.ui.theme.VaultRadius
import com.securevault.vault.ui.theme.VaultSpacing
import java.text.SimpleDateFormat
import java.util.*

@Composable
fun VaultGlassSurface(
    modifier: Modifier = Modifier,
    shape: Shape? = null,
    borderWidth: Dp? = null,
    borderBrush: Brush? = null,
    elevation: Dp? = null,
    containerColor: Color? = null,
    content: @Composable BoxScope.() -> Unit
) {
    val theme = LocalVaultThemeStyle.current
    val effectiveShape = shape ?: RoundedCornerShape(theme.cardCornerRadius)
    val effectiveBorderWidth = borderWidth ?: theme.cardBorderWidth
    val effectiveBorderBrush = borderBrush ?: theme.cardBorderBrush
    val effectiveElevation = elevation ?: theme.cardElevation
    val effectiveColor = containerColor ?: theme.frostedSurfaceColor

    Box(
        modifier = modifier
            .shadow(elevation = effectiveElevation, shape = effectiveShape, clip = false)
            .clip(effectiveShape)
            .background(effectiveColor)
            .then(
                if (effectiveBorderWidth > 0.dp) {
                    Modifier.border(effectiveBorderWidth, effectiveBorderBrush, effectiveShape)
                } else Modifier
            )
    ) {
        content()
    }
}

@Composable
fun CyberShieldAnimation(modifier: Modifier = Modifier) {
    val infiniteTransition = rememberInfiniteTransition(label = "shield")
    val pulse by infiniteTransition.animateFloat(
        initialValue = 0.96f,
        targetValue = 1.04f,
        animationSpec = infiniteRepeatable(
            animation = tween(2400, easing = FastOutSlowInEasing),
            repeatMode = RepeatMode.Reverse
        ),
        label = "pulse"
    )

    Box(modifier = modifier.size(110.dp), contentAlignment = Alignment.Center) {
        Canvas(modifier = Modifier.fillMaxSize()) {
            val center = Offset(size.width / 2, size.height / 2)
            val radius = (size.minDimension / 2) * 0.85f * pulse

            // Outer glowing neon ring
            drawCircle(
                brush = Brush.radialGradient(
                    colors = listOf(Color(0xFF00E5FF).copy(alpha = 0.35f), Color.Transparent),
                    center = center,
                    radius = radius * 1.35f
                ),
                center = center,
                radius = radius * 1.35f
            )
        }
        Image(
            painter = painterResource(id = com.securevault.R.drawable.app_logo),
            contentDescription = "SecureVault Shield",
            modifier = Modifier
                .size(94.dp)
                .clip(RoundedCornerShape(20.dp))
        )
    }
}

@Composable
fun PasswordStrengthBar(result: StrengthResult, modifier: Modifier = Modifier) {
    val barColor = when (result.strength) {
        PasswordStrength.VERY_WEAK -> Color(0xFFD32F2F)
        PasswordStrength.WEAK -> Color(0xFFF57C00)
        PasswordStrength.FAIR -> Color(0xFFFBC02D)
        PasswordStrength.STRONG -> Color(0xFF388E3C)
        PasswordStrength.VERY_STRONG -> Color(0xFF1B5E20)
    }

    Column(modifier = modifier.fillMaxWidth(), verticalArrangement = Arrangement.spacedBy(4.dp)) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Text(
                text = "Strength: ${result.strength.label}",
                style = MaterialTheme.typography.labelMedium,
                fontWeight = FontWeight.SemiBold,
                color = barColor
            )
            Text(
                text = "${result.entropyBits} bits",
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
        LinearProgressIndicator(
            progress = { (result.score + 1) / 5f },
            modifier = Modifier.fillMaxWidth().height(6.dp),
            color = barColor,
            trackColor = MaterialTheme.colorScheme.surfaceVariant
        )
        if (result.feedback.isNotEmpty()) {
            Text(
                text = result.feedback.joinToString(" • "),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
    }
}

@Composable
fun PasswordGeneratorDialog(
    generator: PasswordGenerator,
    strengthMeter: PasswordStrengthMeter,
    onDismiss: () -> Unit,
    onPasswordSelected: (String) -> Unit
) {
    var length by remember { mutableFloatStateOf(20f) }
    var uppercase by remember { mutableStateOf(true) }
    var lowercase by remember { mutableStateOf(true) }
    var digits by remember { mutableStateOf(true) }
    var symbols by remember { mutableStateOf(true) }
    var generatedPassword by remember { mutableStateOf("") }

    fun regenerate() {
        val config = PasswordGeneratorConfig(
            length = length.toInt(),
            includeUppercase = uppercase,
            includeLowercase = lowercase,
            includeDigits = digits,
            includeSymbols = symbols
        )
        generatedPassword = try {
            generator.generate(config)
        } catch (_: Exception) {
            ""
        }
    }

    LaunchedEffect(length, uppercase, lowercase, digits, symbols) {
        regenerate()
    }

    val strengthResult = remember(generatedPassword) {
        strengthMeter.evaluate(generatedPassword)
    }

    val theme = LocalVaultThemeStyle.current

    AlertDialog(
        onDismissRequest = onDismiss,
        shape = RoundedCornerShape(theme.cardCornerRadius),
        containerColor = if (theme.enableFrostedBlur) theme.frostedSurfaceColor else MaterialTheme.colorScheme.surfaceVariant,
        title = { Text("Generate Password", fontWeight = FontWeight.Bold) },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                Surface(
                    shape = RoundedCornerShape(VaultRadius.md),
                    color = MaterialTheme.colorScheme.surfaceVariant,
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Text(
                        text = generatedPassword.ifEmpty { "Select at least 1 class" },
                        fontFamily = FontFamily.Monospace,
                        style = MaterialTheme.typography.titleMedium,
                        fontWeight = FontWeight.SemiBold,
                        color = MaterialTheme.colorScheme.primary,
                        modifier = Modifier.padding(14.dp)
                    )
                }

                if (generatedPassword.isNotEmpty()) {
                    PasswordStrengthBar(result = strengthResult)
                }

                Text("Length: ${length.toInt()} characters", style = MaterialTheme.typography.bodyMedium)
                Slider(
                    value = length,
                    onValueChange = { length = it },
                    valueRange = 8f..64f,
                    steps = 55
                )

                Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Checkbox(checked = uppercase, onCheckedChange = { uppercase = it })
                        Text("A-Z", style = MaterialTheme.typography.bodyMedium)
                    }
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Checkbox(checked = lowercase, onCheckedChange = { lowercase = it })
                        Text("a-z", style = MaterialTheme.typography.bodyMedium)
                    }
                }
                Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Checkbox(checked = digits, onCheckedChange = { digits = it })
                        Text("0-9", style = MaterialTheme.typography.bodyMedium)
                    }
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Checkbox(checked = symbols, onCheckedChange = { symbols = it })
                        Text("!@#$", style = MaterialTheme.typography.bodyMedium)
                    }
                }
            }
        },
        confirmButton = {
            Button(
                onClick = { onPasswordSelected(generatedPassword) },
                enabled = generatedPassword.isNotEmpty()
            ) {
                Text("Use Password")
            }
        },
        dismissButton = {
            OutlinedButton(onClick = onDismiss) {
                Text("Cancel")
            }
        }
    )
}

@Composable
fun AddEditPasswordDialog(
    initialEntry: PasswordEntry?,
    generator: PasswordGenerator,
    strengthMeter: PasswordStrengthMeter,
    onDismiss: () -> Unit,
    onSave: (title: String, user: String, pass: String, web: String, notes: String, cat: String, sens: Boolean, fav: Boolean, icon: String) -> Unit
) {
    var title by remember { mutableStateOf(initialEntry?.title ?: "") }
    var categoryType by remember { mutableStateOf(if (initialEntry?.category in listOf("Website", "App")) initialEntry?.category ?: "Website" else if (!initialEntry?.website.isNullOrEmpty()) "Website" else "None") }
    var websiteUrl by remember { mutableStateOf(initialEntry?.website ?: "") }
    var username by remember { mutableStateOf(initialEntry?.username ?: "") }
    var password by remember { mutableStateOf(initialEntry?.password ?: "") }
    var notes by remember { mutableStateOf(initialEntry?.notes ?: "") }
    var isFavorite by remember { mutableStateOf(initialEntry?.isFavorite ?: false) }
    var isSensitive by remember { mutableStateOf(initialEntry?.isSensitive ?: false) }
    var iconName by remember { mutableStateOf(initialEntry?.iconUri ?: "default") }

    var isPasswordVisible by remember { mutableStateOf(false) }

    val popularIcons = listOf(
        "default" to "🔑 Default",
        "google" to "🌐 Google",
        "netflix" to "🎬 Netflix",
        "apple" to "🍎 Apple",
        "amazon" to "📦 Amazon",
        "github" to "🐙 GitHub",
        "microsoft" to "🪟 Microsoft",
        "twitter" to "✖️ X",
        "spotify" to "🎵 Spotify"
    )
    val galleryLauncher = rememberLauncherForActivityResult(ActivityResultContracts.GetContent()) { uri ->
        if (uri != null) {
            iconName = uri.toString()
        }
    }

    val strengthResult = remember(password) { strengthMeter.evaluate(password) }
    val theme = LocalVaultThemeStyle.current

    AlertDialog(
        onDismissRequest = onDismiss,
        shape = RoundedCornerShape(theme.cardCornerRadius),
        containerColor = if (theme.enableFrostedBlur) theme.frostedSurfaceColor else MaterialTheme.colorScheme.surfaceVariant,
        title = { Text(if (initialEntry == null) "New Password" else "Edit Password", fontWeight = FontWeight.Bold) },
        text = {
            Column(
                modifier = Modifier.fillMaxWidth(),
                verticalArrangement = Arrangement.spacedBy(10.dp)
            ) {
                OutlinedTextField(
                    value = title,
                    onValueChange = { title = it },
                    label = { Text("Title *") },
                    placeholder = { Text("e.g. Netflix, Gmail, Work SSO") },
                    modifier = Modifier.fillMaxWidth(),
                    singleLine = true
                )

                // Icon selection row
                Text("Select Icon:", style = MaterialTheme.typography.labelMedium)
                LazyRow(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(6.dp)
                ) {
                    items(popularIcons) { (id, label) ->
                        FilterChip(
                            selected = iconName == id,
                            onClick = { iconName = id },
                            label = { Text(label) }
                        )
                    }
                    item {
                        FilterChip(
                            selected = iconName.startsWith("content://") || iconName.startsWith("file://"),
                            onClick = { galleryLauncher.launch("image/*") },
                            label = { Text(if (iconName.startsWith("content://")) "📷 Custom" else "📷 Gallery") }
                        )
                    }
                }

                // Category selection: None, Website, App
                Text("Category:", style = MaterialTheme.typography.labelMedium)
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    listOf("None", "Website", "App").forEach { cat ->
                        FilterChip(
                            selected = categoryType == cat,
                            onClick = { categoryType = cat },
                            label = { Text(cat) }
                        )
                    }
                }

                // If Website: show Link/URL field
                if (categoryType == "Website") {
                    OutlinedTextField(
                        value = websiteUrl,
                        onValueChange = { websiteUrl = it },
                        label = { Text("Link / URL *") },
                        placeholder = { Text("https://...") },
                        modifier = Modifier.fillMaxWidth(),
                        singleLine = true
                    )
                }

                OutlinedTextField(
                    value = username,
                    onValueChange = { username = it },
                    label = { Text("Username / Email *") },
                    placeholder = { Text("alex@example.com") },
                    modifier = Modifier.fillMaxWidth(),
                    singleLine = true
                )

                OutlinedTextField(
                    value = password,
                    onValueChange = { password = it },
                    label = { Text("Password *") },
                    modifier = Modifier.fillMaxWidth(),
                    singleLine = true,
                    visualTransformation = if (isPasswordVisible) VisualTransformation.None else PasswordVisualTransformation(),
                    trailingIcon = {
                        IconButton(onClick = { isPasswordVisible = !isPasswordVisible }) {
                            Text(if (isPasswordVisible) "👁️" else "🔒", fontSize = 16.sp)
                        }
                    }
                )

                if (password.isNotEmpty()) {
                    PasswordStrengthBar(result = strengthResult)
                }

                OutlinedTextField(
                    value = notes,
                    onValueChange = { notes = it },
                    label = { Text("Notes (Optional)") },
                    modifier = Modifier.fillMaxWidth(),
                    maxLines = 3
                )

                Row(verticalAlignment = Alignment.CenterVertically) {
                    Checkbox(checked = isFavorite, onCheckedChange = { isFavorite = it })
                    Spacer(modifier = Modifier.width(4.dp))
                    Text("Add to Favorites", style = MaterialTheme.typography.bodyMedium)
                }
            }
        },
        confirmButton = {
            Button(
                onClick = {
                    val finalCategory = if (categoryType == "None") "General" else categoryType
                    onSave(title, username, password, websiteUrl, notes, finalCategory, isSensitive, isFavorite, iconName)
                },
                enabled = title.isNotBlank() && username.isNotBlank() && password.isNotEmpty()
            ) {
                Text("Save")
            }
        },
        dismissButton = {
            OutlinedButton(onClick = onDismiss) {
                Text("Cancel")
            }
        }
    )
}

@Composable
fun AddEditNoteDialog(
    initialNote: SecureNote?,
    onDismiss: () -> Unit,
    onSave: (title: String, content: String, cat: String, sens: Boolean, theme: String, fav: Boolean) -> Unit
) {
    var title by remember { mutableStateOf(initialNote?.title ?: "") }
    var content by remember { mutableStateOf(initialNote?.content ?: "") }
    var category by remember { mutableStateOf(initialNote?.category ?: "Personal") }
    var isSensitive by remember { mutableStateOf(initialNote?.isSensitive ?: false) }
    var selectedTheme by remember { mutableStateOf(initialNote?.theme ?: "Midnight Cyber") }
    var isFavorite by remember { mutableStateOf(initialNote?.isFavorite ?: false) }

    val themes = listOf("Midnight Cyber", "Amethyst Ink", "Emerald Forest", "Sunset Paper", "Minimal Slate")
    val theme = LocalVaultThemeStyle.current

    AlertDialog(
        onDismissRequest = onDismiss,
        shape = RoundedCornerShape(theme.cardCornerRadius),
        containerColor = if (theme.enableFrostedBlur) theme.frostedSurfaceColor else MaterialTheme.colorScheme.surfaceVariant,
        title = { Text(if (initialNote == null) "New Private Diary / Note" else "Edit Note", fontWeight = FontWeight.Bold) },
        text = {
            Column(
                modifier = Modifier.fillMaxWidth(),
                verticalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                OutlinedTextField(
                    value = title,
                    onValueChange = { title = it },
                    label = { Text("Title *") },
                    placeholder = { Text("Diary title or subject") },
                    modifier = Modifier.fillMaxWidth(),
                    singleLine = true
                )

                Text("Theme & Atmosphere:", style = MaterialTheme.typography.labelSmall)
                Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                    themes.take(3).forEach { th ->
                        FilterChip(
                            selected = selectedTheme == th,
                            onClick = { selectedTheme = th },
                            label = { Text(th.split(" ").first()) }
                        )
                    }
                }

                OutlinedTextField(
                    value = content,
                    onValueChange = { content = it },
                    label = { Text("Private Writing *") },
                    placeholder = { Text("Write your thoughts freely. Encrypted locally with your vault keys...") },
                    modifier = Modifier.fillMaxWidth().height(180.dp),
                    maxLines = 10
                )

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Text(
                        text = "${content.split("\\s+".toRegex()).filter { it.isNotBlank() }.size} words",
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Checkbox(checked = isFavorite, onCheckedChange = { isFavorite = it })
                        Text("Favorite", style = MaterialTheme.typography.bodySmall)
                    }
                }
            }
        },
        confirmButton = {
            Button(
                onClick = { onSave(title, content, category, isSensitive, selectedTheme, isFavorite) },
                enabled = title.isNotBlank() && content.isNotBlank()
            ) {
                Text("Save")
            }
        },
        dismissButton = {
            OutlinedButton(onClick = onDismiss) {
                Text("Cancel")
            }
        }
    )
}

@Composable
fun VaultPasswordCard(
    entry: PasswordEntry,
    isRevealed: Boolean,
    onToggleReveal: () -> Unit,
    onCopyPassword: () -> Unit,
    onCopyUsername: () -> Unit,
    onEdit: () -> Unit,
    onDelete: () -> Unit,
    onFavorite: () -> Unit,
    onStrength: () -> Unit,
    onShare: () -> Unit
) {
    var showMenu by remember { mutableStateOf(false) }

    VaultGlassSurface(
        modifier = Modifier.fillMaxWidth()
    ) {
        Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                    // Website / App icon badge
                    val iconDisplay = when (entry.iconUri) {
                        "google" -> "🌐"
                        "netflix" -> "🎬"
                        "apple" -> "🍎"
                        "amazon" -> "📦"
                        "github" -> "🐙"
                        "microsoft" -> "🪟"
                        "twitter" -> "✖️"
                        "spotify" -> "🎵"
                        else -> if (entry.iconUri.startsWith("content://") || entry.iconUri.startsWith("file://")) "📷" else entry.title.take(1).uppercase()
                    }
                    Surface(
                        shape = CircleShape,
                        color = MaterialTheme.colorScheme.primaryContainer,
                        modifier = Modifier.size(40.dp)
                    ) {
                        Box(contentAlignment = Alignment.Center) {
                            Text(
                                text = iconDisplay,
                                style = MaterialTheme.typography.titleMedium,
                                fontWeight = FontWeight.Bold,
                                color = MaterialTheme.colorScheme.onPrimaryContainer
                            )
                        }
                    }
                    Column {
                        Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(4.dp)) {
                            Text(text = entry.title, style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold)
                            if (entry.isFavorite) {
                                Text("★", color = Color(0xFFFFD700), fontSize = 16.sp)
                            }
                        }
                        Text(
                            text = if (entry.category.isNotEmpty()) entry.category else "Credential",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.primary
                        )
                    }
                }

                // Three-dot action menu
                Box {
                    IconButton(onClick = { showMenu = true }) {
                        Text("⋮", fontSize = 22.sp, fontWeight = FontWeight.Bold)
                    }
                    DropdownMenu(expanded = showMenu, onDismissRequest = { showMenu = false }) {
                        DropdownMenuItem(text = { Text("Edit") }, onClick = { showMenu = false; onEdit() })
                        DropdownMenuItem(text = { Text(if (entry.isFavorite) "Unfavorite" else "Favorite") }, onClick = { showMenu = false; onFavorite() })
                        DropdownMenuItem(text = { Text("Password Strength") }, onClick = { showMenu = false; onStrength() })
                        DropdownMenuItem(text = { Text("Share") }, onClick = { showMenu = false; onShare() })
                        DropdownMenuItem(text = { Text("Delete", color = MaterialTheme.colorScheme.error) }, onClick = { showMenu = false; onDelete() })
                    }
                }
            }

            HorizontalDivider(color = MaterialTheme.colorScheme.surface.copy(alpha = 0.5f))

            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(text = entry.username, style = MaterialTheme.typography.bodyMedium)
                TextButton(onClick = onCopyUsername) { Text("Copy User") }
            }

            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(
                    text = if (isRevealed) entry.password else "••••••••••••••••",
                    fontFamily = FontFamily.Monospace,
                    style = MaterialTheme.typography.bodyMedium,
                    fontWeight = FontWeight.SemiBold
                )
                Row {
                    TextButton(onClick = onToggleReveal) {
                        Text(if (isRevealed) "Hide" else "Show (15s)")
                    }
                    TextButton(onClick = onCopyPassword) {
                        Text("Copy Pass")
                    }
                }
            }

            if (entry.website.isNotEmpty()) {
                Text(text = entry.website, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
        }
    }
}

@Composable
fun VaultDocumentCard(
    doc: DocumentEntry,
    onView: () -> Unit,
    onEdit: () -> Unit,
    onDelete: () -> Unit,
    onFavorite: () -> Unit,
    onShare: () -> Unit
) {
    var showMenu by remember { mutableStateOf(false) }

    VaultGlassSurface(
        modifier = Modifier.fillMaxWidth().clickable(onClick = onView)
    ) {
        Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                    Surface(
                        shape = RoundedCornerShape(8.dp),
                        color = Color(0xFF7B5CFA).copy(alpha = 0.2f),
                        modifier = Modifier.size(42.dp)
                    ) {
                        Box(contentAlignment = Alignment.Center) {
                            Text("📄", fontSize = 20.sp)
                        }
                    }
                    Column {
                        Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(4.dp)) {
                            Text(text = doc.title, style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold)
                            if (doc.isFavorite) {
                                Text("★", color = Color(0xFFFFD700), fontSize = 16.sp)
                            }
                        }
                        Text(
                            text = "${doc.category} • ${doc.pages.size} page(s)",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.primary
                        )
                    }
                }

                Box {
                    IconButton(onClick = { showMenu = true }) {
                        Text("⋮", fontSize = 22.sp, fontWeight = FontWeight.Bold)
                    }
                    DropdownMenu(expanded = showMenu, onDismissRequest = { showMenu = false }) {
                        DropdownMenuItem(text = { Text("View Document") }, onClick = { showMenu = false; onView() })
                        DropdownMenuItem(text = { Text("Edit Title/Category") }, onClick = { showMenu = false; onEdit() })
                        DropdownMenuItem(text = { Text(if (doc.isFavorite) "Unfavorite" else "Favorite") }, onClick = { showMenu = false; onFavorite() })
                        DropdownMenuItem(text = { Text("Share") }, onClick = { showMenu = false; onShare() })
                        DropdownMenuItem(text = { Text("Delete", color = MaterialTheme.colorScheme.error) }, onClick = { showMenu = false; onDelete() })
                    }
                }
            }

            if (doc.ocrText.isNotEmpty()) {
                Text(
                    text = "OCR: ${doc.ocrText.take(120)}...",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        }
    }
}

@Composable
fun VaultNoteCard(
    note: SecureNote,
    onCopyContent: () -> Unit,
    onEdit: () -> Unit,
    onDelete: () -> Unit,
    onFavorite: () -> Unit,
    onShare: () -> Unit
) {
    var showMenu by remember { mutableStateOf(false) }

    VaultGlassSurface(
        modifier = Modifier.fillMaxWidth().clickable(onClick = onEdit)
    ) {
        Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    Surface(
                        shape = CircleShape,
                        color = Color(0xFF00E5FF).copy(alpha = 0.2f),
                        modifier = Modifier.size(36.dp)
                    ) {
                        Box(contentAlignment = Alignment.Center) {
                            Text("✍️", fontSize = 16.sp)
                        }
                    }
                    Column {
                        Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(4.dp)) {
                            Text(text = note.title, style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold)
                            if (note.isFavorite) {
                                Text("★", color = Color(0xFFFFD700), fontSize = 16.sp)
                            }
                        }
                        Text(
                            text = "${note.category} • Theme: ${note.theme}",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.primary
                        )
                    }
                }

                Box {
                    IconButton(onClick = { showMenu = true }) {
                        Text("⋮", fontSize = 22.sp, fontWeight = FontWeight.Bold)
                    }
                    DropdownMenu(expanded = showMenu, onDismissRequest = { showMenu = false }) {
                        DropdownMenuItem(text = { Text("Edit") }, onClick = { showMenu = false; onEdit() })
                        DropdownMenuItem(text = { Text("Copy Content") }, onClick = { showMenu = false; onCopyContent() })
                        DropdownMenuItem(text = { Text(if (note.isFavorite) "Unfavorite" else "Favorite") }, onClick = { showMenu = false; onFavorite() })
                        DropdownMenuItem(text = { Text("Share") }, onClick = { showMenu = false; onShare() })
                        DropdownMenuItem(text = { Text("Delete", color = MaterialTheme.colorScheme.error) }, onClick = { showMenu = false; onDelete() })
                    }
                }
            }

            Text(
                text = note.content.take(160) + if (note.content.length > 160) "..." else "",
                style = MaterialTheme.typography.bodyMedium
            )
        }
    }
}

@Composable
fun ShareItemDialog(
    itemTitle: String,
    onDismiss: () -> Unit,
    onConfirmShare: (expiresInSeconds: Int, maxViews: Int) -> Unit
) {
    val theme = LocalVaultThemeStyle.current
    var expiryChoice by remember { mutableStateOf("24 Hours") }
    var oneTimeView by remember { mutableStateOf(false) }

    AlertDialog(
        onDismissRequest = onDismiss,
        shape = RoundedCornerShape(theme.cardCornerRadius),
        containerColor = if (theme.enableFrostedBlur) theme.frostedSurfaceColor else MaterialTheme.colorScheme.surfaceVariant,
        title = { Text("Secure Share", fontWeight = FontWeight.Bold) },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                Text(
                    text = "Generate zero-knowledge link for '$itemTitle'. Ephemeral key is contained only in the URL fragment.",
                    style = MaterialTheme.typography.bodySmall
                )

                Text("Link Expiration:", style = MaterialTheme.typography.labelMedium)
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    listOf("1 Hour", "24 Hours", "7 Days").forEach { exp ->
                        FilterChip(
                            selected = expiryChoice == exp,
                            onClick = { expiryChoice = exp },
                            label = { Text(exp) }
                        )
                    }
                }

                Row(verticalAlignment = Alignment.CenterVertically) {
                    Checkbox(checked = oneTimeView, onCheckedChange = { oneTimeView = it })
                    Spacer(modifier = Modifier.width(6.dp))
                    Text("One-Time View (Revoke immediately after first open)", style = MaterialTheme.typography.bodyMedium)
                }
            }
        },
        confirmButton = {
            Button(
                onClick = {
                    val seconds = when (expiryChoice) {
                        "1 Hour" -> 3600
                        "7 Days" -> 7 * 86400
                        else -> 86400
                    }
                    val views = if (oneTimeView) 1 else 1000
                    onConfirmShare(seconds, views)
                }
            ) {
                Text("Generate Link")
            }
        },
        dismissButton = {
            OutlinedButton(onClick = onDismiss) { Text("Cancel") }
        }
    )
}

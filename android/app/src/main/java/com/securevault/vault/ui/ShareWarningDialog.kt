package com.securevault.vault.ui

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.core.tween
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.ContentCopy
import androidx.compose.material.icons.outlined.Share
import androidx.compose.material.icons.outlined.Shield
import androidx.compose.material.icons.outlined.Warning
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.securevault.vault.ui.theme.LocalVaultThemeStyle
import com.securevault.vault.ui.theme.VaultRadius
import com.securevault.vault.ui.theme.VaultSpacing

/**
 * Item type classification for share warning dialog — controls which
 * security disclosures are shown and whether the password-inclusion
 * opt-in checkbox is visible.
 */
enum class ShareItemType {
    PASSWORD, NOTE, DOCUMENT
}

/**
 * Expiry option for the share link picker.
 */
data class ShareExpiryOption(
    val label: String,
    val seconds: Int
)

/**
 * Max-views option for the share link picker.
 */
data class ShareViewsOption(
    val label: String,
    val count: Int
)

private val EXPIRY_OPTIONS = listOf(
    ShareExpiryOption("1 Hour", 3600),
    ShareExpiryOption("24 Hours", 86400),
    ShareExpiryOption("7 Days", 7 * 86400),
    ShareExpiryOption("30 Days", 30 * 86400)
)

private val VIEWS_OPTIONS = listOf(
    ShareViewsOption("1 View", 1),
    ShareViewsOption("3 Views", 3),
    ShareViewsOption("10 Views", 10),
    ShareViewsOption("Unlimited", 1000)
)

/**
 * Mandatory security warning dialog shown BEFORE a share link is created.
 *
 * The user MUST explicitly acknowledge all security disclosures (via a
 * checkbox) before the "Generate Link" button becomes enabled. This gates
 * every call to [VaultCoordinator.createShare].
 *
 * For password items, there is an additional opt-in checkbox to include
 * the actual password in the shared payload. By default only the
 * username/URL metadata is shared.
 */
@Composable
fun ShareWarningDialog(
    itemTitle: String,
    itemType: ShareItemType,
    onDismiss: () -> Unit,
    onConfirmShare: (
        expiresInSeconds: Int,
        maxViews: Int,
        includePassword: Boolean
    ) -> Unit,
    onShareViaSystem: ((includePassword: Boolean) -> Unit)? = null
) {
    val theme = LocalVaultThemeStyle.current
    val scrollState = rememberScrollState()
    var acknowledged by remember { mutableStateOf(false) }
    var includePassword by remember { mutableStateOf(false) }
    var selectedExpiry by remember { mutableStateOf(EXPIRY_OPTIONS[1]) } // default 24h
    var selectedViews by remember { mutableStateOf(VIEWS_OPTIONS[0]) }  // default 1 view

    AlertDialog(
        onDismissRequest = onDismiss,
        shape = RoundedCornerShape(theme.cardCornerRadius),
        containerColor = if (theme.enableFrostedBlur) theme.frostedSurfaceColor
                         else MaterialTheme.colorScheme.surfaceVariant,
        title = {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(VaultSpacing.sm)
            ) {
                Icon(
                    imageVector = Icons.Outlined.Warning,
                    contentDescription = "Security warning",
                    tint = MaterialTheme.colorScheme.error,
                    modifier = Modifier.size(24.dp)
                )
                Text(
                    text = "Share Security Warning",
                    fontWeight = FontWeight.Bold,
                    style = MaterialTheme.typography.titleMedium
                )
            }
        },
        text = {
            Column(
                modifier = Modifier.verticalScroll(scrollState),
                verticalArrangement = Arrangement.spacedBy(VaultSpacing.md)
            ) {
                // ── Security disclosures ────────────────────────────────────
                Surface(
                    shape = RoundedCornerShape(VaultRadius.md),
                    color = MaterialTheme.colorScheme.errorContainer.copy(alpha = 0.35f),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Column(
                        modifier = Modifier.padding(VaultSpacing.md),
                        verticalArrangement = Arrangement.spacedBy(VaultSpacing.sm)
                    ) {
                        Text(
                            text = "⚠️  Please read carefully:",
                            style = MaterialTheme.typography.labelMedium,
                            fontWeight = FontWeight.Bold,
                            color = MaterialTheme.colorScheme.error
                        )
                        WarningBullet(
                            "The shared item's decrypted content will be accessible to anyone who possesses the link."
                        )
                        WarningBullet(
                            "The decryption key is placed ONLY in the URL fragment (#key=…) — our server never receives it."
                        )
                        WarningBullet(
                            "Once shared, you cannot control how the recipient uses or forwards the data."
                        )
                        WarningBullet(
                            "You can revoke the link at any time from the Share Center to prevent further access."
                        )
                    }
                }

                // ── Zero-knowledge guarantee badge ──────────────────────────
                Surface(
                    shape = RoundedCornerShape(VaultRadius.md),
                    color = MaterialTheme.colorScheme.primaryContainer.copy(alpha = 0.4f),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Row(
                        modifier = Modifier.padding(VaultSpacing.sm + 2.dp),
                        horizontalArrangement = Arrangement.spacedBy(VaultSpacing.sm),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Icon(
                            imageVector = Icons.Outlined.Shield,
                            contentDescription = "Zero-knowledge encryption",
                            tint = MaterialTheme.colorScheme.primary,
                            modifier = Modifier.size(20.dp)
                        )
                        Text(
                            text = "Zero-Knowledge: Server never sees the plaintext or key.",
                            style = MaterialTheme.typography.labelSmall,
                            color = MaterialTheme.colorScheme.primary,
                            fontWeight = FontWeight.SemiBold
                        )
                    }
                }

                // ── Item info ───────────────────────────────────────────────
                Text(
                    text = "Sharing: $itemTitle",
                    style = MaterialTheme.typography.bodyMedium,
                    fontWeight = FontWeight.SemiBold
                )

                // ── Expiry picker ───────────────────────────────────────────
                Text(
                    text = "LINK EXPIRATION",
                    style = MaterialTheme.typography.labelSmall,
                    fontWeight = FontWeight.Bold,
                    letterSpacing = 1.sp,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                Row(
                    horizontalArrangement = Arrangement.spacedBy(6.dp),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    EXPIRY_OPTIONS.forEach { option ->
                        FilterChip(
                            selected = selectedExpiry == option,
                            onClick = { selectedExpiry = option },
                            label = { Text(option.label, style = MaterialTheme.typography.labelSmall) },
                            modifier = Modifier.semantics {
                                contentDescription = "Set link expiry to ${option.label}"
                            }
                        )
                    }
                }

                // ── Max views picker ────────────────────────────────────────
                Text(
                    text = "MAXIMUM VIEWS",
                    style = MaterialTheme.typography.labelSmall,
                    fontWeight = FontWeight.Bold,
                    letterSpacing = 1.sp,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                Row(
                    horizontalArrangement = Arrangement.spacedBy(6.dp),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    VIEWS_OPTIONS.forEach { option ->
                        FilterChip(
                            selected = selectedViews == option,
                            onClick = { selectedViews = option },
                            label = { Text(option.label, style = MaterialTheme.typography.labelSmall) },
                            modifier = Modifier.semantics {
                                contentDescription = "Set maximum views to ${option.label}"
                            }
                        )
                    }
                }

                // ── Password inclusion opt-in (passwords only) ──────────────
                if (itemType == ShareItemType.PASSWORD) {
                    HorizontalDivider(modifier = Modifier.padding(vertical = 4.dp))
                    Surface(
                        shape = RoundedCornerShape(VaultRadius.md),
                        color = MaterialTheme.colorScheme.errorContainer.copy(alpha = 0.2f),
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Row(
                            modifier = Modifier
                                .clip(RoundedCornerShape(VaultRadius.md))
                                .clickable { includePassword = !includePassword }
                                .padding(VaultSpacing.sm),
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Checkbox(
                                checked = includePassword,
                                onCheckedChange = { includePassword = it },
                                modifier = Modifier.semantics {
                                    contentDescription = "Include password in shared link"
                                }
                            )
                            Spacer(modifier = Modifier.width(4.dp))
                            Column {
                                Text(
                                    text = "Include actual password",
                                    style = MaterialTheme.typography.bodySmall,
                                    fontWeight = FontWeight.Bold,
                                    color = MaterialTheme.colorScheme.error
                                )
                                Text(
                                    text = "By default, only the username and URL are shared. Check this to include the password — use with extreme caution.",
                                    style = MaterialTheme.typography.labelSmall,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant
                                )
                            }
                        }
                    }
                }

                // ── Mandatory acknowledgment checkbox ───────────────────────
                HorizontalDivider(modifier = Modifier.padding(vertical = 4.dp))
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .clip(RoundedCornerShape(VaultRadius.sm))
                        .clickable { acknowledged = !acknowledged }
                        .padding(vertical = VaultSpacing.xs),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Checkbox(
                        checked = acknowledged,
                        onCheckedChange = { acknowledged = it },
                        modifier = Modifier.semantics {
                            contentDescription = "Acknowledge share security warnings"
                        }
                    )
                    Spacer(modifier = Modifier.width(4.dp))
                    Text(
                        text = "I understand that this item's decrypted content will leave the vault boundary and can be viewed by anyone with the link.",
                        style = MaterialTheme.typography.bodySmall,
                        fontWeight = FontWeight.SemiBold
                    )
                }
            }
        },
        confirmButton = {
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                if (onShareViaSystem != null) {
                    OutlinedButton(
                        onClick = { onShareViaSystem(includePassword) },
                        enabled = acknowledged,
                        modifier = Modifier.semantics {
                            contentDescription = "Share via Android system sheet"
                        }
                    ) {
                        Text("Share via OS")
                    }
                }
                Button(
                    onClick = {
                        onConfirmShare(
                            selectedExpiry.seconds,
                            selectedViews.count,
                            includePassword
                        )
                    },
                    enabled = acknowledged,
                    modifier = Modifier.semantics {
                        contentDescription = "Generate secure share link"
                    }
                ) {
                    Icon(
                        imageVector = Icons.Outlined.Share,
                        contentDescription = null,
                        modifier = Modifier.size(ButtonDefaults.IconSize)
                    )
                    Spacer(Modifier.width(ButtonDefaults.IconSpacing))
                    Text("Generate Link")
                }
            }
        },
        dismissButton = {
            OutlinedButton(
                onClick = onDismiss,
                modifier = Modifier.semantics {
                    contentDescription = "Cancel share"
                }
            ) { Text("Cancel") }
        }
    )
}

/**
 * A single bullet point in the security warning disclosure list.
 */
@Composable
private fun WarningBullet(text: String) {
    Row(
        horizontalArrangement = Arrangement.spacedBy(6.dp),
        modifier = Modifier.fillMaxWidth()
    ) {
        Text(
            text = "•",
            style = MaterialTheme.typography.bodySmall,
            fontWeight = FontWeight.Bold,
            color = MaterialTheme.colorScheme.error
        )
        Text(
            text = text,
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurface
        )
    }
}

/**
 * Post-share status card displayed after a share link is created.
 * Shows the generated link (masked), a copy button, and a quick-revoke
 * shortcut. Includes a privacy reminder.
 */
@Composable
fun ShareSuccessBanner(
    shareLink: String,
    onCopyLink: () -> Unit,
    onRevoke: (() -> Unit)? = null,
    onDismiss: () -> Unit,
    modifier: Modifier = Modifier
) {
    var visible by remember { mutableStateOf(true) }

    AnimatedVisibility(
        visible = visible,
        enter = fadeIn(tween(200)),
        exit = fadeOut(tween(150)),
        modifier = modifier
    ) {
        Surface(
            shape = RoundedCornerShape(VaultRadius.lg),
            color = MaterialTheme.colorScheme.primaryContainer,
            modifier = Modifier.fillMaxWidth()
        ) {
            Column(
                modifier = Modifier.padding(VaultSpacing.md),
                verticalArrangement = Arrangement.spacedBy(VaultSpacing.sm)
            ) {
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(VaultSpacing.sm)
                ) {
                    Icon(
                        imageVector = Icons.Outlined.Shield,
                        contentDescription = "Secure share created",
                        tint = MaterialTheme.colorScheme.primary,
                        modifier = Modifier.size(22.dp)
                    )
                    Text(
                        text = "Zero-Knowledge Share Link Created",
                        style = MaterialTheme.typography.titleSmall,
                        fontWeight = FontWeight.Bold,
                        color = MaterialTheme.colorScheme.onPrimaryContainer
                    )
                }

                // Masked link preview
                val masked = if (shareLink.length > 50) {
                    shareLink.take(35) + "…" + shareLink.takeLast(10)
                } else shareLink

                Text(
                    text = masked,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onPrimaryContainer.copy(alpha = 0.7f),
                    maxLines = 2
                )

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(VaultSpacing.sm)
                ) {
                    FilledTonalButton(
                        onClick = onCopyLink,
                        modifier = Modifier
                            .weight(1f)
                            .semantics { contentDescription = "Copy share link to clipboard" }
                    ) {
                        Icon(
                            imageVector = Icons.Outlined.ContentCopy,
                            contentDescription = null,
                            modifier = Modifier.size(ButtonDefaults.IconSize)
                        )
                        Spacer(Modifier.width(4.dp))
                        Text("Copy Link", style = MaterialTheme.typography.labelMedium)
                    }

                    if (onRevoke != null) {
                        OutlinedButton(
                            onClick = {
                                onRevoke()
                                visible = false
                                onDismiss()
                            },
                            colors = ButtonDefaults.outlinedButtonColors(
                                contentColor = MaterialTheme.colorScheme.error
                            ),
                            modifier = Modifier.semantics {
                                contentDescription = "Revoke share link immediately"
                            }
                        ) {
                            Text("Revoke", style = MaterialTheme.typography.labelMedium)
                        }
                    }
                }

                // Privacy reminder
                Text(
                    text = "Link copied with auto-clear (30s). Revoke anytime from Share Center.",
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onPrimaryContainer.copy(alpha = 0.6f),
                    textAlign = TextAlign.Center,
                    modifier = Modifier.fillMaxWidth()
                )
            }
        }
    }
}

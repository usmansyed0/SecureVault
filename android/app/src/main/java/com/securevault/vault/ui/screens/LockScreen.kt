package com.securevault.vault.ui.screens

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.core.tween
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.scaleIn
import androidx.compose.animation.scaleOut
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.securevault.vault.ui.CyberShieldAnimation
import com.securevault.vault.ui.theme.VaultRadius
import com.securevault.vault.ui.theme.VaultSpacing

@Composable
fun LockScreen(
    hasPin: Boolean,
    lockoutSecondsRemaining: Long,
    failedAttempts: Int,
    errorMessage: String?,
    pinLength: Int = 4,
    onUnlockWithPin: (String) -> Unit,
    onUnlockWithBiometric: () -> Unit,
    onLogout: () -> Unit,
    onNavigateToRecovery: (() -> Unit)? = null
) {
    var enteredPin by remember { mutableStateOf("") }
    var isVerifying by remember { mutableStateOf(false) }

    // When an error message arrives, clear entered PIN and unlock the keypad
    LaunchedEffect(errorMessage) {
        if (!errorMessage.isNullOrEmpty()) {
            enteredPin = ""
            isVerifying = false
        }
    }

    // visible starts false and is set true immediately via LaunchedEffect.
    // When the parent removes LockScreen on successful unlock the exit animation
    // runs (180 ms) — fast enough that unlocking still feels instant.
    var visible by remember { mutableStateOf(false) }
    LaunchedEffect(Unit) { visible = true }

    AnimatedVisibility(
        visible = visible,
        enter = fadeIn(tween(180)) + scaleIn(tween(200), initialScale = 0.97f),
        exit  = fadeOut(tween(160)) + scaleOut(tween(180), targetScale = 1.02f)
    ) {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .background(MaterialTheme.colorScheme.background)
                .padding(VaultSpacing.xxl),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.SpaceBetween
        ) {
            // Top Brand Header
            Column(
                horizontalAlignment = Alignment.CenterHorizontally,
                verticalArrangement = Arrangement.spacedBy(VaultSpacing.md),
                modifier = Modifier.padding(top = VaultSpacing.xl)
            ) {
                CyberShieldAnimation()
                Text(
                    text = "SECURE VAULT",
                    style = MaterialTheme.typography.titleLarge,
                    fontWeight = FontWeight.Black,
                    letterSpacing = 3.sp,
                    color = MaterialTheme.colorScheme.onBackground
                )
                Text(
                    text = "Vault Locked — Authenticate to Access",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }

            // PIN Input Dots & Status
            Column(
                horizontalAlignment = Alignment.CenterHorizontally,
                verticalArrangement = Arrangement.spacedBy(VaultSpacing.lg)
            ) {
                if (lockoutSecondsRemaining > 0) {
                    Surface(
                        shape = RoundedCornerShape(VaultRadius.md),
                        color = MaterialTheme.colorScheme.errorContainer,
                        modifier = Modifier.padding(horizontal = VaultSpacing.lg)
                    ) {
                        Text(
                            text = "Too many attempts. Locked out for ${lockoutSecondsRemaining}s",
                            style = MaterialTheme.typography.bodyMedium,
                            fontWeight = FontWeight.Bold,
                            color = MaterialTheme.colorScheme.onErrorContainer,
                            modifier = Modifier.padding(VaultSpacing.md)
                        )
                    }
                } else {
                    // PIN Dots Display (matches configured pinLength, 4 dots)
                    Row(
                        horizontalArrangement = Arrangement.spacedBy(VaultSpacing.md + 4.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        val dotCount = enteredPin.length
                        for (i in 0 until pinLength) {
                            val isFilled = i < dotCount
                            Box(
                                modifier = Modifier
                                    .size(18.dp)
                                    .clip(CircleShape)
                                    .background(
                                        if (isFilled) MaterialTheme.colorScheme.primary
                                        else MaterialTheme.colorScheme.surfaceVariant
                                    )
                            )
                        }
                    }

                    if (isVerifying) {
                        CircularProgressIndicator(
                            modifier = Modifier.size(24.dp),
                            strokeWidth = 2.5.dp,
                            color = MaterialTheme.colorScheme.primary
                        )
                    } else if (!errorMessage.isNullOrEmpty()) {
                        Text(
                            text = errorMessage,
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.error,
                            fontWeight = FontWeight.SemiBold
                        )
                    } else if (failedAttempts > 0) {
                        Text(
                            text = "Failed attempts: $failedAttempts / 10 (10 wipes local data)",
                            style = MaterialTheme.typography.labelSmall,
                            color = MaterialTheme.colorScheme.error
                        )
                    }
                }
            }

            // Numeric Keypad
            Column(
                modifier = Modifier.fillMaxWidth().padding(bottom = VaultSpacing.md),
                verticalArrangement = Arrangement.spacedBy(VaultSpacing.md)
            ) {
                val keyRows = listOf(
                    listOf("1", "2", "3"),
                    listOf("4", "5", "6"),
                    listOf("7", "8", "9"),
                    listOf("FP", "0", "⌫")
                )

                keyRows.forEach { row ->
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceEvenly
                    ) {
                        row.forEach { key ->
                            when (key) {
                                "FP" -> {
                                    KeypadButton(
                                        label = "👆",
                                        isSpecial = true,
                                        onClick = {
                                            if (!isVerifying) onUnlockWithBiometric()
                                        }
                                    )
                                }
                                "⌫" -> {
                                    KeypadButton(
                                        label = "⌫",
                                        isSpecial = true,
                                        onClick = {
                                            if (!isVerifying && enteredPin.isNotEmpty()) {
                                                enteredPin = enteredPin.dropLast(1)
                                            }
                                        }
                                    )
                                }
                                else -> {
                                    KeypadButton(
                                        label = key,
                                        onClick = {
                                            if (!isVerifying && enteredPin.length < pinLength && lockoutSecondsRemaining <= 0) {
                                                val next = enteredPin + key
                                                enteredPin = next
                                                if (next.length == pinLength) {
                                                    isVerifying = true
                                                    onUnlockWithPin(next)
                                                }
                                            }
                                        }
                                    )
                                }
                            }
                        }
                    }
                }

                Spacer(modifier = Modifier.height(VaultSpacing.xs + 2.dp))

                // Bottom Links
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceEvenly,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    TextButton(onClick = onLogout) {
                        Text("Account Logout", color = MaterialTheme.colorScheme.outline)
                    }

                    if (onNavigateToRecovery != null) {
                        TextButton(onClick = onNavigateToRecovery) {
                            Text("Recover Vault", color = MaterialTheme.colorScheme.primary)
                        }
                    }
                }
            }
        } // end Column
    } // end AnimatedVisibility
}

@Composable
fun KeypadButton(
    label: String,
    isSpecial: Boolean = false,
    onClick: () -> Unit
) {
    Surface(
        shape = CircleShape,
        color = if (isSpecial) Color.Transparent else MaterialTheme.colorScheme.surfaceVariant,
        modifier = Modifier
            .size(72.dp)
            .clip(CircleShape)
            .clickable(onClick = onClick)
    ) {
        Box(contentAlignment = Alignment.Center) {
            Text(
                text = label,
                fontSize = if (isSpecial) 22.sp else 24.sp,
                fontWeight = FontWeight.Bold,
                color = if (isSpecial) MaterialTheme.colorScheme.primary
                        else MaterialTheme.colorScheme.onSurface
            )
        }
    }
}

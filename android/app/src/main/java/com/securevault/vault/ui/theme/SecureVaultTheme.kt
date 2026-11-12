package com.securevault.vault.ui.theme

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.staticCompositionLocalOf
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp

enum class VaultThemeOption(val displayName: String) {
    CYBER_DARK("Cyber Obsidian (Default)"),
    LIGHT_SECURITY("Clean Light Security"),
    AMETHYST_VAULT("Amethyst Twilight"),
    EMERALD_MATRIX("Emerald Shield")
}

// Cyber Obsidian Dark
val CyberBackground = Color(0xFF0A0E1A)
val CyberSurface = Color(0xFF131B2E)
val CyberSurfaceVariant = Color(0xFF1C2740)
val CyberPrimary = Color(0xFF4E80EE)
val CyberPrimaryVariant = Color(0xFF7B5CFA)
val CyberAccent = Color(0xFF00E5FF)
val CyberSuccess = Color(0xFF00E676)
val CyberWarning = Color(0xFFFFB300)
val CyberError = Color(0xFFFF3366)
val CyberTextPrimary = Color(0xFFF0F4FF)
val CyberTextSecondary = Color(0xFF8A99B5)

// Clean Light
val LightBackground = Color(0xFFF4F7FC)
val LightSurface = Color(0xFFFFFFFF)
val LightSurfaceVariant = Color(0xFFE6EDF8)
val LightPrimary = Color(0xFF2563EB)
val LightPrimaryVariant = Color(0xFF4F46E5)
val LightAccent = Color(0xFF0284C7)
val LightTextPrimary = Color(0xFF0F172A)
val LightTextSecondary = Color(0xFF64748B)

// Amethyst Twilight
val AmethystBackground = Color(0xFF0D0A1A)
val AmethystSurface = Color(0xFF1B1433)
val AmethystSurfaceVariant = Color(0xFF281E4B)
val AmethystPrimary = Color(0xFF9D4EDD)
val AmethystAccent = Color(0xFFE0AAFF)

// Emerald Shield
val EmeraldBackground = Color(0xFF061412)
val EmeraldSurface = Color(0xFF0E2420)
val EmeraldSurfaceVariant = Color(0xFF183B35)
val EmeraldPrimary = Color(0xFF10B981)
val EmeraldAccent = Color(0xFF34D399)

data class VaultThemeStyle(
    val option: VaultThemeOption,
    val isLight: Boolean,
    val cardCornerRadius: Dp,
    val cardElevation: Dp,
    val cardBorderWidth: Dp,
    val cardBorderBrush: Brush,
    val accentGlowColor: Color,
    val enableFrostedBlur: Boolean,
    val frostedSurfaceColor: Color,
    val passwordsGradient: Brush,
    val documentsGradient: Brush,
    val notesGradient: Brush,
    val imageToPdfGradient: Brush,
    val shareGradient: Brush,
    val headerGlowColors: List<Color>
)

val CyberThemeStyle = VaultThemeStyle(
    option = VaultThemeOption.CYBER_DARK,
    isLight = false,
    cardCornerRadius = 16.dp,
    cardElevation = 0.dp,
    cardBorderWidth = 1.dp,
    cardBorderBrush = Brush.linearGradient(
        listOf(CyberAccent.copy(alpha = 0.65f), CyberPrimary.copy(alpha = 0.25f))
    ),
    accentGlowColor = CyberAccent,
    enableFrostedBlur = true,
    frostedSurfaceColor = CyberSurface.copy(alpha = 0.75f),
    passwordsGradient = Brush.linearGradient(
        listOf(CyberPrimary, Color(0xFF1D4ED8))
    ),
    documentsGradient = Brush.linearGradient(
        listOf(CyberPrimaryVariant, Color(0xFF5B21B6))
    ),
    notesGradient = Brush.linearGradient(
        listOf(Color(0xFF00ACC1), Color(0xFF00796B))
    ),
    imageToPdfGradient = Brush.linearGradient(
        listOf(CyberAccent, CyberPrimary)
    ),
    shareGradient = Brush.linearGradient(
        listOf(CyberAccent, CyberPrimaryVariant)
    ),
    headerGlowColors = listOf(
        CyberAccent.copy(alpha = 0.35f),
        CyberPrimary.copy(alpha = 0.20f),
        Color.Transparent
    )
)

val AmethystThemeStyle = VaultThemeStyle(
    option = VaultThemeOption.AMETHYST_VAULT,
    isLight = false,
    cardCornerRadius = 24.dp,
    cardElevation = 2.dp,
    cardBorderWidth = 1.dp,
    cardBorderBrush = Brush.linearGradient(
        listOf(AmethystAccent.copy(alpha = 0.45f), AmethystPrimary.copy(alpha = 0.20f))
    ),
    accentGlowColor = AmethystAccent,
    enableFrostedBlur = true,
    frostedSurfaceColor = AmethystSurface.copy(alpha = 0.75f),
    passwordsGradient = Brush.linearGradient(
        listOf(AmethystPrimary, Color(0xFF5A189A))
    ),
    documentsGradient = Brush.linearGradient(
        listOf(Color(0xFF7B2CBF), Color(0xFF3C096C))
    ),
    notesGradient = Brush.linearGradient(
        listOf(AmethystAccent, AmethystPrimary)
    ),
    imageToPdfGradient = Brush.linearGradient(
        listOf(Color(0xFFC77DFF), Color(0xFF7B2CBF))
    ),
    shareGradient = Brush.linearGradient(
        listOf(AmethystAccent, Color(0xFF9D4EDD))
    ),
    headerGlowColors = listOf(
        AmethystAccent.copy(alpha = 0.30f),
        AmethystPrimary.copy(alpha = 0.18f),
        Color.Transparent
    )
)

val EmeraldThemeStyle = VaultThemeStyle(
    option = VaultThemeOption.EMERALD_MATRIX,
    isLight = false,
    cardCornerRadius = 14.dp,
    cardElevation = 4.dp,
    cardBorderWidth = 1.dp,
    cardBorderBrush = Brush.verticalGradient(
        listOf(EmeraldAccent.copy(alpha = 0.50f), EmeraldPrimary.copy(alpha = 0.15f))
    ),
    accentGlowColor = EmeraldAccent,
    enableFrostedBlur = true,
    frostedSurfaceColor = EmeraldSurface.copy(alpha = 0.80f),
    passwordsGradient = Brush.linearGradient(
        listOf(EmeraldPrimary, Color(0xFF047857))
    ),
    documentsGradient = Brush.linearGradient(
        listOf(Color(0xFF059669), Color(0xFF064E3B))
    ),
    notesGradient = Brush.linearGradient(
        listOf(EmeraldAccent, Color(0xFF059669))
    ),
    imageToPdfGradient = Brush.linearGradient(
        listOf(Color(0xFF10B981), Color(0xFF0F766E))
    ),
    shareGradient = Brush.linearGradient(
        listOf(EmeraldAccent, EmeraldPrimary)
    ),
    headerGlowColors = listOf(
        EmeraldAccent.copy(alpha = 0.35f),
        EmeraldPrimary.copy(alpha = 0.15f),
        Color.Transparent
    )
)

val LightThemeStyle = VaultThemeStyle(
    option = VaultThemeOption.LIGHT_SECURITY,
    isLight = true,
    cardCornerRadius = 16.dp,
    cardElevation = 3.dp,
    cardBorderWidth = 1.dp,
    cardBorderBrush = Brush.linearGradient(
        listOf(Color(0xFFE2E8F0), Color(0xFFCBD5E1))
    ),
    accentGlowColor = Color.Transparent,
    enableFrostedBlur = false,
    frostedSurfaceColor = LightSurface,
    passwordsGradient = Brush.linearGradient(
        listOf(LightPrimary, Color(0xFF1D4ED8))
    ),
    documentsGradient = Brush.linearGradient(
        listOf(LightPrimaryVariant, Color(0xFF4338CA))
    ),
    notesGradient = Brush.linearGradient(
        listOf(LightAccent, Color(0xFF0369A1))
    ),
    imageToPdfGradient = Brush.linearGradient(
        listOf(Color(0xFF0284C7), LightPrimary))
    ,
    shareGradient = Brush.linearGradient(
        listOf(LightPrimary, LightAccent)
    ),
    headerGlowColors = listOf(
        LightPrimary.copy(alpha = 0.08f),
        LightAccent.copy(alpha = 0.04f),
        Color.Transparent
    )
)

val LocalVaultThemeStyle = staticCompositionLocalOf { CyberThemeStyle }

private val CyberDarkColorScheme = darkColorScheme(
    primary = CyberPrimary,
    onPrimary = Color.White,
    primaryContainer = CyberPrimaryVariant,
    secondary = CyberAccent,
    background = CyberBackground,
    surface = CyberSurface,
    surfaceVariant = CyberSurfaceVariant,
    onBackground = CyberTextPrimary,
    onSurface = CyberTextPrimary,
    onSurfaceVariant = CyberTextSecondary,
    error = CyberError
)

private val LightColorScheme = lightColorScheme(
    primary = LightPrimary,
    onPrimary = Color.White,
    primaryContainer = LightPrimaryVariant,
    secondary = LightAccent,
    background = LightBackground,
    surface = LightSurface,
    surfaceVariant = LightSurfaceVariant,
    onBackground = LightTextPrimary,
    onSurface = LightTextPrimary,
    onSurfaceVariant = LightTextSecondary,
    error = Color(0xFFDC2626)
)

private val AmethystColorScheme = darkColorScheme(
    primary = AmethystPrimary,
    onPrimary = Color.White,
    secondary = AmethystAccent,
    background = AmethystBackground,
    surface = AmethystSurface,
    surfaceVariant = AmethystSurfaceVariant,
    onBackground = Color(0xFFF3E8FF),
    onSurface = Color(0xFFF3E8FF),
    onSurfaceVariant = Color(0xFFC084FC),
    error = CyberError
)

private val EmeraldColorScheme = darkColorScheme(
    primary = EmeraldPrimary,
    onPrimary = Color.Black,
    secondary = EmeraldAccent,
    background = EmeraldBackground,
    surface = EmeraldSurface,
    surfaceVariant = EmeraldSurfaceVariant,
    onBackground = Color(0xFFECFDF5),
    onSurface = Color(0xFFECFDF5),
    onSurfaceVariant = Color(0xFF6EE7B7),
    error = CyberError
)

@Composable
fun SecureVaultTheme(
    selectedTheme: VaultThemeOption = VaultThemeOption.CYBER_DARK,
    content: @Composable () -> Unit
) {
    val colorScheme = when (selectedTheme) {
        VaultThemeOption.CYBER_DARK -> CyberDarkColorScheme
        VaultThemeOption.LIGHT_SECURITY -> LightColorScheme
        VaultThemeOption.AMETHYST_VAULT -> AmethystColorScheme
        VaultThemeOption.EMERALD_MATRIX -> EmeraldColorScheme
    }

    val themeStyle = when (selectedTheme) {
        VaultThemeOption.CYBER_DARK -> CyberThemeStyle
        VaultThemeOption.LIGHT_SECURITY -> LightThemeStyle
        VaultThemeOption.AMETHYST_VAULT -> AmethystThemeStyle
        VaultThemeOption.EMERALD_MATRIX -> EmeraldThemeStyle
    }

    CompositionLocalProvider(LocalVaultThemeStyle provides themeStyle) {
        MaterialTheme(
            colorScheme = colorScheme,
            typography = Typography(),
            content = content
        )
    }
}

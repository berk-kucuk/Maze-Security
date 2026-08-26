package com.maze.security.ui.theme

import android.app.Activity
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.SideEffect
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.toArgb
import androidx.compose.ui.platform.LocalView
import androidx.core.view.WindowCompat

/** User-selectable theme mode persisted in settings. */
enum class ThemeMode { OLED, WHITE, SYSTEM }

private val OledColorScheme = darkColorScheme(
    primary = MazeGreen,
    onPrimary = Color.Black,
    primaryContainer = MazeGreenDim,
    onPrimaryContainer = Color.Black,
    secondary = MazeCyan,
    onSecondary = Color.Black,
    tertiary = MazeAmber,
    background = OledBackground,
    onBackground = OledOnBackground,
    surface = OledSurface,
    onSurface = OledOnBackground,
    surfaceVariant = OledSurfaceVariant,
    onSurfaceVariant = OledOnSurfaceVariant,
    outline = OledOutline,
    error = MazeRed,
    onError = Color.Black
)

private val WhiteColorScheme = lightColorScheme(
    primary = LightGreen,
    onPrimary = Color.White,
    primaryContainer = MazeGreen,
    onPrimaryContainer = Color.Black,
    secondary = Color(0xFF00838F),
    onSecondary = Color.White,
    tertiary = Color(0xFFB37400),
    background = LightBackground,
    onBackground = LightOnBackground,
    surface = LightSurface,
    onSurface = LightOnBackground,
    surfaceVariant = LightSurfaceVariant,
    onSurfaceVariant = LightOnSurfaceVariant,
    outline = LightOutline,
    error = Color(0xFFD32F2F),
    onError = Color.White
)

@Composable
fun MazeSecurityTheme(
    themeMode: ThemeMode = ThemeMode.OLED,
    content: @Composable () -> Unit
) {
    val useDark = when (themeMode) {
        ThemeMode.OLED -> true
        ThemeMode.WHITE -> false
        ThemeMode.SYSTEM -> isSystemInDarkTheme()
    }
    val colorScheme = if (useDark) OledColorScheme else WhiteColorScheme

    val view = LocalView.current
    if (!view.isInEditMode) {
        SideEffect {
            val window = (view.context as Activity).window
            window.statusBarColor = colorScheme.background.toArgb()
            window.navigationBarColor = colorScheme.background.toArgb()
            WindowCompat.getInsetsController(window, view).isAppearanceLightStatusBars = !useDark
            WindowCompat.getInsetsController(window, view).isAppearanceLightNavigationBars = !useDark
        }
    }

    MaterialTheme(
        colorScheme = colorScheme,
        typography = Typography,
        content = content
    )
}

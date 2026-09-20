package com.security.radioguard.ui.theme

import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color

val CyberCyan = Color(0xFF00E5FF)
val CyberDarkBg = Color(0xFF0D1117)
val CyberSurface = Color(0xFF161B22)
val CyberSurfaceBorder = Color(0xFF30363D)
val ThreatGreen = Color(0xFF00E676)
val ThreatYellow = Color(0xFFFFD600)
val ThreatRed = Color(0xFFFF1744)

private val DarkColorScheme = darkColorScheme(
    primary = CyberCyan,
    background = CyberDarkBg,
    surface = CyberSurface,
    onPrimary = Color.Black,
    onBackground = Color.White,
    onSurface = Color.White
)

@Composable
fun RadioGuardTheme(content: @Composable () -> Unit) {
    MaterialTheme(
        colorScheme = DarkColorScheme,
        content = content
    )
}

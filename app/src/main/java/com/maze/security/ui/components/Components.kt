package com.maze.security.ui.components

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.maze.security.domain.model.Severity
import com.maze.security.ui.theme.MazeAmber
import com.maze.security.ui.theme.MazeCyan
import com.maze.security.ui.theme.MazeGreen
import com.maze.security.ui.theme.MazeRed

@Composable
fun SectionTitle(text: String, modifier: Modifier = Modifier) {
    Text(
        text = text.uppercase(),
        style = MaterialTheme.typography.labelSmall,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
        modifier = modifier.padding(bottom = 8.dp)
    )
}

@Composable
fun Pill(text: String, color: Color, modifier: Modifier = Modifier) {
    Box(
        modifier = modifier
            .clip(RoundedCornerShape(50))
            .background(color.copy(alpha = 0.16f))
            .padding(horizontal = 10.dp, vertical = 4.dp)
    ) {
        Text(text, style = MaterialTheme.typography.labelSmall, color = color,
            fontWeight = FontWeight.SemiBold)
    }
}

@Composable
fun SeverityChip(severity: Severity, modifier: Modifier = Modifier) {
    val color = severityColor(severity)
    Pill(severity.name, color, modifier)
}

fun severityColor(severity: Severity): Color = when (severity) {
    Severity.INFO -> MazeCyan
    Severity.LOW -> MazeGreen
    Severity.MEDIUM -> MazeAmber
    Severity.HIGH -> MazeAmber
    Severity.CRITICAL -> MazeRed
}

@Composable
fun InfoBanner(text: String, color: Color, modifier: Modifier = Modifier) {
    Box(
        modifier = modifier
            .clip(RoundedCornerShape(12.dp))
            .background(color.copy(alpha = 0.10f))
            .padding(14.dp)
    ) {
        Text(text, style = MaterialTheme.typography.bodyMedium, color = color)
    }
}

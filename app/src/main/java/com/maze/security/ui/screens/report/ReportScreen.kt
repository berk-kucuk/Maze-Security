package com.maze.security.ui.screens.report

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.Home
import androidx.compose.material.icons.filled.Share
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.collectAsState
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import com.maze.security.domain.model.Finding
import com.maze.security.ui.SessionViewModel
import com.maze.security.ui.components.SectionTitle
import com.maze.security.ui.components.SeverityChip
import com.maze.security.ui.components.severityColor

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ReportScreen(
    session: SessionViewModel,
    onBack: () -> Unit,
    onHome: () -> Unit
) {
    val scan by session.scan.collectAsState()
    val target by session.target.collectAsState()
    val tool by session.selectedTool.collectAsState()
    val context = LocalContext.current

    val reportText = buildReport(
        targetLabel = target?.display ?: "-",
        toolLabel = tool?.title ?: "-",
        findings = scan.findings,
        log = scan.lines.map { it.text },
        exitCode = scan.exitCode,
        durationMs = scan.durationMs
    )

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Report") },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                    }
                },
                actions = {
                    IconButton(onClick = { copyToClipboard(context, reportText) }) {
                        Icon(Icons.Filled.ContentCopy, contentDescription = "Copy")
                    }
                    IconButton(onClick = { shareText(context, reportText) }) {
                        Icon(Icons.Filled.Share, contentDescription = "Share")
                    }
                    IconButton(onClick = onHome) {
                        Icon(Icons.Filled.Home, contentDescription = "Home")
                    }
                }
            )
        }
    ) { padding ->
        LazyColumn(
            modifier = Modifier.fillMaxSize().padding(padding).padding(horizontal = 16.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp)
        ) {
            item {
                Spacer(Modifier.height(8.dp))
                SummaryCard(
                    target = target?.display ?: "-",
                    tool = tool?.title ?: "-",
                    findingCount = scan.findings.size,
                    exitCode = scan.exitCode,
                    durationMs = scan.durationMs,
                    error = scan.error
                )
            }
            item { SectionTitle("Findings (${scan.findings.size})") }
            if (scan.findings.isEmpty()) {
                item {
                    Text("No structured findings extracted.",
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant)
                }
            } else {
                items(scan.findings) { f -> FindingCard(f) }
            }
            item {
                Spacer(Modifier.height(8.dp))
                OutlinedButton(onClick = { shareText(context, reportText) },
                    modifier = Modifier.fillMaxWidth()) {
                    Icon(Icons.Filled.Share, contentDescription = null)
                    Text("  Share full report")
                }
                Spacer(Modifier.height(24.dp))
            }
        }
    }
}

@Composable
private fun SummaryCard(
    target: String, tool: String, findingCount: Int,
    exitCode: Int?, durationMs: Long?, error: String?
) {
    Card(
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
        border = BorderStroke(1.dp, MaterialTheme.colorScheme.outline),
        modifier = Modifier.fillMaxWidth()
    ) {
        Column(Modifier.padding(16.dp)) {
            RowKV("Target", target)
            RowKV("Tool", tool)
            RowKV("Findings", findingCount.toString())
            durationMs?.let { RowKV("Duration", "$it ms") }
            exitCode?.let { RowKV("Exit code", it.toString()) }
            error?.let { RowKV("Error", it) }
        }
    }
}

@Composable
private fun RowKV(k: String, v: String) {
    Row(Modifier.fillMaxWidth().padding(vertical = 3.dp)) {
        Text(k, style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.height(20.dp))
        Spacer(Modifier.height(0.dp))
        Text("  $v", style = MaterialTheme.typography.bodyMedium,
            fontFamily = FontFamily.Monospace)
    }
}

@Composable
private fun FindingCard(f: Finding) {
    Card(
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
        border = BorderStroke(1.dp, severityColor(f.severity).copy(alpha = 0.5f)),
        modifier = Modifier.fillMaxWidth()
    ) {
        Column(Modifier.padding(14.dp)) {
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                Text(f.title, style = MaterialTheme.typography.titleMedium)
                SeverityChip(f.severity)
            }
            Spacer(Modifier.height(4.dp))
            Text(f.detail, style = MaterialTheme.typography.bodyMedium,
                fontFamily = FontFamily.Monospace,
                color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
    }
}

private fun buildReport(
    targetLabel: String, toolLabel: String,
    findings: List<Finding>, log: List<String>,
    exitCode: Int?, durationMs: Long?
): String = buildString {
    appendLine("=== Maze Security scan report ===")
    appendLine("Target:   $targetLabel")
    appendLine("Tool:     $toolLabel")
    appendLine("Duration: ${durationMs ?: "-"} ms")
    appendLine("Exit:     ${exitCode ?: "-"}")
    appendLine()
    appendLine("--- Findings (${findings.size}) ---")
    findings.forEach { appendLine("[${it.severity}] ${it.title} — ${it.detail}") }
    appendLine()
    appendLine("--- Raw output ---")
    log.forEach { appendLine(it) }
}

private fun copyToClipboard(context: Context, text: String) {
    val cm = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
    cm.setPrimaryClip(ClipData.newPlainText("Maze Security report", text))
}

private fun shareText(context: Context, text: String) {
    val intent = Intent(Intent.ACTION_SEND).apply {
        type = "text/plain"
        putExtra(Intent.EXTRA_SUBJECT, "Maze Security scan report")
        putExtra(Intent.EXTRA_TEXT, text)
    }
    context.startActivity(Intent.createChooser(intent, "Share report"))
}

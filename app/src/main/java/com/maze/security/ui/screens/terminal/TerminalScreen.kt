package com.maze.security.ui.screens.terminal

import androidx.compose.foundation.background
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
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Assessment
import androidx.compose.material.icons.filled.Stop
import androidx.compose.material3.Button
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.collectAsState
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import com.maze.security.domain.model.LineStream
import com.maze.security.ui.SessionViewModel
import com.maze.security.ui.theme.MazeAmber
import com.maze.security.ui.theme.MazeCyan
import com.maze.security.ui.theme.MazeGreen
import com.maze.security.ui.theme.MazeRed
import com.maze.security.ui.theme.TerminalTextStyle

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun TerminalScreen(
    session: SessionViewModel,
    onViewReport: () -> Unit,
    onBack: () -> Unit
) {
    val scan by session.scan.collectAsState()
    val tool by session.selectedTool.collectAsState()
    val listState = rememberLazyListState()

    // Auto-scroll to the newest line.
    LaunchedEffect(scan.lines.size) {
        if (scan.lines.isNotEmpty()) listState.animateScrollToItem(scan.lines.size - 1)
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = {
                    val pct = scan.progress?.let { " · ${(it * 100).toInt()}%" } ?: ""
                    Text((tool?.title ?: "Scan") + pct)
                },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                    }
                }
            )
        },
        bottomBar = {
            Row(
                modifier = Modifier.fillMaxWidth().padding(16.dp),
                horizontalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                if (scan.running) {
                    OutlinedButton(onClick = { session.stopScan() }, modifier = Modifier.weight(1f)) {
                        Icon(Icons.Filled.Stop, contentDescription = null)
                        Text("  Stop")
                    }
                } else {
                    Button(onClick = onViewReport, modifier = Modifier.weight(1f)) {
                        Icon(Icons.Filled.Assessment, contentDescription = null)
                        Text("  View report (${scan.findings.size})")
                    }
                }
            }
        }
    ) { padding ->
        Column(modifier = Modifier.fillMaxSize().padding(padding)) {
            if (scan.running) {
                if (scan.progress != null) {
                    LinearProgressIndicator(
                        progress = { scan.progress ?: 0f },
                        modifier = Modifier.fillMaxWidth()
                    )
                } else {
                    LinearProgressIndicator(modifier = Modifier.fillMaxWidth())
                }
            }
            LazyColumn(
                state = listState,
                modifier = Modifier
                    .fillMaxSize()
                    .background(MaterialTheme.colorScheme.background)
                    .padding(horizontal = 12.dp, vertical = 8.dp)
            ) {
                items(scan.lines) { line ->
                    Text(
                        text = line.text,
                        style = TerminalTextStyle,
                        fontFamily = FontFamily.Monospace,
                        color = when (line.stream) {
                            LineStream.STDERR -> MazeRed
                            LineStream.SYSTEM -> MazeCyan
                            LineStream.STDOUT -> MaterialTheme.colorScheme.onBackground
                        }
                    )
                }
            }
        }
    }
}

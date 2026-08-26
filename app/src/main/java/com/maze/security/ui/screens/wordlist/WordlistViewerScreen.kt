package com.maze.security.ui.screens.wordlist

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.itemsIndexed
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import com.maze.security.AppContainer
import com.maze.security.data.wordlist.WordlistPreview
import com.maze.security.ui.components.SectionTitle

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun WordlistViewerScreen(container: AppContainer, path: String, onBack: () -> Unit) {
    val name = remember(path) { path.substringAfterLast('/') }
    var preview by remember { mutableStateOf<WordlistPreview?>(null) }
    var query by remember { mutableStateOf("") }

    LaunchedEffect(path) { preview = container.wordlists.preview(path) }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(name, fontFamily = FontFamily.Monospace) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                    }
                }
            )
        }
    ) { padding ->
        val p = preview
        if (p == null) {
            Box(Modifier.fillMaxSize().padding(padding), contentAlignment = Alignment.Center) {
                CircularProgressIndicator()
            }
            return@Scaffold
        }
        val filtered = if (query.isBlank()) p.lines
        else p.lines.filter { it.contains(query, ignoreCase = true) }

        Column(Modifier.fillMaxSize().padding(padding)) {
            Row(
                Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 6.dp),
                horizontalArrangement = Arrangement.SpaceBetween
            ) {
                Text("${p.total} entries" + if (p.truncated) " (showing first ${p.lines.size})" else "",
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant)
                if (query.isNotBlank())
                    Text("${filtered.size} match", style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.primary)
            }
            OutlinedTextField(
                value = query,
                onValueChange = { query = it },
                singleLine = true,
                label = { Text("Filter") },
                modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp)
            )
            Spacer(Modifier.padding(4.dp))
            LazyColumn(Modifier.fillMaxSize().padding(horizontal = 12.dp)) {
                itemsIndexed(filtered) { index, line ->
                    Row {
                        Text("%5d".format(index + 1),
                            style = MaterialTheme.typography.labelSmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                            fontFamily = FontFamily.Monospace)
                        Spacer(Modifier.width(10.dp))
                        Text(line, style = MaterialTheme.typography.bodyMedium,
                            fontFamily = FontFamily.Monospace)
                    }
                }
            }
        }
    }
}

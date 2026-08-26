package com.maze.security.ui.screens.target

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.History
import androidx.compose.material3.Button
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
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.ui.unit.dp
import com.maze.security.AppContainer
import com.maze.security.domain.TargetValidator
import com.maze.security.domain.model.InputKind
import com.maze.security.domain.model.Target
import com.maze.security.domain.model.TargetType
import com.maze.security.ui.SessionViewModel
import com.maze.security.ui.components.InfoBanner
import com.maze.security.ui.components.SectionTitle
import com.maze.security.ui.theme.MazeCyan
import kotlinx.coroutines.launch

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun TargetScreen(
    container: AppContainer,
    session: SessionViewModel,
    onContinue: () -> Unit,
    onBack: () -> Unit
) {
    val tool = session.selectedTool.collectAsState().value ?: return
    var input by remember { mutableStateOf(session.target.value?.raw ?: "") }
    var resolving by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }
    val scope = rememberCoroutineScope()
    val recent by container.history.recentTargets.collectAsState(initial = emptyList())

    val isHostTool = tool.input == InputKind.HOST
    val label = when (tool.input) {
        InputKind.HOST -> "IP address or domain"
        InputKind.TEXT -> "Text / keyword"
        InputKind.PASSWORD -> "Password"
    }
    val hint = when (tool.input) {
        InputKind.HOST -> "Enter the IP or domain of the system you are authorised to test."
        InputKind.TEXT -> "Enter the text this tool should process (e.g. a string, token or product keyword)."
        InputKind.PASSWORD -> "Enter the password to analyse — it is processed on-device."
    }

    fun submit(value: String) {
        val v = value.trim()
        if (v.isEmpty()) { error = "This field is required"; return }
        error = null
        if (!isHostTool) {
            // Offline / text tools: take the input verbatim, no resolution.
            session.setTarget(Target(raw = v, type = TargetType.DOMAIN))
            onContinue(); return
        }
        resolving = true
        scope.launch {
            val target = TargetValidator.resolve(v)
            resolving = false
            if (target == null) { error = "Could not use that target"; return@launch }
            container.history.add(target.raw)
            session.setTarget(target)
            onContinue()
        }
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(tool.title) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                    }
                }
            )
        }
    ) { padding ->
        Column(modifier = Modifier.fillMaxSize().padding(padding).padding(20.dp)) {
            Text(if (isHostTool) "Enter a target" else "Enter input",
                style = MaterialTheme.typography.titleLarge)
            Spacer(Modifier.height(4.dp))
            Text(hint, style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant)
            Spacer(Modifier.height(16.dp))

            OutlinedTextField(
                value = input,
                onValueChange = { input = it; error = null },
                singleLine = true,
                label = { Text(label) },
                isError = error != null,
                visualTransformation = if (tool.input == InputKind.PASSWORD)
                    PasswordVisualTransformation() else androidx.compose.ui.text.input.VisualTransformation.None,
                keyboardOptions = KeyboardOptions(
                    keyboardType = if (tool.input == InputKind.PASSWORD) KeyboardType.Password else KeyboardType.Uri,
                    imeAction = ImeAction.Go
                ),
                supportingText = { error?.let { Text(it, color = MaterialTheme.colorScheme.error) } },
                modifier = Modifier.fillMaxWidth()
            )
            Spacer(Modifier.height(12.dp))
            Button(
                onClick = { submit(input) },
                enabled = !resolving && input.isNotBlank(),
                modifier = Modifier.fillMaxWidth()
            ) {
                if (resolving) {
                    CircularProgressIndicator(modifier = Modifier.height(18.dp).width(18.dp),
                        strokeWidth = 2.dp, color = MaterialTheme.colorScheme.onPrimary)
                    Spacer(Modifier.width(8.dp)); Text("Resolving…")
                } else Text("Continue")
            }

            if (tool.requiresWordlist) {
                Spacer(Modifier.height(12.dp))
                InfoBanner("This tool also needs a password wordlist — pick it on the next screen.", MazeCyan)
            }

            if (isHostTool && recent.isNotEmpty()) {
                Spacer(Modifier.height(28.dp))
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Icon(Icons.Filled.History, contentDescription = null,
                        tint = MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.height(16.dp).width(16.dp))
                    Spacer(Modifier.width(6.dp))
                    SectionTitle("Recent targets")
                }
                LazyColumn {
                    items(recent) { t ->
                        Text(t, style = MaterialTheme.typography.bodyLarge, fontFamily = FontFamily.Monospace,
                            modifier = Modifier.fillMaxWidth().clickable { input = t; submit(t) }
                                .padding(vertical = 12.dp))
                    }
                }
            }
        }
    }
}

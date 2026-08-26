package com.maze.security.ui.screens.consent

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.Checkbox
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.maze.security.AppContainer
import com.maze.security.ui.components.InfoBanner
import com.maze.security.ui.theme.MazeAmber
import com.maze.security.ui.theme.MazeGreen
import kotlinx.coroutines.launch

@Composable
fun ConsentScreen(container: AppContainer, onAccepted: () -> Unit) {
    var checked by remember { mutableStateOf(false) }
    val scope = rememberCoroutineScope()

    Scaffold { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(24.dp)
                .verticalScroll(rememberScrollState()),
        ) {
            Text("Maze Security", style = MaterialTheme.typography.headlineSmall,
                color = MazeGreen, fontWeight = FontWeight.Bold)
            Spacer(Modifier.height(4.dp))
            Text("Root-free mobile pentest toolkit",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant)
            Spacer(Modifier.height(24.dp))

            InfoBanner(
                "This app runs active reconnaissance and brute-force tooling against the " +
                    "target you enter. Use it ONLY against systems you own or are explicitly " +
                    "authorised to test. Unauthorised scanning or credential attacks are illegal " +
                    "in most jurisdictions and are entirely your responsibility.",
                color = MazeAmber
            )
            Spacer(Modifier.height(20.dp))

            Text("What it does", style = MaterialTheme.typography.titleMedium)
            Spacer(Modifier.height(8.dp))
            Text(
                "• Information gathering (DNS, HTTP, TLS, banners)\n" +
                    "• TCP port scanning\n" +
                    "• Nmap connect scan with service detection\n" +
                    "• Hydra & Medusa login brute-force\n\n" +
                    "All tools use unprivileged network connections — no root required.",
                style = MaterialTheme.typography.bodyLarge,
                color = MaterialTheme.colorScheme.onBackground
            )
            Spacer(Modifier.height(24.dp))

            Row(verticalAlignment = Alignment.CenterVertically) {
                Checkbox(checked = checked, onCheckedChange = { checked = it })
                Spacer(Modifier.width(4.dp))
                Text(
                    "I am authorised to test the systems I will target, and I accept full " +
                        "responsibility for my use of this tool.",
                    style = MaterialTheme.typography.bodyMedium
                )
            }
            Spacer(Modifier.height(20.dp))

            Button(
                onClick = {
                    scope.launch {
                        container.settings.setConsentAccepted(true)
                        onAccepted()
                    }
                },
                enabled = checked,
                modifier = Modifier.align(Alignment.End)
            ) {
                Text("Agree & continue")
            }
        }
    }
}

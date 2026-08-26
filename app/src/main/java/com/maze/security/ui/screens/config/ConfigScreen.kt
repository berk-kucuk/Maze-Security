package com.maze.security.ui.screens.config

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.PlayArrow
import androidx.compose.material3.Button
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.runtime.collectAsState
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import com.maze.security.AppContainer
import com.maze.security.data.wordlist.Wordlist
import com.maze.security.data.wordlist.WordlistKind
import com.maze.security.domain.model.BruteService
import com.maze.security.domain.model.ToolType
import com.maze.security.ui.SessionViewModel
import com.maze.security.ui.components.InfoBanner
import com.maze.security.ui.components.SectionTitle
import com.maze.security.ui.theme.MazeAmber
import com.maze.security.ui.theme.MazeCyan

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ConfigScreen(
    container: AppContainer,
    session: SessionViewModel,
    onRun: () -> Unit,
    onBack: () -> Unit,
    onOpenWordlists: () -> Unit
) {
    val tool = session.selectedTool.collectAsState().value ?: return
    val config by session.config.collectAsState()
    var wordlists by remember { mutableStateOf<List<Wordlist>>(emptyList()) }

    LaunchedEffect(Unit) { wordlists = container.wordlists.list() }

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
        },
        bottomBar = {
            Button(
                onClick = {
                    session.startScan()
                    onRun()
                },
                modifier = Modifier.fillMaxWidth().padding(16.dp)
            ) {
                Icon(Icons.Filled.PlayArrow, contentDescription = null)
                Spacer(Modifier.height(0.dp))
                Text("  Run scan")
            }
        }
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(horizontal = 20.dp)
                .verticalScroll(rememberScrollState())
        ) {
            Spacer(Modifier.height(8.dp))
            Text(tool.subtitle, style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant)
            Spacer(Modifier.height(20.dp))

            when (tool) {
                ToolType.INFO_GATHERING -> InfoGatheringConfig(session)
                ToolType.NMAP -> NmapConfig(session)
                ToolType.HYDRA, ToolType.MEDUSA ->
                    BruteConfig(session, wordlists, onOpenWordlists)
                ToolType.DIR_SCAN -> DirScanConfig(session, wordlists, onOpenWordlists)
                ToolType.SUBDOMAINS -> SubdomainConfig(session, wordlists, onOpenWordlists)
                ToolType.SMTP_RELAY, ToolType.SNMP -> PortConfig(session, tool)
                else -> SimpleReconConfig(tool)
            }

            // Extra-args field is only meaningful for the binary tools.
            if (tool == ToolType.NMAP || tool == ToolType.HYDRA || tool == ToolType.MEDUSA) {
                Spacer(Modifier.height(20.dp))
                SectionTitle("Advanced")
                LabeledField("Extra arguments", config.extraArgs) { v ->
                    session.updateConfig { it.copy(extraArgs = v) }
                }
            }
            Spacer(Modifier.height(90.dp))
        }
    }
}

@Composable
private fun InfoGatheringConfig(session: SessionViewModel) {
    val c by session.config.collectAsState()
    SectionTitle("Recon modules")
    ToggleRow("DNS resolution", c.doDns) { session.updateConfig { it.copy(doDns = !c.doDns) } }
    ToggleRow("Reverse DNS", c.doReverseDns) { session.updateConfig { it.copy(doReverseDns = !c.doReverseDns) } }
    ToggleRow("HTTP headers", c.doHttpHeaders) { session.updateConfig { it.copy(doHttpHeaders = !c.doHttpHeaders) } }
    ToggleRow("TLS certificate", c.doTlsInfo) { session.updateConfig { it.copy(doTlsInfo = !c.doTlsInfo) } }
    ToggleRow("Banner grabbing", c.doBanner) { session.updateConfig { it.copy(doBanner = !c.doBanner) } }
}

private fun List<Wordlist>.forKind(kind: WordlistKind): List<Wordlist> =
    filter { it.kind == kind || (it.kind == WordlistKind.GENERIC && !it.bundled) }

@Composable
private fun DirScanConfig(session: SessionViewModel, wordlists: List<Wordlist>, onOpenWordlists: () -> Unit) {
    val c by session.config.collectAsState()
    InfoBanner("Probes each path from the selected wordlist over HTTP/HTTPS and reports the " +
        "status codes (with soft-404 filtering).", MazeAmber)
    Spacer(Modifier.height(16.dp))
    SectionTitle("Wordlist")
    WordlistPicker("Path wordlist (none = built-in list)",
        wordlists.forKind(WordlistKind.DIRECTORY), c.wordlistPath, allowNone = true) { path ->
        session.updateConfig { it.copy(wordlistPath = path) }
    }
    WordlistLink(onOpenWordlists)
    Spacer(Modifier.height(16.dp))
    SectionTitle("Tuning")
    NumberField("Concurrent requests", c.threads) { session.updateConfig { cfg -> cfg.copy(threads = it) } }
}

@Composable
private fun SubdomainConfig(session: SessionViewModel, wordlists: List<Wordlist>, onOpenWordlists: () -> Unit) {
    val c by session.config.collectAsState()
    InfoBanner("Combines certificate-transparency (crt.sh) with a DNS brute of the selected " +
        "subdomain wordlist, then resolves every candidate.", MazeAmber)
    Spacer(Modifier.height(16.dp))
    SectionTitle("Brute wordlist")
    WordlistPicker("Subdomain wordlist (none = built-in list)",
        wordlists.forKind(WordlistKind.SUBDOMAIN), c.wordlistPath, allowNone = true) { path ->
        session.updateConfig { it.copy(wordlistPath = path) }
    }
    WordlistLink(onOpenWordlists)
}

@Composable
private fun WordlistLink(onOpenWordlists: () -> Unit) {
    Text("Manage / import wordlists →", style = MaterialTheme.typography.labelLarge,
        color = MaterialTheme.colorScheme.primary,
        modifier = Modifier.padding(top = 6.dp).clickableNoRipple(onOpenWordlists))
}

@Composable
private fun SimpleReconConfig(tool: ToolType) {
    val msg = when (tool.input) {
        com.maze.security.domain.model.InputKind.TEXT ->
            "This is an offline tool. The text you entered as the target is used as the input. Press Run."
        com.maze.security.domain.model.InputKind.PASSWORD ->
            "The value you entered as the target is treated as the password to analyse. Press Run."
        else -> "No configuration required — runs directly against the target. Press Run scan."
    }
    InfoBanner(msg, MazeCyan)
}

@Composable
private fun PortConfig(session: SessionViewModel, tool: ToolType) {
    val c by session.config.collectAsState()
    val default = if (tool == ToolType.SNMP) 161 else 25
    SimpleReconConfig(tool)
    Spacer(Modifier.height(16.dp))
    SectionTitle("Connection")
    LabeledField("Port (default $default)", c.port?.toString() ?: "") { v ->
        session.updateConfig { it.copy(port = v.toIntOrNull()) }
    }
}

@Composable
private fun NmapConfig(session: SessionViewModel) {
    val c by session.config.collectAsState()
    InfoBanner("Runs as -sT -Pn (unprivileged connect scan). SYN/OS raw-socket modes " +
        "are disabled because they need root. Progress is shown live.", MazeAmber)
    Spacer(Modifier.height(16.dp))
    SectionTitle("Ports")
    ToggleRow("Fast scan — top 100 ports (-F)", c.nmapFastScan) {
        session.updateConfig { it.copy(nmapFastScan = !c.nmapFastScan) }
    }
    if (!c.nmapFastScan) {
        Spacer(Modifier.height(8.dp))
        LabeledField("Port range (e.g. 1-1024, 22,80,443)", c.portRange) { v ->
            session.updateConfig { it.copy(portRange = v) }
        }
    }
    Spacer(Modifier.height(16.dp))
    SectionTitle("Detection")
    ToggleRow("Service / version detection (-sV)", c.nmapServiceDetection) {
        session.updateConfig { it.copy(nmapServiceDetection = !c.nmapServiceDetection) }
    }
    ToggleRow("Default scripts (-sC)", c.nmapDefaultScripts) {
        session.updateConfig { it.copy(nmapDefaultScripts = !c.nmapDefaultScripts) }
    }
    Spacer(Modifier.height(16.dp))
    SectionTitle("Timing")
    DropdownField(
        label = "Timing template (-T)",
        options = listOf("0 · paranoid", "1 · sneaky", "2 · polite", "3 · normal", "4 · aggressive", "5 · insane"),
        selectedIndex = c.nmapTiming,
        onSelected = { idx -> session.updateConfig { it.copy(nmapTiming = idx) } }
    )
}

@Composable
private fun BruteConfig(
    session: SessionViewModel,
    wordlists: List<Wordlist>,
    onOpenWordlists: () -> Unit
) {
    val c by session.config.collectAsState()
    SectionTitle("Service")
    DropdownField(
        label = "Protocol",
        options = BruteService.entries.map { it.label },
        selectedIndex = BruteService.entries.indexOf(c.service),
        onSelected = { idx -> session.updateConfig { it.copy(service = BruteService.entries[idx]) } }
    )
    Spacer(Modifier.height(12.dp))
    LabeledField("Port (blank = default ${c.service.defaultPort})", c.port?.toString() ?: "") { v ->
        session.updateConfig { it.copy(port = v.toIntOrNull()) }
    }

    Spacer(Modifier.height(20.dp))
    SectionTitle("Usernames")
    LabeledField("Single username (used if no user list)", c.singleUsername) { v ->
        session.updateConfig { it.copy(singleUsername = v) }
    }
    Spacer(Modifier.height(8.dp))
    WordlistPicker("Username list (optional)", wordlists.forKind(WordlistKind.USERNAME), c.userlistPath, allowNone = true) { path ->
        session.updateConfig { it.copy(userlistPath = path) }
    }

    Spacer(Modifier.height(20.dp))
    SectionTitle("Passwords")
    WordlistPicker("Password list", wordlists.forKind(WordlistKind.PASSWORD), c.passwordListPath, allowNone = false) { path ->
        session.updateConfig { it.copy(passwordListPath = path) }
    }
    Text("Manage wordlists →", style = MaterialTheme.typography.labelLarge,
        color = MaterialTheme.colorScheme.primary,
        modifier = Modifier.padding(top = 6.dp)
            .clickableNoRipple(onOpenWordlists))

    Spacer(Modifier.height(20.dp))
    SectionTitle("Tuning")
    NumberField("Parallel tasks", c.threads) { session.updateConfig { cfg -> cfg.copy(threads = it) } }
    Spacer(Modifier.height(8.dp))
    ToggleRow("Stop on first valid credential", c.stopOnFirst) {
        session.updateConfig { it.copy(stopOnFirst = !c.stopOnFirst) }
    }
}

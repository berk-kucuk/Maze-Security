package com.maze.security.ui.screens.dashboard

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.automirrored.filled.KeyboardArrowRight
import androidx.compose.material.icons.filled.AccountTree
import androidx.compose.material.icons.filled.Badge
import androidx.compose.material.icons.filled.Bolt
import androidx.compose.material.icons.filled.Cookie
import androidx.compose.material.icons.filled.Dns
import androidx.compose.material.icons.filled.Email
import androidx.compose.material.icons.filled.Fingerprint
import androidx.compose.material.icons.filled.FolderOpen
import androidx.compose.material.icons.filled.History
import androidx.compose.material.icons.filled.Http
import androidx.compose.material.icons.filled.ListAlt
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material.icons.filled.Key
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Memory
import androidx.compose.material.icons.filled.Password
import androidx.compose.material.icons.filled.Public
import androidx.compose.material.icons.filled.Radar
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material.icons.filled.Tag
import androidx.compose.material.icons.filled.Traffic
import androidx.compose.material.icons.filled.Transform
import androidx.compose.material.icons.filled.Token
import androidx.compose.material.icons.filled.TravelExplore
import androidx.compose.material.icons.filled.VpnKey
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material.icons.filled.Wysiwyg
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.runtime.collectAsState
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import com.maze.security.AppContainer
import com.maze.security.domain.model.ToolCategory
import com.maze.security.domain.model.ToolType
import com.maze.security.ui.SessionViewModel
import com.maze.security.ui.components.Pill
import com.maze.security.ui.theme.MazeCyan
import com.maze.security.ui.theme.MazeGreen
import com.maze.security.ui.theme.MazeRed

private fun iconFor(tool: ToolType): ImageVector = when (tool) {
    ToolType.INFO_GATHERING -> Icons.Filled.TravelExplore
    ToolType.WHOIS -> Icons.Filled.Badge
    ToolType.DNS_RECORDS -> Icons.Filled.Dns
    ToolType.SUBDOMAINS -> Icons.Filled.AccountTree
    ToolType.GEOIP -> Icons.Filled.Public
    ToolType.REVERSE_IP -> Icons.Filled.Public
    ToolType.WAYBACK -> Icons.Filled.History
    ToolType.HARVESTER -> Icons.Filled.Email
    ToolType.HTTP_HEADERS -> Icons.Filled.Http
    ToolType.TECH_DETECT -> Icons.Filled.Memory
    ToolType.DIR_SCAN -> Icons.Filled.FolderOpen
    ToolType.SSL_TLS -> Icons.Filled.Lock
    ToolType.WAF_DETECT -> Icons.Filled.Shield
    ToolType.CORS -> Icons.Filled.Security
    ToolType.HTTP_METHODS -> Icons.Filled.Http
    ToolType.COOKIES -> Icons.Filled.Cookie
    ToolType.WORDPRESS -> Icons.Filled.Wysiwyg
    ToolType.TAKEOVER -> Icons.Filled.Warning
    ToolType.FAVICON -> Icons.Filled.Fingerprint
    ToolType.MAIL_SEC -> Icons.Filled.Email
    ToolType.DNSBL -> Icons.Filled.Warning
    ToolType.ZONE_TRANSFER -> Icons.Filled.Dns
    ToolType.NMAP -> Icons.Filled.Traffic
    ToolType.CVE_LOOKUP -> Icons.Filled.Security
    ToolType.SMTP_RELAY -> Icons.Filled.Email
    ToolType.SNMP -> Icons.Filled.Radar
    ToolType.HYDRA -> Icons.Filled.Key
    ToolType.MEDUSA -> Icons.Filled.VpnKey
    ToolType.HASH -> Icons.Filled.Tag
    ToolType.ENCODER -> Icons.Filled.Transform
    ToolType.PASSWORD_ANALYZER -> Icons.Filled.Password
    ToolType.JWT -> Icons.Filled.Token
    ToolType.HIBP -> Icons.Filled.Warning
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun DashboardScreen(
    container: AppContainer,
    session: SessionViewModel,
    onToolSelected: () -> Unit,
    onOpenSettings: () -> Unit,
    onOpenWordlists: () -> Unit
) {
    var category by remember { mutableStateOf(ToolCategory.ALL) }
    val tools = ToolType.entries.filter { category == ToolCategory.ALL || it.category == category }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Maze Security") },
                actions = {
                    IconButton(onClick = onOpenWordlists) {
                        Icon(Icons.Filled.ListAlt, contentDescription = "Wordlists")
                    }
                    IconButton(onClick = onOpenSettings) {
                        Icon(Icons.Filled.Settings, contentDescription = "Settings")
                    }
                }
            )
        }
    ) { padding ->
        Column(modifier = Modifier.fillMaxSize().padding(padding)) {
            // Category filter chips
            Row(
                modifier = Modifier.fillMaxWidth().horizontalScroll(rememberScrollState())
                    .padding(horizontal = 16.dp, vertical = 4.dp),
                horizontalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                ToolCategory.entries.forEach { cat ->
                    FilterChip(
                        selected = category == cat,
                        onClick = { category = cat },
                        label = { Text(cat.label) }
                    )
                }
            }
            Text("${tools.size} tools", style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.padding(start = 20.dp, top = 4.dp))
            LazyColumn(
                contentPadding = androidx.compose.foundation.layout.PaddingValues(16.dp),
                verticalArrangement = Arrangement.spacedBy(10.dp)
            ) {
                items(tools) { tool ->
                    ToolCard(tool, container.isToolAvailable(tool)) {
                        session.selectTool(tool); onToolSelected()
                    }
                }
            }
        }
    }
}

@Composable
private fun ToolCard(tool: ToolType, available: Boolean, onClick: () -> Unit) {
    Card(
        onClick = onClick,
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
        border = BorderStroke(1.dp, MaterialTheme.colorScheme.outline),
        modifier = Modifier.fillMaxWidth()
    ) {
        Row(modifier = Modifier.padding(16.dp), verticalAlignment = Alignment.CenterVertically) {
            Icon(iconFor(tool), contentDescription = null, tint = MazeGreen, modifier = Modifier.size(26.dp))
            Spacer(Modifier.width(16.dp))
            Column(modifier = Modifier.weight(1f)) {
                Text(tool.title, style = MaterialTheme.typography.titleMedium)
                Spacer(Modifier.height(2.dp))
                Text(tool.subtitle, style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant)
                Spacer(Modifier.height(8.dp))
                Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                    Pill("NO ROOT", MazeCyan)
                    if (tool.requiresBinary) {
                        if (available) Pill("BINARY READY", MazeGreen) else Pill("BINARY MISSING", MazeRed)
                    }
                    if (tool.requiresWordlist) Pill("WORDLIST", MazeCyan)
                }
            }
            Icon(Icons.AutoMirrored.Filled.KeyboardArrowRight, contentDescription = null,
                tint = MaterialTheme.colorScheme.onSurfaceVariant)
        }
    }
}

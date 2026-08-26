package com.maze.security.domain.scanner

import com.maze.security.domain.model.Finding
import com.maze.security.domain.model.ScanConfig
import com.maze.security.domain.model.ScanEvent
import com.maze.security.domain.model.Severity
import com.maze.security.domain.model.Target
import com.maze.security.domain.model.ToolType
import com.maze.security.native.NativeBinaries
import com.maze.security.native.ProcessRunner
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flow
import kotlinx.coroutines.flow.flowOn
import kotlinx.coroutines.flow.flowOf
import kotlinx.coroutines.flow.emitAll

/**
 * Wraps the bundled nmap binary. Only the unprivileged TCP connect scan (-sT) and
 * -Pn are used so it runs without root. SYN/OS-fingerprint modes that need raw
 * sockets are intentionally never passed.
 */
class NmapScanner(
    private val binaries: NativeBinaries,
    private val runner: ProcessRunner
) : ScannerEngine {

    override val tool = ToolType.NMAP

    override fun isAvailable(): Boolean = binaries.isPresent("nmap")

    override fun run(target: Target, config: ScanConfig): Flow<ScanEvent> {
        if (!isAvailable()) {
            return flowOf(ScanEvent.Failed(
                "nmap binary not bundled for this device's CPU (arch not built yet). " +
                    "Build it via native-tools/build.sh and reinstall."))
        }
        return flow {
            binaries.ensureNmapData()
            val bin = binaries.binary("nmap").absolutePath
            val args = buildList {
                add(bin)
                add("--datadir"); add(binaries.nmapDataDir.absolutePath)
                add("-sT")                       // unprivileged connect scan
                add("-Pn")                       // skip host discovery (needs raw sockets)
                add("--system-dns")              // use Android's resolver (no /etc/resolv.conf)
                add("--stats-every"); add("2s")  // periodic progress lines
                add("-T${config.nmapTiming.coerceIn(0, 5)}")
                if (config.nmapServiceDetection) add("-sV")
                if (config.nmapDefaultScripts) add("-sC")
                if (config.nmapFastScan) add("-F") else { add("-p"); add(config.portRange) }
                config.extraArgs.trim().takeIf { it.isNotEmpty() }
                    ?.split(" ")?.forEach { add(it) }
                add(target.hostForTools)
            }
            emitAll(runner.run(args, environment = binaries.runtimeEnv(),
                parseLine = ::parse, parseProgress = ::parseProgress))
        }.flowOn(Dispatchers.IO)
    }

    // "Connect Scan Timing: About 45.32% done; ETC: 13:52 (0:00:05 remaining)"
    private val progressRegex = Regex("""About\s+([\d.]+)%\s+done""")
    private fun parseProgress(line: String): Float? =
        progressRegex.find(line)?.groupValues?.get(1)?.toFloatOrNull()?.let { it / 100f }

    // Matches lines like: "22/tcp open  ssh     OpenSSH 8.9p1"
    private val portRegex = Regex("""^(\d+)/(tcp|udp)\s+(open\S*)\s+(\S+)\s*(.*)$""")

    private fun parse(line: String): Finding? {
        val m = portRegex.find(line.trim()) ?: return null
        val (port, proto, state, service, version) = m.destructured
        return Finding(
            toolId = tool.id,
            title = "$port/$proto $service",
            detail = listOf(state, version).filter { it.isNotBlank() }.joinToString(" "),
            severity = Severity.MEDIUM
        )
    }
}


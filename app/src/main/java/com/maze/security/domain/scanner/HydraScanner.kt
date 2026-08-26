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
import kotlinx.coroutines.flow.emitAll
import kotlinx.coroutines.flow.flow
import kotlinx.coroutines.flow.flowOf
import kotlinx.coroutines.flow.flowOn

/**
 * Wraps the bundled hydra binary for parallel login brute-forcing. All work is
 * ordinary client network traffic, so no root is required.
 */
class HydraScanner(
    private val binaries: NativeBinaries,
    private val runner: ProcessRunner
) : ScannerEngine {

    override val tool = ToolType.HYDRA

    override fun isAvailable(): Boolean = binaries.isPresent("hydra")

    override fun run(target: Target, config: ScanConfig): Flow<ScanEvent> {
        if (!isAvailable()) {
            return flowOf(ScanEvent.Failed(
                "hydra binary not bundled for this device's CPU. Build via native-tools/build.sh."))
        }
        val pass = config.passwordListPath
        if (pass.isNullOrBlank()) {
            return flowOf(ScanEvent.Failed("Select a password wordlist first."))
        }
        return flow {
            val bin = binaries.binary("hydra").absolutePath
            val port = config.port ?: config.service.defaultPort
            val args = buildList {
                add(bin)
                // user source
                if (config.userlistPath != null) { add("-L"); add(config.userlistPath) }
                else { add("-l"); add(config.singleUsername.ifBlank { "root" }) }
                add("-P"); add(pass)
                add("-s"); add(port.toString())
                add("-t"); add(config.threads.coerceIn(1, 64).toString())
                if (config.stopOnFirst) add("-f")
                add("-I")                        // ignore restore file
                config.extraArgs.trim().takeIf { it.isNotEmpty() }
                    ?.split(" ")?.forEach { add(it) }
                add(target.hostForTools)
                add(config.service.hydraModule)
            }
            emitAll(runner.run(args, environment = binaries.runtimeEnv(), parseLine = ::parse))
        }.flowOn(Dispatchers.IO)
    }

    // "[22][ssh] host: 10.0.0.5   login: root   password: toor"
    private val hitRegex = Regex("""login:\s*(\S+)\s+password:\s*(\S+)""")

    private fun parse(line: String): Finding? {
        val m = hitRegex.find(line) ?: return null
        val (user, pass) = m.destructured
        return Finding(
            toolId = tool.id,
            title = "Credential found",
            detail = "$user : $pass",
            severity = Severity.CRITICAL
        )
    }
}

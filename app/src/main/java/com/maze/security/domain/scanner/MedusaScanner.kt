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
 * Wraps the bundled medusa binary — an alternative modular brute-force engine.
 * Runs entirely as unprivileged client traffic (no root).
 */
class MedusaScanner(
    private val binaries: NativeBinaries,
    private val runner: ProcessRunner
) : ScannerEngine {

    override val tool = ToolType.MEDUSA

    override fun isAvailable(): Boolean = binaries.isPresent("medusa")

    // medusa module names differ slightly from hydra's.
    // Maps the shared BruteService module id to the medusa module shipped in jniLibs
    // (see native-tools/build.sh curated list: ssh ftp http web-form telnet mysql smbnt).
    private fun medusaModule(hydraModule: String): String = when (hydraModule) {
        "ssh" -> "ssh"
        "ftp" -> "ftp"
        "http-get" -> "http"
        "http-post-form" -> "web-form"
        "mysql" -> "mysql"
        "smb" -> "smbnt"
        "telnet" -> "telnet"
        else -> hydraModule
    }

    override fun run(target: Target, config: ScanConfig): Flow<ScanEvent> {
        if (!isAvailable()) {
            return flowOf(ScanEvent.Failed(
                "medusa binary not bundled for this device's CPU. Build via native-tools/build.sh."))
        }
        val pass = config.passwordListPath
        if (pass.isNullOrBlank()) {
            return flowOf(ScanEvent.Failed("Select a password wordlist first."))
        }
        return flow {
            val bin = binaries.binary("medusa").absolutePath
            val port = config.port ?: config.service.defaultPort
            val args = buildList {
                add(bin)
                add("-h"); add(target.hostForTools)
                if (config.userlistPath != null) { add("-U"); add(config.userlistPath) }
                else { add("-u"); add(config.singleUsername.ifBlank { "root" }) }
                add("-P"); add(pass)
                add("-M"); add(medusaModule(config.service.hydraModule))
                add("-n"); add(port.toString())
                add("-t"); add(config.threads.coerceIn(1, 64).toString())
                if (config.stopOnFirst) add("-F")
                config.extraArgs.trim().takeIf { it.isNotEmpty() }
                    ?.split(" ")?.forEach { add(it) }
            }
            // Modules ship in jniLibs as lib<name>_mod.so; point medusa at nativeLibraryDir.
            val env = binaries.runtimeEnv() + ("MEDUSA_MODULE_PATH" to binaries.nativeLibDir.absolutePath)
            emitAll(runner.run(args, environment = env, parseLine = ::parse))
        }.flowOn(Dispatchers.IO)
    }

    // "ACCOUNT FOUND: [ssh] Host: 10.0.0.5 User: root Password: toor [SUCCESS]"
    private val hitRegex = Regex("""User:\s*(\S+)\s+Password:\s*(\S+)\s+\[SUCCESS""")

    private fun parse(line: String): Finding? {
        val m = hitRegex.find(line) ?: return null
        val (user, pass) = m.destructured
        return Finding(tool.id, "Credential found", "$user : $pass", Severity.CRITICAL)
    }
}

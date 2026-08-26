package com.maze.security.domain.scanner

import com.maze.security.domain.model.Finding
import com.maze.security.domain.model.LineStream
import com.maze.security.domain.model.ScanConfig
import com.maze.security.domain.model.ScanEvent
import com.maze.security.domain.model.Severity
import com.maze.security.domain.model.Target
import com.maze.security.domain.model.ToolType
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flow
import kotlinx.coroutines.flow.flowOn
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.sync.withPermit
import kotlin.math.abs
import kotlin.random.Random

/**
 * Probes common web paths & sensitive files. Detects "soft-404" catch-all sites
 * (which return 200 for everything, e.g. WordPress/SPAs) by baselining random
 * non-existent paths first, then only reporting responses that differ. Root-free.
 */
class DirScanScanner : ScannerEngine {
    override val tool = ToolType.DIR_SCAN

    private val builtinPaths = listOf(
        "admin", "administrator", "login", "wp-admin", "wp-login.php", "phpmyadmin",
        "dashboard", "cpanel", "webmail", "manager", "console", "portal",
        ".git/HEAD", ".git/config", ".env", ".htaccess", ".htpasswd", "config.php",
        "backup", "backup.zip", "backup.sql", "db.sql", "dump.sql", "database.sql",
        "robots.txt", "sitemap.xml", "server-status", "server-info", ".svn/entries",
        "api", "api/v1", "swagger", "swagger-ui.html", "openapi.json", "graphql",
        "test", "dev", "staging", "old", "tmp", "temp", "uploads", "files", "logs",
        "error_log", "debug.log", "info.php", "phpinfo.php", "readme.html", "license.txt",
        "web.config", "app.config", ".DS_Store", "crossdomain.xml", "actuator", "actuator/health"
    )

    private data class Probe(val code: Int, val len: Int)

    override fun run(target: Target, config: ScanConfig): Flow<ScanEvent> = flow {
        val start = System.currentTimeMillis()
        emit(ScanEvent.Started)
        val host = target.hostForTools
        val base = if (host.startsWith("http")) host.trimEnd('/') else "https://$host"

        // Use the selected wordlist if any, otherwise the built-in path list.
        val wl = config.wordlistPath?.let { java.io.File(it) }
        val paths = if (wl != null && wl.canRead()) {
            runCatching { wl.readLines().map { it.trim().removePrefix("/") }.filter { it.isNotEmpty() && !it.startsWith("#") } }
                .getOrDefault(emptyList()).ifEmpty { builtinPaths }
        } else builtinPaths
        val source = if (wl != null && wl.canRead()) wl.name else "built-in list"
        emit(ScanEvent.Line("Directory scan on $base", LineStream.SYSTEM))
        emit(ScanEvent.Line("Wordlist: $source (${paths.size} paths)", LineStream.SYSTEM))

        // --- Baseline: request random paths that should NOT exist. ---
        emit(ScanEvent.Line("Calibrating against random paths (soft-404 detection)…", LineStream.SYSTEM))
        val baselines = (1..3).map { probe(base, "maze-404-${Random.nextLong(1_000_000_000)}") }
        val catchAll = baselines.filter { it.code in 200..299 }
        val baseCode = catchAll.firstOrNull()?.code
        val baseLen = catchAll.map { it.len }
        if (baseCode != null) {
            emit(ScanEvent.Line("Site returns HTTP $baseCode for unknown paths (~${baseLen.average().toInt()} bytes) — " +
                "filtering catch-all responses.", LineStream.STDERR))
        } else {
            emit(ScanEvent.Line("No catch-all detected (proper 404s).", LineStream.STDOUT))
        }

        fun isRealHit(p: Probe): Boolean {
            if (p.code < 0) return false
            if (baseCode == null) return p.code != 404          // proper site: anything non-404
            if (p.code != baseCode) return true                 // different status than catch-all
            // same status as catch-all: only interesting if body size differs clearly
            return baseLen.none { abs(it - p.len) <= (it * 0.10).toInt() + 32 }
        }

        val results = Channel<Pair<String, Probe>>(Channel.UNLIMITED)
        coroutineScope {
            val gate = Semaphore(config.threads.coerceIn(4, 32))
            launch {
                for (path in paths) launch {
                    gate.withPermit { results.trySend(path to probe(base, path)) }
                }
            }
            var done = 0; var hits = 0
            repeat(paths.size) {
                val (path, p) = results.receive()
                done++
                if (isRealHit(p)) {
                    hits++
                    val sev = when {
                        p.code in 200..299 && isSensitive(path) -> Severity.HIGH
                        p.code in 200..299 -> Severity.MEDIUM
                        p.code == 401 || p.code == 403 -> Severity.LOW
                        else -> Severity.INFO
                    }
                    emit(ScanEvent.Line("[%d] /%s  (%d bytes)".format(p.code, path, p.len), LineStream.STDOUT))
                    emit(ScanEvent.FindingFound(Finding(tool.id, "/$path", "HTTP ${p.code}, ${p.len} bytes", sev)))
                }
                if (done % 8 == 0 || done == paths.size)
                    emit(ScanEvent.Progress(done.toFloat() / paths.size, "$done/${paths.size}"))
            }
            emit(ScanEvent.Line("", LineStream.SYSTEM))
            emit(ScanEvent.Line("$hits real hit(s) out of ${paths.size} probed", LineStream.SYSTEM))
        }
        results.close()
        emit(ScanEvent.Completed(0, System.currentTimeMillis() - start))
    }.flowOn(Dispatchers.IO)

    private fun probe(base: String, path: String): Probe {
        val r = ReconHttp.get("$base/$path", followRedirects = false, readBody = true, timeoutMs = 6000)
            ?: return Probe(-1, 0)
        return Probe(r.code, r.body.length)
    }

    private fun isSensitive(path: String) =
        path.contains(Regex("(?i)\\.(git|env|sql|htpasswd|config)|backup|dump|phpinfo|actuator"))
}

package com.maze.security.domain.scanner

import com.maze.security.domain.model.Finding
import com.maze.security.domain.model.LineStream
import com.maze.security.domain.model.ScanConfig
import com.maze.security.domain.model.ScanEvent
import com.maze.security.domain.model.Severity
import com.maze.security.domain.model.Target
import com.maze.security.domain.model.TargetType
import com.maze.security.domain.model.ToolType
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flow
import kotlinx.coroutines.flow.flowOn
import org.json.JSONArray

/** Light WordPress recon: version, users, xmlrpc, REST endpoints. Root-free. */
class WordPressScanner : ScannerEngine {
    override val tool = ToolType.WORDPRESS

    override fun run(target: Target, config: ScanConfig): Flow<ScanEvent> = flow {
        val start = System.currentTimeMillis()
        emit(ScanEvent.Started)
        val host = target.hostForTools
        val base = if (host.startsWith("http")) host.trimEnd('/') else "https://$host"
        emit(ScanEvent.Line("WordPress recon on $base", LineStream.SYSTEM))

        val home = ReconHttp.get("$base/")
        val isWp = home != null && (home.body.contains("/wp-content/") ||
            ReconHttp.get("$base/wp-login.php", readBody = false)?.code == 200)
        if (!isWp) {
            emit(ScanEvent.Line("Target does not appear to run WordPress.", LineStream.STDERR))
            emit(ScanEvent.Completed(0, System.currentTimeMillis() - start)); return@flow
        }
        emit(ScanEvent.Line("[+] WordPress detected", LineStream.STDOUT))
        emit(ScanEvent.FindingFound(Finding(tool.id, "WordPress", "Confirmed", Severity.INFO)))

        // Version
        val ver = home?.let { Regex("(?i)<meta name=\"generator\" content=\"WordPress ([0-9.]+)\"").find(it.body)?.groupValues?.get(1) }
            ?: ReconHttp.get("$base/readme.html")?.let { Regex("(?i)Version ([0-9.]+)").find(it.body)?.groupValues?.get(1) }
        if (ver != null) {
            emit(ScanEvent.Line("Version: $ver", LineStream.STDOUT))
            emit(ScanEvent.FindingFound(Finding(tool.id, "WP version", ver, Severity.LOW)))
        }

        // xmlrpc
        ReconHttp.get("$base/xmlrpc.php", readBody = false)?.let {
            if (it.code == 405 || it.code == 200) {
                emit(ScanEvent.Line("[!] xmlrpc.php enabled (${it.code}) — brute/amplification vector", LineStream.STDERR))
                emit(ScanEvent.FindingFound(Finding(tool.id, "xmlrpc.php enabled", "HTTP ${it.code}", Severity.MEDIUM)))
            }
        }

        // User enum via REST API
        emit(ScanEvent.Line("== User enumeration ==", LineStream.SYSTEM))
        val usersJson = ReconHttp.get("$base/wp-json/wp/v2/users")
        var found = 0
        if (usersJson != null && usersJson.code == 200) {
            runCatching {
                val arr = JSONArray(usersJson.body)
                for (i in 0 until arr.length()) {
                    val u = arr.getJSONObject(i)
                    val slug = u.optString("slug"); val nameF = u.optString("name")
                    found++
                    emit(ScanEvent.Line("user: $slug ($nameF)", LineStream.STDOUT))
                    emit(ScanEvent.FindingFound(Finding(tool.id, "WP user", "$slug / $nameF", Severity.MEDIUM)))
                }
            }
        }
        // Fallback: ?author=N redirect
        if (found == 0) {
            for (id in 1..5) {
                val r = ReconHttp.get("$base/?author=$id", followRedirects = false, readBody = false)
                val loc = r?.headers?.entries?.firstOrNull { it.key.equals("Location", true) }?.value
                val slug = loc?.let { Regex("/author/([^/]+)/?").find(it)?.groupValues?.get(1) }
                if (slug != null) {
                    found++
                    emit(ScanEvent.Line("user id $id -> $slug", LineStream.STDOUT))
                    emit(ScanEvent.FindingFound(Finding(tool.id, "WP user (id $id)", slug, Severity.MEDIUM)))
                }
            }
        }
        if (found == 0) emit(ScanEvent.Line("No users enumerated.", LineStream.STDOUT))
        emit(ScanEvent.Completed(0, System.currentTimeMillis() - start))
    }.flowOn(Dispatchers.IO)
}

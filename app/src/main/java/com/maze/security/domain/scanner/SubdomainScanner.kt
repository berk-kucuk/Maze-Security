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
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.sync.withPermit
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flow
import kotlinx.coroutines.flow.flowOn
import org.json.JSONArray
import java.net.InetAddress

/**
 * Enumerates subdomains from certificate-transparency logs (crt.sh) and verifies
 * which currently resolve. Passive + light active, no root.
 */
class SubdomainScanner : ScannerEngine {
    override val tool = ToolType.SUBDOMAINS

    private val commonSubs = listOf(
        "www", "mail", "webmail", "smtp", "pop", "imap", "ftp", "sftp", "ssh", "vpn",
        "ns1", "ns2", "dns", "mx", "mx1", "api", "api-dev", "dev", "test", "staging",
        "stage", "uat", "demo", "beta", "app", "apps", "admin", "portal", "dashboard",
        "cpanel", "whm", "webdisk", "autodiscover", "blog", "shop", "store", "cdn",
        "static", "assets", "img", "images", "media", "files", "download", "downloads",
        "docs", "wiki", "support", "help", "status", "monitor", "grafana", "kibana",
        "jenkins", "git", "gitlab", "svn", "jira", "confluence", "db", "sql", "mysql",
        "phpmyadmin", "pma", "backup", "old", "new", "m", "mobile", "secure", "login",
        "sso", "auth", "oauth", "internal", "intranet", "extranet", "gw", "gateway",
        "proxy", "cache", "redis", "es", "elastic", "server", "host", "cloud", "s3"
    )

    override fun run(target: Target, config: ScanConfig): Flow<ScanEvent> = flow {
        val start = System.currentTimeMillis()
        emit(ScanEvent.Started)
        val domain = target.hostForTools
        emit(ScanEvent.Line("Subdomain enumeration for $domain (crt.sh)", LineStream.SYSTEM))

        val names = sortedSetOf<String>()
        val res = ReconHttp.get("https://crt.sh/?q=%25.$domain&output=json", timeoutMs = 20000)
        if (res != null && res.body.isNotBlank()) {
            runCatching {
                val arr = JSONArray(res.body)
                for (i in 0 until arr.length()) {
                    arr.getJSONObject(i).optString("name_value").split("\n").forEach { n ->
                        val clean = n.trim().lowercase().removePrefix("*.")
                        if (clean.endsWith(domain) && clean != domain) names += clean
                    }
                }
            }
            emit(ScanEvent.Line("crt.sh: ${names.size} names from certificate transparency", LineStream.SYSTEM))
        } else {
            emit(ScanEvent.Line("crt.sh unavailable — using DNS brute only", LineStream.STDERR))
        }

        // Add a subdomain DNS brute (selected wordlist, or the built-in common list).
        val wl = config.wordlistPath?.let { java.io.File(it) }
        val subs = if (wl != null && wl.canRead()) {
            runCatching { wl.readLines().map { it.trim() }.filter { it.isNotEmpty() && !it.startsWith("#") } }
                .getOrDefault(emptyList()).ifEmpty { commonSubs }
        } else commonSubs
        emit(ScanEvent.Line("Brute wordlist: ${if (wl != null && wl.canRead()) wl.name else "built-in"} (${subs.size} entries)",
            LineStream.SYSTEM))
        subs.forEach { names += "$it.$domain" }
        emit(ScanEvent.Line("Resolving ${names.size} candidate names…", LineStream.SYSTEM))

        val nameList = names.toList()
        val results = Channel<Pair<String, String?>>(Channel.UNLIMITED)
        coroutineScope {
            val gate = Semaphore(24)
            launch {
                for (name in nameList) launch {
                    gate.withPermit {
                        val ip = runCatching { InetAddress.getByName(name).hostAddress }.getOrNull()
                        results.trySend(name to ip)
                    }
                }
            }
            var live = 0; var done = 0
            repeat(nameList.size) {
                val (name, ip) = results.receive()
                done++
                if (ip != null) {
                    live++
                    emit(ScanEvent.Line("%-45s %s".format(name, ip), LineStream.STDOUT))
                    emit(ScanEvent.FindingFound(Finding(tool.id, name, ip, Severity.LOW)))
                }
                if (done % 16 == 0 || done == nameList.size)
                    emit(ScanEvent.Progress(done.toFloat() / nameList.size, "$done/${nameList.size}"))
            }
            emit(ScanEvent.Line("", LineStream.SYSTEM))
            emit(ScanEvent.Line("$live live subdomain(s) out of ${nameList.size} checked", LineStream.SYSTEM))
        }
        results.close()
        emit(ScanEvent.Completed(0, System.currentTimeMillis() - start))
    }.flowOn(Dispatchers.IO)
}

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
import org.json.JSONObject

/** Checks a host's CNAME against known dangling-service takeover fingerprints. Root-free. */
class SubdomainTakeoverScanner : ScannerEngine {
    override val tool = ToolType.TAKEOVER

    // service -> (cname hint, body fingerprint of an unclaimed resource)
    private val fingerprints = listOf(
        Triple("GitHub Pages", Regex("(?i)github\\.io"), "There isn't a GitHub Pages site here"),
        Triple("AWS S3", Regex("(?i)s3[.-].*amazonaws\\.com"), "NoSuchBucket"),
        Triple("Heroku", Regex("(?i)herokuapp\\.com|herokudns\\.com"), "No such app"),
        Triple("Azure", Regex("(?i)azurewebsites\\.net|cloudapp\\.net|trafficmanager\\.net"), "404 Web Site not found"),
        Triple("Fastly", Regex("(?i)fastly\\.net"), "Fastly error: unknown domain"),
        Triple("Shopify", Regex("(?i)myshopify\\.com"), "Sorry, this shop is currently unavailable"),
        Triple("Surge.sh", Regex("(?i)surge\\.sh"), "project not found"),
        Triple("Zendesk", Regex("(?i)zendesk\\.com"), "Help Center Closed"),
        Triple("Unbounce", Regex("(?i)unbouncepages\\.com"), "The requested URL was not found"),
        Triple("Pantheon", Regex("(?i)pantheonsite\\.io"), "The gods are wise")
    )

    override fun run(target: Target, config: ScanConfig): Flow<ScanEvent> = flow {
        val start = System.currentTimeMillis()
        emit(ScanEvent.Started)
        val host = target.hostForTools.substringAfter("://").substringBefore("/")
        emit(ScanEvent.Line("Subdomain takeover check for $host", LineStream.SYSTEM))

        val cnameRes = ReconHttp.get("https://dns.google/resolve?name=$host&type=CNAME")
        val cname = cnameRes?.let {
            runCatching { JSONObject(it.body).optJSONArray("Answer")?.getJSONObject(0)?.optString("data") }.getOrNull()
        }?.trimEnd('.')
        if (cname.isNullOrBlank()) {
            emit(ScanEvent.Line("No CNAME — direct A record; takeover unlikely via CNAME.", LineStream.STDOUT))
            emit(ScanEvent.Completed(0, System.currentTimeMillis() - start)); return@flow
        }
        emit(ScanEvent.Line("CNAME -> $cname", LineStream.STDOUT))
        val match = fingerprints.firstOrNull { it.second.containsMatchIn(cname) }
        if (match == null) {
            emit(ScanEvent.Line("CNAME points to a service not in the takeover database.", LineStream.STDOUT))
            emit(ScanEvent.Completed(0, System.currentTimeMillis() - start)); return@flow
        }
        emit(ScanEvent.Line("Points to ${match.first}; checking for unclaimed fingerprint…", LineStream.SYSTEM))
        val page = ReconHttp.get("https://$host/") ?: ReconHttp.get("http://$host/")
        if (page != null && page.body.contains(match.third, true)) {
            emit(ScanEvent.Line("[!] VULNERABLE — unclaimed ${match.first} resource", LineStream.STDERR))
            emit(ScanEvent.FindingFound(Finding(tool.id, "Possible subdomain takeover",
                "${match.first}: '${match.third}'", Severity.CRITICAL)))
        } else {
            emit(ScanEvent.Line("Resource appears claimed (no takeover fingerprint).", LineStream.STDOUT))
        }
        emit(ScanEvent.Completed(0, System.currentTimeMillis() - start))
    }.flowOn(Dispatchers.IO)
}

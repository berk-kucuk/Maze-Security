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

/** Fingerprints common WAFs/CDNs from headers, cookies and block behaviour. Root-free. */
class WafDetectScanner : ScannerEngine {
    override val tool = ToolType.WAF_DETECT

    private val sigs = listOf(
        Triple("Cloudflare", Regex("(?i)cloudflare|cf-ray|__cfduid|cf-cache"), listOf("Server", "CF-RAY", "Set-Cookie")),
        Triple("Akamai", Regex("(?i)akamai|akamaighost"), listOf("Server", "X-Akamai-Transformed")),
        Triple("Imperva/Incapsula", Regex("(?i)incap_ses|visid_incap|imperva"), listOf("Set-Cookie", "X-Iinfo")),
        Triple("Sucuri", Regex("(?i)sucuri"), listOf("Server", "X-Sucuri-ID")),
        Triple("AWS WAF / CloudFront", Regex("(?i)cloudfront|awselb|x-amz"), listOf("Server", "Via", "X-Amz-Cf-Id")),
        Triple("F5 BIG-IP", Regex("(?i)big-?ip|bigipserver|f5"), listOf("Server", "Set-Cookie")),
        Triple("Fastly", Regex("(?i)fastly"), listOf("Server", "X-Served-By")),
        Triple("Barracuda", Regex("(?i)barracuda|barra_counter"), listOf("Set-Cookie"))
    )

    override fun run(target: Target, config: ScanConfig): Flow<ScanEvent> = flow {
        val start = System.currentTimeMillis()
        emit(ScanEvent.Started)
        val host = target.hostForTools
        val base = if (host.startsWith("http")) host.trimEnd('/') else "https://$host"
        emit(ScanEvent.Line("WAF/CDN detection for $base", LineStream.SYSTEM))

        val normal = ReconHttp.get("$base/")
        // A benign-looking suspicious request to trigger blocking behaviour.
        val probe = ReconHttp.get("$base/?maze=<script>alert(1)</script>%20OR%201=1", readBody = false)

        if (normal == null) { emit(ScanEvent.Failed("No response")); return@flow }
        val haystack = buildString {
            append(normal.headers.entries.joinToString(" ") { "${it.key}: ${it.value}" })
            append(" "); append(normal.body.take(4000))
        }
        var found = false
        for ((name, rx, _) in sigs) {
            if (rx.containsMatchIn(haystack)) {
                found = true
                emit(ScanEvent.Line("[+] $name detected", LineStream.STDOUT))
                emit(ScanEvent.FindingFound(Finding(tool.id, "WAF/CDN", name, Severity.INFO)))
            }
        }
        if (probe != null && normal.code != probe.code) {
            emit(ScanEvent.Line("Behaviour: normal=${normal.code}, malicious-probe=${probe.code} " +
                "(status changes on attack payload → WAF likely)", LineStream.STDERR))
            emit(ScanEvent.FindingFound(Finding(tool.id, "Blocking behaviour",
                "normal ${normal.code} vs probe ${probe.code}", Severity.LOW)))
            found = true
        }
        if (!found) emit(ScanEvent.Line("No WAF/CDN fingerprinted.", LineStream.STDOUT))
        emit(ScanEvent.Completed(0, System.currentTimeMillis() - start))
    }.flowOn(Dispatchers.IO)
}

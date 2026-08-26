package com.maze.security.domain.scanner

import com.maze.security.domain.model.Finding
import com.maze.security.domain.model.LineStream
import com.maze.security.domain.model.ScanConfig
import com.maze.security.domain.model.ScanEvent
import com.maze.security.domain.model.Severity
import com.maze.security.domain.model.Target
import com.maze.security.domain.model.ToolType
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flow
import kotlinx.coroutines.flow.flowOn

/** Fetches HTTP headers and flags missing/weak security headers. Root-free. */
class HttpHeadersScanner : ScannerEngine {
    override val tool = ToolType.HTTP_HEADERS

    private val securityHeaders = mapOf(
        "Strict-Transport-Security" to "Enforces HTTPS (HSTS)",
        "Content-Security-Policy" to "Mitigates XSS/injection",
        "X-Frame-Options" to "Clickjacking protection",
        "X-Content-Type-Options" to "MIME-sniffing protection",
        "Referrer-Policy" to "Controls referrer leakage",
        "Permissions-Policy" to "Restricts browser features"
    )

    override fun run(target: Target, config: ScanConfig): Flow<ScanEvent> = flow {
        val start = System.currentTimeMillis()
        emit(ScanEvent.Started)
        val host = target.hostForTools
        val url = if (host.startsWith("http")) host else "https://$host/"
        emit(ScanEvent.Line("Fetching headers from $url", LineStream.SYSTEM))

        val res = ReconHttp.get(url, method = "GET", followRedirects = true, readBody = false)
        if (res == null) { emit(ScanEvent.Failed("No response")); return@flow }
        emit(ScanEvent.Line("HTTP ${res.code} ${res.message}", LineStream.STDOUT))
        emit(ScanEvent.Line("== Response headers ==", LineStream.SYSTEM))
        res.headers.forEach { (k, v) -> emit(ScanEvent.Line("$k: $v", LineStream.STDOUT)) }

        // Info-leaking headers
        listOf("Server", "X-Powered-By", "X-AspNet-Version", "X-Generator").forEach { h ->
            res.headers.entries.firstOrNull { it.key.equals(h, true) }?.let {
                emit(ScanEvent.FindingFound(Finding(tool.id, "Disclosure: ${it.key}", it.value, Severity.LOW)))
            }
        }

        emit(ScanEvent.Line("", LineStream.SYSTEM))
        emit(ScanEvent.Line("== Security header audit ==", LineStream.SYSTEM))
        val present = res.headers.keys.map { it.lowercase() }.toSet()
        for ((header, purpose) in securityHeaders) {
            if (header.lowercase() in present) {
                emit(ScanEvent.Line("[+] $header present", LineStream.STDOUT))
            } else {
                emit(ScanEvent.Line("[-] $header MISSING — $purpose", LineStream.STDERR))
                emit(ScanEvent.FindingFound(Finding(tool.id, "Missing $header", purpose, Severity.MEDIUM)))
            }
        }
        emit(ScanEvent.Completed(0, System.currentTimeMillis() - start))
    }.flowOn(Dispatchers.IO)
}

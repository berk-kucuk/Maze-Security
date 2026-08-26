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

/** Fingerprints web server, framework and CMS from headers, cookies and body. Root-free. */
class TechDetectScanner : ScannerEngine {
    override val tool = ToolType.TECH_DETECT

    override fun run(target: Target, config: ScanConfig): Flow<ScanEvent> = flow {
        val start = System.currentTimeMillis()
        emit(ScanEvent.Started)
        val host = target.hostForTools
        val base = if (host.startsWith("http")) host.trimEnd('/') else "https://$host"
        emit(ScanEvent.Line("Technology fingerprint of $base", LineStream.SYSTEM))

        val res = ReconHttp.get("$base/")
        if (res == null) { emit(ScanEvent.Failed("No response")); return@flow }
        val detected = linkedSetOf<Pair<String, String>>()

        fun header(name: String) = res.headers.entries.firstOrNull { it.key.equals(name, true) }?.value
        header("Server")?.let { detected += "Web server" to it }
        header("X-Powered-By")?.let { detected += "Powered by" to it }
        header("X-Generator")?.let { detected += "Generator" to it }
        header("Via")?.let { detected += "Proxy/CDN" to it }
        val setCookie = res.headers.entries.filter { it.key.equals("Set-Cookie", true) }.joinToString(" ") { it.value }
        when {
            setCookie.contains("wordpress", true) || res.body.contains("/wp-content/") -> detected += "CMS" to "WordPress"
            setCookie.contains("PHPSESSID") -> detected += "Language" to "PHP"
            setCookie.contains("JSESSIONID") -> detected += "Platform" to "Java/JSP"
            setCookie.contains("ASP.NET", true) -> detected += "Platform" to "ASP.NET"
        }
        Regex("(?i)<meta name=\"generator\" content=\"([^\"]+)\"").find(res.body)
            ?.groupValues?.get(1)?.let { detected += "Meta generator" to it }
        if (res.body.contains("cf-ray", true) || header("CF-RAY") != null) detected += "CDN/WAF" to "Cloudflare"
        if (res.body.contains("Drupal", true)) detected += "CMS" to "Drupal"
        if (res.body.contains("/sites/all/") || res.body.contains("Joomla", true)) detected += "CMS" to "Joomla"
        if (res.body.contains("__NEXT_DATA__")) detected += "Framework" to "Next.js"
        if (res.body.contains("ng-version")) detected += "Framework" to "Angular"
        if (res.body.contains("data-reactroot") || res.body.contains("react", true)) detected += "Framework" to "React"

        // Confirm WordPress via wp-login.
        ReconHttp.get("$base/wp-login.php", readBody = false)?.let {
            if (it.code == 200) detected += "CMS" to "WordPress (wp-login.php)"
        }

        if (detected.isEmpty()) {
            emit(ScanEvent.Line("No obvious technologies fingerprinted.", LineStream.STDOUT))
        } else {
            detected.forEach { (k, v) ->
                emit(ScanEvent.Line("%-16s %s".format("$k:", v), LineStream.STDOUT))
                emit(ScanEvent.FindingFound(Finding(tool.id, k, v, Severity.INFO)))
            }
        }
        emit(ScanEvent.Completed(0, System.currentTimeMillis() - start))
    }.flowOn(Dispatchers.IO)
}

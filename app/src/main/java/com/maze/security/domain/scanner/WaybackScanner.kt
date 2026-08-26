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
import org.json.JSONArray

/** Lists archived URLs for a domain from the Wayback Machine CDX API. Passive, root-free. */
class WaybackScanner : ScannerEngine {
    override val tool = ToolType.WAYBACK

    override fun run(target: Target, config: ScanConfig): Flow<ScanEvent> = flow {
        val start = System.currentTimeMillis()
        emit(ScanEvent.Started)
        val domain = target.hostForTools
        emit(ScanEvent.Line("Wayback Machine URLs for $domain", LineStream.SYSTEM))

        val url = "http://web.archive.org/cdx/search/cdx?url=$domain/*&output=json&fl=original&collapse=urlkey&limit=500"
        val res = ReconHttp.get(url, timeoutMs = 20000)
        if (res == null || res.body.isBlank()) { emit(ScanEvent.Failed("Wayback query failed")); return@flow }

        val arr = runCatching { JSONArray(res.body) }.getOrNull()
        if (arr == null || arr.length() <= 1) {
            emit(ScanEvent.Line("No archived URLs found.", LineStream.STDOUT))
            emit(ScanEvent.Completed(0, System.currentTimeMillis() - start)); return@flow
        }
        val interesting = Regex("(?i)\\.(sql|bak|old|zip|tar|gz|log|env|json|xml|conf|config|txt)(\\?|$)|admin|login|api|backup|upload")
        var count = 0
        for (i in 1 until arr.length()) {
            val u = arr.getJSONArray(i).optString(0)
            if (u.isBlank()) continue
            count++
            emit(ScanEvent.Line(u, LineStream.STDOUT))
            if (interesting.containsMatchIn(u))
                emit(ScanEvent.FindingFound(Finding(tool.id, "Notable archived URL", u, Severity.LOW)))
        }
        emit(ScanEvent.Line("", LineStream.SYSTEM))
        emit(ScanEvent.Line("$count archived URLs", LineStream.SYSTEM))
        emit(ScanEvent.Completed(0, System.currentTimeMillis() - start))
    }.flowOn(Dispatchers.IO)
}

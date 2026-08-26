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

/** Harvests email addresses and links from a page (and a couple of common pages). Root-free. */
class HarvesterScanner : ScannerEngine {
    override val tool = ToolType.HARVESTER

    private val emailRx = Regex("[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}")
    private val linkRx = Regex("(?i)href=[\"']([^\"'#]+)[\"']")

    override fun run(target: Target, config: ScanConfig): Flow<ScanEvent> = flow {
        val start = System.currentTimeMillis()
        emit(ScanEvent.Started)
        val host = target.hostForTools
        val base = if (host.startsWith("http")) host.trimEnd('/') else "https://$host"
        emit(ScanEvent.Line("Harvesting emails & links from $base", LineStream.SYSTEM))

        val emails = sortedSetOf<String>()
        val links = sortedSetOf<String>()
        for (path in listOf("/", "/contact", "/about", "/team", "/impressum")) {
            val res = ReconHttp.get("$base$path") ?: continue
            emailRx.findAll(res.body).forEach { emails += it.value.lowercase() }
            linkRx.findAll(res.body).forEach { m ->
                val href = m.groupValues[1]
                if (href.startsWith("http") || href.startsWith("/")) links += href.take(200)
            }
        }
        emit(ScanEvent.Line("== Emails (${emails.size}) ==", LineStream.SYSTEM))
        emails.forEach {
            emit(ScanEvent.Line(it, LineStream.STDOUT))
            emit(ScanEvent.FindingFound(Finding(tool.id, "Email", it, Severity.LOW)))
        }
        if (emails.isEmpty()) emit(ScanEvent.Line("(none)", LineStream.STDOUT))
        emit(ScanEvent.Line("== Links (${links.size}) ==", LineStream.SYSTEM))
        links.take(120).forEach { emit(ScanEvent.Line(it, LineStream.STDOUT)) }
        emit(ScanEvent.Completed(0, System.currentTimeMillis() - start))
    }.flowOn(Dispatchers.IO)
}

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
import java.net.InetAddress

/** Finds other domains hosted on the same IP (reverse-IP), via hackertarget. Root-free. */
class ReverseIpScanner : ScannerEngine {
    override val tool = ToolType.REVERSE_IP

    override fun run(target: Target, config: ScanConfig): Flow<ScanEvent> = flow {
        val start = System.currentTimeMillis()
        emit(ScanEvent.Started)
        val host = target.hostForTools
        val ip = if (target.type == TargetType.IP) host
        else runCatching { InetAddress.getByName(host).hostAddress }.getOrNull() ?: host
        emit(ScanEvent.Line("Reverse IP lookup for $ip", LineStream.SYSTEM))

        val res = ReconHttp.get("https://api.hackertarget.com/reverseiplookup/?q=$ip", timeoutMs = 15000)
        if (res == null || res.body.isBlank()) { emit(ScanEvent.Failed("Lookup failed")); return@flow }
        if (res.body.contains("error", true) || res.body.contains("API count exceeded", true)) {
            emit(ScanEvent.Line(res.body.trim(), LineStream.STDERR))
            emit(ScanEvent.Failed("Provider limit or error")); return@flow
        }
        val domains = res.body.lines().map { it.trim() }.filter { it.isNotEmpty() }
        domains.forEach {
            emit(ScanEvent.Line(it, LineStream.STDOUT))
            emit(ScanEvent.FindingFound(Finding(tool.id, "Co-hosted domain", it, Severity.LOW)))
        }
        emit(ScanEvent.Line("", LineStream.SYSTEM))
        emit(ScanEvent.Line("${domains.size} domain(s) on $ip", LineStream.SYSTEM))
        emit(ScanEvent.Completed(0, System.currentTimeMillis() - start))
    }.flowOn(Dispatchers.IO)
}

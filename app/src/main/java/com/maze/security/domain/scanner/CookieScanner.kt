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

/** Audits Set-Cookie flags (Secure/HttpOnly/SameSite). Root-free. */
class CookieScanner : ScannerEngine {
    override val tool = ToolType.COOKIES

    override fun run(target: Target, config: ScanConfig): Flow<ScanEvent> = flow {
        val start = System.currentTimeMillis()
        emit(ScanEvent.Started)
        val host = target.hostForTools
        val base = if (host.startsWith("http")) host.trimEnd('/') else "https://$host"
        emit(ScanEvent.Line("Cookie audit for $base", LineStream.SYSTEM))

        val res = ReconHttp.get("$base/", readBody = false)
        if (res == null) { emit(ScanEvent.Failed("No response")); return@flow }
        val cookies = res.headers.entries.filter { it.key.equals("Set-Cookie", true) }.map { it.value }
        if (cookies.isEmpty()) {
            emit(ScanEvent.Line("No cookies set.", LineStream.STDOUT))
            emit(ScanEvent.Completed(0, System.currentTimeMillis() - start)); return@flow
        }
        for (c in cookies) {
            val name = c.substringBefore("=")
            val secure = c.contains("Secure", true)
            val httpOnly = c.contains("HttpOnly", true)
            val sameSite = Regex("(?i)SameSite=(\\w+)").find(c)?.groupValues?.get(1)
            emit(ScanEvent.Line("Cookie: $name", LineStream.STDOUT))
            emit(ScanEvent.Line("  Secure=${secure}  HttpOnly=${httpOnly}  SameSite=${sameSite ?: "none"}",
                if (!secure || !httpOnly) LineStream.STDERR else LineStream.STDOUT))
            if (!secure) emit(ScanEvent.FindingFound(Finding(tool.id, "$name missing Secure", "May be sent over HTTP", Severity.MEDIUM)))
            if (!httpOnly) emit(ScanEvent.FindingFound(Finding(tool.id, "$name missing HttpOnly", "Readable by JavaScript (XSS theft)", Severity.MEDIUM)))
            if (sameSite == null || sameSite.equals("None", true))
                emit(ScanEvent.FindingFound(Finding(tool.id, "$name weak SameSite", sameSite ?: "not set", Severity.LOW)))
        }
        emit(ScanEvent.Completed(0, System.currentTimeMillis() - start))
    }.flowOn(Dispatchers.IO)
}

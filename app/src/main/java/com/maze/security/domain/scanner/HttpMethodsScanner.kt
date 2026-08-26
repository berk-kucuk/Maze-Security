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

/** Enumerates allowed HTTP methods and flags dangerous ones. Root-free. */
class HttpMethodsScanner : ScannerEngine {
    override val tool = ToolType.HTTP_METHODS

    private val dangerous = setOf("PUT", "DELETE", "TRACE", "CONNECT", "PATCH")

    override fun run(target: Target, config: ScanConfig): Flow<ScanEvent> = flow {
        val start = System.currentTimeMillis()
        emit(ScanEvent.Started)
        val host = target.hostForTools
        val base = if (host.startsWith("http")) host.trimEnd('/') else "https://$host"
        emit(ScanEvent.Line("HTTP methods on $base", LineStream.SYSTEM))

        val opt = ReconHttp.get("$base/", method = "OPTIONS", readBody = false)
        val allow = opt?.headers?.entries?.firstOrNull { it.key.equals("Allow", true) }?.value
        if (allow != null) {
            emit(ScanEvent.Line("Allow: $allow", LineStream.STDOUT))
            allow.split(",").map { it.trim().uppercase() }.filter { it in dangerous }.forEach {
                emit(ScanEvent.FindingFound(Finding(tool.id, "Dangerous method allowed", it, Severity.MEDIUM)))
            }
        } else emit(ScanEvent.Line("No Allow header from OPTIONS.", LineStream.STDOUT))

        emit(ScanEvent.Line("== Probing individual methods ==", LineStream.SYSTEM))
        for (method in listOf("GET", "POST", "PUT", "DELETE", "TRACE", "PATCH", "OPTIONS")) {
            val r = ReconHttp.get("$base/", method = method, readBody = false)
            val code = r?.code ?: -1
            val enabled = code in 200..405 && code != 405 && code != 501
            emit(ScanEvent.Line("%-8s -> %s".format(method, if (code < 0) "error" else code.toString()),
                if (method in dangerous && code in 200..299) LineStream.STDERR else LineStream.STDOUT))
            if (method in dangerous && code in 200..299) {
                emit(ScanEvent.FindingFound(Finding(tool.id, "$method returned $code",
                    "Potentially usable dangerous method", Severity.HIGH)))
            }
            if (method == "TRACE" && code == 200)
                emit(ScanEvent.FindingFound(Finding(tool.id, "TRACE enabled", "Cross-Site Tracing risk", Severity.MEDIUM)))
        }
        emit(ScanEvent.Completed(0, System.currentTimeMillis() - start))
    }.flowOn(Dispatchers.IO)
}

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
import java.util.Base64

/** Offline JWT decoder and quick security audit (alg=none, weak alg, exp). */
class JwtScanner : ScannerEngine {
    override val tool = ToolType.JWT

    override fun run(target: Target, config: ScanConfig): Flow<ScanEvent> = flow {
        emit(ScanEvent.Started)
        val token = target.hostForTools.trim().removePrefix("Bearer ").trim()
        val parts = token.split(".")
        if (parts.size < 2) { emit(ScanEvent.Failed("Not a JWT (need header.payload.signature)")); return@flow }

        val header = decode(parts[0])
        val payload = decode(parts[1])
        if (header == null || payload == null) { emit(ScanEvent.Failed("Base64URL decode failed")); return@flow }
        emit(ScanEvent.Line("== Header ==", LineStream.SYSTEM))
        emit(ScanEvent.Line(pretty(header), LineStream.STDOUT))
        emit(ScanEvent.Line("== Payload ==", LineStream.SYSTEM))
        emit(ScanEvent.Line(pretty(payload), LineStream.STDOUT))

        val alg = runCatching { JSONObject(header).optString("alg") }.getOrNull()
        emit(ScanEvent.FindingFound(Finding(tool.id, "Algorithm", alg ?: "?", Severity.INFO)))
        if (alg.equals("none", true))
            emit(ScanEvent.FindingFound(Finding(tool.id, "alg=none", "Signature not verified — forgeable", Severity.CRITICAL)))
        if (alg?.startsWith("HS", true) == true)
            emit(ScanEvent.FindingFound(Finding(tool.id, "HMAC ($alg)", "Brute/keyconfusion risk if weak secret", Severity.LOW)))
        if (parts.size < 3 || parts[2].isBlank())
            emit(ScanEvent.FindingFound(Finding(tool.id, "No signature", "Token is unsigned", Severity.HIGH)))

        runCatching {
            val exp = JSONObject(payload).optLong("exp", 0)
            if (exp > 0) {
                val expired = exp * 1000 < System.currentTimeMillis()
                emit(ScanEvent.Line("exp: ${java.util.Date(exp * 1000)} ${if (expired) "(EXPIRED)" else "(valid)"}",
                    if (expired) LineStream.STDERR else LineStream.STDOUT))
            }
        }
        emit(ScanEvent.Completed(0, 0))
    }.flowOn(Dispatchers.IO)

    private fun decode(part: String): String? = runCatching {
        String(Base64.getUrlDecoder().decode(part.padEnd((part.length + 3) / 4 * 4, '=')))
    }.getOrNull()

    private fun pretty(json: String): String = runCatching { JSONObject(json).toString(2) }.getOrDefault(json)
}

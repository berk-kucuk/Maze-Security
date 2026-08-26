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
import java.net.URLDecoder
import java.net.URLEncoder
import java.util.Base64

/** Offline: Base64 / Hex / URL encode and decode of the input, both directions. */
class EncoderScanner : ScannerEngine {
    override val tool = ToolType.ENCODER

    override fun run(target: Target, config: ScanConfig): Flow<ScanEvent> = flow {
        emit(ScanEvent.Started)
        val input = target.hostForTools
        val bytes = input.toByteArray(Charsets.UTF_8)
        emit(ScanEvent.Line("Input: $input", LineStream.SYSTEM))

        suspend fun row(label: String, value: String) {
            emit(ScanEvent.Line("$label:", LineStream.SYSTEM))
            emit(ScanEvent.Line("  $value", LineStream.STDOUT))
            emit(ScanEvent.FindingFound(Finding(tool.id, label, value, Severity.INFO)))
        }

        row("Base64 encode", Base64.getEncoder().encodeToString(bytes))
        runCatching { String(Base64.getDecoder().decode(input.trim()), Charsets.UTF_8) }
            .onSuccess { if (it.isNotBlank() && it.all { c -> c.code in 9..126 }) row("Base64 decode", it) }
        row("Hex encode", bytes.joinToString("") { "%02x".format(it) })
        runCatching {
            val clean = input.trim().replace(" ", "")
            if (clean.matches(Regex("^[0-9a-fA-F]+$")) && clean.length % 2 == 0)
                String(ByteArray(clean.length / 2) { ((clean[it * 2].digitToInt(16) shl 4) + clean[it * 2 + 1].digitToInt(16)).toByte() })
            else null
        }.getOrNull()?.let { row("Hex decode", it) }
        row("URL encode", URLEncoder.encode(input, "UTF-8"))
        runCatching { URLDecoder.decode(input, "UTF-8") }.getOrNull()?.let { if (it != input) row("URL decode", it) }

        emit(ScanEvent.Completed(0, 0))
    }.flowOn(Dispatchers.IO)
}

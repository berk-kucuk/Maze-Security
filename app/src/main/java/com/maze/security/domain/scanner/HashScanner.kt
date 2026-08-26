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
import java.security.MessageDigest

/** Offline: generates common hashes of the input and guesses a supplied hash's type. */
class HashScanner : ScannerEngine {
    override val tool = ToolType.HASH

    override fun run(target: Target, config: ScanConfig): Flow<ScanEvent> = flow {
        emit(ScanEvent.Started)
        val input = target.hostForTools
        emit(ScanEvent.Line("Input: $input", LineStream.SYSTEM))
        emit(ScanEvent.Line("Length: ${input.length} chars", LineStream.STDOUT))

        // If it looks like a hash, identify likely type.
        if (input.matches(Regex("^[a-fA-F0-9]+$"))) {
            val type = when (input.length) {
                32 -> "MD5 / NTLM"; 40 -> "SHA-1"; 56 -> "SHA-224"
                64 -> "SHA-256"; 96 -> "SHA-384"; 128 -> "SHA-512"; else -> null
            }
            if (type != null) {
                emit(ScanEvent.Line("Looks like a hash → likely $type", LineStream.STDERR))
                emit(ScanEvent.FindingFound(Finding(tool.id, "Hash identified", "$type (${input.length} hex chars)", Severity.INFO)))
            }
        }
        emit(ScanEvent.Line("== Hashes of input ==", LineStream.SYSTEM))
        for (algo in listOf("MD5", "SHA-1", "SHA-256", "SHA-512")) {
            val h = MessageDigest.getInstance(algo).digest(input.toByteArray())
                .joinToString("") { "%02x".format(it) }
            emit(ScanEvent.Line("%-8s %s".format(algo, h), LineStream.STDOUT))
            emit(ScanEvent.FindingFound(Finding(tool.id, algo, h, Severity.INFO)))
        }
        emit(ScanEvent.Completed(0, 0))
    }.flowOn(Dispatchers.IO)
}

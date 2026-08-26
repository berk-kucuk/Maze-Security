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
import kotlin.math.ln
import kotlin.math.pow

/** Offline password strength analysis: entropy, charset, crack-time estimate. */
class PasswordAnalyzerScanner : ScannerEngine {
    override val tool = ToolType.PASSWORD_ANALYZER

    private val common = setOf("123456","password","123456789","12345678","12345","qwerty","abc123",
        "password1","111111","123123","admin","root","toor","letmein","welcome","monkey","dragon","iloveyou")

    override fun run(target: Target, config: ScanConfig): Flow<ScanEvent> = flow {
        emit(ScanEvent.Started)
        val pw = target.hostForTools
        emit(ScanEvent.Line("Analyzing password (${pw.length} chars)", LineStream.SYSTEM))

        val lower = pw.any { it.isLowerCase() }
        val upper = pw.any { it.isUpperCase() }
        val digit = pw.any { it.isDigit() }
        val symbol = pw.any { !it.isLetterOrDigit() }
        var pool = 0
        if (lower) pool += 26; if (upper) pool += 26; if (digit) pool += 10; if (symbol) pool += 33
        val entropy = if (pool > 0) pw.length * (ln(pool.toDouble()) / ln(2.0)) else 0.0
        val combos = pool.toDouble().pow(pw.length.toDouble())
        val guessesPerSec = 1e10 // offline GPU estimate
        val seconds = combos / guessesPerSec

        emit(ScanEvent.Line("Charset: " + listOfNotNull(
            if (lower) "a-z" else null, if (upper) "A-Z" else null,
            if (digit) "0-9" else null, if (symbol) "symbols" else null).joinToString(", "),
            LineStream.STDOUT))
        emit(ScanEvent.Line("Pool size: $pool", LineStream.STDOUT))
        emit(ScanEvent.Line("Entropy: %.1f bits".format(entropy), LineStream.STDOUT))
        emit(ScanEvent.Line("Est. offline crack time: ${humanTime(seconds)}", LineStream.STDOUT))

        val rating = when {
            pw.lowercase() in common -> "VERY WEAK (known common password)"
            entropy < 28 -> "VERY WEAK"; entropy < 36 -> "WEAK"
            entropy < 60 -> "REASONABLE"; entropy < 128 -> "STRONG"; else -> "VERY STRONG"
        }
        val sev = when {
            pw.lowercase() in common || entropy < 36 -> Severity.HIGH
            entropy < 60 -> Severity.MEDIUM; else -> Severity.LOW
        }
        emit(ScanEvent.Line("Rating: $rating", if (sev == Severity.HIGH) LineStream.STDERR else LineStream.SYSTEM))
        emit(ScanEvent.FindingFound(Finding(tool.id, "Strength", "$rating (${"%.0f".format(entropy)} bits)", sev)))
        if (pw.lowercase() in common)
            emit(ScanEvent.FindingFound(Finding(tool.id, "Common password", "Appears in top wordlists", Severity.CRITICAL)))
        emit(ScanEvent.Completed(0, 0))
    }.flowOn(Dispatchers.IO)

    private fun humanTime(seconds: Double): String {
        if (seconds < 1) return "instant"
        val units = listOf("second" to 60.0, "minute" to 60.0, "hour" to 24.0, "day" to 365.0, "year" to 1e9)
        var v = seconds
        for ((name, factor) in units) {
            if (v < factor) return "%.1f %s(s)".format(v, name)
            v /= factor
        }
        return "%.1e years".format(v * 1e9)
    }
}

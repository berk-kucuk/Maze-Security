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

/** Have I Been Pwned password check using the free k-anonymity range API. Root-free & private. */
class HibpScanner : ScannerEngine {
    override val tool = ToolType.HIBP

    override fun run(target: Target, config: ScanConfig): Flow<ScanEvent> = flow {
        val start = System.currentTimeMillis()
        emit(ScanEvent.Started)
        val pw = target.hostForTools
        emit(ScanEvent.Line("Checking password against Have I Been Pwned (k-anonymity)", LineStream.SYSTEM))
        emit(ScanEvent.Line("Only the first 5 chars of the SHA-1 leave the device — the password never does.",
            LineStream.SYSTEM))

        val sha1 = MessageDigest.getInstance("SHA-1").digest(pw.toByteArray())
            .joinToString("") { "%02x".format(it) }.uppercase()
        val prefix = sha1.substring(0, 5)
        val suffix = sha1.substring(5)

        val res = ReconHttp.get("https://api.pwnedpasswords.com/range/$prefix", timeoutMs = 12000)
        if (res == null) { emit(ScanEvent.Failed("HIBP request failed")); return@flow }
        val match = res.body.lines().map { it.trim().split(":") }
            .firstOrNull { it.size == 2 && it[0].equals(suffix, true) }
        if (match != null) {
            val count = match[1].toIntOrNull() ?: 0
            emit(ScanEvent.Line("[!] PWNED — seen in $count breaches", LineStream.STDERR))
            emit(ScanEvent.FindingFound(Finding(tool.id, "Password breached",
                "Found $count times in known breaches — do not use", Severity.CRITICAL)))
        } else {
            emit(ScanEvent.Line("[+] Not found in any known breach.", LineStream.STDOUT))
            emit(ScanEvent.FindingFound(Finding(tool.id, "Not breached", "No match in HIBP dataset", Severity.INFO)))
        }
        emit(ScanEvent.Completed(0, System.currentTimeMillis() - start))
    }.flowOn(Dispatchers.IO)
}

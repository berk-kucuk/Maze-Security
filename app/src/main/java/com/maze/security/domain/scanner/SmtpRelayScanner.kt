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
import java.io.BufferedReader
import java.io.PrintWriter
import java.net.InetSocketAddress
import java.net.Socket

/** SMTP banner, VRFY and open-relay test. Root-free (socket to 25/587). */
class SmtpRelayScanner : ScannerEngine {
    override val tool = ToolType.SMTP_RELAY

    override fun run(target: Target, config: ScanConfig): Flow<ScanEvent> = flow {
        val start = System.currentTimeMillis()
        emit(ScanEvent.Started)
        val host = target.hostForTools
        val port = config.port ?: 25
        emit(ScanEvent.Line("SMTP test on $host:$port", LineStream.SYSTEM))

        try {
            Socket().use { s ->
                s.connect(InetSocketAddress(host, port), 8000)
                s.soTimeout = 8000
                val reader = s.getInputStream().bufferedReader()
                val writer = PrintWriter(s.getOutputStream(), true)
                fun cmd(c: String?): String {
                    if (c != null) { writer.print("$c\r\n"); writer.flush() }
                    return readReply(reader)
                }
                val banner = cmd(null)
                emit(ScanEvent.Line("Banner: ${banner.trim()}", LineStream.STDOUT))
                emit(ScanEvent.FindingFound(Finding(tool.id, "SMTP banner", banner.trim().take(80), Severity.INFO)))

                val ehlo = cmd("EHLO maze.test")
                emit(ScanEvent.Line("EHLO:\n${ehlo.trim()}", LineStream.STDOUT))
                if (ehlo.contains("VRFY", true))
                    emit(ScanEvent.FindingFound(Finding(tool.id, "VRFY advertised", "User enumeration possible", Severity.LOW)))

                val vrfy = cmd("VRFY root")
                emit(ScanEvent.Line("VRFY root: ${vrfy.trim()}", LineStream.STDOUT))
                if (vrfy.startsWith("25")) emit(ScanEvent.FindingFound(Finding(tool.id, "VRFY works", vrfy.trim().take(60), Severity.MEDIUM)))

                // Open relay test: external sender + external recipient.
                cmd("MAIL FROM:<test@maze-external.example>")
                val rcpt = cmd("RCPT TO:<relay-test@example.com>")
                emit(ScanEvent.Line("Relay RCPT: ${rcpt.trim()}", if (rcpt.startsWith("25")) LineStream.STDERR else LineStream.STDOUT))
                if (rcpt.startsWith("25")) {
                    emit(ScanEvent.Line("[!] Server may be an OPEN RELAY", LineStream.STDERR))
                    emit(ScanEvent.FindingFound(Finding(tool.id, "Possible open relay", rcpt.trim().take(60), Severity.HIGH)))
                } else {
                    emit(ScanEvent.Line("[+] Relay refused (good)", LineStream.STDOUT))
                }
                cmd("QUIT")
            }
        } catch (e: Exception) {
            emit(ScanEvent.Failed("SMTP connection failed: ${e.message}")); return@flow
        }
        emit(ScanEvent.Completed(0, System.currentTimeMillis() - start))
    }.flowOn(Dispatchers.IO)

    private fun readReply(reader: BufferedReader): String {
        val sb = StringBuilder()
        while (true) {
            val line = reader.readLine() ?: break
            sb.append(line).append("\n")
            if (line.length >= 4 && line[3] == ' ') break   // last line of a multiline reply
        }
        return sb.toString()
    }
}

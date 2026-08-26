package com.maze.security.native

import com.maze.security.domain.model.Finding
import com.maze.security.domain.model.LineStream
import com.maze.security.domain.model.ScanEvent
import kotlinx.coroutines.channels.awaitClose
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.callbackFlow
import kotlinx.coroutines.isActive
import java.io.BufferedReader
import java.io.File
import kotlin.concurrent.thread

/**
 * Runs an external binary via ProcessBuilder and streams its combined output as
 * [ScanEvent]s. [parseLine] lets each scanner turn raw lines into structured findings.
 */
class ProcessRunner {

    fun run(
        command: List<String>,
        workingDir: File? = null,
        environment: Map<String, String> = emptyMap(),
        parseLine: (String) -> Finding? = { null },
        parseProgress: (String) -> Float? = { null }
    ): Flow<ScanEvent> = callbackFlow {
        val start = System.currentTimeMillis()
        trySend(ScanEvent.Started)
        trySend(ScanEvent.Line("\$ ${command.joinToString(" ")}", LineStream.SYSTEM))

        val process = try {
            ProcessBuilder(command)
                .redirectErrorStream(true)
                .apply {
                    workingDir?.let { directory(it) }
                    environment().putAll(environment)
                }
                .start()
        } catch (e: Exception) {
            trySend(ScanEvent.Failed("Failed to start: ${e.message}"))
            close()
            return@callbackFlow
        }

        val reader = thread(start = true, name = "proc-reader") {
            try {
                process.inputStream.bufferedReader().useLines { lines ->
                    for (line in lines) {
                        if (!isActive) break
                        trySend(ScanEvent.Line(line, LineStream.STDOUT))
                        parseLine(line)?.let { trySend(ScanEvent.FindingFound(it)) }
                        parseProgress(line)?.let { trySend(ScanEvent.Progress(it)) }
                    }
                }
            } catch (_: Exception) {
                // stream closed (process killed) — ignore
            }
        }

        val waiter = thread(start = true, name = "proc-waiter") {
            val exit = try { process.waitFor() } catch (_: InterruptedException) { -1 }
            reader.join(1000)
            trySend(ScanEvent.Completed(exit, System.currentTimeMillis() - start))
            close()
        }

        awaitClose {
            runCatching { process.destroy() }
            runCatching { if (process.isAlive) process.destroyForcibly() }
            waiter.interrupt()
        }
    }

    /** Convenience for reading a whole stream (unused by streaming path, handy for tests). */
    fun BufferedReader.drain(onLine: (String) -> Unit) = forEachLine(onLine)
}

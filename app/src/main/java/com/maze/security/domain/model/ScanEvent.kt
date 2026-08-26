package com.maze.security.domain.model

/** Streaming events emitted by a scanner during a run. */
sealed interface ScanEvent {
    data object Started : ScanEvent
    data class Line(val text: String, val stream: LineStream = LineStream.STDOUT) : ScanEvent
    data class Progress(val fraction: Float, val label: String? = null) : ScanEvent
    data class FindingFound(val finding: Finding) : ScanEvent
    data class Completed(val exitCode: Int, val durationMs: Long) : ScanEvent
    data class Failed(val message: String) : ScanEvent
}

enum class LineStream { STDOUT, STDERR, SYSTEM }

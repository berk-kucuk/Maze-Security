package com.maze.security.domain.scanner

import com.maze.security.domain.model.ScanConfig
import com.maze.security.domain.model.ScanEvent
import com.maze.security.domain.model.Target
import com.maze.security.domain.model.ToolType
import kotlinx.coroutines.flow.Flow

/** Common contract implemented by every scanning tool (Kotlin-native or binary-backed). */
interface ScannerEngine {
    val tool: ToolType

    /** True if this engine is ready to run (e.g. its binary is present on this device). */
    fun isAvailable(): Boolean = true

    /** Executes the scan, streaming output/findings until completion. */
    fun run(target: Target, config: ScanConfig): Flow<ScanEvent>
}

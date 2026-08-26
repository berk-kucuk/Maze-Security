package com.maze.security.ui

import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.viewModelScope
import com.maze.security.AppContainer
import com.maze.security.domain.model.Finding
import com.maze.security.domain.model.LineStream
import com.maze.security.domain.model.ScanConfig
import com.maze.security.domain.model.ScanEvent
import com.maze.security.domain.model.Target
import com.maze.security.domain.model.ToolType
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch

data class TerminalLine(val text: String, val stream: LineStream)

data class ScanState(
    val running: Boolean = false,
    val lines: List<TerminalLine> = emptyList(),
    val findings: List<Finding> = emptyList(),
    val progress: Float? = null,
    val exitCode: Int? = null,
    val durationMs: Long? = null,
    val error: String? = null
)

/**
 * Activity-scoped session state: the chosen target, selected tool, per-tool config,
 * and the live scan output. Kept above the NavHost so a scan survives navigation.
 */
class SessionViewModel(private val container: AppContainer) : ViewModel() {

    private val _target = MutableStateFlow<Target?>(null)
    val target: StateFlow<Target?> = _target.asStateFlow()

    private val _selectedTool = MutableStateFlow<ToolType?>(null)
    val selectedTool: StateFlow<ToolType?> = _selectedTool.asStateFlow()

    private val _config = MutableStateFlow(ScanConfig())
    val config: StateFlow<ScanConfig> = _config.asStateFlow()

    private val _scan = MutableStateFlow(ScanState())
    val scan: StateFlow<ScanState> = _scan.asStateFlow()

    private var scanJob: Job? = null

    fun setTarget(target: Target) { _target.value = target }
    fun selectTool(tool: ToolType) { _selectedTool.value = tool }
    fun updateConfig(transform: (ScanConfig) -> ScanConfig) { _config.value = transform(_config.value) }

    val container_: AppContainer get() = container

    fun startScan() {
        val target = _target.value ?: return
        val tool = _selectedTool.value ?: return
        scanJob?.cancel()
        _scan.value = ScanState(running = true)
        val engine = container.scannerFor(tool)
        scanJob = viewModelScope.launch {
            try {
                engine.run(target, _config.value).collect { event -> reduce(event) }
            } catch (e: Exception) {
                _scan.value = _scan.value.copy(running = false, error = e.message ?: "Scan error")
            }
        }
    }

    fun stopScan() {
        scanJob?.cancel()
        _scan.value = _scan.value.copy(
            running = false,
            lines = _scan.value.lines + TerminalLine("^C scan stopped by user", LineStream.SYSTEM)
        )
    }

    fun clearScan() {
        scanJob?.cancel()
        _scan.value = ScanState()
    }

    private fun reduce(event: ScanEvent) {
        val s = _scan.value
        _scan.value = when (event) {
            is ScanEvent.Started -> s.copy(running = true)
            is ScanEvent.Line -> s.copy(lines = s.lines + TerminalLine(event.text, event.stream))
            is ScanEvent.Progress -> s.copy(progress = event.fraction)
            is ScanEvent.FindingFound -> s.copy(findings = s.findings + event.finding)
            is ScanEvent.Completed -> s.copy(
                running = false, progress = null,
                exitCode = event.exitCode, durationMs = event.durationMs,
                lines = s.lines + TerminalLine(
                    "process finished (exit ${event.exitCode}) in ${event.durationMs} ms",
                    LineStream.SYSTEM)
            )
            is ScanEvent.Failed -> s.copy(running = false, error = event.message,
                lines = s.lines + TerminalLine("ERROR: ${event.message}", LineStream.STDERR))
        }
    }

    class Factory(private val container: AppContainer) : ViewModelProvider.Factory {
        @Suppress("UNCHECKED_CAST")
        override fun <T : ViewModel> create(modelClass: Class<T>): T =
            SessionViewModel(container) as T
    }
}

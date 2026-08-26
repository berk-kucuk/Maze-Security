package com.maze.security.domain.model

/** A structured result extracted from a scan (open port, credential, service, etc.). */
data class Finding(
    val toolId: String,
    val title: String,
    val detail: String,
    val severity: Severity = Severity.INFO
)

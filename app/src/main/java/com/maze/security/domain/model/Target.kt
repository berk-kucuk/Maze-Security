package com.maze.security.domain.model

/** A validated scan target: either a raw IP or a hostname/domain. */
data class Target(
    val raw: String,
    val type: TargetType,
    val resolvedIp: String? = null
) {
    val display: String get() = if (resolvedIp != null && type == TargetType.DOMAIN) {
        "$raw ($resolvedIp)"
    } else raw

    /** The address handed to the scanning tools. */
    val hostForTools: String get() = raw
}

enum class TargetType { IP, DOMAIN }

package com.maze.security.domain

import com.maze.security.domain.model.Target
import com.maze.security.domain.model.TargetType
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.net.InetAddress

object TargetValidator {

    private val ipv4 = Regex(
        """^((25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(25[0-5]|2[0-4]\d|1?\d?\d)$"""
    )
    private val hostname = Regex(
        """^(?=.{1,253}$)(([a-zA-Z0-9](-?[a-zA-Z0-9])*)\.)+[a-zA-Z]{2,}$"""
    )

    /** Cheap syntactic check for enabling the Continue button. */
    fun looksValid(raw: String): Boolean {
        val t = raw.trim()
        return ipv4.matches(t) || hostname.matches(t) || t.contains(":") && t.length in 3..45
    }

    /** True for a strict host (IP/domain). Non-hosts are allowed as free-text input for offline tools. */
    fun isHost(raw: String): Boolean {
        val t = raw.trim()
        return ipv4.matches(t) || hostname.matches(t)
    }

    /**
     * Builds a Target from any non-empty input. Hosts are resolved for display;
     * arbitrary text (for offline tools like Hash/JWT) is accepted as-is.
     */
    suspend fun resolve(raw: String): Target? = withContext(Dispatchers.IO) {
        val t = raw.trim()
        if (t.isEmpty()) return@withContext null
        val isIp = ipv4.matches(t) || (t.contains(":") && runCatching { InetAddress.getByName(t) }.isSuccess)
        val type = if (isIp) TargetType.IP else TargetType.DOMAIN
        return@withContext try {
            val addr = if (isHost(t)) InetAddress.getByName(t) else null
            Target(raw = t, type = type, resolvedIp = addr?.hostAddress)
        } catch (_: Exception) {
            Target(t, type)
        }
    }
}

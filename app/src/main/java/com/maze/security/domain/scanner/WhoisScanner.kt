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
import java.net.InetSocketAddress
import java.net.Socket

/**
 * WHOIS over port 43. Resolves the authoritative server via IANA (whois.iana.org),
 * then follows the registry -> registrar referral chain. Works for gTLDs and ccTLDs
 * (e.g. .com.tr) alike. Root-free.
 */
class WhoisScanner : ScannerEngine {
    override val tool = ToolType.WHOIS

    override fun run(target: Target, config: ScanConfig): Flow<ScanEvent> = flow {
        val start = System.currentTimeMillis()
        emit(ScanEvent.Started)
        val host = target.hostForTools

        if (target.type == TargetType.IP) {
            emit(ScanEvent.Line("WHOIS $host via whois.iana.org", LineStream.SYSTEM))
            queryChain("whois.iana.org", host).forEach { emit(it) }
            emit(ScanEvent.Completed(0, System.currentTimeMillis() - start))
            return@flow
        }

        // 1) Ask IANA which WHOIS server is authoritative for this TLD.
        val tld = host.substringAfterLast('.')
        emit(ScanEvent.Line("Resolving WHOIS server for .$tld via IANA…", LineStream.SYSTEM))
        val ianaResp = whois("whois.iana.org", tld)
        val registryServer = ianaResp
            ?.let { Regex("(?im)^whois:\\s*(\\S+)").find(it)?.groupValues?.get(1)?.trim() }
        if (registryServer == null) {
            emit(ScanEvent.Line("IANA gave no server; trying whois.iana.org directly.", LineStream.STDERR))
            queryChain("whois.iana.org", host).forEach { emit(it) }
        } else {
            emit(ScanEvent.Line("Registry WHOIS: $registryServer", LineStream.SYSTEM))
            queryChain(registryServer, host).forEach { emit(it) }
        }
        emit(ScanEvent.Completed(0, System.currentTimeMillis() - start))
    }.flowOn(Dispatchers.IO)

    /** Queries [server], emits its response, then follows one registrar referral. */
    private fun queryChain(server: String, query: String): List<ScanEvent> {
        val events = mutableListOf<ScanEvent>()
        val response = whois(server, query)
        if (response == null) {
            events += ScanEvent.Line("Query to $server failed", LineStream.STDERR)
            return events
        }
        response.lines().forEach { events += ScanEvent.Line(it, LineStream.STDOUT) }
        extractFindings(response).forEach { events += ScanEvent.FindingFound(it) }

        val referral = Regex("(?im)(Registrar WHOIS Server|ReferralServer|refer):\\s*(\\S+)")
            .find(response)?.groupValues?.get(2)
            ?.removePrefix("whois://")?.trim()
        if (referral != null && referral != server && referral.contains('.')) {
            events += ScanEvent.Line("", LineStream.SYSTEM)
            events += ScanEvent.Line("== Referral: $referral ==", LineStream.SYSTEM)
            whois(referral, query)?.let { r ->
                r.lines().forEach { events += ScanEvent.Line(it, LineStream.STDOUT) }
                extractFindings(r).forEach { events += ScanEvent.FindingFound(it) }
            }
        }
        return events
    }

    private fun whois(server: String, query: String): String? = try {
        Socket().use { s ->
            s.connect(InetSocketAddress(server, 43), 8000)
            s.soTimeout = 10000
            s.getOutputStream().write("$query\r\n".toByteArray())
            s.getOutputStream().flush()
            s.getInputStream().bufferedReader().readText().takeIf { it.isNotBlank() }
        }
    } catch (_: Exception) { null }

    private fun extractFindings(text: String): List<Finding> {
        val keys = listOf(
            "Registrar", "Creation Date", "Registry Expiry Date", "Expiry Date", "Updated Date",
            "Name Server", "Registrant Organization", "OrgName", "NetRange", "CIDR", "Country", "Domain Status"
        )
        return keys.mapNotNull { key ->
            Regex("(?im)^\\s*$key:\\s*(.+)$").find(text)?.groupValues?.get(1)?.trim()
                ?.takeIf { it.isNotEmpty() }
                ?.let { Finding(tool.id, key, it, Severity.INFO) }
        }
    }
}

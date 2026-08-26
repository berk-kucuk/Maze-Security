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
import org.json.JSONObject
import java.net.InetAddress

/** Checks an IP against DNS blocklists (DNSBL). Root-free (DoH lookups). */
class DnsblScanner : ScannerEngine {
    override val tool = ToolType.DNSBL

    private val zones = listOf(
        "zen.spamhaus.org", "bl.spamcop.net", "b.barracudacentral.org",
        "dnsbl.sorbs.net", "cbl.abuseat.org", "psbl.surriel.com",
        "dnsbl-1.uceprotect.net", "spam.dnsbl.anonmails.de"
    )

    override fun run(target: Target, config: ScanConfig): Flow<ScanEvent> = flow {
        val start = System.currentTimeMillis()
        emit(ScanEvent.Started)
        val host = target.hostForTools
        val ip = if (target.type == TargetType.IP) host
        else runCatching { InetAddress.getByName(host).hostAddress }.getOrNull()
        if (ip == null || !ip.matches(Regex("""\d+\.\d+\.\d+\.\d+"""))) {
            emit(ScanEvent.Failed("Need a resolvable IPv4 target")); return@flow
        }
        val rev = ip.split(".").reversed().joinToString(".")
        emit(ScanEvent.Line("DNSBL check for $ip (${zones.size} lists)", LineStream.SYSTEM))

        var listed = 0
        for (zone in zones) {
            val res = ReconHttp.get("https://dns.google/resolve?name=$rev.$zone&type=A", timeoutMs = 6000)
            val answer = res?.let { runCatching { JSONObject(it.body).optJSONArray("Answer") }.getOrNull() }
            if (answer != null && answer.length() > 0) {
                listed++
                val code = answer.getJSONObject(0).optString("data")
                emit(ScanEvent.Line("[!] LISTED on $zone ($code)", LineStream.STDERR))
                emit(ScanEvent.FindingFound(Finding(tool.id, "Blacklisted", "$zone -> $code", Severity.HIGH)))
            } else {
                emit(ScanEvent.Line("[+] clean on $zone", LineStream.STDOUT))
            }
        }
        emit(ScanEvent.Line("", LineStream.SYSTEM))
        emit(ScanEvent.Line(if (listed == 0) "Not listed on any checked blocklist." else "Listed on $listed blocklist(s).",
            LineStream.SYSTEM))
        emit(ScanEvent.Completed(0, System.currentTimeMillis() - start))
    }.flowOn(Dispatchers.IO)
}

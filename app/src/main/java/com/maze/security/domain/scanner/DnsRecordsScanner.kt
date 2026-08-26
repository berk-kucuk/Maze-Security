package com.maze.security.domain.scanner

import com.maze.security.domain.model.Finding
import com.maze.security.domain.model.LineStream
import com.maze.security.domain.model.ScanConfig
import com.maze.security.domain.model.ScanEvent
import com.maze.security.domain.model.Severity
import com.maze.security.domain.model.Target
import com.maze.security.domain.model.ToolType
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flow
import kotlinx.coroutines.flow.flowOn
import org.json.JSONObject

/** Resolves DNS record types via DNS-over-HTTPS (dns.google). Root-free, no UDP needed. */
class DnsRecordsScanner : ScannerEngine {
    override val tool = ToolType.DNS_RECORDS

    private val types = listOf("A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "CAA")

    override fun run(target: Target, config: ScanConfig): Flow<ScanEvent> = flow {
        val start = System.currentTimeMillis()
        emit(ScanEvent.Started)
        val name = target.hostForTools
        emit(ScanEvent.Line("DNS records for $name (via DoH)", LineStream.SYSTEM))

        for (type in types) {
            val res = ReconHttp.get("https://dns.google/resolve?name=$name&type=$type", readBody = true)
            if (res == null) { emit(ScanEvent.Line("$type: query failed", LineStream.STDERR)); continue }
            val answers = runCatching { JSONObject(res.body).optJSONArray("Answer") }.getOrNull()
            if (answers == null || answers.length() == 0) {
                emit(ScanEvent.Line("$type: (none)", LineStream.STDOUT)); continue
            }
            for (i in 0 until answers.length()) {
                val data = answers.getJSONObject(i).optString("data")
                emit(ScanEvent.Line("%-6s %s".format(type, data), LineStream.STDOUT))
                val sev = if (type == "TXT" && data.contains("spf", true)) Severity.LOW else Severity.INFO
                emit(ScanEvent.FindingFound(Finding(tool.id, "$type record", data, sev)))
            }
        }
        emit(ScanEvent.Completed(0, System.currentTimeMillis() - start))
    }.flowOn(Dispatchers.IO)
}

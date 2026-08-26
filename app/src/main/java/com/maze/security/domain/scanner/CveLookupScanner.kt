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
import java.net.URLEncoder

/** Searches the NVD for known CVEs by product/keyword (e.g. "apache 2.4.49"). Root-free. */
class CveLookupScanner : ScannerEngine {
    override val tool = ToolType.CVE_LOOKUP

    override fun run(target: Target, config: ScanConfig): Flow<ScanEvent> = flow {
        val start = System.currentTimeMillis()
        emit(ScanEvent.Started)
        val keyword = target.hostForTools
        emit(ScanEvent.Line("NVD CVE search: \"$keyword\"", LineStream.SYSTEM))

        val q = URLEncoder.encode(keyword, "UTF-8")
        val res = ReconHttp.get(
            "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=$q&resultsPerPage=15",
            timeoutMs = 20000)
        if (res == null || res.body.isBlank()) { emit(ScanEvent.Failed("NVD query failed (rate-limited?)")); return@flow }

        val json = runCatching { JSONObject(res.body) }.getOrNull()
        val vulns = json?.optJSONArray("vulnerabilities")
        if (vulns == null || vulns.length() == 0) {
            emit(ScanEvent.Line("No CVEs found for that keyword.", LineStream.STDOUT))
            emit(ScanEvent.Completed(0, System.currentTimeMillis() - start)); return@flow
        }
        emit(ScanEvent.Line("Total matches: ${json.optInt("totalResults")} (showing ${vulns.length()})", LineStream.SYSTEM))
        for (i in 0 until vulns.length()) {
            val cve = vulns.getJSONObject(i).getJSONObject("cve")
            val id = cve.optString("id")
            val desc = cve.optJSONArray("descriptions")?.let { d ->
                (0 until d.length()).map { d.getJSONObject(it) }.firstOrNull { it.optString("lang") == "en" }?.optString("value")
            } ?: ""
            val score = runCatching {
                val m = cve.getJSONObject("metrics")
                val arr = m.optJSONArray("cvssMetricV31") ?: m.optJSONArray("cvssMetricV30") ?: m.optJSONArray("cvssMetricV2")
                arr?.getJSONObject(0)?.getJSONObject("cvssData")?.optDouble("baseScore")
            }.getOrNull()
            val sev = when {
                score == null -> Severity.INFO
                score >= 9.0 -> Severity.CRITICAL
                score >= 7.0 -> Severity.HIGH
                score >= 4.0 -> Severity.MEDIUM
                else -> Severity.LOW
            }
            emit(ScanEvent.Line("$id  ${score?.let { "CVSS $it" } ?: ""}", LineStream.STDOUT))
            emit(ScanEvent.Line("  ${desc.take(180)}", LineStream.STDOUT))
            emit(ScanEvent.FindingFound(Finding(tool.id, id, desc.take(120), sev)))
        }
        emit(ScanEvent.Completed(0, System.currentTimeMillis() - start))
    }.flowOn(Dispatchers.IO)
}

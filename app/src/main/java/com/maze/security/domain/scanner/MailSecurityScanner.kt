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

/** Analyses SPF, DMARC and DKIM email-authentication records via DoH. Root-free. */
class MailSecurityScanner : ScannerEngine {
    override val tool = ToolType.MAIL_SEC

    private val dkimSelectors = listOf("default", "google", "selector1", "selector2", "k1", "mail", "dkim", "s1", "s2")

    override fun run(target: Target, config: ScanConfig): Flow<ScanEvent> = flow {
        val start = System.currentTimeMillis()
        emit(ScanEvent.Started)
        val domain = target.hostForTools.substringAfter("://").substringBefore("/")
        emit(ScanEvent.Line("Email security records for $domain", LineStream.SYSTEM))

        // SPF
        val spf = txt(domain).firstOrNull { it.contains("v=spf1", true) }
        if (spf != null) {
            emit(ScanEvent.Line("SPF:   $spf", LineStream.STDOUT))
            emit(ScanEvent.FindingFound(Finding(tool.id, "SPF", spf, Severity.INFO)))
            if (spf.contains("+all")) emit(ScanEvent.FindingFound(Finding(tool.id, "SPF +all", "Any host may send mail", Severity.HIGH)))
            else if (spf.contains("~all")) emit(ScanEvent.Line("  (soft-fail ~all)", LineStream.STDOUT))
            else if (!spf.contains("-all")) emit(ScanEvent.FindingFound(Finding(tool.id, "SPF not strict", "No -all qualifier", Severity.LOW)))
        } else {
            emit(ScanEvent.Line("SPF:   (missing)", LineStream.STDERR))
            emit(ScanEvent.FindingFound(Finding(tool.id, "SPF missing", "Sender spoofing possible", Severity.MEDIUM)))
        }

        // DMARC
        val dmarc = txt("_dmarc.$domain").firstOrNull { it.contains("v=DMARC1", true) }
        if (dmarc != null) {
            emit(ScanEvent.Line("DMARC: $dmarc", LineStream.STDOUT))
            emit(ScanEvent.FindingFound(Finding(tool.id, "DMARC", dmarc, Severity.INFO)))
            val policy = Regex("(?i)p=(\\w+)").find(dmarc)?.groupValues?.get(1)
            if (policy.equals("none", true)) emit(ScanEvent.FindingFound(Finding(tool.id, "DMARC p=none", "Monitoring only, not enforced", Severity.LOW)))
        } else {
            emit(ScanEvent.Line("DMARC: (missing)", LineStream.STDERR))
            emit(ScanEvent.FindingFound(Finding(tool.id, "DMARC missing", "No spoofing enforcement", Severity.MEDIUM)))
        }

        // DKIM (probe common selectors)
        emit(ScanEvent.Line("== DKIM selectors ==", LineStream.SYSTEM))
        var dkimFound = false
        for (sel in dkimSelectors) {
            val rec = txt("$sel._domainkey.$domain").firstOrNull { it.contains("v=DKIM1", true) || it.contains("p=", true) }
            if (rec != null) {
                dkimFound = true
                emit(ScanEvent.Line("[+] selector '$sel' present", LineStream.STDOUT))
                emit(ScanEvent.FindingFound(Finding(tool.id, "DKIM selector $sel", rec.take(80), Severity.INFO)))
            }
        }
        if (!dkimFound) emit(ScanEvent.Line("No common DKIM selectors found.", LineStream.STDOUT))
        emit(ScanEvent.Completed(0, System.currentTimeMillis() - start))
    }.flowOn(Dispatchers.IO)

    private fun txt(name: String): List<String> {
        val res = ReconHttp.get("https://dns.google/resolve?name=$name&type=TXT") ?: return emptyList()
        return runCatching {
            val arr = JSONObject(res.body).optJSONArray("Answer") ?: return emptyList()
            (0 until arr.length()).map { arr.getJSONObject(it).optString("data").trim('"') }
        }.getOrDefault(emptyList())
    }
}

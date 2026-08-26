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

/** IP geolocation, ISP, ASN and organisation via ip-api.com (free, no key). */
class GeoIpScanner : ScannerEngine {
    override val tool = ToolType.GEOIP

    override fun run(target: Target, config: ScanConfig): Flow<ScanEvent> = flow {
        val start = System.currentTimeMillis()
        emit(ScanEvent.Started)
        val host = target.hostForTools
        emit(ScanEvent.Line("GeoIP & ASN lookup for $host", LineStream.SYSTEM))

        val fields = "status,message,continent,country,regionName,city,zip,lat,lon,timezone,isp,org,as,asname,reverse,mobile,proxy,hosting,query"
        val res = ReconHttp.get("http://ip-api.com/json/$host?fields=$fields")
        if (res == null) { emit(ScanEvent.Failed("Lookup failed")); return@flow }
        val json = runCatching { JSONObject(res.body) }.getOrNull()
        if (json == null || json.optString("status") != "success") {
            emit(ScanEvent.Failed(json?.optString("message") ?: "Lookup failed"))
            return@flow
        }
        val rows = listOf(
            "IP" to json.optString("query"),
            "Country" to "${json.optString("country")} (${json.optString("continent")})",
            "Region" to json.optString("regionName"),
            "City" to "${json.optString("city")} ${json.optString("zip")}",
            "Coordinates" to "${json.optDouble("lat")}, ${json.optDouble("lon")}",
            "Timezone" to json.optString("timezone"),
            "ISP" to json.optString("isp"),
            "Organisation" to json.optString("org"),
            "ASN" to "${json.optString("as")} ${json.optString("asname")}",
            "Reverse DNS" to json.optString("reverse")
        )
        rows.forEach { (k, v) ->
            if (v.isNotBlank() && v != "null null" && v != " ") {
                emit(ScanEvent.Line("%-14s %s".format("$k:", v), LineStream.STDOUT))
                emit(ScanEvent.FindingFound(Finding(tool.id, k, v, Severity.INFO)))
            }
        }
        val flags = buildList {
            if (json.optBoolean("hosting")) add("hosting/datacenter")
            if (json.optBoolean("proxy")) add("proxy/VPN")
            if (json.optBoolean("mobile")) add("mobile network")
        }
        if (flags.isNotEmpty()) {
            emit(ScanEvent.Line("Flags: ${flags.joinToString(", ")}", LineStream.SYSTEM))
            emit(ScanEvent.FindingFound(Finding(tool.id, "Network type", flags.joinToString(", "), Severity.LOW)))
        }
        emit(ScanEvent.Completed(0, System.currentTimeMillis() - start))
    }.flowOn(Dispatchers.IO)
}

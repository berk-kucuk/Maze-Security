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
import java.io.BufferedReader
import java.net.HttpURLConnection
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.net.URL
import javax.net.ssl.HttpsURLConnection
import java.security.cert.X509Certificate

/**
 * Pure-Kotlin reconnaissance: DNS, reverse DNS, HTTP headers, TLS certificate,
 * and service banner grabbing. Requires no root and no bundled binaries.
 */
class InfoGatheringScanner : ScannerEngine {

    override val tool = ToolType.INFO_GATHERING

    override fun run(target: Target, config: ScanConfig): Flow<ScanEvent> = flow {
        val start = System.currentTimeMillis()
        emit(ScanEvent.Started)
        val host = target.hostForTools
        emit(sys("Reconnaissance on $host"))

        // 1. DNS resolution
        if (config.doDns) {
            emit(sys("== DNS resolution =="))
            try {
                val addrs = InetAddress.getAllByName(host)
                for (a in addrs) {
                    emit(out("A/AAAA  ${a.hostAddress}"))
                    emit(ScanEvent.FindingFound(Finding(tool.id, "IP address", a.hostAddress ?: "", Severity.INFO)))
                }
            } catch (e: Exception) {
                emit(err("DNS resolution failed: ${e.message}"))
            }
        }

        // 2. Reverse DNS
        if (config.doReverseDns) {
            emit(sys("== Reverse DNS =="))
            try {
                val ip = InetAddress.getByName(host)
                val ptr = ip.canonicalHostName
                emit(out("PTR    $ptr"))
                if (ptr != ip.hostAddress) {
                    emit(ScanEvent.FindingFound(Finding(tool.id, "Reverse DNS", ptr, Severity.INFO)))
                }
            } catch (e: Exception) {
                emit(err("Reverse lookup failed: ${e.message}"))
            }
        }

        // 3. HTTP headers (port 80 / 443)
        if (config.doHttpHeaders) {
            emit(sys("== HTTP headers =="))
            for (scheme in listOf("http", "https")) {
                fetchHeaders(scheme, host)?.let { (status, headers) ->
                    emit(out("[$scheme] $status"))
                    headers.forEach { (k, v) -> emit(out("  $k: $v")) }
                    headers["Server"]?.let {
                        emit(ScanEvent.FindingFound(Finding(tool.id, "Web server", "$scheme -> $it", Severity.LOW)))
                    }
                } ?: emit(err("[$scheme] no response"))
            }
        }

        // 4. TLS certificate
        if (config.doTlsInfo) {
            emit(sys("== TLS certificate (443) =="))
            tlsInfo(host)?.let { lines ->
                lines.forEach { emit(out(it)) }
            } ?: emit(err("No TLS on 443"))
        }

        // 5. Banner grabbing on a few common ports
        if (config.doBanner) {
            emit(sys("== Banner grabbing =="))
            val commonPorts = listOf(21, 22, 25, 23, 110, 143, 3306, 6379)
            for (p in commonPorts) {
                grabBanner(host, p, config.timeoutMs.toInt())?.let { banner ->
                    emit(out("$p/tcp  $banner"))
                    emit(ScanEvent.FindingFound(Finding(tool.id, "Banner :$p", banner, Severity.LOW)))
                }
            }
        }

        emit(ScanEvent.Completed(0, System.currentTimeMillis() - start))
    }.flowOn(Dispatchers.IO)

    private fun fetchHeaders(scheme: String, host: String): Pair<String, Map<String, String>>? {
        return try {
            val url = URL("$scheme://$host/")
            val conn = url.openConnection() as HttpURLConnection
            conn.connectTimeout = 4000
            conn.readTimeout = 4000
            conn.instanceFollowRedirects = false
            conn.requestMethod = "HEAD"
            if (conn is HttpsURLConnection) {
                conn.hostnameVerifier = javax.net.ssl.HostnameVerifier { _, _ -> true }
            }
            val status = "${conn.responseCode} ${conn.responseMessage}"
            val headers = LinkedHashMap<String, String>()
            for (i in 0..30) {
                val key = conn.getHeaderFieldKey(i) ?: continue
                headers[key] = conn.getHeaderField(i) ?: ""
            }
            conn.disconnect()
            status to headers
        } catch (_: Exception) { null }
    }

    private fun tlsInfo(host: String): List<String>? {
        return try {
            val url = URL("https://$host/")
            val conn = url.openConnection() as HttpsURLConnection
            conn.connectTimeout = 4000
            conn.readTimeout = 4000
            conn.hostnameVerifier = javax.net.ssl.HostnameVerifier { _, _ -> true }
            conn.connect()
            val certs = conn.serverCertificates
            val out = mutableListOf<String>()
            (certs.firstOrNull() as? X509Certificate)?.let { c ->
                out += "Subject:  ${c.subjectX500Principal.name}"
                out += "Issuer:   ${c.issuerX500Principal.name}"
                out += "Valid:    ${c.notBefore} -> ${c.notAfter}"
                out += "SigAlg:   ${c.sigAlgName}"
            }
            conn.disconnect()
            out.ifEmpty { null }
        } catch (_: Exception) { null }
    }

    private fun grabBanner(host: String, port: Int, timeoutMs: Int): String? {
        return try {
            Socket().use { s ->
                s.connect(InetSocketAddress(host, port), timeoutMs)
                s.soTimeout = timeoutMs
                val reader: BufferedReader = s.getInputStream().bufferedReader()
                val line = reader.readLine()
                line?.trim()?.take(200)
            }
        } catch (_: Exception) { null }
    }

    private fun out(t: String) = ScanEvent.Line(t, LineStream.STDOUT)
    private fun err(t: String) = ScanEvent.Line(t, LineStream.STDERR)
    private fun sys(t: String) = ScanEvent.Line(t, LineStream.SYSTEM)
}

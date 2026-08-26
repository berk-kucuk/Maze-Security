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
import java.net.HttpURLConnection
import java.net.URL
import javax.net.ssl.HostnameVerifier
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SSLContext
import javax.net.ssl.X509TrustManager
import java.security.cert.X509Certificate

/** Tests for permissive/reflective CORS (Access-Control-Allow-Origin). Root-free. */
class CorsScanner : ScannerEngine {
    override val tool = ToolType.CORS

    private val trustAll = object : X509TrustManager {
        override fun checkClientTrusted(c: Array<out X509Certificate>?, a: String?) {}
        override fun checkServerTrusted(c: Array<out X509Certificate>?, a: String?) {}
        override fun getAcceptedIssuers() = arrayOf<X509Certificate>()
    }

    override fun run(target: Target, config: ScanConfig): Flow<ScanEvent> = flow {
        val start = System.currentTimeMillis()
        emit(ScanEvent.Started)
        val host = target.hostForTools
        val base = if (host.startsWith("http")) host.trimEnd('/') else "https://$host"
        val evil = "https://maze-evil.example"
        emit(ScanEvent.Line("CORS test on $base with Origin: $evil", LineStream.SYSTEM))

        val (acao, acac) = try {
            val conn = URL("$base/").openConnection() as HttpURLConnection
            if (conn is HttpsURLConnection) {
                val ctx = SSLContext.getInstance("TLS"); ctx.init(null, arrayOf(trustAll), null)
                conn.sslSocketFactory = ctx.socketFactory
                conn.hostnameVerifier = HostnameVerifier { _, _ -> true }
            }
            conn.setRequestProperty("Origin", evil)
            conn.connectTimeout = 8000; conn.readTimeout = 8000
            conn.responseCode
            val acao = conn.getHeaderField("Access-Control-Allow-Origin")
            val acac = conn.getHeaderField("Access-Control-Allow-Credentials")
            conn.disconnect(); acao to acac
        } catch (e: Exception) { emit(ScanEvent.Failed("Request failed: ${e.message}")); return@flow }

        emit(ScanEvent.Line("Access-Control-Allow-Origin: ${acao ?: "(none)"}", LineStream.STDOUT))
        emit(ScanEvent.Line("Access-Control-Allow-Credentials: ${acac ?: "(none)"}", LineStream.STDOUT))
        when {
            acao == evil && acac?.equals("true", true) == true -> {
                emit(ScanEvent.Line("[!] CRITICAL: reflects arbitrary origin WITH credentials", LineStream.STDERR))
                emit(ScanEvent.FindingFound(Finding(tool.id, "CORS reflects origin + credentials",
                    "Any site can read authenticated responses", Severity.HIGH)))
            }
            acao == evil -> {
                emit(ScanEvent.Line("[!] Reflects arbitrary origin", LineStream.STDERR))
                emit(ScanEvent.FindingFound(Finding(tool.id, "CORS reflects arbitrary origin", evil, Severity.MEDIUM)))
            }
            acao == "*" -> {
                emit(ScanEvent.Line("[i] Wildcard ACAO (ok only for public data)", LineStream.STDOUT))
                emit(ScanEvent.FindingFound(Finding(tool.id, "Wildcard CORS", "Access-Control-Allow-Origin: *", Severity.LOW)))
            }
            else -> emit(ScanEvent.Line("[+] No permissive CORS detected", LineStream.STDOUT))
        }
        emit(ScanEvent.Completed(0, System.currentTimeMillis() - start))
    }.flowOn(Dispatchers.IO)
}

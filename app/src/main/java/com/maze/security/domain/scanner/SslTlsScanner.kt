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
import java.security.cert.X509Certificate
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocket
import javax.net.ssl.X509TrustManager

/** Probes supported TLS protocols and cipher suites, flags weak config. Root-free. */
class SslTlsScanner : ScannerEngine {
    override val tool = ToolType.SSL_TLS

    private val trustAll = object : X509TrustManager {
        override fun checkClientTrusted(c: Array<out X509Certificate>?, a: String?) {}
        override fun checkServerTrusted(c: Array<out X509Certificate>?, a: String?) {}
        override fun getAcceptedIssuers() = arrayOf<X509Certificate>()
    }
    private val weakProtocols = setOf("SSLv3", "TLSv1", "TLSv1.1")
    private val weakCipher = Regex("(?i)_(RC4|3DES|DES|NULL|EXPORT|MD5|anon)_?")

    override fun run(target: Target, config: ScanConfig): Flow<ScanEvent> = flow {
        val start = System.currentTimeMillis()
        emit(ScanEvent.Started)
        val host = target.hostForTools.substringAfter("://").substringBefore("/")
        val port = 443
        emit(ScanEvent.Line("TLS scan of $host:$port", LineStream.SYSTEM))

        emit(ScanEvent.Line("== Protocols ==", LineStream.SYSTEM))
        for (proto in listOf("SSLv3", "TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3")) {
            val ok = handshake(host, port, proto)
            if (ok) {
                val weak = proto in weakProtocols
                emit(ScanEvent.Line("[+] $proto supported${if (weak) "  (WEAK)" else ""}",
                    if (weak) LineStream.STDERR else LineStream.STDOUT))
                emit(ScanEvent.FindingFound(Finding(tool.id, "$proto supported",
                    if (weak) "Deprecated protocol should be disabled" else "OK",
                    if (weak) Severity.MEDIUM else Severity.INFO)))
            } else emit(ScanEvent.Line("[-] $proto not supported", LineStream.STDOUT))
        }

        // Cipher suites via a default handshake.
        emit(ScanEvent.Line("", LineStream.SYSTEM))
        emit(ScanEvent.Line("== Negotiated session & certificate ==", LineStream.SYSTEM))
        runCatching {
            val ctx = SSLContext.getInstance("TLS"); ctx.init(null, arrayOf(trustAll), null)
            (ctx.socketFactory.createSocket() as SSLSocket).use { s ->
                s.connect(InetSocketAddress(host, port), 8000)
                s.startHandshake()
                val session = s.session
                emit(ScanEvent.Line("Protocol: ${session.protocol}", LineStream.STDOUT))
                val cs = session.cipherSuite
                val weak = weakCipher.containsMatchIn(cs)
                emit(ScanEvent.Line("Cipher:   $cs${if (weak) "  (WEAK)" else ""}",
                    if (weak) LineStream.STDERR else LineStream.STDOUT))
                if (weak) emit(ScanEvent.FindingFound(Finding(tool.id, "Weak cipher", cs, Severity.MEDIUM)))
                (session.peerCertificates.firstOrNull() as? X509Certificate)?.let { c ->
                    emit(ScanEvent.Line("Subject:  ${c.subjectX500Principal.name}", LineStream.STDOUT))
                    emit(ScanEvent.Line("Issuer:   ${c.issuerX500Principal.name}", LineStream.STDOUT))
                    emit(ScanEvent.Line("Expires:  ${c.notAfter}", LineStream.STDOUT))
                    if (c.notAfter.before(java.util.Date()))
                        emit(ScanEvent.FindingFound(Finding(tool.id, "Certificate expired", "${c.notAfter}", Severity.HIGH)))
                    emit(ScanEvent.FindingFound(Finding(tool.id, "Certificate", c.subjectX500Principal.name, Severity.INFO)))
                }
            }
        }.onFailure { emit(ScanEvent.Line("Handshake error: ${it.message}", LineStream.STDERR)) }

        emit(ScanEvent.Completed(0, System.currentTimeMillis() - start))
    }.flowOn(Dispatchers.IO)

    private fun handshake(host: String, port: Int, protocol: String): Boolean = try {
        val ctx = SSLContext.getInstance("TLS"); ctx.init(null, arrayOf(trustAll), null)
        (ctx.socketFactory.createSocket() as SSLSocket).use { s ->
            s.enabledProtocols = arrayOf(protocol)
            s.connect(InetSocketAddress(host, port), 6000)
            s.startHandshake()
            true
        }
    } catch (_: Exception) { false }
}

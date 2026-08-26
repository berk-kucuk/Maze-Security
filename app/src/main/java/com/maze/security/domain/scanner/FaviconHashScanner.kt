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
import java.net.URL
import java.security.MessageDigest
import java.util.Base64
import javax.net.ssl.HostnameVerifier
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SSLContext
import javax.net.ssl.X509TrustManager
import java.security.cert.X509Certificate

/** Computes the Shodan-style MurmurHash3 favicon hash + MD5 for fingerprinting. Root-free. */
class FaviconHashScanner : ScannerEngine {
    override val tool = ToolType.FAVICON

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
        emit(ScanEvent.Line("Favicon hash for $base/favicon.ico", LineStream.SYSTEM))

        val bytes = fetch("$base/favicon.ico") ?: fetch("$base/favicon.png")
        if (bytes == null || bytes.isEmpty()) { emit(ScanEvent.Failed("No favicon found")); return@flow }

        // Shodan: mmh3.hash(base64.encodebytes(favicon)) — MIME base64 with \n every 76 chars + trailing \n
        val b64 = Base64.getMimeEncoder(76, "\n".toByteArray()).encodeToString(bytes) + "\n"
        val mmh3 = murmur3_32(b64.toByteArray(Charsets.UTF_8), 0)
        val md5 = MessageDigest.getInstance("MD5").digest(bytes).joinToString("") { "%02x".format(it) }

        emit(ScanEvent.Line("Size:        ${bytes.size} bytes", LineStream.STDOUT))
        emit(ScanEvent.Line("MMH3 (Shodan): $mmh3", LineStream.STDOUT))
        emit(ScanEvent.Line("MD5:         $md5", LineStream.STDOUT))
        emit(ScanEvent.Line("Shodan pivot: http.favicon.hash:$mmh3", LineStream.SYSTEM))
        emit(ScanEvent.FindingFound(Finding(tool.id, "Favicon MMH3", "$mmh3 (Shodan: http.favicon.hash:$mmh3)", Severity.INFO)))
        emit(ScanEvent.FindingFound(Finding(tool.id, "Favicon MD5", md5, Severity.INFO)))
        emit(ScanEvent.Completed(0, System.currentTimeMillis() - start))
    }.flowOn(Dispatchers.IO)

    private fun fetch(url: String): ByteArray? = try {
        val conn = URL(url).openConnection() as java.net.HttpURLConnection
        if (conn is HttpsURLConnection) {
            val ctx = SSLContext.getInstance("TLS"); ctx.init(null, arrayOf(trustAll), null)
            conn.sslSocketFactory = ctx.socketFactory
            conn.hostnameVerifier = HostnameVerifier { _, _ -> true }
        }
        conn.connectTimeout = 8000; conn.readTimeout = 8000
        if (conn.responseCode == 200) conn.inputStream.readBytes() else null
    } catch (_: Exception) { null }

    /** MurmurHash3 x86_32 (signed), matching Python mmh3.hash default. */
    private fun murmur3_32(data: ByteArray, seed: Int): Int {
        val c1 = -0x3361d2af; val c2 = 0x1b873593
        var h1 = seed
        val len = data.size
        val roundedEnd = len and 0x03.inv()
        var i = 0
        while (i < roundedEnd) {
            var k1 = (data[i].toInt() and 0xff) or
                ((data[i + 1].toInt() and 0xff) shl 8) or
                ((data[i + 2].toInt() and 0xff) shl 16) or
                ((data[i + 3].toInt() and 0xff) shl 24)
            k1 *= c1; k1 = Integer.rotateLeft(k1, 15); k1 *= c2
            h1 = h1 xor k1; h1 = Integer.rotateLeft(h1, 13); h1 = h1 * 5 + -0x19ab949c
            i += 4
        }
        var k1 = 0
        val tail = len and 0x03
        if (tail == 3) k1 = k1 or ((data[roundedEnd + 2].toInt() and 0xff) shl 16)
        if (tail >= 2) k1 = k1 or ((data[roundedEnd + 1].toInt() and 0xff) shl 8)
        if (tail >= 1) { k1 = k1 or (data[roundedEnd].toInt() and 0xff); k1 *= c1; k1 = Integer.rotateLeft(k1, 15); k1 *= c2; h1 = h1 xor k1 }
        h1 = h1 xor len
        h1 = h1 xor (h1 ushr 16); h1 *= -0x7a143595
        h1 = h1 xor (h1 ushr 13); h1 *= -0x3d4d51cb
        h1 = h1 xor (h1 ushr 16)
        return h1
    }
}

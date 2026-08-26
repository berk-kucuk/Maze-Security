package com.maze.security.domain.scanner

import java.io.BufferedReader
import java.net.HttpURLConnection
import java.net.URL
import javax.net.ssl.HostnameVerifier
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SSLContext
import javax.net.ssl.X509TrustManager
import java.security.cert.X509Certificate

data class HttpResult(
    val code: Int,
    val message: String,
    val headers: Map<String, String>,
    val body: String
)

/** Minimal, permissive HTTP client shared by the recon scanners (root-free). */
object ReconHttp {

    private val trustAll = object : X509TrustManager {
        override fun checkClientTrusted(c: Array<out X509Certificate>?, a: String?) {}
        override fun checkServerTrusted(c: Array<out X509Certificate>?, a: String?) {}
        override fun getAcceptedIssuers(): Array<X509Certificate> = arrayOf()
    }

    fun get(
        url: String,
        method: String = "GET",
        followRedirects: Boolean = true,
        readBody: Boolean = true,
        timeoutMs: Int = 8000,
        userAgent: String = "MazeSecurity/1.0"
    ): HttpResult? {
        return try {
            val conn = URL(url).openConnection() as HttpURLConnection
            if (conn is HttpsURLConnection) {
                val ctx = SSLContext.getInstance("TLS")
                ctx.init(null, arrayOf(trustAll), java.security.SecureRandom())
                conn.sslSocketFactory = ctx.socketFactory
                conn.hostnameVerifier = HostnameVerifier { _, _ -> true }
            }
            conn.requestMethod = method
            conn.connectTimeout = timeoutMs
            conn.readTimeout = timeoutMs
            conn.instanceFollowRedirects = followRedirects
            conn.setRequestProperty("User-Agent", userAgent)
            conn.setRequestProperty("Accept", "*/*")
            val code = conn.responseCode
            val headers = LinkedHashMap<String, String>()
            for (i in 0..40) {
                val key = conn.getHeaderFieldKey(i) ?: continue
                headers[key] = conn.getHeaderField(i) ?: ""
            }
            val body = if (readBody) {
                val stream = if (code in 200..399) conn.inputStream else conn.errorStream
                stream?.let { s -> BufferedReader(s.reader()).use { it.readText() } } ?: ""
            } else ""
            conn.disconnect()
            HttpResult(code, conn.responseMessage ?: "", headers, body)
        } catch (_: Exception) {
            null
        }
    }
}

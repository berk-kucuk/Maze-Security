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
import java.io.DataInputStream
import java.io.DataOutputStream
import java.net.InetSocketAddress
import java.net.Socket

/** Tests each nameserver for an open DNS zone transfer (AXFR) over TCP/53. Root-free. */
class ZoneTransferScanner : ScannerEngine {
    override val tool = ToolType.ZONE_TRANSFER

    override fun run(target: Target, config: ScanConfig): Flow<ScanEvent> = flow {
        val start = System.currentTimeMillis()
        emit(ScanEvent.Started)
        val domain = target.hostForTools.substringAfter("://").substringBefore("/")
        emit(ScanEvent.Line("Zone transfer (AXFR) test for $domain", LineStream.SYSTEM))

        val nsRes = ReconHttp.get("https://dns.google/resolve?name=$domain&type=NS")
        val servers = nsRes?.let {
            runCatching {
                val arr = JSONObject(it.body).optJSONArray("Answer") ?: return@runCatching emptyList<String>()
                (0 until arr.length()).map { i -> arr.getJSONObject(i).optString("data").trimEnd('.') }
            }.getOrDefault(emptyList())
        } ?: emptyList()
        if (servers.isEmpty()) { emit(ScanEvent.Failed("No NS records found")); return@flow }
        emit(ScanEvent.Line("Nameservers: ${servers.joinToString(", ")}", LineStream.STDOUT))

        var vulnerable = false
        for (ns in servers) {
            emit(ScanEvent.Line("Trying AXFR @ $ns …", LineStream.SYSTEM))
            val result = tryAxfr(ns, domain)
            when {
                result == null -> emit(ScanEvent.Line("  $ns: connection failed / no TCP 53", LineStream.STDOUT))
                result.first -> {
                    vulnerable = true
                    emit(ScanEvent.Line("  [!] $ns ALLOWS zone transfer (${result.second} records)", LineStream.STDERR))
                    emit(ScanEvent.FindingFound(Finding(tool.id, "Open zone transfer",
                        "$ns leaked ${result.second} records", Severity.HIGH)))
                }
                else -> emit(ScanEvent.Line("  $ns: refused (secure)", LineStream.STDOUT))
            }
        }
        if (!vulnerable) emit(ScanEvent.Line("No nameserver allowed AXFR — good.", LineStream.SYSTEM))
        emit(ScanEvent.Completed(0, System.currentTimeMillis() - start))
    }.flowOn(Dispatchers.IO)

    /** Returns (allowed, answerCount) or null on connection failure. */
    private fun tryAxfr(ns: String, domain: String): Pair<Boolean, Int>? = try {
        Socket().use { s ->
            s.connect(InetSocketAddress(ns, 53), 6000)
            s.soTimeout = 8000
            val out = DataOutputStream(s.getOutputStream())
            val query = buildAxfrQuery(domain)
            out.writeShort(query.size)      // TCP length prefix
            out.write(query); out.flush()

            val din = DataInputStream(s.getInputStream())
            val len = din.readUnsignedShort()
            val msg = ByteArray(len); din.readFully(msg)
            // header: id(2) flags(2) qd(2) an(2) ns(2) ar(2)
            val rcode = msg[3].toInt() and 0x0f
            val ancount = ((msg[6].toInt() and 0xff) shl 8) or (msg[7].toInt() and 0xff)
            (rcode == 0 && ancount > 0) to ancount
        }
    } catch (_: Exception) { null }

    private fun buildAxfrQuery(domain: String): ByteArray {
        val header = byteArrayOf(
            0x13, 0x37,             // id
            0x00, 0x00,             // flags (standard query)
            0x00, 0x01,             // qdcount
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00
        )
        val qname = ArrayList<Byte>()
        for (label in domain.split(".")) {
            qname.add(label.length.toByte())
            label.forEach { qname.add(it.code.toByte()) }
        }
        qname.add(0)
        // QTYPE=252 (AXFR), QCLASS=1 (IN)
        val tail = byteArrayOf(0x00, 0xFC.toByte(), 0x00, 0x01)
        return header + qname.toByteArray() + tail
    }
}

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
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress

/** Tries common SNMP v1 community strings (UDP/161) with a sysDescr GET. Root-free. */
class SnmpScanner : ScannerEngine {
    override val tool = ToolType.SNMP

    private val communities = listOf("public", "private", "manager", "admin", "cisco", "community", "read", "write")
    private val sysDescrOid = byteArrayOf(0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00) // 1.3.6.1.2.1.1.1.0

    override fun run(target: Target, config: ScanConfig): Flow<ScanEvent> = flow {
        val start = System.currentTimeMillis()
        emit(ScanEvent.Started)
        val host = target.hostForTools
        val port = config.port ?: 161
        emit(ScanEvent.Line("SNMP community check on $host:$port (UDP)", LineStream.SYSTEM))
        val addr = runCatching { InetAddress.getByName(host) }.getOrNull()
        if (addr == null) { emit(ScanEvent.Failed("Cannot resolve host")); return@flow }

        var hit = false
        for (community in communities) {
            val reply = snmpGet(addr, port, community)
            if (reply != null) {
                hit = true
                val descr = extractString(reply)
                emit(ScanEvent.Line("[+] '$community' VALID  ${descr?.let { "-> $it" } ?: ""}", LineStream.STDERR))
                emit(ScanEvent.FindingFound(Finding(tool.id, "SNMP community: $community",
                    descr ?: "responded", Severity.HIGH)))
            } else {
                emit(ScanEvent.Line("[-] '$community' no response", LineStream.STDOUT))
            }
        }
        if (!hit) emit(ScanEvent.Line("No community string responded (SNMP closed or filtered).", LineStream.SYSTEM))
        emit(ScanEvent.Completed(0, System.currentTimeMillis() - start))
    }.flowOn(Dispatchers.IO)

    private fun snmpGet(addr: InetAddress, port: Int, community: String): ByteArray? {
        return try {
            val packet = buildGetRequest(community)
            DatagramSocket().use { sock ->
                sock.soTimeout = 2500
                sock.send(DatagramPacket(packet, packet.size, addr, port))
                val buf = ByteArray(2048)
                val resp = DatagramPacket(buf, buf.size)
                sock.receive(resp)
                buf.copyOf(resp.length)
            }
        } catch (_: Exception) { null }
    }

    private fun tlv(tag: Int, value: ByteArray): ByteArray {
        // short-form length only (sufficient for our small packets)
        return byteArrayOf(tag.toByte(), value.size.toByte()) + value
    }

    private fun buildGetRequest(community: String): ByteArray {
        val version = tlv(0x02, byteArrayOf(0x00))                        // INTEGER 0 (v1)
        val comm = tlv(0x04, community.toByteArray(Charsets.US_ASCII))    // OCTET STRING
        val reqId = tlv(0x02, byteArrayOf(0x13, 0x37))                    // request id
        val errStatus = tlv(0x02, byteArrayOf(0x00))
        val errIndex = tlv(0x02, byteArrayOf(0x00))
        val oid = tlv(0x06, sysDescrOid)
        val nullVal = byteArrayOf(0x05, 0x00)
        val varbind = tlv(0x30, oid + nullVal)
        val varbindList = tlv(0x30, varbind)
        val pdu = tlv(0xA0, reqId + errStatus + errIndex + varbindList)   // GetRequest PDU
        return tlv(0x30, version + comm + pdu)                            // top SEQUENCE
    }

    /** Pulls the first reasonably-long printable OCTET STRING (sysDescr) out of the reply. */
    private fun extractString(data: ByteArray): String? {
        var i = 0
        while (i < data.size - 2) {
            if (data[i].toInt() and 0xff == 0x04) {
                val len = data[i + 1].toInt() and 0xff
                if (len in 4..255 && i + 2 + len <= data.size) {
                    val s = String(data, i + 2, len, Charsets.ISO_8859_1)
                    if (s.count { it.isLetterOrDigit() || it == ' ' } >= len / 2) return s.trim()
                }
            }
            i++
        }
        return null
    }
}

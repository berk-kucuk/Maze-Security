package com.maze.security.domain.model

/**
 * Configuration for a single scan run. Fields are shared across tools; each
 * scanner reads only the ones relevant to it. Sensible defaults keep the UI simple.
 */
data class ScanConfig(
    // Port scan / nmap
    val portRange: String = "1-1024",
    val nmapServiceDetection: Boolean = true,
    val nmapDefaultScripts: Boolean = false,   // -sC
    val nmapFastScan: Boolean = false,         // -F (top 100 ports)
    val nmapOsGuess: Boolean = false,
    val nmapTiming: Int = 4,               // -T0..-T5
    // Info gathering toggles
    val doDns: Boolean = true,
    val doReverseDns: Boolean = true,
    val doHttpHeaders: Boolean = true,
    val doTlsInfo: Boolean = true,
    val doBanner: Boolean = true,
    // Brute force (hydra / medusa)
    val service: BruteService = BruteService.SSH,
    val port: Int? = null,                 // null -> service default
    val singleUsername: String = "",       // used when userlistPath is null
    val userlistPath: String? = null,
    val passwordListPath: String? = null,
    val stopOnFirst: Boolean = true,
    // Path/subdomain wordlist (Directory Scanner, Subdomain Enumeration)
    val wordlistPath: String? = null,
    // Shared
    val threads: Int = 16,
    val timeoutMs: Long = 4000,
    val extraArgs: String = ""
)

enum class BruteService(val label: String, val defaultPort: Int, val hydraModule: String) {
    SSH("SSH", 22, "ssh"),
    FTP("FTP", 21, "ftp"),
    HTTP_GET("HTTP Basic (GET)", 80, "http-get"),
    HTTP_POST_FORM("HTTP Form (POST)", 80, "http-post-form"),
    MYSQL("MySQL", 3306, "mysql"),
    POSTGRES("PostgreSQL", 5432, "postgres"),
    SMB("SMB", 445, "smb"),
    RDP("RDP", 3389, "rdp"),
    TELNET("Telnet", 23, "telnet")
}

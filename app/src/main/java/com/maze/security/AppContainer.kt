package com.maze.security

import android.content.Context
import com.maze.security.data.history.TargetHistoryRepository
import com.maze.security.data.prefs.SettingsRepository
import com.maze.security.data.wordlist.WordlistManager
import com.maze.security.domain.model.ToolType
import com.maze.security.domain.scanner.CookieScanner
import com.maze.security.domain.scanner.CorsScanner
import com.maze.security.domain.scanner.CveLookupScanner
import com.maze.security.domain.scanner.DirScanScanner
import com.maze.security.domain.scanner.DnsRecordsScanner
import com.maze.security.domain.scanner.DnsblScanner
import com.maze.security.domain.scanner.EncoderScanner
import com.maze.security.domain.scanner.FaviconHashScanner
import com.maze.security.domain.scanner.GeoIpScanner
import com.maze.security.domain.scanner.HarvesterScanner
import com.maze.security.domain.scanner.HashScanner
import com.maze.security.domain.scanner.HibpScanner
import com.maze.security.domain.scanner.HttpHeadersScanner
import com.maze.security.domain.scanner.HttpMethodsScanner
import com.maze.security.domain.scanner.HydraScanner
import com.maze.security.domain.scanner.InfoGatheringScanner
import com.maze.security.domain.scanner.JwtScanner
import com.maze.security.domain.scanner.MailSecurityScanner
import com.maze.security.domain.scanner.MedusaScanner
import com.maze.security.domain.scanner.NmapScanner
import com.maze.security.domain.scanner.PasswordAnalyzerScanner
import com.maze.security.domain.scanner.ReverseIpScanner
import com.maze.security.domain.scanner.SmtpRelayScanner
import com.maze.security.domain.scanner.SnmpScanner
import com.maze.security.domain.scanner.SslTlsScanner
import com.maze.security.domain.scanner.SubdomainScanner
import com.maze.security.domain.scanner.SubdomainTakeoverScanner
import com.maze.security.domain.scanner.TechDetectScanner
import com.maze.security.domain.scanner.WafDetectScanner
import com.maze.security.domain.scanner.WaybackScanner
import com.maze.security.domain.scanner.WhoisScanner
import com.maze.security.domain.scanner.WordPressScanner
import com.maze.security.domain.scanner.ZoneTransferScanner
import com.maze.security.domain.scanner.ScannerEngine
import com.maze.security.native.NativeBinaries
import com.maze.security.native.ProcessRunner

/** Manual dependency container held by the Application. Keeps the app Hilt-free. */
class AppContainer(context: Context) {

    val settings = SettingsRepository(context)
    val history = TargetHistoryRepository(context)
    val wordlists = WordlistManager(context)

    private val binaries = NativeBinaries(context)
    private val runner = ProcessRunner()

    private val engines: Map<ToolType, ScannerEngine> = mapOf(
        ToolType.INFO_GATHERING to InfoGatheringScanner(),
        ToolType.WHOIS to WhoisScanner(),
        ToolType.DNS_RECORDS to DnsRecordsScanner(),
        ToolType.SUBDOMAINS to SubdomainScanner(),
        ToolType.GEOIP to GeoIpScanner(),
        ToolType.REVERSE_IP to ReverseIpScanner(),
        ToolType.WAYBACK to WaybackScanner(),
        ToolType.HARVESTER to HarvesterScanner(),
        ToolType.HTTP_HEADERS to HttpHeadersScanner(),
        ToolType.TECH_DETECT to TechDetectScanner(),
        ToolType.DIR_SCAN to DirScanScanner(),
        ToolType.SSL_TLS to SslTlsScanner(),
        ToolType.WAF_DETECT to WafDetectScanner(),
        ToolType.CORS to CorsScanner(),
        ToolType.HTTP_METHODS to HttpMethodsScanner(),
        ToolType.COOKIES to CookieScanner(),
        ToolType.WORDPRESS to WordPressScanner(),
        ToolType.TAKEOVER to SubdomainTakeoverScanner(),
        ToolType.FAVICON to FaviconHashScanner(),
        ToolType.MAIL_SEC to MailSecurityScanner(),
        ToolType.DNSBL to DnsblScanner(),
        ToolType.ZONE_TRANSFER to ZoneTransferScanner(),
        ToolType.NMAP to NmapScanner(binaries, runner),
        ToolType.CVE_LOOKUP to CveLookupScanner(),
        ToolType.SMTP_RELAY to SmtpRelayScanner(),
        ToolType.SNMP to SnmpScanner(),
        ToolType.HYDRA to HydraScanner(binaries, runner),
        ToolType.MEDUSA to MedusaScanner(binaries, runner),
        ToolType.HASH to HashScanner(),
        ToolType.ENCODER to EncoderScanner(),
        ToolType.PASSWORD_ANALYZER to PasswordAnalyzerScanner(),
        ToolType.JWT to JwtScanner(),
        ToolType.HIBP to HibpScanner()
    )

    fun scannerFor(tool: ToolType): ScannerEngine = engines.getValue(tool)

    fun isToolAvailable(tool: ToolType): Boolean = engines.getValue(tool).isAvailable()
}

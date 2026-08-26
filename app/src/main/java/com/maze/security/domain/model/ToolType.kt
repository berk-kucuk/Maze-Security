package com.maze.security.domain.model

/** Broad grouping used for the dashboard filter chips. */
enum class ToolCategory(val label: String) {
    ALL("All"), RECON("Recon"), WEB("Web"), MAIL_DNS("Mail/DNS"),
    NETWORK("Network"), BRUTE("Brute"), UTIL("Utility")
}

/** What the tool expects the user to enter as its target/input. */
enum class InputKind { HOST, TEXT, PASSWORD }

/** The scanning tools exposed on the dashboard. */
enum class ToolType(
    val id: String,
    val title: String,
    val subtitle: String,
    val category: ToolCategory,
    val requiresBinary: Boolean = false,
    val requiresWordlist: Boolean = false,
    val input: InputKind = InputKind.HOST
) {
    // ---- Recon ----
    INFO_GATHERING("info", "Information Gathering", "DNS, reverse DNS, HTTP, TLS, banners", ToolCategory.RECON),
    WHOIS("whois", "WHOIS Lookup", "Registration, registrar, dates (IANA chain)", ToolCategory.RECON),
    DNS_RECORDS("dns", "DNS Records", "A/AAAA/MX/NS/TXT/CNAME/SOA/CAA via DoH", ToolCategory.RECON),
    SUBDOMAINS("subdomains", "Subdomain Enumeration", "crt.sh + DNS brute", ToolCategory.RECON),
    GEOIP("geoip", "GeoIP & ASN", "Geolocation, ISP, ASN, organisation", ToolCategory.RECON),
    REVERSE_IP("revip", "Reverse IP", "Other domains sharing the IP", ToolCategory.RECON),
    WAYBACK("wayback", "Wayback URLs", "Archived URLs from the Wayback Machine", ToolCategory.RECON),
    HARVESTER("harvester", "Email & Link Harvester", "Collect emails and links from a page", ToolCategory.RECON),

    // ---- Web ----
    HTTP_HEADERS("headers", "HTTP Security Headers", "HSTS/CSP audit + info leaks", ToolCategory.WEB),
    TECH_DETECT("tech", "Tech / CMS Detection", "Server, framework, WordPress fingerprint", ToolCategory.WEB),
    DIR_SCAN("dirscan", "Directory Scanner", "Common paths & sensitive files (soft-404 aware)", ToolCategory.WEB),
    SSL_TLS("ssltls", "SSL/TLS Deep Scan", "Protocols, ciphers, weak config, cert chain", ToolCategory.WEB),
    WAF_DETECT("waf", "WAF Detection", "Cloudflare/Akamai/Imperva fingerprint", ToolCategory.WEB),
    CORS("cors", "CORS Misconfiguration", "Reflective / wildcard ACAO test", ToolCategory.WEB),
    HTTP_METHODS("methods", "HTTP Methods", "OPTIONS/PUT/DELETE/TRACE test", ToolCategory.WEB),
    COOKIES("cookies", "Cookie Security", "Secure / HttpOnly / SameSite audit", ToolCategory.WEB),
    WORDPRESS("wpscan", "WordPress Scanner", "Users, version, xmlrpc, endpoints", ToolCategory.WEB),
    TAKEOVER("takeover", "Subdomain Takeover", "Dangling CNAME fingerprint check", ToolCategory.WEB),
    FAVICON("favicon", "Favicon Hash", "Shodan-style favicon fingerprint", ToolCategory.WEB),

    // ---- Mail / DNS ----
    MAIL_SEC("mailsec", "Mail Security (SPF/DMARC/DKIM)", "Analyse email auth records", ToolCategory.MAIL_DNS),
    DNSBL("dnsbl", "DNSBL / Blacklist", "Check IP against spam blocklists", ToolCategory.MAIL_DNS),
    ZONE_TRANSFER("axfr", "Zone Transfer (AXFR)", "Test nameservers for open AXFR", ToolCategory.MAIL_DNS),

    // ---- Network / Service ----
    NMAP("nmap", "Nmap", "Connect scan (-sT) + service detection", ToolCategory.NETWORK, requiresBinary = true),
    CVE_LOOKUP("cve", "CVE Lookup", "Search known CVEs by product/keyword", ToolCategory.NETWORK, input = InputKind.TEXT),
    SMTP_RELAY("smtp", "SMTP Relay Test", "Banner, VRFY, open-relay check", ToolCategory.NETWORK),
    SNMP("snmp", "SNMP Community Check", "Try common community strings (UDP)", ToolCategory.NETWORK),

    // ---- Brute ----
    HYDRA("hydra", "Hydra", "Parallel login brute-force", ToolCategory.BRUTE, requiresBinary = true, requiresWordlist = true),
    MEDUSA("medusa", "Medusa", "Modular brute-force (alt engine)", ToolCategory.BRUTE, requiresBinary = true, requiresWordlist = true),

    // ---- Utility (offline) ----
    HASH("hash", "Hash Generator", "MD5/SHA1/SHA256/SHA512 of input", ToolCategory.UTIL, input = InputKind.TEXT),
    ENCODER("encoder", "Encode / Decode", "Base64, Hex, URL both ways", ToolCategory.UTIL, input = InputKind.TEXT),
    PASSWORD_ANALYZER("pwcheck", "Password Analyzer", "Entropy, charset, crack-time estimate", ToolCategory.UTIL, input = InputKind.PASSWORD),
    JWT("jwt", "JWT Decoder", "Decode & audit a JSON Web Token", ToolCategory.UTIL, input = InputKind.TEXT),
    HIBP("hibp", "Have I Been Pwned", "Password breach check (k-anonymity)", ToolCategory.UTIL, input = InputKind.PASSWORD);

    companion object {
        fun fromId(id: String): ToolType = entries.first { it.id == id }
    }
}

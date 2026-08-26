<p align="center">
  <img src="assets/logo.png" alt="Maze Security" width="170" />
</p>

<h1 align="center">Maze Security</h1>

<p align="center">
  <b>A root-free mobile penetration-testing toolkit for Android.</b><br/>
  33 recon, web, network, brute-force and offline tools in one app — no root, no Termux, no setup.
</p>

<p align="center">
  <img src="https://img.shields.io/badge/platform-Android%208.0%2B-3DDC84?logo=android&logoColor=white" alt="platform" />
  <img src="https://img.shields.io/badge/Kotlin-2.0.21-7F52FF?logo=kotlin&logoColor=white" alt="kotlin" />
  <img src="https://img.shields.io/badge/UI-Jetpack%20Compose-4285F4?logo=jetpackcompose&logoColor=white" alt="compose" />
  <img src="https://img.shields.io/badge/root-not%20required-00E676" alt="no root" />
  <img src="https://img.shields.io/badge/tools-33-00E5FF" alt="tools" />
</p>

---

> **Legal notice.** Maze Security is for **authorised security testing and education only**.
> Run it exclusively against systems you own or have **explicit written permission** to test.
> Unauthorised scanning, brute-forcing or probing is illegal in most jurisdictions and is entirely
> your responsibility. The app shows a consent gate on first launch for this reason.

---

## Highlights

- **100% root-free.** Kotlin scanners use ordinary sockets/HTTP; the bundled binaries run from
  `nativeLibraryDir` using unprivileged flags only (`nmap -sT`, never `-sS`).
- **33 tools** across Recon, Web, Mail/DNS, Network, Brute-force and offline Utilities — filterable
  by category on the dashboard.
- **Real binaries.** Genuine **nmap 7.95**, **hydra 9.5** and **medusa 2.3** cross-compiled for
  Android with the NDK and shipped inside the APK.
- **One target box.** Type an IP, domain, URL — or plain text for the offline tools — and go.
- **Live terminal.** Streaming output, progress bars, structured findings, and a shareable report.
- **OLED & White themes** (plus follow-system). True-black AMOLED palette with a terminal-green accent.
- **Selectable + importable wordlists** for the directory, subdomain and brute-force tools, with an
  in-app wordlist viewer.

## Tool catalogue

Type legend: **K** = pure Kotlin (no binary) · **B** = bundled native binary · **A** = uses a public API

### Recon
| Tool | What it does | Type |
|------|--------------|:----:|
| Information Gathering | DNS, reverse DNS, HTTP headers, TLS certificate, banner grabbing | K |
| WHOIS Lookup | Registration data via the IANA -> registry -> registrar referral chain (gTLD & ccTLD) | K |
| DNS Records | A / AAAA / MX / NS / TXT / CNAME / SOA / CAA over DNS-over-HTTPS | K, A |
| Subdomain Enumeration | Certificate-transparency (crt.sh) plus a selectable DNS-brute wordlist, parallelised | K, A |
| GeoIP & ASN | Geolocation, ISP, ASN, organisation, hosting/proxy flags | K, A |
| Reverse IP | Other domains sharing the same IP | K, A |
| Wayback URLs | Archived URLs from the Wayback Machine CDX API | K, A |
| Email & Link Harvester | Scrapes emails and links from the target's pages | K |

### Web
| Tool | What it does | Type |
|------|--------------|:----:|
| HTTP Security Headers | Audits HSTS/CSP/X-Frame/…; flags info-leaking headers | K |
| Tech / CMS Detection | Fingerprints server, framework and CMS (WordPress, Drupal, Next.js, React…) | K |
| Directory Scanner | Probes a selectable path wordlist with soft-404 / catch-all detection | K |
| SSL/TLS Deep Scan | Supported protocols (SSLv3 -> TLS 1.3), cipher suites, weak-config & cert checks | K |
| WAF Detection | Fingerprints Cloudflare/Akamai/Imperva/F5/… plus a block-behaviour probe | K |
| CORS Misconfiguration | Reflective / wildcard `Access-Control-Allow-Origin` + credentials test | K |
| HTTP Methods | Enumerates allowed methods, flags PUT/DELETE/TRACE | K |
| Cookie Security | `Secure` / `HttpOnly` / `SameSite` audit | K |
| WordPress Scanner | User enumeration (REST + `?author=`), version, xmlrpc | K |
| Subdomain Takeover | Dangling-CNAME fingerprints (GitHub Pages, S3, Heroku, Azure…) | K, A |
| Favicon Hash | Shodan-style MurmurHash3 (`http.favicon.hash`) + MD5 fingerprint | K |

### Mail & DNS
| Tool | What it does | Type |
|------|--------------|:----:|
| Mail Security | SPF, DMARC and DKIM record analysis with policy weaknesses | K, A |
| DNSBL / Blacklist | Checks an IP against 8 spam blocklists | K, A |
| Zone Transfer (AXFR) | Raw DNS AXFR against each nameserver to detect open transfers | K |

### Network & Service
| Tool | What it does | Type |
|------|--------------|:----:|
| Nmap | `-sT -Pn` connect scan with `-sV` service/version detection, live progress | B |
| CVE Lookup | Searches the NVD for known CVEs by product/keyword (with CVSS) | K, A |
| SMTP Relay Test | Banner, `VRFY`, and open-relay check | K |
| SNMP Community Check | Tries common community strings with a raw SNMPv1 GET over UDP | K |

### Brute-force
| Tool | What it does | Type |
|------|--------------|:----:|
| Hydra | Parallel login brute-force (ssh, ftp, http, telnet, …) | B |
| Medusa | Modular brute-force engine (ssh, ftp, http, web-form, telnet, mysql, smb) | B |

### Utility (offline — type the input as the target)
| Tool | What it does | Type |
|------|--------------|:----:|
| Hash Generator | MD5 / SHA-1 / SHA-256 / SHA-512 of the input + hash-type identification | K |
| Encode / Decode | Base64, Hex and URL, both directions | K |
| Password Analyzer | Entropy, character-set, and offline crack-time estimate | K |
| JWT Decoder | Decodes header/payload and audits (`alg=none`, unsigned, expiry) | K |
| Have I Been Pwned | Password breach check via the k-anonymity range API — the password never leaves the device | K, A |

## Wordlists

Directory, Subdomain and brute-force tools use selectable wordlists. The app bundles path,
subdomain, password and username lists, groups them by purpose, and lets you import your own `.txt`
files (SecLists, dirb, rockyou, …). A built-in viewer shows any list's contents with a filter box.

## Architecture

```
app/                                Android app (Kotlin + Jetpack Compose)
├── ui/                             screens, theme (OLED/White), navigation
├── domain/
│   ├── model/                      Target, ScanConfig, ScanEvent, Finding, ToolType…
│   └── scanner/                    ScannerEngine + 33 implementations (+ ReconHttp helper)
├── data/                           DataStore prefs, target history, wordlists
└── native/                         binary resolution + ProcessBuilder runner
native-tools/                       NDK cross-compilation of nmap / hydra / medusa
```

Every tool implements a single interface and streams its output as a `Flow`:

```kotlin
interface ScannerEngine {
    val tool: ToolType
    fun isAvailable(): Boolean = true
    fun run(target: Target, config: ScanConfig): Flow<ScanEvent>   // Line | Progress | Finding | Completed | Failed
}
```

An activity-scoped `SessionViewModel` holds the target, selected tool, config and live scan state, so
scans survive navigation. Dependencies are wired manually in `AppContainer` (no Hilt).

### Why no root

- **Kotlin scanners** use `Socket` / `HttpURLConnection` / DNS-over-HTTPS — nothing privileged.
- **Native binaries** ship as `jniLibs/<abi>/lib*.so`, so the OS extracts them into
  `nativeLibraryDir` — the one app-owned location Android 10+ lets you `exec` — with
  `extractNativeLibs=true`. They run with unprivileged flags only (nmap connect scan; hydra/medusa are
  plain TCP clients). Medusa's `dlopen` plugins ship the same way (`lib<name>_mod.so`).

## Building

**Requirements:** JDK 17+, Android SDK (compileSdk 35). For the native binaries: Android NDK r26+,
plus `make`, `cmake`, `autoconf/automake`, `flex`, `bison`.

```bash
# 1) Build the app. Kotlin tools work immediately; the binary tools show
#    "BINARY MISSING" until step 2 is run.
./gradlew :app:assembleDebug

# 2) Cross-compile nmap / hydra / medusa for Android (see native-tools/README.md)
export ANDROID_NDK_HOME=$HOME/Android/Sdk/ndk/27.2.12479018
cd native-tools && ./build.sh          # arm64-v8a (add more: ABIS="arm64-v8a x86_64" ./build.sh)
cd .. && ./gradlew :app:assembleDebug   # re-package with the binaries

# install
adb install app/build/outputs/apk/debug/app-debug.apk
```

The native build produces self-contained binaries (only `libc`/`libm`/`libdl` — present on every
device). See [`native-tools/README.md`](native-tools/README.md) for the full dependency chain
(zlib, OpenSSL, pcre2, libssh, libssh2) and the Android-specific fixes applied.

### Signed release build

Create a keystore and a `keystore.properties` in the project root (both are git-ignored), then:

```bash
./gradlew :app:assembleRelease   # -> app/build/outputs/apk/release/app-release.apk
```

`keystore.properties` format:

```
storeFile=../keystore/maze-release.jks
storePassword=...
keyAlias=...
keyPassword=...
```

Keep the keystore and passwords private and backed up — the same key is required to sign every update.

## Toolchain

| | Version |
|---|---|
| AGP | 8.7.3 |
| Gradle | 8.9 |
| Kotlin | 2.0.21 |
| Compose BOM | 2024.10.01 |
| compileSdk / targetSdk | 35 |
| minSdk | 26 (Android 8.0) |
| NDK | 27.2.12479018 |
| nmap / hydra / medusa | 7.95 / 9.5 / 2.3 |

## Bundled binary ABIs

Native tools are built for **arm64-v8a** (all modern devices). Build the other ABIs with
`ABIS="arm64-v8a armeabi-v7a x86_64" ./build.sh` if you need them; on an unsupported ABI the binary
tools simply show a *BINARY MISSING* badge while the Kotlin tools keep working.

## Out of scope

By design Maze Security **does not** include offensive-only capabilities such as denial-of-service,
persistent web shells / backdoors, or phishing/website-cloning tools. It focuses on reconnaissance,
assessment and authorised credential testing.

## License & disclaimer

Provided **as-is, for educational and authorised testing purposes only**. The authors accept no
liability for misuse or for any damage caused by this software. By using it you agree to comply with
all applicable laws and to test only systems you are authorised to assess.

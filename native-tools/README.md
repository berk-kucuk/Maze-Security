# native-tools

Cross-compiles the bundled pentest binaries for Android and drops them into
`app/src/main/jniLibs/<abi>/lib<tool>.so`.

## Why `lib*.so`?

Android 10+ forbids executing files from an app's `filesDir`. The only app-owned
directory we may `exec` from is `nativeLibraryDir`, which the OS populates from
`jniLibs/<abi>/`. Files there must be named `lib*.so` and the manifest must set
`android:extractNativeLibs="true"` (already configured). At runtime the app calls
`ProcessBuilder(nativeLibraryDir + "/libnmap.so", ...)`.

None of the tools need root: nmap uses `-sT` (connect scan), and hydra/medusa
are ordinary TCP clients.

## Build

```bash
export ANDROID_NDK_HOME=$HOME/Android/Sdk/ndk/27.2.12479018
cd native-tools
./build.sh                       # arm64-v8a, all tools
ABIS="arm64-v8a x86_64" ./build.sh
TOOLS="nmap" ./build.sh          # subset
```

Host requirements: Linux x86_64, Android NDK r26+, `make`, `cmake`,
`autoconf/automake` (for medusa), `curl`, `tar`, `bzip2`, `xz`.

## Components

| Component | Version | Purpose |
|-----------|---------|---------|
| pcre2     | 10.44   | nmap + hydra regex |
| zlib      | 1.3.1   | compression dep |
| OpenSSL   | 3.0.15  | TLS/crypto for all tools |
| libssh2   | 1.11.0  | medusa SSH module |
| libssh    | 0.11.1  | hydra SSH module |
| nmap      | 7.95    | connect scan + service detection |
| hydra     | 9.5     | login brute-force |
| medusa    | 2.3     | login brute-force (alt engine) |

## Notes / caveats

* nmap data files (`nmap-services`, `nmap-service-probes`, NSE scripts) are
  copied to `app/src/main/assets/nmap-data/` and shipped in the APK; the app
  copies them to `filesDir` at first run and passes `--datadir`.
* hydra's `configure` is bespoke; if a protocol module is missing, install its
  dev headers into the ABI prefix (`work/out/<abi>`) and rebuild. SSH is the
  primary module and is covered by libssh.
* After building, rebuild the app: `./gradlew :app:assembleDebug`. The new
  binaries are picked up automatically from `jniLibs`.
* To verify a binary loads on-device:
  `adb shell run-as com.maze.security ./lib/arm64/libnmap.so --version` (debug).


## Android cross-compile fixes applied

These are handled automatically by `build.sh`; documented here for maintenance:

* **Self-contained binaries** — nmap links `-static-libstdc++`; all three depend
  only on `libc`/`libm`/`libdl` (always present on Android). No co-shipped `.so`.
* **exec + LD_LIBRARY_PATH** — scanners run the binary from `nativeLibraryDir`
  and set `LD_LIBRARY_PATH` to it as a safety net.
* **nmap** — external pcre2 (`--with-libpcre`), bundled libpcap kept (connect
  scan needs it only at build time, not root at runtime).
* **medusa** — bionic has no separate `libpthread` (empty stub archive added), no
  `pthread_cancel` / `PTHREAD_CANCEL_*` / `pthread_attr_*inheritsched` at API 26
  (force-included compat shim), and uses BSD `index()`/`rindex()` (mapped to
  `strchr`/`strrchr`); configure's hardcoded `-I/usr/include` is stripped.
* **hydra** — its bespoke configure scans host lib dirs and would pull in
  host-installed optional libs (libidn, gcrypt, freerdp, postgres, mysql...) whose
  headers break the NDK build; `LIBDIRS`/`INCDIRS` are pinned to the cross prefix
  so only ssh/ssl/zlib/pcre2 modules build. Enabled modules include ssh, ftp,
  http(s), telnet, and other pure-network protocols.
* **Runtime fixes (found via on-device testing):**
  * hydra aborts under bionic **fdsan** when it closes a FILE*-owned fd — an
    `libtoolshim.so` (built here) is `LD_PRELOAD`ed to disable fdsan per process.
  * nmap `-sV` initialises NSE (version scripts), so the full `nselib/` is shipped
    in assets alongside `nse_main.lua`/`scripts/`.
  * medusa hard-failed on the OpenSSL 3 **legacy provider** (a separate module we
    do not ship); its load is patched to be non-fatal (default provider covers
    ssh/ftp/http).

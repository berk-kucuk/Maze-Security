#!/usr/bin/env bash
###############################################################################
# Maze Security — native tool build system
#
# Cross-compiles the bundled pentest binaries (nmap, hydra, medusa) and their
# dependencies (zlib, OpenSSL, libssh2, libssh) for Android using the NDK, then
# copies them into app/src/main/jniLibs/<abi>/lib<tool>.so so the app can exec
# them from nativeLibraryDir without root.
#
# Usage:
#   ./build.sh [abi ...]         # default: arm64-v8a
#   ABIS="arm64-v8a x86_64" ./build.sh
#   TOOLS="nmap" ./build.sh      # build a subset
#
# Requirements: Android NDK (ANDROID_NDK_HOME or SDK default), make, cmake,
#               autoconf, curl/wget, tar. Runs on Linux x86_64 hosts.
###############################################################################
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
WORK="$HERE/work"
SRC="$WORK/src"
OUT="$WORK/out"          # per-abi install prefixes
JNI="$ROOT/app/src/main/jniLibs"
ASSET_NMAP="$ROOT/app/src/main/assets/nmap-data"

API=26
ABIS="${ABIS:-${*:-arm64-v8a}}"
TOOLS="${TOOLS:-nmap hydra medusa}"

# ---- versions ----
ZLIB_V=1.3.1
OPENSSL_V=3.0.15
LIBSSH2_V=1.11.0
LIBSSH_V=0.11.1
PCRE2_V=10.44
NMAP_V=7.95
HYDRA_V=9.5
MEDUSA_V=2.3
LIBIDN_V=1.42

# ---- locate NDK ----
NDK="${ANDROID_NDK_HOME:-${ANDROID_NDK_ROOT:-}}"
if [ -z "$NDK" ]; then
  local_sdk="${ANDROID_HOME:-$HOME/Android/Sdk}"
  NDK="$(ls -d "$local_sdk"/ndk/* 2>/dev/null | sort -V | tail -1 || true)"
fi
[ -n "$NDK" ] && [ -d "$NDK" ] || { echo "ERROR: NDK not found. Set ANDROID_NDK_HOME."; exit 1; }
TOOLCHAIN="$NDK/toolchains/llvm/prebuilt/linux-x86_64"
export PATH="$TOOLCHAIN/bin:$PATH"
echo ">> NDK: $NDK"

mkdir -p "$SRC" "$OUT"

# Map Android ABI -> clang target triple / cmake abi
triple_for() {
  case "$1" in
    arm64-v8a)     echo "aarch64-linux-android" ;;
    armeabi-v7a)   echo "armv7a-linux-androideabi" ;;
    x86_64)        echo "x86_64-linux-android" ;;
    x86)           echo "i686-linux-android" ;;
    *) echo "unknown"; return 1 ;;
  esac
}
# OpenSSL Configure target
openssl_target_for() {
  case "$1" in
    arm64-v8a)   echo "android-arm64" ;;
    armeabi-v7a) echo "android-arm" ;;
    x86_64)      echo "android-x86_64" ;;
    x86)         echo "android-x86" ;;
  esac
}

fetch() {  # fetch <url> <outfile>
  local url="$1" out="$SRC/$2"
  [ -s "$out" ] && { echo "   cached $2"; return; }
  echo "   downloading $2"
  if ! curl -fSL --retry 3 -o "$out" "$url"; then
    rm -f "$out"
    echo "ERROR: download failed: $url"; return 1
  fi
  [ -s "$out" ] || { echo "ERROR: empty download: $url"; return 1; }
}

setup_env() {  # setup_env <abi>
  local abi="$1"
  TRIPLE="$(triple_for "$abi")"
  export AR="$TOOLCHAIN/bin/llvm-ar"
  export RANLIB="$TOOLCHAIN/bin/llvm-ranlib"
  export STRIP="$TOOLCHAIN/bin/llvm-strip"
  export CC="$TOOLCHAIN/bin/${TRIPLE}${API}-clang"
  export CXX="$TOOLCHAIN/bin/${TRIPLE}${API}-clang++"
  export LD="$TOOLCHAIN/bin/ld"
  export PREFIX="$OUT/$abi"
  mkdir -p "$PREFIX"
  export CFLAGS="-fPIC -Os -I$PREFIX/include"
  export LDFLAGS="-L$PREFIX/lib -pie"
  export CPPFLAGS="-I$PREFIX/include"
  export PKG_CONFIG_PATH="$PREFIX/lib/pkgconfig"
  # bionic keeps pthread/rt inside libc; provide empty stub archives so build
  # systems that link -lpthread / -lrt resolve them.
  local empty="$PREFIX/.empty.c"; echo "" > "$empty"
  for lib in pthread rt; do
    if [ ! -f "$PREFIX/lib/lib$lib.a" ]; then
      "$CC" -c "$empty" -o "$PREFIX/lib/.empty_$lib.o"
      "$AR" rcs "$PREFIX/lib/lib$lib.a" "$PREFIX/lib/.empty_$lib.o"
    fi
  done
}

###############################################################################
# Dependency builds (per ABI, installed into $PREFIX)
###############################################################################

build_zlib() {
  local abi="$1"; setup_env "$abi"
  [ -f "$PREFIX/lib/libz.a" ] && { echo "   zlib present"; return; }
  fetch "https://github.com/madler/zlib/releases/download/v$ZLIB_V/zlib-$ZLIB_V.tar.gz" "zlib-$ZLIB_V.tar.gz"
  local d="$WORK/$abi/zlib-$ZLIB_V"; rm -rf "$d"; mkdir -p "$WORK/$abi"
  tar -xf "$SRC/zlib-$ZLIB_V.tar.gz" -C "$WORK/$abi"
  ( cd "$d"
    CHOST="$(triple_for "$abi")" ./configure --static --prefix="$PREFIX"
    make -j"$(nproc)"; make install )
  echo "   zlib built"
}

build_openssl() {
  local abi="$1"; setup_env "$abi"
  [ -f "$PREFIX/lib/libssl.a" ] && { echo "   openssl present"; return; }
  fetch "https://github.com/openssl/openssl/releases/download/openssl-$OPENSSL_V/openssl-$OPENSSL_V.tar.gz" "openssl-$OPENSSL_V.tar.gz"
  local d="$WORK/$abi/openssl-$OPENSSL_V"; rm -rf "$d"
  tar -xf "$SRC/openssl-$OPENSSL_V.tar.gz" -C "$WORK/$abi"
  ( cd "$d"
    export ANDROID_NDK_ROOT="$NDK"
    ./Configure "$(openssl_target_for "$abi")" -D__ANDROID_API__=$API \
        no-shared no-tests --prefix="$PREFIX" --openssldir="$PREFIX/ssl"
    make -j"$(nproc)"; make install_sw )
  echo "   openssl built"
}

build_libssh2() {
  local abi="$1"; setup_env "$abi"
  [ -f "$PREFIX/lib/libssh2.a" ] && { echo "   libssh2 present"; return; }
  fetch "https://github.com/libssh2/libssh2/releases/download/libssh2-$LIBSSH2_V/libssh2-$LIBSSH2_V.tar.gz" "libssh2-$LIBSSH2_V.tar.gz"
  local d="$WORK/$abi/libssh2-$LIBSSH2_V"; rm -rf "$d"
  tar -xf "$SRC/libssh2-$LIBSSH2_V.tar.gz" -C "$WORK/$abi"
  ( cd "$d"
    ./configure --host="$(triple_for "$abi")" --prefix="$PREFIX" \
        --with-crypto=openssl --with-libssl-prefix="$PREFIX" \
        --disable-shared --enable-static
    make -j"$(nproc)"; make install )
  echo "   libssh2 built"
}

build_libidn() {
  local abi="$1"; setup_env "$abi"
  [ -f "$PREFIX/lib/libidn.a" ] && { echo "   libidn present"; return; }
  fetch "https://ftp.gnu.org/gnu/libidn/libidn-$LIBIDN_V.tar.gz" "libidn-$LIBIDN_V.tar.gz"
  local d="$WORK/$abi/libidn-$LIBIDN_V"; rm -rf "$d"
  tar -xf "$SRC/libidn-$LIBIDN_V.tar.gz" -C "$WORK/$abi"
  ( cd "$d"
    ./configure --host="$(triple_for "$abi")" --prefix="$PREFIX" \
        --disable-shared --enable-static --disable-doc --disable-gtk-doc
    # gnulib leaves gl/stdint.h ungenerated on hosts with a usable stdint.h,
    # breaking the idn-int.h rule; pre-create it (rule has no prereqs).
    echo "#include <stdint.h>" > lib/idn-int.h
    make -j"$(nproc)" -C lib; make -C lib install )
  echo "   libidn built"
}

build_libssh() {
  local abi="$1"; setup_env "$abi"
  [ -f "$PREFIX/lib/libssh.a" ] || [ -f "$PREFIX/lib/libssh.so" ] && { echo "   libssh present"; return; }
  fetch "https://www.libssh.org/files/0.11/libssh-$LIBSSH_V.tar.xz" "libssh-$LIBSSH_V.tar.xz"
  local d="$WORK/$abi/libssh-$LIBSSH_V"; rm -rf "$d"
  tar -xf "$SRC/libssh-$LIBSSH_V.tar.xz" -C "$WORK/$abi"
  local b="$d/build"; mkdir -p "$b"
  ( cd "$b"
    cmake .. \
      -DCMAKE_TOOLCHAIN_FILE="$NDK/build/cmake/android.toolchain.cmake" \
      -DCMAKE_POLICY_VERSION_MINIMUM=3.5 \
      -DCMAKE_C_FLAGS="-DS_IWRITE=S_IWUSR -DS_IREAD=S_IRUSR -DS_IEXEC=S_IXUSR" \
      -DANDROID_ABI="$abi" -DANDROID_PLATFORM="android-$API" \
      -DCMAKE_INSTALL_PREFIX="$PREFIX" \
      -DWITH_GSSAPI=OFF -DWITH_ZLIB=ON -DWITH_EXAMPLES=OFF \
      -DBUILD_SHARED_LIBS=OFF \
      -DOPENSSL_ROOT_DIR="$PREFIX" \
      -DOPENSSL_CRYPTO_LIBRARY="$PREFIX/lib/libcrypto.a" \
      -DOPENSSL_SSL_LIBRARY="$PREFIX/lib/libssl.a" \
      -DOPENSSL_INCLUDE_DIR="$PREFIX/include" \
      -DZLIB_LIBRARY="$PREFIX/lib/libz.a" -DZLIB_INCLUDE_DIR="$PREFIX/include"
    make -j"$(nproc)"; make install )
  echo "   libssh built"
}

###############################################################################
# Runtime shim: disable Android fdsan for the exec'd tools
###############################################################################
# Some tools (e.g. hydra) close() a raw fd that bionic's fdsan believes is owned
# by a FILE*, which aborts the process (SIGABRT / exit 134). We LD_PRELOAD a tiny
# library whose constructor disables fdsan for the tool's process only.
build_fdsan_shim() {
  local abi="$1"; setup_env "$abi"
  local src="$WORK/$abi/toolshim.c"
  {
    printf "%s\n" "#include <dlfcn.h>"
    printf "%s\n" "#include <stdint.h>"
    printf "%s\n" "typedef void (*set_fn)(uint32_t);"
    printf "%s\n" "__attribute__((constructor)) static void off(void){"
    printf "%s\n" "  void *f = dlsym((void*)0 /*RTLD_DEFAULT*/, \"android_fdsan_set_error_level\");"
    printf "%s\n" "  if (f) ((set_fn)f)(0u); /* ANDROID_FDSAN_ERROR_LEVEL_DISABLED */"
    printf "%s\n" "}"
  } > "$src"
  "$CC" -shared -fPIC -Os -o "$JNI/$abi/libtoolshim.so" "$src"
  "$STRIP" "$JNI/$abi/libtoolshim.so"
  echo ">> toolshim -> $JNI/$abi/libtoolshim.so"
}

###############################################################################
# Tool builds
###############################################################################

build_pcre2() {
  local abi="$1"; setup_env "$abi"
  [ -f "$PREFIX/lib/libpcre2-8.a" ] && { echo "   pcre2 present"; return; }
  fetch "https://github.com/PCRE2Project/pcre2/releases/download/pcre2-$PCRE2_V/pcre2-$PCRE2_V.tar.gz" "pcre2-$PCRE2_V.tar.gz"
  local d="$WORK/$abi/pcre2-$PCRE2_V"; rm -rf "$d"
  tar -xf "$SRC/pcre2-$PCRE2_V.tar.gz" -C "$WORK/$abi"
  ( cd "$d"
    ./configure --host="$(triple_for "$abi")" --prefix="$PREFIX" \
        --disable-shared --enable-static --enable-pcre2-8
    make -j"$(nproc)"; make install )
  echo "   pcre2 built"
}

build_nmap() {
  local abi="$1"; setup_env "$abi"
  fetch "https://nmap.org/dist/nmap-$NMAP_V.tar.bz2" "nmap-$NMAP_V.tar.bz2"
  local d="$WORK/$abi/nmap-$NMAP_V"; rm -rf "$d"
  tar -xf "$SRC/nmap-$NMAP_V.tar.bz2" -C "$WORK/$abi"
  ( cd "$d"
    # Static link against our OpenSSL; disable features that need root or that
    # -static-libstdc++ makes the binary self-contained (only libc/libm/libdl).
    export LDFLAGS="$LDFLAGS -static-libstdc++"
    ac_cv_func_getpwnam=yes ac_cv_func_getpwuid=yes \
    ./configure --host="$(triple_for "$abi")" \
        --with-openssl="$PREFIX" --with-libz="$PREFIX" \
        --without-ndiff --without-zenmap --without-nping \
        --with-libpcre="$PREFIX" --with-liblua=included \
        --enable-static LIBS="-lssl -lcrypto -lz"
    make -j"$(nproc)" nmap
    "$STRIP" nmap )
  install -Dm755 "$d/nmap" "$JNI/$abi/libnmap.so"
  # ship data files (only once; ABI-independent)
  if [ ! -f "$ASSET_NMAP/nmap-services" ]; then
    for f in nmap-services nmap-service-probes nmap-protocols nmap-rpc nmap-mac-prefixes; do
      [ -f "$d/$f" ] && cp "$d/$f" "$ASSET_NMAP/"
    done
    [ -d "$d/scripts" ] && cp -r "$d/scripts" "$ASSET_NMAP/" || true
    [ -d "$d/nselib" ] && cp -r "$d/nselib" "$ASSET_NMAP/" || true
    [ -f "$d/nse_main.lua" ] && cp "$d/nse_main.lua" "$ASSET_NMAP/" || true
  fi
  echo ">> nmap -> $JNI/$abi/libnmap.so"
}

build_hydra() {
  local abi="$1"; setup_env "$abi"
  fetch "https://github.com/vanhauser-thc/thc-hydra/archive/refs/tags/v$HYDRA_V.tar.gz" "hydra-$HYDRA_V.tar.gz"
  local d="$WORK/$abi/thc-hydra-$HYDRA_V"; rm -rf "$d"
  tar -xf "$SRC/hydra-$HYDRA_V.tar.gz" -C "$WORK/$abi"

  # hydra's configure would detect the HOST's libidn and define -DLIBIDN, after
  # which sasl.h pulls host stringprep.h that the NDK cross build cannot see.
  # Disable the libidn probe entirely; the ssh/ftp/http/telnet modules we expose
  # do not need SASL/stringprep.
  # Constrain hydra's library/header search to our cross prefix only, so it can
  # never detect host-installed optional libs (libidn, gcrypt, freerdp, postgres,
  # mysql...) whose modules would then pull incompatible host headers. Only the
  # libs we actually cross-built (libssh, openssl, zlib, pcre2) live in $PREFIX.
  sed -i "s#^LIBDIRS=.*#LIBDIRS=\"$PREFIX/lib\"#; s#^INCDIRS=.*#INCDIRS=\"$PREFIX/include\"#" "$WORK/$abi/thc-hydra-$HYDRA_V/configure"

  # hydra's bespoke configure probes the HOST for DB client libs (pg_config,
  # mysql_config...) and injects their /usr/include paths, which then drag in
  # host glibc headers incompatible with the NDK. Shadow those tools so hydra
  # only builds modules backed by libs in our cross prefix (ssh, ftp, http, ...).
  local shim="$WORK/$abi/shim"; mkdir -p "$shim"
  for t in pg_config mysql_config mariadb_config mariadb-config firebird pcre-config; do
    printf '#!/bin/sh\nexit 1\n' > "$shim/$t"; chmod +x "$shim/$t"
  done

  ( cd "$d"
    export PATH="$shim:$PATH"
    export CFLAGS="$CFLAGS -I$PREFIX/include"
    export LDFLAGS="$LDFLAGS -L$PREFIX/lib"
    export LIBS="-lssh -lpcre2-8 -lssl -lcrypto -lz"
    ./configure --prefix="$PREFIX"
    # Scrub any host include/lib paths that still leaked into the Makefiles.
    sed -i 's#-I/usr/include[^[:space:]]*##g; s#-L/usr/lib[^[:space:]]*##g' Makefile 2>/dev/null || true
    make -j"$(nproc)" CC="$CC" \
      XIPATHS="-I$PREFIX/include" XLIBPATHS="-L$PREFIX/lib" \
      XLIBS="-lssh -lpcre2-8 -lssl -lcrypto -lz"
    "$STRIP" hydra )
  install -Dm755 "$d/hydra" "$JNI/$abi/libhydra.so"
  echo ">> hydra -> $JNI/$abi/libhydra.so"
}

build_medusa() {
  local abi="$1"; setup_env "$abi"
  fetch "https://github.com/jmk-foofus/medusa/archive/refs/tags/$MEDUSA_V.tar.gz" "medusa-$MEDUSA_V.tar.gz"
  local d="$WORK/$abi/medusa-$MEDUSA_V"; rm -rf "$d"
  tar -xf "$SRC/medusa-$MEDUSA_V.tar.gz" -C "$WORK/$abi"
  # OpenSSL 3 loads the "legacy" provider from a separate module we do not ship;
  # make its absence non-fatal (the default provider covers ssh/ftp/http).
  sed -i 's#writeError(ERR_FATAL, "Error loading OpenSSL .legacy. provider.");#writeError(ERR_NOTICE, "OpenSSL legacy provider unavailable (ok for ssh/ftp/http).");#' "$d/src/medusa.c"
  # Force-enable the SSH2 module: with a static libssh2 (no .so) medusa's configure
  # cannot ldd-probe it and wrongly assumes libgcrypt/gnutls are required, disabling
  # ssh. Skip that guard block (our libssh2 uses OpenSSL, linked via -lssh2 -lssl).
  sed -i 's/^if test x"$check_module_ssh" = "xtrue"; then$/if false; then/' "$d/configure"
  # Android can only dlopen shared libs from nativeLibraryDir (W^X/SELinux), where
  # files must be named lib*.so. Make medusa load "<path>/lib<name>_mod.so" so the
  # modules can ship in jniLibs; the app sets MEDUSA_MODULE_PATH to nativeLibraryDir.
  sed -i 's#".mod"#"_mod.so"#' "$d/src/modsrc/module.h"
  sed -i 's#strcat(modPath, "/");#strcat(modPath, "/lib");#' "$d/src/medusa.c"
  sed -i 's#strlen(MODULE_EXTENSION) + 2;#strlen(MODULE_EXTENSION) + 8;#' "$d/src/medusa.c"
  # medusa configure hardcodes host include/lib paths; strip them for the NDK build.
  sed -i 's# -I/usr/include##g; s# -I/usr/local/include##g; s# -I${postgresql_prefix}/include/postgresql##g; s# -I${postgresql_prefix}/include/pgsql##g; s# -I${afpfsng_prefix}/include/afpfs-ng##g; s# -I/usr/include/freerdp3##g; s# -I/usr/include/winpr3##g; s# -I/usr/include/smb2##g; s# -L/usr/lib##g; s# -L/usr/local/lib##g' "$d/configure"
  # bionic lacks pthread_cancel + PTHREAD_CANCEL_* constants; force-include a
  # compat shim that no-ops thread cancellation (medusa tolerates this).
  local hdr="$PREFIX/include/android_pthread_compat.h"
  {
    printf "%s\n" "#pragma once"
    printf "%s\n" "#include <pthread.h>"
    printf "%s\n" "#ifndef PTHREAD_CANCEL_ENABLE"
    printf "%s\n" "#define PTHREAD_CANCEL_ENABLE 0"
    printf "%s\n" "#define PTHREAD_CANCEL_DISABLE 1"
    printf "%s\n" "#define PTHREAD_CANCEL_DEFERRED 0"
    printf "%s\n" "#define PTHREAD_CANCEL_ASYNCHRONOUS 1"
    printf "%s\n" "static inline int pthread_setcancelstate(int s,int *o){(void)s;if(o)*o=0;return 0;}"
    printf "%s\n" "static inline int pthread_setcanceltype(int t,int *o){(void)t;if(o)*o=0;return 0;}"
    printf "%s\n" "static inline int pthread_cancel(pthread_t t){(void)t;return 0;}"
    printf "%s\n" "#ifndef PTHREAD_INHERIT_SCHED"
    printf "%s\n" "#define PTHREAD_INHERIT_SCHED 0"
    printf "%s\n" "#define PTHREAD_EXPLICIT_SCHED 1"
    printf "%s\n" "#endif"
    printf "%s\n" "static inline int pthread_attr_setinheritsched(pthread_attr_t *a,int i){(void)a;(void)i;return 0;}"
    printf "%s\n" "static inline int pthread_attr_getinheritsched(const pthread_attr_t *a,int *i){(void)a;if(i)*i=0;return 0;}"
    printf "%s\n" "#endif"
  } > "$hdr"
  ( cd "$d"
    export CFLAGS="$CFLAGS -I$PREFIX/include -include $hdr -Dindex=strchr -Drindex=strrchr -Wno-implicit-function-declaration"
    export LDFLAGS="$LDFLAGS -L$PREFIX/lib"
    export LIBS="-lssh2 -lssl -lcrypto -lz"
    ./configure --host="$(triple_for "$abi")" --prefix="$PREFIX" \
        --with-ssl="$PREFIX" --enable-static
    make -j"$(nproc)"
    "$STRIP" src/medusa 2>/dev/null || true )
  install -Dm755 "$d/src/medusa" "$JNI/$abi/libmedusa.so"
  # Ship a curated set of stripped modules (matching the app's BruteService list)
  # so the app can load them from nativeLibraryDir. Each statically embeds its
  # crypto libs, so we avoid shipping all 22.
  local nmod=0
  for base in ssh ftp http web-form telnet mysql smbnt; do
    local m="$d/src/modsrc/$base.mod"
    [ -f "$m" ] || continue
    install -Dm755 "$m" "$JNI/$abi/lib${base}_mod.so"
    "$STRIP" "$JNI/$abi/lib${base}_mod.so"
    nmod=$((nmod+1))
  done
  echo ">> medusa -> $JNI/$abi/libmedusa.so (+ $nmod modules)"
}

###############################################################################
# Orchestration
###############################################################################
mkdir -p "$ASSET_NMAP"
for abi in $ABIS; do
  echo "==================== ABI: $abi ===================="
  build_fdsan_shim "$abi"
  build_zlib "$abi"
  build_openssl "$abi"
  for t in $TOOLS; do
    case "$t" in
      nmap)   build_pcre2 "$abi"; build_nmap "$abi" ;;
      hydra)  build_libssh "$abi"; build_hydra "$abi" ;;
      medusa) build_libssh2 "$abi"; build_medusa "$abi" ;;
    esac
  done
done
echo "ALL DONE. Binaries in $JNI/<abi>/lib<tool>.so"

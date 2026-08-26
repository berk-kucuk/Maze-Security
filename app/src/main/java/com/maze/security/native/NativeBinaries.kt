package com.maze.security.native

import android.content.Context
import java.io.File

/**
 * Resolves bundled native tool binaries and their data files.
 *
 * Binaries are shipped inside the APK as jniLibs/<abi>/lib<tool>.so. The OS extracts
 * them into [android.content.pm.ApplicationInfo.nativeLibraryDir] — the only app-owned
 * directory we may exec from on Android 10+ (exec from filesDir is blocked). Data files
 * (e.g. nmap-services) are shipped in assets/ and copied to filesDir on first launch.
 */
class NativeBinaries(private val context: Context) {

    val nativeLibDir: File
        get() = File(context.applicationInfo.nativeLibraryDir)

    /** Value for LD_LIBRARY_PATH so exec'd binaries find any co-shipped .so libs. */
    val libraryPath: String
        get() = nativeLibDir.absolutePath

    /**
     * Environment for exec'd tool binaries: sets the library path and LD_PRELOADs
     * libtoolshim.so, which disables Android fdsan (some tools close fds that fdsan
     * guards, aborting the process otherwise).
     */
    fun runtimeEnv(): Map<String, String> {
        val env = HashMap<String, String>()
        env["LD_LIBRARY_PATH"] = libraryPath
        val shim = File(nativeLibDir, "libtoolshim.so")
        if (shim.exists()) env["LD_PRELOAD"] = shim.absolutePath
        return env
    }

    /** Directory extracted from assets where tool data files live. */
    val dataDir: File
        get() = File(context.filesDir, "tooldata").apply { if (!exists()) mkdirs() }

    val nmapDataDir: File get() = File(dataDir, "nmap")

    fun binary(name: String): File = File(nativeLibDir, "lib$name.so")

    fun isPresent(name: String): Boolean = binary(name).let { it.exists() && it.canExecute() }

    // Bump when the bundled nmap data changes so an app update re-extracts it
    // (filesDir survives updates, so a plain "installed" marker would go stale).
    private val nmapDataVersion = "2"

    /** Copies bundled tool data (nmap-services, probes, NSE) out of assets on first use. */
    fun ensureNmapData() {
        val target = nmapDataDir
        val marker = File(target, ".installed")
        if (marker.exists() && marker.readText().trim() == nmapDataVersion) return
        target.mkdirs()
        copyAssetDir("nmap-data", target)
        marker.writeText(nmapDataVersion)
    }

    private fun copyAssetDir(assetPath: String, destination: File) {
        val assets = context.assets
        val entries = assets.list(assetPath) ?: return
        if (entries.isEmpty()) {
            // It's a file.
            assets.open(assetPath).use { input ->
                destination.outputStream().use { input.copyTo(it) }
            }
            return
        }
        destination.mkdirs()
        for (entry in entries) {
            val childAsset = "$assetPath/$entry"
            val childDest = File(destination, entry)
            val sub = assets.list(childAsset)
            if (sub.isNullOrEmpty()) {
                assets.open(childAsset).use { input ->
                    childDest.outputStream().use { input.copyTo(it) }
                }
            } else {
                copyAssetDir(childAsset, childDest)
            }
        }
    }
}

package com.maze.security.data.wordlist

import android.content.Context
import android.net.Uri
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File

/** The purpose a wordlist is suited for; drives which lists a tool shows. */
enum class WordlistKind { PASSWORD, USERNAME, DIRECTORY, SUBDOMAIN, GENERIC }

data class Wordlist(
    val name: String,
    val path: String,
    val lineCount: Int,
    val bundled: Boolean,
    val kind: WordlistKind
)

/**
 * Manages wordlists grouped by purpose. Bundled lists ship in assets/wordlists and are
 * copied to filesDir on first launch; the user can also import their own .txt files
 * (imported lists are GENERIC and show up for every tool).
 */
class WordlistManager(private val context: Context) {

    private val dir: File get() = File(context.filesDir, "wordlists").apply { if (!exists()) mkdirs() }

    private val bundled = listOf(
        "passwords-common.txt",
        "passwords-top100.txt",
        "usernames-common.txt",
        "directories-common.txt",
        "subdomains-common.txt"
    )
    // Bump to re-extract bundled lists after they change (filesDir survives app updates).
    private val version = "2"

    suspend fun ensureBundled() = withContext(Dispatchers.IO) {
        val marker = File(dir, ".v")
        val fresh = !marker.exists() || marker.readText().trim() != version
        for (name in bundled) {
            val dest = File(dir, name)
            if (fresh || !dest.exists()) {
                runCatching {
                    context.assets.open("wordlists/$name").use { input ->
                        dest.outputStream().use { input.copyTo(it) }
                    }
                }
            }
        }
        marker.writeText(version)
    }

    private fun kindOf(name: String, bundled: Boolean): WordlistKind = when {
        name.startsWith("passwords") -> WordlistKind.PASSWORD
        name.startsWith("usernames") || name.startsWith("users") -> WordlistKind.USERNAME
        name.startsWith("directories") || name.startsWith("dirs") || name.startsWith("paths") -> WordlistKind.DIRECTORY
        name.startsWith("subdomains") || name.startsWith("subs") -> WordlistKind.SUBDOMAIN
        else -> WordlistKind.GENERIC
    }

    suspend fun list(): List<Wordlist> = withContext(Dispatchers.IO) {
        ensureBundled()
        (dir.listFiles()?.toList() ?: emptyList())
            .filter { it.isFile && !it.name.startsWith(".") }
            .sortedBy { it.name }
            .map {
                Wordlist(
                    name = it.name,
                    path = it.absolutePath,
                    lineCount = runCatching { it.useLines { s -> s.count() } }.getOrDefault(0),
                    bundled = it.name in bundled,
                    kind = kindOf(it.name, it.name in bundled)
                )
            }
    }

    /** Lists suited to a tool: matching-kind lists plus any user-imported GENERIC lists. */
    suspend fun listFor(kind: WordlistKind): List<Wordlist> =
        list().filter { it.kind == kind || (it.kind == WordlistKind.GENERIC && !it.bundled) }

    suspend fun import(uri: Uri, displayName: String): String = withContext(Dispatchers.IO) {
        val safe = displayName.replace(Regex("[^A-Za-z0-9._-]"), "_").ifBlank { "imported.txt" }
        val dest = File(dir, safe)
        context.contentResolver.openInputStream(uri)?.use { input ->
            dest.outputStream().use { input.copyTo(it) }
        }
        dest.absolutePath
    }

    suspend fun delete(path: String): Boolean = withContext(Dispatchers.IO) {
        val f = File(path)
        if (f.name in bundled) false else f.delete()
    }

    /** Reads up to [maxLines] lines of a wordlist for in-app viewing (avoids OOM on huge lists). */
    suspend fun preview(path: String, maxLines: Int = 3000): WordlistPreview = withContext(Dispatchers.IO) {
        val f = File(path)
        if (!f.canRead()) return@withContext WordlistPreview(emptyList(), 0, false)
        var total = 0
        val lines = ArrayList<String>(minOf(maxLines, 1024))
        f.useLines { seq ->
            for (line in seq) {
                total++
                if (lines.size < maxLines) lines.add(line)
            }
        }
        WordlistPreview(lines, total, total > lines.size)
    }
}

data class WordlistPreview(val lines: List<String>, val total: Int, val truncated: Boolean)

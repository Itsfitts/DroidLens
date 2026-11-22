package com.Cali.droidlens

import java.io.File
import java.util.zip.ZipFile

/**
 * Scans APK assets/ and res/raw/ for shell scripts and privileged utilities.
 * Extracts executed binaries (resetprop, iptables, dd, mount, pm, etc.) that
 * reveal root capabilities outside AndroidManifest.xml.
 */
object RootScriptExtractor {

    private const val MAX_SCRIPT_SIZE = 512 * 1024 // 512 KB per script to stay light on memory

    data class ScriptFinding(
        val entryName: String,
        val sizeBytes: Long,
        val shebang: String?,
        val privilegedHits: List<CommandHit>,
        val preview: String
    )

    data class CommandHit(
        val command: String,
        val capability: String,
        val line: String,
        val lineNumber: Int
    )

    data class Summary(
        val scripts: List<ScriptFinding>,
        val totalScripts: Int,
        val totalPrivilegedHits: Int,
        val executedBinaries: Set<String>,
        val requiredCaps: Set<String>,
        val requiresGlobalMount: Boolean,
        val error: String? = null
    )

    private val PRIVILEGED_PATTERNS = listOf(
        Regex("""(?i)\b(resetprop)\b""") to ("CAP_SYS_ADMIN" to "resetprop"),
        Regex("""(?i)\b(iptables|ip6tables|nftables)\b""") to ("CAP_NET_ADMIN" to "iptables"),
        Regex("""(?i)\b(mount)\s+.*(-o\s+.*remount|/system|/vendor|/product|--bind)""") to ("CAP_SYS_ADMIN" to "mount"),
        Regex("""(?i)\b(umount|umount2)\b""") to ("CAP_SYS_ADMIN" to "umount"),
        Regex("""(?i)\b(dd)\s+.*(if=/dev/|of=/dev/)""") to ("CAP_SYS_RAWIO" to "dd"),
        Regex("""(?i)\b(insmod|rmmod|modprobe)\b""") to ("CAP_SYS_MODULE" to "insmod"),
        Regex("""(?i)\b(ptrace)\b""") to ("CAP_SYS_PTRACE" to "ptrace"),
        Regex("""(?i)\b(chown|chmod)\b""") to ("CAP_CHOWN" to "chown"),
        Regex("""(?i)\b(kill|pkill|killall)\b""") to ("CAP_KILL" to "kill"),
        Regex("""(?i)\b(setprop)\b""") to ("CAP_SYS_ADMIN" to "setprop"),
        Regex("""(?i)\b(pm\s+(grant|install|uninstall))\b""") to ("CAP_DAC_OVERRIDE" to "pm"),
        Regex("""(?i)\b(cmd\s+appops|settings\s+put)\b""") to ("CAP_DAC_OVERRIDE" to "settings"),
        Regex("""(?i)\b(su\s+(-c|--command)?)\b""") to ("ROOT_EXEC" to "su")
    )

    fun scan(apk: File): Summary {
        val scripts = mutableListOf<ScriptFinding>()
        val binaries = mutableSetOf<String>()
        val caps = mutableSetOf<String>()
        var globalMount = false

        try {
            ZipFile(apk).use { zip ->
                val entries = zip.entries().asSequence()
                    .filter { isPotentialScript(it.name) }
                    .sortedBy { it.name }
                    .toList()

                for (entry in entries) {
                    if (entry.size > MAX_SCRIPT_SIZE || entry.isDirectory) continue
                    try {
                        val bytes = zip.getInputStream(entry).use { it.readBytes() }
                        if (bytes.isEmpty()) continue

                        // Check if file is text/script (has shebang or printable script content)
                        val shebang = readShebang(bytes)
                        val isScriptByContent = shebang != null || isTextScript(bytes, entry.name)
                        if (!isScriptByContent) continue

                        val text = String(bytes, Charsets.UTF_8)
                        val hits = analyzeScriptText(text)

                        for (hit in hits) {
                            if (hit.capability.startsWith("CAP_")) {
                                caps.add(hit.capability)
                            }
                            binaries.add(hit.command)
                            if (hit.command == "mount" || hit.command == "umount") {
                                globalMount = true
                            }
                        }

                        val previewLines = text.lines().take(15).joinToString("\n")
                        scripts.add(
                            ScriptFinding(
                                entryName = entry.name,
                                sizeBytes = entry.size.coerceAtLeast(0L),
                                shebang = shebang,
                                privilegedHits = hits,
                                preview = previewLines
                            )
                        )
                    } catch (_: Throwable) { }
                }
            }
        } catch (e: Throwable) {
            return Summary(emptyList(), 0, 0, emptySet(), emptySet(), false, "Script scan failed: ${e.message}")
        }

        val totalHits = scripts.sumOf { it.privilegedHits.size }
        return Summary(
            scripts = scripts,
            totalScripts = scripts.size,
            totalPrivilegedHits = totalHits,
            executedBinaries = binaries,
            requiredCaps = caps,
            requiresGlobalMount = globalMount
        )
    }

    private fun isPotentialScript(name: String): Boolean {
        val lower = name.lowercase()
        return (lower.startsWith("assets/") || lower.startsWith("res/raw/")) ||
               lower.endsWith(".sh") || lower.endsWith(".bash") || lower.endsWith(".rc") ||
               lower.endsWith(".prop") || lower.endsWith(".conf") || lower.endsWith(".bin")
    }

    private fun readShebang(bytes: ByteArray): String? {
        if (bytes.size >= 2 && bytes[0] == '#'.code.toByte() && bytes[1] == '!'.code.toByte()) {
            val end = bytes.indexOfFirst { it == '\n'.code.toByte() || it == '\r'.code.toByte() }
            val len = if (end > 0) end else bytes.size.coerceAtMost(80)
            return String(bytes, 0, len, Charsets.UTF_8).trim()
        }
        return null
    }

    private fun isTextScript(bytes: ByteArray, name: String): Boolean {
        val lower = name.lowercase()
        if (lower.endsWith(".sh") || lower.endsWith(".bash") || lower.endsWith(".rc")) return true
        // Sample first 200 bytes for printable text
        val sampleSize = bytes.size.coerceAtMost(200)
        var printable = 0
        for (i in 0 until sampleSize) {
            val b = bytes[i].toInt() and 0xFF
            if (b in 0x20..0x7E || b == 0x0A || b == 0x0D || b == 0x09) {
                printable++
            }
        }
        return printable.toDouble() / sampleSize > 0.90
    }

    private fun analyzeScriptText(text: String): List<CommandHit> {
        val hits = mutableListOf<CommandHit>()
        val lines = text.lines()
        for ((idx, line) in lines.withIndex()) {
            val trimmed = line.trim()
            if (trimmed.startsWith("#") && !trimmed.startsWith("#!")) continue // skip normal comments

            for ((pattern, capAndCmd) in PRIVILEGED_PATTERNS) {
                val (cap, cmd) = capAndCmd
                if (pattern.containsMatchIn(line)) {
                    hits.add(
                        CommandHit(
                            command = cmd,
                            capability = cap,
                            line = trimmed.take(120),
                            lineNumber = idx + 1
                        )
                    )
                }
            }
        }
        return hits
    }

    fun format(s: Summary): String {
        if (s.error != null) return s.error
        if (s.scripts.isEmpty()) return "No bundled shell scripts found in assets/ or res/raw/."

        return buildString {
            append("${s.totalScripts} bundled script${if (s.totalScripts == 1) "" else "s"} found")
            append(" · ${s.totalPrivilegedHits} privileged command invocations\n\n")

            if (s.executedBinaries.isNotEmpty()) {
                append("Detected Privileged Binaries:\n")
                append("  ").append(s.executedBinaries.sorted().joinToString(", ")).append("\n\n")
            }

            for (script in s.scripts) {
                append("• ${script.entryName} (${script.sizeBytes} B)")
                if (script.shebang != null) append(" [${script.shebang}]")
                append("\n")

                if (script.privilegedHits.isNotEmpty()) {
                    for (hit in script.privilegedHits) {
                        append("    L${hit.lineNumber}: [${hit.command} -> ${hit.capability}] ${hit.line}\n")
                    }
                } else {
                    append("    (No direct privileged binary patterns matched)\n")
                }
                append("\n")
            }
        }.trimEnd()
    }
}

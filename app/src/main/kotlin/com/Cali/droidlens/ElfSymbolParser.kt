package com.Cali.droidlens

import java.io.File
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.zip.ZipFile

/**
 * In-process ELF binary and dynamic symbol inspector for native libraries (.so).
 * Replaces the need for desktop `nm -D` and `strings <lib>.so | grep -E "mount|ptrace|ioctl|..."`
 * on-device.
 */
object ElfSymbolParser {

    private val TARGET_SYMBOLS = setOf(
        "mount", "umount", "umount2", "ptrace", "kill", "capset",
        "setresuid", "setresgid", "setuid", "setgid",
        "system", "popen", "execve", "execv", "execl", "ioctl"
    )

    private val DEVICE_PATTERNS = listOf(
        Regex("""/dev/block/[a-zA-Z0-9_\-\/]+""") to "Block device direct access",
        Regex("""/dev/(mem|kmem|port)""") to "Raw physical/kernel memory access",
        Regex("""/dev/kmsg""") to "Kernel message log access",
        Regex("""/dev/socket/[a-zA-Z0-9_\-]+""") to "System/root daemon UNIX domain socket",
        Regex("""/proc/kallsyms""") to "Kernel symbol table inspection",
        Regex("""/proc/self/mem""") to "Direct process memory manipulation",
        Regex("""(?i)\b(resetprop|kernelsu|ksud|magisk|supersu)\b""") to "Root management utility interaction"
    )

    data class LibFinding(
        val libName: String,
        val arch: String,
        val is64Bit: Boolean,
        val matchedSymbols: List<String>,
        val matchedDevicesOrPaths: List<Pair<String, String>>,
        val maxLoadAlign: Long = 4096L,
        val is16KbCompatible: Boolean = true
    )

    data class Summary(
        val findings: List<LibFinding>,
        val totalLibsScanned: Int,
        val detectedSyscalls: Set<String>,
        val requiredCaps: Set<String>,
        val non16KbLibs: List<String> = emptyList(),
        val error: String? = null
    )

    fun scan(apk: File): Summary {
        val findings = mutableListOf<LibFinding>()
        val syscalls = mutableSetOf<String>()
        val caps = mutableSetOf<String>()
        val non16Kb = mutableListOf<String>()

        try {
            ZipFile(apk).use { zip ->
                val entries = zip.entries().asSequence()
                    .filter { it.name.startsWith("lib/") && it.name.endsWith(".so") }
                    .sortedBy { it.name }
                    .toList()

                for (entry in entries) {
                    try {
                        val bytes = zip.getInputStream(entry).use { it.readBytes() }
                        if (bytes.size < 52) continue
                        // Check ELF Magic: 0x7F 'E' 'L' 'F'
                        if (bytes[0] != 0x7F.toByte() || bytes[1] != 'E'.code.toByte() ||
                            bytes[2] != 'L'.code.toByte() || bytes[3] != 'F'.code.toByte()
                        ) continue

                        val is64Bit = bytes[4] == 2.toByte()
                        val isLittleEndian = bytes[5] == 1.toByte()

                        val parts = entry.name.split('/')
                        val arch = if (parts.size >= 3) parts[1] else "unknown"
                        val libName = parts.lastOrNull() ?: entry.name

                        // Android 16 / 16 KB page-alignment check
                        val maxAlign = check16KbAlignment(bytes, is64Bit, isLittleEndian)
                        val is64Arch = arch in setOf("arm64-v8a", "x86_64")
                        val is16Kb = !is64Arch || maxAlign >= 16384L
                        if (!is16Kb) {
                            non16Kb.add("$libName ($arch, align ${maxAlign}B)")
                        }

                        // Extract Dynamic Symbol Table if possible, plus printable strings
                        val symbolsFound = extractSymbols(bytes, is64Bit, isLittleEndian)
                        val strings = extractStrings(bytes)

                        val deviceHits = mutableListOf<Pair<String, String>>()
                        for (s in strings) {
                            for ((pattern, desc) in DEVICE_PATTERNS) {
                                val m = pattern.find(s)
                                if (m != null) {
                                    deviceHits.add(m.value to desc)
                                }
                            }
                        }

                        // Also cross check target symbols against extracted strings
                        val allMatchedSymbols = (symbolsFound + strings.filter { it in TARGET_SYMBOLS }).distinct()

                        for (sym in allMatchedSymbols) {
                            syscalls.add(sym)
                            mapSymbolToCapability(sym)?.let { caps.add(it) }
                        }

                        if (allMatchedSymbols.isNotEmpty() || deviceHits.isNotEmpty() || !is16Kb) {
                            findings.add(
                                LibFinding(
                                    libName = libName,
                                    arch = arch,
                                    is64Bit = is64Bit,
                                    matchedSymbols = allMatchedSymbols.sorted(),
                                    matchedDevicesOrPaths = deviceHits.distinctBy { it.first },
                                    maxLoadAlign = maxAlign,
                                    is16KbCompatible = is16Kb
                                )
                            )
                        }
                    } catch (_: Throwable) { }
                }
            }
        } catch (e: Throwable) {
            return Summary(emptyList(), 0, emptySet(), emptySet(), emptyList(), "Native symbol scan failed: ${e.message}")
        }

        return Summary(
            findings = findings,
            totalLibsScanned = findings.size,
            detectedSyscalls = syscalls,
            requiredCaps = caps,
            non16KbLibs = non16Kb
        )
    }

    private fun mapSymbolToCapability(sym: String): String? {
        return when (sym) {
            "mount", "umount", "umount2" -> "CAP_SYS_ADMIN"
            "ptrace" -> "CAP_SYS_PTRACE"
            "kill" -> "CAP_KILL"
            "capset" -> "CAP_SETPCAP"
            "setresuid", "setuid", "setresgid", "setgid" -> "CAP_SETUID"
            "ioctl" -> "CAP_SYS_ADMIN"
            else -> null
        }
    }

    private fun extractSymbols(bytes: ByteArray, is64Bit: Boolean, isLittleEndian: Boolean): Set<String> {
        val found = mutableSetOf<String>()
        try {
            val order = if (isLittleEndian) ByteOrder.LITTLE_ENDIAN else ByteOrder.BIG_ENDIAN
            val buf = ByteBuffer.wrap(bytes).order(order)
            // Read Section Header Offset
            val shoff = if (is64Bit) {
                if (bytes.size < 48) return emptySet()
                buf.getLong(40)
            } else {
                if (bytes.size < 36) return emptySet()
                buf.getInt(32).toLong() and 0xFFFFFFFFL
            }
            val shentsize = (if (is64Bit) buf.getShort(58) else buf.getShort(46)).toInt() and 0xFFFF
            val shnum = (if (is64Bit) buf.getShort(60) else buf.getShort(48)).toInt() and 0xFFFF

            if (shoff <= 0 || shnum <= 0 || shentsize <= 0) return emptySet()
            if (shoff + shnum * shentsize > bytes.size) return emptySet()

            // Look for SHT_DYNSYM (11) and its link to string table
            // In ELF: sh_type is at offset 4
            for (i in 0 until shnum) {
                val headerOffset = (shoff + i * shentsize).toInt()
                val shType = buf.getInt(headerOffset + 4)
                if (shType == 11) { // SHT_DYNSYM
                    val link = buf.getInt(headerOffset + (if (is64Bit) 40 else 24))
                    if (link in 0 until shnum) {
                        val strHeaderOffset = (shoff + link * shentsize).toInt()
                        val strOffset = if (is64Bit) buf.getLong(strHeaderOffset + 24) else (buf.getInt(strHeaderOffset + 16).toLong() and 0xFFFFFFFFL)
                        val strSize = if (is64Bit) buf.getLong(strHeaderOffset + 32) else (buf.getInt(strHeaderOffset + 20).toLong() and 0xFFFFFFFFL)

                        if (strOffset > 0 && strOffset + strSize <= bytes.size) {
                            val strData = String(bytes, strOffset.toInt(), strSize.toInt(), Charsets.US_ASCII)
                            for (target in TARGET_SYMBOLS) {
                                if (strData.contains(target)) {
                                    found.add(target)
                                }
                            }
                        }
                    }
                }
            }
        } catch (_: Throwable) { }
        return found
    }

    private fun extractStrings(bytes: ByteArray): List<String> {
        val out = ArrayList<String>()
        val sb = StringBuilder()
        for (b in bytes) {
            val i = b.toInt() and 0xFF
            if (i in 0x20..0x7E) {
                sb.append(i.toChar())
                if (sb.length > 256) sb.setLength(0)
            } else {
                if (sb.length in 4..120) out.add(sb.toString())
                sb.setLength(0)
            }
        }
        return out
    }

    private fun check16KbAlignment(bytes: ByteArray, is64Bit: Boolean, isLittleEndian: Boolean): Long {
        try {
            val order = if (isLittleEndian) ByteOrder.LITTLE_ENDIAN else ByteOrder.BIG_ENDIAN
            val buf = ByteBuffer.wrap(bytes).order(order)
            val phoff = if (is64Bit) {
                if (bytes.size < 40) return 4096L
                buf.getLong(32)
            } else {
                if (bytes.size < 32) return 4096L
                buf.getInt(28).toLong() and 0xFFFFFFFFL
            }
            val phentsize = (if (is64Bit) buf.getShort(54) else buf.getShort(42)).toInt() and 0xFFFF
            val phnum = (if (is64Bit) buf.getShort(56) else buf.getShort(44)).toInt() and 0xFFFF

            if (phoff <= 0 || phnum <= 0 || phentsize <= 0) return 4096L
            if (phoff + phnum * phentsize > bytes.size) return 4096L

            var maxAlign = 0L
            for (i in 0 until phnum) {
                val offset = (phoff + i * phentsize).toInt()
                val pType = buf.getInt(offset)
                if (pType == 1) { // PT_LOAD
                    val align = if (is64Bit) {
                        buf.getLong(offset + 48)
                    } else {
                        buf.getInt(offset + 28).toLong() and 0xFFFFFFFFL
                    }
                    if (align > maxAlign) maxAlign = align
                }
            }
            return if (maxAlign > 0) maxAlign else 4096L
        } catch (_: Throwable) {
            return 4096L
        }
    }

    fun format(s: Summary): String {
        if (s.error != null) return s.error
        if (s.findings.isEmpty() && s.non16KbLibs.isEmpty()) return "No privileged native symbols or device nodes detected in .so libraries."

        return buildString {
            if (s.non16KbLibs.isNotEmpty()) {
                append("⚠️ Android 16 Alert: ${s.non16KbLibs.size} 64-bit lib(s) lack 16 KB page alignment:\n")
                for (lib in s.non16KbLibs) {
                    append("  • $lib\n")
                }
                append("\n")
            } else if (s.findings.isNotEmpty()) {
                append("✓ 16 KB Page Alignment: Verified for 64-bit native libraries (Android 16 compatible)\n\n")
            }

            append("${s.findings.size} native librar${if (s.findings.size == 1) "y" else "ies"} with privileged references\n\n")

            if (s.detectedSyscalls.isNotEmpty()) {
                append("Detected Kernel Interacting Syscalls / Symbols:\n")
                append("  ").append(s.detectedSyscalls.sorted().joinToString(", ")).append("\n\n")
            }

            for (f in s.findings) {
                append("• ${f.libName} (${f.arch}, ${if (f.is64Bit) "64-bit" else "32-bit"})\n")
                if (!f.is16KbCompatible) {
                    append("    ⚠️ Page Alignment: ${f.maxLoadAlign} B (< 16 KB — Incompatible with Android 16)\n")
                }
                if (f.matchedSymbols.isNotEmpty()) {
                    append("    Symbols: ").append(f.matchedSymbols.joinToString(", ")).append("\n")
                }
                if (f.matchedDevicesOrPaths.isNotEmpty()) {
                    for ((path, desc) in f.matchedDevicesOrPaths) {
                        append("    Device/Node: $path ($desc)\n")
                    }
                }
                append("\n")
            }
        }.trimEnd()
    }
}

package com.Cali.droidlens

import java.io.File

/**
 * Scans Dalvik/ART bytecode strings and class references for root execution patterns:
 * `su`, `libsu`, `Shell.cmd`, `Runtime.getRuntime().exec`, `ProcessBuilder`, and `app_process`.
 */
object DexRootScanner {

    data class Finding(
        val category: String,
        val match: String,
        val description: String
    )

    data class Summary(
        val findings: List<Finding>,
        val rootFrameworksDetected: List<String>,
        val rootCommandStrings: List<String>,
        val detectedBinaries: Set<String>,
        val error: String? = null
    )

    private val ROOT_FRAMEWORK_PATTERNS = listOf(
        "com.topjohnwu.superuser" to "libsu (TopJohnWu)",
        "eu.chainfire.libsuperuser" to "libsuperuser (Chainfire)",
        "com.stericson.RootTools" to "RootTools",
        "stericson.busybox" to "Stericson BusyBox",
        "rikka.shizuku" to "Rikka Shizuku / Sui"
    )

    private val PROCESS_PATTERNS = listOf(
        Regex("""(?i)\b(Runtime\.getRuntime\(\)\.exec|ProcessBuilder)\b""") to "Java process execution API",
        Regex("""(?i)\b(/system/bin/su|/system/xbin/su|/sbin/su|/su/bin/su)\b""") to "Hardcoded su binary path",
        Regex("""(?i)\bsu\s+(-c|--command)\b""") to "su shell command execution",
        Regex("""(?i)\bapp_process\s+(/system/bin|/data/local/tmp)\b""") to "app_process privileged daemon launcher"
    )

    private val PRIVILEGED_SHELL_STRINGS = listOf(
        "resetprop" to "System property override",
        "iptables" to "Firewall / network manipulation",
        "nftables" to "Firewall / network manipulation",
        "mount -o remount" to "Partition remounting",
        "--bind" to "Bind mount",
        "setenforce 0" to "SELinux permissive mode switch",
        "insmod" to "Kernel module insertion",
        "pm grant" to "Direct permission grant bypass"
    )

    fun scan(apk: File, extractedStrings: List<String>? = null): Summary {
        val strings = extractedStrings ?: try {
            StringExtractor.extract(apk).strings
        } catch (e: Throwable) {
            return Summary(emptyList(), emptyList(), emptyList(), emptySet(), "DEX scan failed: ${e.message}")
        }

        val findings = mutableListOf<Finding>()
        val frameworks = mutableListOf<String>()
        val rootCmds = mutableListOf<String>()
        val binaries = mutableSetOf<String>()

        // 1. Detect root frameworks
        for ((pkg, name) in ROOT_FRAMEWORK_PATTERNS) {
            if (strings.any { it.contains(pkg) }) {
                frameworks.add(name)
                findings.add(
                    Finding(
                        category = "Framework",
                        match = pkg,
                        description = "Bundles $name root framework."
                    )
                )
            }
        }

        // 2. Detect process execution / su invocations
        for (s in strings) {
            for ((pattern, desc) in PROCESS_PATTERNS) {
                if (pattern.containsMatchIn(s)) {
                    findings.add(
                        Finding(
                            category = "Process Execution",
                            match = s.take(100),
                            description = desc
                        )
                    )
                }
            }

            // 3. Detect privileged shell commands embedded in bytecode
            for ((kw, desc) in PRIVILEGED_SHELL_STRINGS) {
                if (s.contains(kw, ignoreCase = true)) {
                    rootCmds.add(s)
                    binaries.add(kw.split(" ").first())
                    findings.add(
                        Finding(
                            category = "Privileged Command",
                            match = s.take(100),
                            description = desc
                        )
                    )
                }
            }
        }

        return Summary(
            findings = findings.distinctBy { it.match },
            rootFrameworksDetected = frameworks.distinct(),
            rootCommandStrings = rootCmds.distinct().take(30),
            detectedBinaries = binaries
        )
    }

    fun format(s: Summary): String {
        if (s.error != null) return s.error
        if (s.findings.isEmpty()) return "No root frameworks, su invocations, or privileged commands found in DEX."

        return buildString {
            if (s.rootFrameworksDetected.isNotEmpty()) {
                append("Root Frameworks: ")
                append(s.rootFrameworksDetected.joinToString(", ")).append("\n\n")
            }

            append("${s.findings.size} root-related DEX references:\n")
            for (f in s.findings.take(20)) {
                append("• [${f.category}] ${f.description}\n")
                append("    ${f.match}\n")
            }
            if (s.findings.size > 20) {
                append("… and ${s.findings.size - 20} more references\n")
            }
        }.trimEnd()
    }
}

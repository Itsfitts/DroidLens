package com.Cali.droidlens

import java.io.File

/**
 * Synthesizes static & dynamic signals into a least-privilege KernelSU App Profile.
 */
object KernelSuProfileGenerator {

    data class ProfileScope(
        val packageId: String,
        val profileName: String,
        val description: String,
        val namespace: String, // "GLOBAL" or "REQUESTER"
        val uid: Int,
        val gid: Int,
        val groups: List<String>,
        val capabilities: List<String>,
        val context: String,
        val flags: List<String>,
        val jsonString: String,
        val breakdownRows: List<BreakdownRow>,
        val hasRootUsage: Boolean
    )

    data class BreakdownRow(
        val component: String,
        val value: String,
        val justification: String
    )

    data class SynthesisInput(
        val packageId: String,
        val appLabel: String?,
        val scriptSummary: RootScriptExtractor.Summary,
        val elfSummary: ElfSymbolParser.Summary,
        val dexSummary: DexRootScanner.Summary,
        val traceResult: SyscallTraceParser.AnalysisResult? = null
    )

    fun generate(input: SynthesisInput): ProfileScope {
        val allCaps = mutableSetOf<String>()
        val allGroups = mutableSetOf<String>()
        val justifications = mutableListOf<BreakdownRow>()

        var hasGlobalMount = input.scriptSummary.requiresGlobalMount ||
                             input.traceResult?.requiresGlobalMount == true ||
                             input.dexSummary.detectedBinaries.contains("mount")

        // 1. Evaluate Capabilities
        allCaps.addAll(input.scriptSummary.requiredCaps)
        allCaps.addAll(input.elfSummary.requiredCaps)
        if (input.traceResult != null) {
            allCaps.addAll(input.traceResult.requiredCaps)
        }

        // Add specific capabilities based on observed binaries
        val allBinaries = input.scriptSummary.executedBinaries +
                          input.dexSummary.detectedBinaries +
                          (input.traceResult?.executedBinaries ?: emptySet())

        if (allBinaries.any { it.contains("iptables") || it.contains("nftables") }) {
            allCaps.add("CAP_NET_ADMIN")
            allCaps.add("CAP_NET_RAW")
            allGroups.add("NET_ADMIN")
            justifications.add(BreakdownRow("Capabilities", "CAP_NET_ADMIN, CAP_NET_RAW", "Firewall / packet manipulation via iptables/nftables"))
        }

        if (allBinaries.contains("mount") || allBinaries.contains("umount") ||
            input.elfSummary.detectedSyscalls.contains("mount") || input.elfSummary.detectedSyscalls.contains("ioctl")
        ) {
            allCaps.add("CAP_SYS_ADMIN")
            justifications.add(BreakdownRow("Capabilities", "CAP_SYS_ADMIN", "Filesystem mounting, remounting, or low-level ioctls"))
        }

        if (allBinaries.contains("dd")) {
            allCaps.add("CAP_SYS_RAWIO")
            allGroups.add("DISK")
            justifications.add(BreakdownRow("Capabilities", "CAP_SYS_RAWIO", "Raw block device read/write via dd"))
        }

        if (allBinaries.contains("kill") || input.elfSummary.detectedSyscalls.contains("kill")) {
            allCaps.add("CAP_KILL")
            justifications.add(BreakdownRow("Capabilities", "CAP_KILL", "Sending POSIX signals across process boundaries"))
        }

        if (allBinaries.contains("ptrace") || input.elfSummary.detectedSyscalls.contains("ptrace")) {
            allCaps.add("CAP_SYS_PTRACE")
            justifications.add(BreakdownRow("Capabilities", "CAP_SYS_PTRACE", "Debugging, tracing, or hooking foreign processes"))
        }

        if (allBinaries.contains("insmod") || allBinaries.contains("rmmod")) {
            allCaps.add("CAP_SYS_MODULE")
            justifications.add(BreakdownRow("Capabilities", "CAP_SYS_MODULE", "Loading or unloading Linux kernel modules"))
        }

        if (allBinaries.contains("chown")) {
            allCaps.add("CAP_CHOWN")
            justifications.add(BreakdownRow("Capabilities", "CAP_CHOWN", "Changing file ownership across UIDs"))
        }

        if (allBinaries.contains("resetprop") || allBinaries.contains("setprop")) {
            allGroups.add("SYSTEM")
            justifications.add(BreakdownRow("Groups", "SYSTEM", "Interacting with Android system property service"))
        }

        // Determine if root is actually used
        val hasRootUsage = allCaps.isNotEmpty() ||
                           allBinaries.isNotEmpty() ||
                           input.dexSummary.rootFrameworksDetected.isNotEmpty() ||
                           input.dexSummary.findings.isNotEmpty() ||
                           (input.traceResult != null && input.traceResult.events.isNotEmpty())

        // Default baseline root permissions
        allGroups.add("ROOT")
        allGroups.add("SHELL")
        justifications.add(BreakdownRow("Groups", "ROOT, SHELL", "Baseline execution environment for su child processes"))

        if (allCaps.isEmpty()) {
            if (hasRootUsage) {
                // Generic root fallback (least-privilege read access)
                allCaps.add("CAP_DAC_READ_SEARCH")
                justifications.add(BreakdownRow("Capabilities", "CAP_DAC_READ_SEARCH", "Fallback permission to inspect protected app/system data"))
            } else {
                justifications.add(BreakdownRow("Capabilities", "None", "No privileged root calls detected in APK"))
            }
        }

        val namespace = if (hasGlobalMount) "GLOBAL" else "REQUESTER"
        justifications.add(
            BreakdownRow(
                "Namespace",
                namespace,
                if (hasGlobalMount) "Requires system-wide partition or bind-mount visibility"
                else "Confined mount namespace — standard commands operate inside caller's isolated mount view"
            )
        )

        val profileName = (input.appLabel?.takeIf { it.isNotBlank() } ?: input.packageId) + " Root Profile"
        val desc = if (hasRootUsage) {
            "Least-privilege profile generated by DroidLens based on ${allBinaries.size} binaries and ${allCaps.size} capabilities."
        } else {
            "Unprivileged app profile. No root operations detected in APK."
        }

        val json = buildJson(
            id = input.packageId,
            name = profileName,
            description = desc,
            namespace = namespace,
            groups = allGroups.sorted(),
            capabilities = allCaps.sorted()
        )

        return ProfileScope(
            packageId = input.packageId,
            profileName = profileName,
            description = desc,
            namespace = namespace,
            uid = 0,
            gid = 0,
            groups = allGroups.sorted(),
            capabilities = allCaps.sorted(),
            context = "u:r:ksu:s0",
            flags = emptyList(),
            jsonString = json,
            breakdownRows = justifications,
            hasRootUsage = hasRootUsage
        )
    }

    private fun buildJson(
        id: String,
        name: String,
        description: String,
        namespace: String,
        groups: List<String>,
        capabilities: List<String>
    ): String {
        val groupsJson = groups.joinToString(", ") { "\"$it\"" }
        val capsJson = capabilities.joinToString(", ") { "\"$it\"" }

        return """
[
  {
    "id": "$id",
    "name": "$name",
    "description": "$description",
    "author": "DroidLens Analyzer",
    "namespace": "$namespace",
    "uid": 0,
    "gid": 0,
    "groups": [
      $groupsJson
    ],
    "capabilities": [
      $capsJson
    ],
    "context": "u:r:ksu:s0",
    "flags": []
  }
]
""".trimIndent()
    }

    fun toFindings(scope: ProfileScope): List<FindingsEngine.Finding> {
        val list = mutableListOf<FindingsEngine.Finding>()
        if (!scope.hasRootUsage) return list

        if (scope.capabilities.contains("CAP_SYS_ADMIN")) {
            list.add(
                FindingsEngine.Finding(
                    severity = FindingsEngine.Severity.HIGH,
                    title = "KernelSU: Requires CAP_SYS_ADMIN (Mount / Raw System Control)",
                    detail = "App bundles scripts or native code that remounts partitions, modifies mounts, or issues privileged ioctls.",
                    category = "Kernel Privilege"
                )
            )
        }

        if (scope.capabilities.contains("CAP_SYS_PTRACE")) {
            list.add(
                FindingsEngine.Finding(
                    severity = FindingsEngine.Severity.CRITICAL,
                    title = "KernelSU: Requires CAP_SYS_PTRACE (Process Hooking / Tracing)",
                    detail = "App invokes ptrace or manipulates process memory, allowing inspection or modification of foreign processes.",
                    category = "Kernel Privilege"
                )
            )
        }

        if (scope.capabilities.contains("CAP_NET_ADMIN")) {
            list.add(
                FindingsEngine.Finding(
                    severity = FindingsEngine.Severity.MEDIUM,
                    title = "KernelSU: Requires CAP_NET_ADMIN (Firewall / iptables)",
                    detail = "App executes iptables/nftables or manipulates network interfaces and routing tables.",
                    category = "Kernel Privilege"
                )
            )
        }

        if (scope.namespace == "GLOBAL") {
            list.add(
                FindingsEngine.Finding(
                    severity = FindingsEngine.Severity.MEDIUM,
                    title = "KernelSU: Requires GLOBAL Mount Namespace",
                    detail = "App executes mount operations that affect the global mount table rather than an isolated mount sandbox.",
                    category = "Kernel Privilege"
                )
            )
        }

        return list
    }

    fun formatBreakdownTable(scope: ProfileScope): String {
        return buildString {
            append("KernelSU App Profile Scope:\n")
            append("• Target Package: ${scope.packageId}\n")
            append("• Mount Namespace: ${scope.namespace}\n")
            append("• Supplementary Groups: ${scope.groups.joinToString(", ")}\n")
            append("• Linux Capabilities: ${if (scope.capabilities.isEmpty()) "None" else scope.capabilities.joinToString(", ")}\n\n")

            append("Privilege Justification Breakdown:\n")
            for (row in scope.breakdownRows) {
                append("• [${row.component}] ${row.value}: ${row.justification}\n")
            }
        }.trimEnd()
    }
}

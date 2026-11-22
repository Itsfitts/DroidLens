package com.Cali.droidlens

/**
 * Parses runtime syscall traces (strace output) captured from su children or app processes:
 * `su -c "strace -f -e trace=execve,mount,umount2,ptrace,kill,capset -p $(pidof <package.name>)"`
 */
object SyscallTraceParser {

    data class TraceEvent(
        val syscall: String,
        val target: String,
        val rawLine: String,
        val isDenied: Boolean // EPERM
    )

    data class AnalysisResult(
        val events: List<TraceEvent>,
        val executedBinaries: Set<String>,
        val detectedSyscalls: Set<String>,
        val deniedSyscalls: Set<String>,
        val requiredCaps: Set<String>,
        val requiresGlobalMount: Boolean
    )

    private val REGEX_EXECVE = Regex("""execve\("([^"]+)",\s*\[([^\]]*)\],?""")
    private val REGEX_MOUNT = Regex("""mount\("([^"]*)",\s*"([^"]*)"""")
    private val REGEX_UMOUNT = Regex("""umount2?\("([^"]*)"""")
    private val REGEX_PTRACE = Regex("""ptrace\(([^,]+),\s*(\d+)""")
    private val REGEX_KILL = Regex("""kill\((-?\d+),\s*([^\)]+)\)""")
    private val REGEX_CAPSET = Regex("""capset\((.*)\)""")

    fun generateStraceCommand(packageName: String): String {
        return """su -c "strace -f -e trace=execve,mount,umount2,ptrace,kill,capset -s 256 -p \$(pidof $packageName)""""
    }

    fun parse(traceText: String): AnalysisResult {
        val events = mutableListOf<TraceEvent>()
        val binaries = mutableSetOf<String>()
        val syscalls = mutableSetOf<String>()
        val denied = mutableSetOf<String>()
        val caps = mutableSetOf<String>()
        var globalMount = false

        for (line in traceText.lines()) {
            val trimmed = line.trim()
            if (trimmed.isEmpty()) continue

            val isDenied = trimmed.contains("EPERM") || trimmed.contains("Operation not permitted")

            // 1. execve
            val mExec = REGEX_EXECVE.find(trimmed)
            if (mExec != null) {
                val binPath = mExec.groupValues[1]
                val binName = binPath.split("/").last()
                binaries.add(binName)
                syscalls.add("execve")
                events.add(TraceEvent("execve", "$binPath [${mExec.groupValues[2]}]", trimmed, isDenied))

                mapBinaryToCaps(binName, caps)
                if (binName == "mount" || binName == "umount") globalMount = true
                continue
            }

            // 2. mount
            val mMount = REGEX_MOUNT.find(trimmed)
            if (mMount != null) {
                val target = "${mMount.groupValues[1]} -> ${mMount.groupValues[2]}"
                syscalls.add("mount")
                caps.add("CAP_SYS_ADMIN")
                globalMount = true
                events.add(TraceEvent("mount", target, trimmed, isDenied))
                if (isDenied) denied.add("mount")
                continue
            }

            // 3. umount
            val mUmount = REGEX_UMOUNT.find(trimmed)
            if (mUmount != null) {
                val target = mUmount.groupValues[1]
                syscalls.add("umount")
                caps.add("CAP_SYS_ADMIN")
                globalMount = true
                events.add(TraceEvent("umount", target, trimmed, isDenied))
                if (isDenied) denied.add("umount")
                continue
            }

            // 4. ptrace
            val mPtrace = REGEX_PTRACE.find(trimmed)
            if (mPtrace != null) {
                val target = "${mPtrace.groupValues[1]} on PID ${mPtrace.groupValues[2]}"
                syscalls.add("ptrace")
                caps.add("CAP_SYS_PTRACE")
                events.add(TraceEvent("ptrace", target, trimmed, isDenied))
                if (isDenied) denied.add("ptrace")
                continue
            }

            // 5. kill
            val mKill = REGEX_KILL.find(trimmed)
            if (mKill != null) {
                val target = "sig ${mKill.groupValues[2]} to PID ${mKill.groupValues[1]}"
                syscalls.add("kill")
                caps.add("CAP_KILL")
                events.add(TraceEvent("kill", target, trimmed, isDenied))
                if (isDenied) denied.add("kill")
                continue
            }

            // 6. capset
            val mCapset = REGEX_CAPSET.find(trimmed)
            if (mCapset != null) {
                syscalls.add("capset")
                caps.add("CAP_SETPCAP")
                events.add(TraceEvent("capset", mCapset.groupValues[1], trimmed, isDenied))
                if (isDenied) denied.add("capset")
                continue
            }
        }

        return AnalysisResult(
            events = events,
            executedBinaries = binaries,
            detectedSyscalls = syscalls,
            deniedSyscalls = denied,
            requiredCaps = caps,
            requiresGlobalMount = globalMount
        )
    }

    private fun mapBinaryToCaps(binName: String, caps: MutableSet<String>) {
        when {
            binName.contains("iptables") || binName.contains("nftables") -> {
                caps.add("CAP_NET_ADMIN")
                caps.add("CAP_NET_RAW")
            }
            binName == "mount" || binName == "umount" -> caps.add("CAP_SYS_ADMIN")
            binName == "resetprop" -> caps.add("CAP_SYS_ADMIN")
            binName == "dd" -> caps.add("CAP_SYS_RAWIO")
            binName == "insmod" || binName == "rmmod" || binName == "modprobe" -> caps.add("CAP_SYS_MODULE")
            binName == "chown" -> caps.add("CAP_CHOWN")
            binName == "chmod" -> caps.add("CAP_FOWNER")
            binName == "kill" || binName == "pkill" -> caps.add("CAP_KILL")
        }
    }

    fun format(res: AnalysisResult): String {
        if (res.events.isEmpty()) return "No targeted syscalls or child process executions detected in trace."

        return buildString {
            append("${res.events.size} privileged events traced\n\n")

            if (res.executedBinaries.isNotEmpty()) {
                append("Spawned Executables (via execve):\n")
                append("  ").append(res.executedBinaries.sorted().joinToString(", ")).append("\n\n")
            }

            if (res.detectedSyscalls.isNotEmpty()) {
                append("Syscalls Observed: ")
                append(res.detectedSyscalls.sorted().joinToString(", ")).append("\n")
            }

            if (res.deniedSyscalls.isNotEmpty()) {
                append("Denied Syscalls (EPERM): ")
                append(res.deniedSyscalls.sorted().joinToString(", ")).append("\n")
            }

            append("\nRecent Trace Lines:\n")
            for (ev in res.events.take(15)) {
                val mark = if (ev.isDenied) "[DENIED] " else ""
                append("• $mark[${ev.syscall}] ${ev.target}\n")
            }
        }.trimEnd()
    }
}

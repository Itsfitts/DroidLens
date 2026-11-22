# DroidLens Tutorial: KernelSU App Profile & Privilege Scope Guide

Welcome to the DroidLens Privilege & Kernel Analysis Guide. This tutorial explains the new inspection capabilities in DroidLens, how to use them to profile Android apps, and how to configure DroidLens's own KernelSU App Profile so that live tracing and child process inspection operate smoothly.

---

## 1. Why DroidLens Needs Root Access

Android applications run under isolated Linux User IDs (UIDs) controlled by Zygote, Linux Discretionary Access Control (DAC), and SELinux policies. Under normal operating conditions:

1. **Process Isolation:** An unprivileged app cannot attach `strace` or `ptrace` to another app's processes.
2. **Child Process Invisibility:** When a target root app executes `su`, it spawns an independent child process (`/system/bin/sh` or `/system/bin/app_process`) under root (UID 0). Unprivileged apps cannot monitor what this child process does or which binaries it invokes.
3. **Log & Memory Restrictions:** Reading foreign `/proc/<pid>/` status or private device nodes requires elevated kernel capabilities.

### The KernelSU Least-Privilege Philosophy
Unlike legacy root solutions that grant blanket root access (`root:root` with all capabilities and full SELinux bypass), **KernelSU App Profiles** enforce least privilege. DroidLens does not need blanket root; it only requires bounded capabilities (`CAP_SYS_PTRACE`, `CAP_KILL`, `CAP_DAC_READ_SEARCH`, `CAP_SYS_ADMIN`) and standard supplementary groups to perform process tracing and log inspection safely.

---

## 2. Configuring DroidLens in KernelSU Manager

To enable live syscall tracing and child process inspection, apply the bundled KernelSU App Profile to DroidLens:

### DroidLens KernelSU Profile Template
```json
[
  {
    "id": "com.Cali.droidlens",
    "name": "DroidLens Security & Kernel Profiler",
    "description": "Least-privilege profile granting process tracing, child execve inspection, and logcat extraction for APK dynamic strace profiling and privilege auditing.",
    "author": "DroidLens",
    "namespace": "GLOBAL",
    "uid": 0,
    "gid": 0,
    "groups": [
      "ROOT",
      "SYSTEM",
      "SHELL"
    ],
    "capabilities": [
      "CAP_SYS_PTRACE",
      "CAP_KILL",
      "CAP_DAC_READ_SEARCH",
      "CAP_SYS_ADMIN"
    ],
    "context": "u:r:ksu:s0",
    "flags": []
  }
]
```

### Step-by-Step Setup
1. In DroidLens, tap the **"Guide & KSU Setup"** button at the top (or open the in-app tutorial screen) and tap **"Copy Profile JSON"**.
2. Open **KernelSU Manager** on your device.
3. Navigate to the **Superuser** tab.
4. Locate and tap **DroidLens** (`com.Cali.droidlens`).
5. Open **App Profile** / Configure Profile.
6. Paste the configuration and save.
7. Return to DroidLens. Live tracing and su child process auditing are now fully active.

### Capability Breakdown for DroidLens
| Component | Value | Technical Justification |
| :--- | :--- | :--- |
| **Capabilities** | `CAP_SYS_PTRACE` | Allows `strace` to attach to target process PIDs and read syscall arguments. |
| | `CAP_KILL` | Allows signaling target processes during fuzzing or trace termination. |
| | `CAP_DAC_READ_SEARCH` | Allows reading `/proc/<pid>/` entries and target process status. |
| | `CAP_SYS_ADMIN` | Allows strace to observe `mount`, `umount`, and ioctl operations across namespaces. |
| **Namespace** | `GLOBAL` | Allows DroidLens to observe system-wide mounts and namespace switches. |
| **Groups** | `ROOT`, `SYSTEM`, `SHELL` | Baseline groups required for executing Android shell commands and interacting with property services. |

---

## 3. How to Use the New Inspection Features

### A. Bundled Privileged Script Scanner
Many root utilities place their core privileged logic inside shell scripts bundled within the APK rather than in Java.
* **Where to find it:** In the main analysis results under **"KERNELSU APP PROFILE SCOPE"** → **"BUNDLED PRIVILEGED SCRIPTS"**.
* **What it shows:**
  * Discovered scripts from `assets/` and `res/raw/`.
  * Shebang headers (`#!/system/bin/sh`).
  * Privileged command hits with line numbers (`resetprop`, `iptables`, `mount`, `dd`, `pm grant`, `insmod`).

### B. Dalvik/ART Bytecode Root Invocation Scanner
Identifies whether the app communicates with root daemons or invokes root shells directly in bytecode.
* **Where to find it:** Under **"DEX ROOT CALLS & FRAMEWORKS"**.
* **What it shows:**
  * Detected root frameworks (`libsu`, `libsuperuser`, `RootTools`, `BusyBox`).
  * Process spawning primitives (`Runtime.getRuntime().exec`, `ProcessBuilder`, `app_process`).
  * Embedded privileged commands and property modifications.

### C. Native ELF Symbol & Device Node Inspector
Reveals low-level interactions inside compiled C/C++/Rust shared libraries (`lib/*.so`).
* **Where to find it:** Under **"NATIVE PRIVILEGED SYMBOLS & DEV NODES"**.
* **What it shows:**
  * Dynamic symbol table imports (`mount`, `umount2`, `ptrace`, `kill`, `capset`, `ioctl`).
  * Raw block device nodes (`/dev/block/*`).
  * Physical memory or kernel interfaces (`/dev/mem`, `/dev/kmsg`, `/proc/kallsyms`).

### D. Runtime Syscall Tracing (strace)
When you need definitive runtime proof of what an app's `su` child process executes:
1. Tap **"Copy Strace Cmd"** to copy the pre-built command:
   ```sh
   su -c "strace -f -e trace=execve,mount,umount2,ptrace,kill,capset -s 256 -p $(pidof <package.name>)"
   ```
2. Launch the target app on your device.
3. Tap **"Run Live Trace"** directly in DroidLens (using your configured KernelSU privileges or Shizuku).
4. DroidLens attaches to the running PID, intercepts `execve`, `mount`, `ptrace`, `kill`, `capset`, and flags any `EPERM` denials.

### E. Exporting the Target App's KernelSU Profile
* At the bottom of the card, DroidLens automatically generates a tailored, least-privilege KernelSU App Profile JSON for the analyzed app.
* Tap **"Copy KernelSU Profile JSON"**.
* You can now paste this JSON directly into KernelSU Manager for the target app, confining it to only the specific Linux capabilities and mount namespaces it genuinely requires.

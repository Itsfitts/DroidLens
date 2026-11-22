# DroidLens Changelog: KernelSU App Profile & Privileged Scope Inspection

## Overview
This update introduces comprehensive **privileged capability discovery and KernelSU App Profile generation** to DroidLens.

Traditional APK analysis tools only evaluate `AndroidManifest.xml`. However, declared Android permissions (`INTERNET`, `WRITE_SECURE_SETTINGS`, etc.) only govern the parent application sandbox. Root utilities and privileged modules execute their actual capabilities inside child processes spawned via `su`, which are governed by the Linux kernel, Linux `CAP_*` capabilities, mount namespaces, and SELinux contexts—none of which are declared in `AndroidManifest.xml`.

DroidLens now inspects an app's true privilege scope across **three static layers and one dynamic runtime layer**, and automatically synthesizes a least-privilege **KernelSU App Profile JSON**.

---

## New Features & Modules

### 1. Bundled Privileged Script Extractor
* **Module:** `com.Cali.droidlens.RootScriptExtractor`
* **Path:** `app/src/main/kotlin/com/Cali/droidlens/RootScriptExtractor.kt`
* **Capabilities:**
  * Walks through `assets/`, `res/raw/`, and checks file headers for shebangs (`#!/system/bin/sh`, `#!/bin/sh`, `#!/system/bin/bash`).
  * Scans script bodies for privileged binaries and commands:
    * `resetprop` & `setprop` (System property manipulation)
    * `iptables`, `ip6tables`, `nftables` (Network packet filtering)
    * `mount` (`-o remount`, `--bind`, system partition overlays)
    * `umount` & `umount2`
    * `dd` targeting raw block devices (`if=/dev/`, `of=/dev/`)
    * `insmod`, `rmmod`, `modprobe` (Kernel module insertion)
    * `kill`, `pkill`, `killall`
    * `chown`, `chmod`
    * `pm grant`, `settings put`, `cmd appops`

### 2. Dalvik/ART Bytecode Root Invocation Scanner
* **Module:** `com.Cali.droidlens.DexRootScanner`
* **Path:** `app/src/main/kotlin/com/Cali/droidlens/DexRootScanner.kt`
* **Capabilities:**
  * Analyzes DEX string pools and class references without full decompilation.
  * Flags bundled root framework SDKs:
    * `libsu` (`com.topjohnwu.superuser`)
    * `libsuperuser` (`eu.chainfire.libsuperuser`)
    * `RootTools` (`com.stericson.RootTools`)
    * `Stericson BusyBox` (`stericson.busybox`)
  * Flags execution primitives:
    * `Runtime.getRuntime().exec`
    * `ProcessBuilder`
    * `/system/bin/su`, `/system/xbin/su`, `su -c`
    * `app_process` daemon launchers

### 3. Native ELF Binary Dynamic Symbol & Device Inspector
* **Module:** `com.Cali.droidlens.ElfSymbolParser`
* **Path:** `app/src/main/kotlin/com/Cali/droidlens/ElfSymbolParser.kt`
* **Capabilities:**
  * Pure Kotlin on-device ELF 32-bit and 64-bit parser for `.so` native libraries in `lib/<arch>/`.
  * Inspects dynamic symbol tables (`.dynsym`/`.dynstr`), replacing desktop `nm -D` on-device.
  * Flags low-level kernel syscalls: `mount`, `umount`, `umount2`, `ptrace`, `kill`, `capset`, `setresuid`, `setresgid`, `ioctl`, `system`, `popen`, `execve`.
  * Flags direct kernel device interactions: `/dev/block/*`, `/dev/mem`, `/dev/kmsg`, `/dev/socket/*`, `/proc/kallsyms`, and root hooks (`resetprop`, `ksud`, `kernelsu`, `magisk`).

### 4. Runtime Syscall Trace Parser & One-Liner Generator
* **Module:** `com.Cali.droidlens.SyscallTraceParser`
* **Path:** `app/src/main/kotlin/com/Cali/droidlens/SyscallTraceParser.kt`
* **Capabilities:**
  * Generates the targeted syscall trace command:
    ```sh
    su -c "strace -f -e trace=execve,mount,umount2,ptrace,kill,capset -s 256 -p $(pidof <package.name>)"
    ```
  * Parses raw `strace` output (live or imported).
  * Extracts child `execve` binaries and `EPERM` denials to deduce exact Linux capabilities.

### 5. Automated KernelSU Profile Generator & Findings Integration
* **Module:** `com.Cali.droidlens.KernelSuProfileGenerator`
* **Path:** `app/src/main/kotlin/com/Cali/droidlens/KernelSuProfileGenerator.kt`
* **Capabilities:**
  * Aggregates signals across scripts, DEX bytecode, native symbols, and syscall traces.
  * Determines mount namespace: `GLOBAL` vs `REQUESTER`.
  * Selects supplementary groups: `ROOT`, `SHELL`, `SYSTEM`, `NET_ADMIN`, `DISK`.
  * Selects bounded Linux capabilities (`CAP_SYS_ADMIN`, `CAP_SYS_PTRACE`, `CAP_NET_ADMIN`, `CAP_KILL`, `CAP_SYS_RAWIO`, or least-privilege `CAP_DAC_READ_SEARCH` fallback).
  * Outputs standardized KernelSU Profile JSON conforming strictly to the specification.
  * Formats a Privilege Justification Breakdown table.
  * Emits high-priority security findings to `FindingsEngine`.

### 6. In-App Interactive Tutorial & Setup Guide
* **Activity:** `com.Cali.droidlens.TutorialActivity`
* **Path:** `app/src/main/kotlin/com/Cali/droidlens/TutorialActivity.kt`
* **Layout:** `app/src/main/res/layout/activity_tutorial.xml`
* **Capabilities:**
  * Explains why DroidLens requires root privileges (`CAP_SYS_PTRACE`, `CAP_KILL`, `CAP_DAC_READ_SEARCH`, `CAP_SYS_ADMIN`) to attach `strace` and inspect target processes.
  * Bundles a copy-pasteable KernelSU App Profile template for DroidLens itself (`app/src/main/assets/kernelsu_profile.json`).
  * Provides a direct button to launch KernelSU Manager (`me.weishu.kernelsu`).
  * Features a complete walkthrough of all new inspection tools.
  * Launches automatically on first app startup and remains accessible via the top "Guide & KSU Setup" toolbar button.

### 7. UI Enhancements in MainActivity
* **Layout:** `app/src/main/res/layout/activity_main.xml`
* **Code:** `app/src/main/kotlin/com/Cali/droidlens/MainActivity.kt`
* **Additions:**
  * Added **KERNELSU APP PROFILE SCOPE** card with `#00E676` styling.
  * Real-time collapsible view for privileged scripts, DEX calls, native symbols, and breakdown rationale.
  * **"Copy Strace Cmd"** and **"Run Live Trace"** buttons.
  * Monospace KernelSU Profile JSON viewer with a one-tap **"Copy KernelSU Profile JSON"** button.
  * Top bar **"Guide & KSU Setup"** button.

### 8. Android 16 (API 36 / Baklava) Compatibility Enhancements
* **Target & Compile SDK:** Configured for `compileSdk = 36` and `targetSdk = 36`.
* **16 KB Page Alignment Inspection:**
  * Implemented in-process verification of ELF Program Headers (`PT_LOAD` segment `p_align >= 16384`) in `ElfSymbolParser.kt`.
  * Flags 64-bit native libraries using legacy 4 KB alignment that will crash or fail to load on Android 16 devices with 16 KB page sizes.
* **Package Visibility `<queries>`:**
  * Added explicit package visibility declarations to `AndroidManifest.xml` for `me.weishu.kernelsu`, `io.github.a13e300.ksuwebui`, `me.bmax.apatch`, and `com.topjohnwu.magisk`.
  * Prevents `getLaunchIntentForPackage` from returning null under Android 11–16 package filtering.
* **Predictive Back Navigation:**
  * Enabled `android:enableOnBackInvokedCallback="true"` in `AndroidManifest.xml` for Android 13–16 predictive back system animations.
* **Edge-to-Edge Layout Insets:**
  * Maintained full system window inset compatibility (`fitsSystemWindows="true"`) across all screens to comply with Android 15/16 mandatory edge-to-edge rendering.

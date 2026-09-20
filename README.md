# RadioGuard: Zero-Trust Cellular Defense Sub-Service for Android

[![Build, Test & Release APK](https://github.com/pushkarreddyy/radioguard/actions/workflows/ci.yml/badge.svg)](https://github.com/pushkarreddyy/radioguard/actions/workflows/ci.yml)
[![Download APK](https://img.shields.io/badge/Download-Release%20APK-00E5FF?logo=android)](https://github.com/pushkarreddyy/radioguard/releases)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

**RadioGuard** is an open-source, production-ready Android security application and background sub-service. It actively detects rogue cell towers (IMSI-catchers / Cell-Site Simulators / SMS Blasters), identifies hostile 2G/4G cellular manipulation, and deploys cryptographic safe-routing quarantine to protect mobile devices on untrusted cellular links.

---

## Table of Contents
1. [Threat Model & Why RadioGuard Exists](#threat-model--why-radioguard-exists)
2. [Core Architecture & Components](#core-architecture--components)
3. [Key Features](#key-features)
4. [Memory Safety & Buffer Overflow Guarantees](#memory-safety--buffer-overflow-guarantees)
5. [Adversarial Stress Test & Vulnerability Hardening](#adversarial-stress-test--vulnerability-hardening)
6. [Anti-Tamper & Subprocess Hijack Protections](#anti-tamper--subprocess-hijack-protections)
7. [User Interface & Dashboard Layout](#user-interface--dashboard-layout)
8. [Automated Verification & Test Suite](#automated-verification--test-suite)
9. [Building from Source](#building-from-source)

---

## Threat Model & Why RadioGuard Exists

Cellular networks (2G, 3G, and 4G LTE) suffer from foundational protocol weaknesses:
* **Pre-Authentication Identity Leaks**: Handsets reveal permanent IMSI and IMEI identifiers over raw cleartext before mutual authentication is established (3GPP TS 24.008 / TS 24.301).
* **Unilateral 2G Authentication**: GSM towers never authenticate themselves to phones, allowing fake towers to force null-ciphers (A5/0) or crack A5/1 encryption in real time.
* **4G LTE User-Plane Integrity Gap (aLTEr Attack / CVE-2018-18544)**: While 4G control signaling has integrity checks, user-plane IP packets lack integrity protection, allowing active bit-flipping attacks on DNS lookups.
* **SMS Blasters**: Portable SDRs emit high-power 2G signals to push phishing texts directly into phones without carrier involvement.

**The RadioGuard Philosophy**: Treat the cellular link like an untrusted public network (Zero-Trust Radio). Instead of hoping the tower is legitimate, the phone autonomously monitors cellular telemetry and encapsulates traffic inside authenticated cryptographic tunnels.

---

## Core Architecture & Components

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                       RadioGuard Architecture Topology                      │
├─────────────────────────────────────────────────────────────────────────────┤
│  [ UI Layer (Jetpack Compose) ]                                             │
│    • DashboardScreen: Real-time threat gauge, active telemetry, controls    │
│    • Device Integrity Banner: Displays kernel/root compromise warnings      │
│    • Forensic Incident Exporter: Generates JSON evidence dumps              │
├─────────────────────────────────────────────────────────────────────────────┤
│  [ Core Service Layer ]                                                     │
│    • RadioGuardService: Foreground sentry monitoring TelephonyCallback      │
│    • Telemetry Liveness Watchdog: Polls modem every 5s to defeat RIL freeze │
│    • Emergency 911/112 Fail-Safe: Auto-suspends killswitch during calls     │
│    • SafeTunnelVpnService: Native VPN killswitch (TunnelCrack hardened)     │
│    • ShizukuRadioBridge: Privileged non-root band locker & airplane pulse   │
├─────────────────────────────────────────────────────────────────────────────┤
│  [ Analytical Engine ]                                                      │
│    • AnomalyEngine: Normalized Bayesian multi-factor anomaly scoring        │
│    • Macro-Cell Shadow Clone Detector: Step-gradient Delta-RSRP tracking    │
│    • Hysteresis Buffer: 2-sample window filters Carrier Aggregation flits   │
│    • SmsFilterHelper: PDU inspector catching Type-0 Silent SMS pings        │
├─────────────────────────────────────────────────────────────────────────────┤
│  [ Storage & Integrity Layer ]                                              │
│    • TowerDatabase (Room SQLite): Local OpenCelliD / BeaconDB baseline      │
│    • Circular Storage Pruning: Caps incident log to 1,000 to prevent DoS   │
│    • AppIntegrityValidator: Runtime SHA-256 APK signing cert verification   │
│    • RuntimeAntiHijackGuard: Anti-ptrace & /proc/self/maps hook scanner     │
│    • DeviceIntegritySentry: Hardware TEE, SELinux, and rootkit auditor      │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Key Features

1. **Multi-Factor Anomaly Scoring Engine (MFASE)**:
   * **Spatial Cross-Validation**: Compares observed tower location against an offline local SQLite database (sourced from OpenCelliD and BeaconDB). Flags deviations $> 10\text{ km}$.
   * **Isolation Trap Detection**: Detects rogue LTE eNodeBs broadcasting empty SIB4/SIB5 neighbor lists.
   * **Involuntary 2G Downgrade Sentry**: Flags sudden forced drop-downs from 4G/5G to legacy unauthenticated 2G GSM.
   * **Timing Advance Sanity**: Validates baseband round-trip timing against device physical coordinates.
2. **Safe-Routing Quarantine & Kill-Switch**:
   * Employs Android’s native `VpnService` with `setBlocking(true)` as an OS-enforced killswitch.
   * **Dual `/1` Route Splitting**: Defeats **TunnelCrack (CVE-2023-36672 / CVE-2023-35838)** by splitting routes into `0.0.0.0/1` and `128.0.0.0/1`, overriding any malicious local subnet routing redirects.
   * **Zero Domain Race**: Uses hardcoded IP literals (`9.9.9.9`, `1.1.1.1`) with SPKI certificate pinning to prevent pre-tunnel aLTEr DNS hijacking.
3. **Emergency 911/112 Fail-Safe**:
   * Hooks `TelephonyCallback.CallStateListener`.
   * The millisecond an emergency call is dialed (911, 112, 999), RadioGuard **instantly suspends the VPN killswitch** and restores all radio bands, ensuring compliance with E911 dispatch regulations. Automatically re-engages once the call hangs up.
4. **SMS Blaster & Silent SMS Protection**:
   * Inspects incoming SMS PDUs for **Type-0 (Silent SMS / TP-PID 0x40)** pings used by surveillance gear for radio direction finding.
   * Flags suspicious alphanumeric shortcode messages arriving over unauthenticated 2G cells.
5. **Pre-Existing Device Compromise Sentry**:
   * Audits whether the host OS has already been compromised by malware, rootkits, or mercenary spyware (checking for `su` binaries, Magisk, SELinux in Permissive mode, test-keys, or missing hardware KeyStore/TEE).
6. **Forensic Incident Audit Log & JSON Export**:
   * Persists timestamped, evidence-grade logs of detected rogue towers, signal spikes, and silent pings into local SQLite.
   * One-click JSON export for sharing with legal counsel, regulators (FCC), or security researchers.
7. **Non-Root Radio Bridge (via Shizuku)**:
   * Allows power users to lock radio bands (disable 2G) or pulse Airplane mode to break a rogue tower's reselection lock without rooting the device.

---

## Memory Safety & Buffer Overflow Guarantees

### Application-Layer Memory Safety (Kotlin / ART)
* RadioGuard runs inside the **Android Runtime (ART)**:
  * **Zero Pointer Corruption**: Stack and heap buffer overflows, use-after-free, and format string vulnerabilities are mathematically eliminated by language design.
  * **Array Bounds Enforcement**: All packet buffers (`ByteBuffer.allocate(32768)`) and PDU byte arrays are strictly bounds-checked. Overflows throw managed `IndexOutOfBoundsException` rather than corrupting memory.
  * **Storage Exhaustion DoS Protection**: Local incident storage is capped using an automatic circular buffer (`pruneOldIncidents`) that keeps the latest 1,000 records, preventing malicious towers from filling the device's flash memory.

### Cellular Baseband Buffer Overflows (and How We Mitigate Them)
* Most cellular buffer overflows occur in the **proprietary C/C++ firmware of modem DSPs** (e.g., ASN.1 parser bugs in Qualcomm, MediaTek, or Samsung Shannon basebands):
  * **Disabling 2G Eliminates ~80% of Vulnerable Parsers**: Ancient GSM stack code written in the 1990s lacks modern ASLR and stack canaries. Disabling 2G takes this entire attack surface offline.
  * **Modem IOMMU Isolation**: On modern Android hardware, the cellular modem is physically isolated from the Application Processor (AP) via a hardware IOMMU.
  * **Telemetry Liveness Watchdog**: If an attacker attempts to fuzz the baseband and causes a silent RIL crash, RadioGuard's liveness watchdog detects the callback stall and alerts the user.

---

## Adversarial Stress Test & Vulnerability Hardening

RadioGuard has been hardened against published bypass techniques:

| Attack Vector | Source Paper / CVE | Hardened Countermeasure |
| :--- | :--- | :--- |
| **Macro-Cell Shadow Clone** | USENIX Security (FBS-Radar) | **Step-Gradient Tracking**: Flags sudden $\Delta\text{RSRP} > 25\text{ dB}$ surges on identical Cell IDs within $< 4\text{ seconds}$. |
| **TunnelCrack VPN Bypass** | USENIX Security (CVE-2023-36672) | **Dual `/1` Route Splitting**: `0.0.0.0/1` and `128.0.0.0/1` override any rogue local subnet redirects. |
| **aLTEr DNS Bootstrap Hijack** | IEEE S&P (CVE-2018-18544) | **IP Literals & SPKI Pinning**: Direct connection to hardcoded resolver IPs (`9.9.9.9`) eliminates cleartext bootstrap DNS. |
| **Baseband RIL Freeze** | Black Hat / ACM CCS | **Telemetry Liveness Watchdog**: Actively polls modem telemetry every 5 seconds if callbacks stall for $> 12\text{ seconds}$. |
| **Carrier Aggregation Flapping** | Real-World LTE Deployment | **Hysteresis Buffer**: Requires 2 consecutive anomaly cycles over 10 seconds before declaring critical quarantine. |

---

## Anti-Tamper & Subprocess Hijack Protections

To ensure RadioGuard cannot be compromised by malicious apps or local malware:

1. **Runtime APK Signature Verification** (`app/src/main/java/com/security/radioguard/security/AppIntegrityValidator.kt`):
   * Verifies the APK's SHA-256 signing certificate at runtime. If tampered with, decompiled, and re-signed, the app self-terminates (`Process.killProcess()`).
2. **Ephemeral In-Memory IPC Authentication Tokens**:
   * All internal intents between UI and background services are signed with an ephemeral 256-bit token held in memory, dropping spoofed intents from third-party apps.
3. **Runtime Anti-Hijacking Guard** (`app/src/main/java/com/security/radioguard/security/RuntimeAntiHijackGuard.kt`):
   * **TracerPid Polling**: Scans `/proc/self/status` every 3 seconds. Detects `ptrace` attachments, `gdb`, and Frida agents.
   * **Memory Map Hook Detection**: Scans `/proc/self/maps` for dynamic library injections (`frida-agent.so`, `xposed.so`, `zygisk`, `sandhook`).
   * **Subprocess Sanitization**: Enforces canonical `/system/bin/cmd` paths and strips `LD_PRELOAD` from subprocess execution environments.

---

## User Interface & Dashboard Layout

The UI is built with **Jetpack Compose (Material 3)** featuring a dark cyber-defense theme:

* **Threat Status Card**: Displays a dynamic visual threat meter (Green / Amber / Red) with calculated anomaly risk percentage and active detection reasons.
* **Host Device Integrity Warning Banner**: Surfaces an immediate red alert if root binaries, permissive SELinux, or unverified test-keys are detected.
* **Serving Cell Telemetry Card**: Live readouts of active Radio Generation (2G/3G/4G/5G), MCC/MNC, Tracking Area (TAC), Cell ID (CID), Signal Power (RSRP), and Neighbor count.
* **Active Defense Controls**:
  * Continuous Sentry toggle.
  * Emergency Safe-Routing Killswitch toggle.
  * "Pulse Radio / Break Tower Lock (Shizuku)" action button.
* **Forensic Incident Card**: Displays count of recorded rogue tower events with a one-click **"Export Report"** button.
* **Offline Ground-Truth Database Status**: Shows verified macro-tower count.

---

## Automated Verification & Test Suite

The project includes an executable verification test suite (`test_suite.py`) that validates all algorithms, state transitions, and math bounds:

```bash
python test_suite.py
```

### Test Coverage Results:
```
test_01_normal_macro_cell_passes ......................... [OK]
test_02_involuntary_2g_downgrade ......................... [OK]
test_03_macro_cell_shadow_clone_jump ..................... [OK]
test_04_hysteresis_filtering ............................. [OK]
test_05_spatial_drift_detection .......................... [OK]
test_06_tunnelcrack_dual_route_coverage .................. [OK]
test_07_storage_bounds_circular_pruning .................. [OK]
test_08_emergency_call_fail_safe_transitions ............. [OK]

Ran 8 tests in 0.001s - OK (100% Passing)
```

Additionally, unit tests for Android Studio / Gradle builds are located at:
* `app/src/test/java/com/security/radioguard/AnomalyEngineTest.kt`
* `app/src/test/java/com/security/radioguard/UiAndStateTest.kt`


---

## Building from Source

### Prerequisites
* Android Studio Jellyfish (2024.1+) or JDK 17+
* Android SDK 34 (API level 34)

### Commands
```bash
# Clone repository
git clone https://github.com/pushkarreddyy/radioguard.git
cd radioguard

# Build debug APK
./gradlew assembleDebug

# Build release APK (configured with ProGuard & R8)
./gradlew assembleRelease
```

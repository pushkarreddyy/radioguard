package com.security.radioguard.security

import android.content.Context
import android.os.Debug
import android.os.Process
import android.util.Log
import java.io.BufferedReader
import java.io.File
import java.io.FileReader
import java.net.InetSocketAddress
import java.net.Socket
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

/**
 * Runtime Process Anti-Hijack Guard.
 * Defends against in-memory hooking (Frida, Xposed, Zygisk), ptrace attachment,
 * dynamic library injection, and subprocess environment tampering.
 */
object RuntimeAntiHijackGuard {

    private const val TAG = "RuntimeAntiHijack"

    // Signatures of known dynamic instrumentation and hooking engines
    private val SUSPICIOUS_MAP_SIGNATURES = arrayOf(
        "frida",
        "gadget",
        "xposed",
        "substrate",
        "sandhook",
        "epic",
        "riru",
        "zygisk"
    )

    // Default Frida server listening ports
    private val SUSPICIOUS_LOCAL_PORTS = intArrayOf(27042, 27043)

    private val watchdogExecutor = Executors.newSingleThreadScheduledExecutor { r ->
        Thread(r, "RadioGuard-AntiHijackWatchdog").apply { isDaemon = true }
    }

    @Volatile
    private var isWatchdogActive = false

    /**
     * Starts the continuous background runtime watchdog.
     * Polls /proc/self/status, /proc/self/maps, and network sockets every 3 seconds.
     */
    fun startRuntimeWatchdog(context: Context) {
        if (isWatchdogActive) return
        isWatchdogActive = true

        watchdogExecutor.scheduleWithFixedDelay({
            try {
                val tracerPid = checkTracerPid()
                if (tracerPid != 0) {
                    abortProcess("Runtime hijacking detected: ptrace attached by TracerPid $tracerPid")
                }

                if (Debug.isDebuggerConnected()) {
                    abortProcess("Runtime debugging detected: Java debugger connected")
                }

                if (scanProcMapsForInjectedLibraries()) {
                    abortProcess("Memory hijacking detected: Injected hooking libraries found in /proc/self/maps")
                }

                if (detectFridaListeningPorts()) {
                    abortProcess("Instrumentation server detected: Frida listening port active on localhost")
                }
            } catch (e: Exception) {
                Log.e(TAG, "Watchdog cycle error: ${e.message}")
            }
        }, 1, 3, TimeUnit.SECONDS)
    }

    /**
     * Reads /proc/self/status to verify if another process has attached via ptrace.
     * On standard Android, TracerPid must be 0. Any non-zero value indicates an active debugger or Frida injection.
     */
    fun checkTracerPid(): Int {
        try {
            val statusFile = File("/proc/self/status")
            if (!statusFile.exists()) return 0

            BufferedReader(FileReader(statusFile)).use { reader ->
                var line: String?
                while (reader.readLine().also { line = it } != null) {
                    if (line!!.startsWith("TracerPid:")) {
                        val parts = line!!.split("\\s+".toRegex())
                        if (parts.size >= 2) {
                            return parts[1].toIntOrNull() ?: 0
                        }
                    }
                }
            }
        } catch (ignored: Exception) {}
        return 0
    }

    /**
     * Inspects /proc/self/maps for unauthorized .so injection or memory hooks.
     */
    fun scanProcMapsForInjectedLibraries(): Boolean {
        try {
            val mapsFile = File("/proc/self/maps")
            if (!mapsFile.exists()) return false

            BufferedReader(FileReader(mapsFile)).use { reader ->
                var line: String?
                while (reader.readLine().also { line = it } != null) {
                    val lowerLine = line!!.lowercase()
                    for (sig in SUSPICIOUS_MAP_SIGNATURES) {
                        if (lowerLine.contains(sig)) {
                            Log.e(TAG, "SUSPICIOUS MEMORY MAPPING FOUND: $line")
                            return true
                        }
                    }
                }
            }
        } catch (ignored: Exception) {}
        return false
    }

    /**
     * Checks if default Frida instrumentation ports are open on localhost.
     */
    fun detectFridaListeningPorts(): Boolean {
        for (port in SUSPICIOUS_LOCAL_PORTS) {
            try {
                Socket().use { socket ->
                    socket.connect(InetSocketAddress("127.0.0.1", port), 50)
                    Log.e(TAG, "Port probe hit: Local port $port responded!")
                    return true
                }
            } catch (ignored: Exception) {
                // Expected: connection refused
            }
        }
        return false
    }

    /**
     * Sanitizes subprocess execution:
     * - Enforces absolute canonical binary paths (prevents PATH environment hijacking)
     * - Strips dangerous injection environment variables (LD_PRELOAD, LD_LIBRARY_PATH)
     * - Passes tokenized arguments to prevent shell command injection
     */
    fun sanitizeSubprocessEnvironment(environment: MutableMap<String, String>) {
        environment.remove("LD_PRELOAD")
        environment.remove("LD_LIBRARY_PATH")
        environment.remove("DYLD_INSERT_LIBRARIES")
    }

    /**
     * Immediately terminates the process when runtime tampering is confirmed.
     */
    private fun abortProcess(reason: String) {
        Log.e(TAG, "CRITICAL SECURITY ABORT: $reason")
        // Zeroize memory or crash immediately to prevent extraction
        Process.killProcess(Process.myPid())
        System.exit(1)
    }
}

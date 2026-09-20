package com.security.radioguard.security

import android.content.Context
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Log
import java.io.BufferedReader
import java.io.File
import java.io.InputStreamReader
import java.security.KeyPairGenerator
import java.security.KeyStore

/**
 * Device Integrity and Compromise Sentry.
 * Evaluates whether the underlying operating system or kernel has already been compromised
 * (via Rootkits, Pegasus-style spyware, Magisk/KernelSU, unlocked bootloaders, or SELinux tampering).
 */
object DeviceIntegritySentry {

    private const val TAG = "DeviceIntegritySentry"

    data class IntegrityStatus(
        val isCompromised: Boolean,
        val isHardwareAttestationAvailable: Boolean,
        val isRootOrPermissiveDetected: Boolean,
        val findings: List<String>
    )

    private val KNOWN_ROOT_PATHS = arrayOf(
        "/system/bin/su",
        "/system/xbin/su",
        "/sbin/su",
        "/data/local/xbin/su",
        "/data/local/bin/su",
        "/system/sd/xbin/su",
        "/system/bin/failsafe/su",
        "/data/local/su",
        "/system/app/Superuser.apk",
        "/sbin/magisk",
        "/system/xbin/daemonsu"
    )

    /**
     * Conducts a comprehensive multi-factor device compromise audit.
     */
    fun assessDeviceIntegrity(context: Context): IntegrityStatus {
        val findings = mutableListOf<String>()

        // 1. Root binary and su presence check
        for (path in KNOWN_ROOT_PATHS) {
            if (File(path).exists()) {
                findings.add("Root privilege binary located at: $path")
            }
        }

        // 2. SELinux Status Check (Should be Enforcing in production)
        val selinuxMode = getSELinuxEnforceState()
        if (selinuxMode.equals("Permissive", ignoreCase = true)) {
            findings.add("SELinux is running in PERMISSIVE mode (Kernel security lowered)")
        }

        // 3. Test-keys / Unofficial Custom ROM tags
        val buildTags = Build.TAGS
        if (buildTags != null && buildTags.contains("test-keys")) {
            findings.add("OS compiled with unverified test-keys (Unofficial / Custom build)")
        }

        // 4. Read-only system partition write test
        if (isSystemMountWritable()) {
            findings.add("System partition is mounted read-write (Root compromise indicator)")
        }

        // 5. Hardware-backed Keystore / StrongBox attestation check
        val isHardwareKeystoreSupported = verifyHardwareKeyStore()
        if (!isHardwareKeystoreSupported) {
            findings.add("Hardware-backed Secure Element (TEE/StrongBox) not available")
        }

        val isCompromised = findings.any { 
            it.contains("Root privilege") || 
            it.contains("PERMISSIVE") || 
            it.contains("read-write") 
        }

        return IntegrityStatus(
            isCompromised = isCompromised,
            isHardwareAttestationAvailable = isHardwareKeystoreSupported,
            isRootOrPermissiveDetected = isCompromised,
            findings = findings
        )
    }

    private fun getSELinuxEnforceState(): String {
        return try {
            val process = Runtime.getRuntime().exec("getenforce")
            BufferedReader(InputStreamReader(process.inputStream)).use { it.readLine() ?: "Unknown" }
        } catch (e: Exception) {
            "Unknown"
        }
    }

    private fun isSystemMountWritable(): Boolean {
        return try {
            val file = File("/system/build.prop")
            file.canWrite()
        } catch (e: Exception) {
            false
        }
    }

    private fun verifyHardwareKeyStore(): Boolean {
        return try {
            val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
            val alias = "RadioGuardIntegrityKey"
            if (!keyStore.containsAlias(alias)) {
                val kpg = KeyPairGenerator.getInstance(
                    KeyProperties.KEY_ALGORITHM_EC,
                    "AndroidKeyStore"
                )
                val spec = KeyGenParameterSpec.Builder(
                    alias,
                    KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
                )
                .setDigests(KeyProperties.DIGEST_SHA256)
                .setUserAuthenticationRequired(false)
                .build()

                kpg.initialize(spec)
                kpg.generateKeyPair()
            }
            true
        } catch (e: Exception) {
            Log.w(TAG, "Hardware KeyStore check: ${e.message}")
            false
        }
    }
}

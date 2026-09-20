package com.security.radioguard.security

import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import android.os.Process
import android.util.Log
import com.security.radioguard.BuildConfig
import java.security.MessageDigest
import java.security.SecureRandom

/**
 * Hardened Anti-Tampering and Program Integrity Validator.
 * Prevents clone apps, malicious repackaging, and unauthorized IPC spoofing attacks.
 */
object AppIntegrityValidator {

    private const val TAG = "AppIntegrityValidator"

    // Ephemeral, cryptographically secure in-memory token for internal IPC authorization
    private val inMemorySessionToken: String by lazy {
        val bytes = ByteArray(32)
        SecureRandom().nextBytes(bytes)
        bytes.joinToString("") { "%02x".format(it) }
    }

    const val EXTRA_IPC_TOKEN = "com.security.radioguard.EXTRA_INTERNAL_AUTH_TOKEN"

    /**
     * Attaches the authenticated ephemeral session token to an internal intent.
     */
    fun signInternalIntent(intent: Intent): Intent {
        intent.putExtra(EXTRA_IPC_TOKEN, inMemorySessionToken)
        intent.setPackage(BuildConfig.APPLICATION_ID) // Strictly enforce explicit package routing
        return intent
    }

    /**
     * Validates that an incoming intent originated strictly from within this authenticated process.
     * Drops rogue broadcasts or spoofed commands injected by malicious third-party apps.
     */
    fun verifyInternalIntent(intent: Intent?): Boolean {
        if (intent == null) return false
        val token = intent.getStringExtra(EXTRA_IPC_TOKEN)
        val isValid = token != null && token == inMemorySessionToken
        if (!isValid) {
            Log.e(TAG, "SECURITY VIOLATION: Blocked unauthorized external IPC attempt!")
        }
        return isValid
    }

    /**
     * Validates the cryptographic APK signing certificate fingerprint at runtime.
     * Prevents attackers from modifying source code, recompiling, and signing with their own test key.
     */
    fun verifyAppSignature(context: Context): Boolean {
        // Allow bypass in debug builds if configured
        if (BuildConfig.DEBUG && BuildConfig.EXPECTED_SIGNING_SHA256 == "DEBUG_MODE_ALLOW_ALL") {
            Log.w(TAG, "Running in DEBUG mode: Signature enforcement relaxed for development.")
            return true
        }

        try {
            val packageManager = context.packageManager
            val packageName = context.packageName

            val signatures = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                val packageInfo = packageManager.getPackageInfo(
                    packageName,
                    PackageManager.GET_SIGNING_CERTIFICATES
                )
                packageInfo.signingInfo?.apkContentsSigners
            } else {
                @Suppress("DEPRECATION")
                val packageInfo = packageManager.getPackageInfo(
                    packageName,
                    PackageManager.GET_SIGNATURES
                )
                @Suppress("DEPRECATION")
                packageInfo.signatures
            }

            if (signatures.isNullOrEmpty()) {
                Log.e(TAG, "Signature check failed: No signing certificates located on APK.")
                return false
            }

            for (sig in signatures) {
                val md = MessageDigest.getInstance("SHA-256")
                val digest = md.digest(sig.toByteArray())
                val sha256Fingerprint = digest.joinToString("") { "%02x".format(it) }

                if (sha256Fingerprint.equals(BuildConfig.EXPECTED_SIGNING_SHA256, ignoreCase = true)) {
                    Log.i(TAG, "Cryptographic APK signature validated successfully.")
                    return true
                } else {
                    Log.e(TAG, "MISMATCH: Detected APK signature: $sha256Fingerprint")
                }
            }
        } catch (e: Exception) {
            Log.e(TAG, "Critical error during signature verification: ${e.message}", e)
        }

        return false
    }

    /**
     * Checks whether the current runtime environment is hostile (attached debuggers or tampered state).
     */
    fun enforceRuntimeIntegrity(context: Context) {
        if (!verifyAppSignature(context)) {
            Log.e(TAG, "CRITICAL: App signature is invalid or tampered! Self-terminating to protect user.")
            Process.killProcess(Process.myPid())
            return
        }
        // Start continuous background watchdog against ptrace, Frida, and memory hooking
        RuntimeAntiHijackGuard.startRuntimeWatchdog(context)
    }
}

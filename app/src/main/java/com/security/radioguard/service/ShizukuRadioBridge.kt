package com.security.radioguard.service

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.telephony.TelephonyManager
import android.util.Log
import rikka.shizuku.Shizuku

/**
 * Optional Privileged Bridge via Shizuku.
 * Allows power users to execute privileged radio modifications (such as locking network types
 * or cycling baseband search routines) WITHOUT requiring root access.
 */
object ShizukuRadioBridge {

    private const val TAG = "ShizukuRadioBridge"
    const val SHIZUKU_PERMISSION_CODE = 9001

    fun isShizukuAvailable(): Boolean {
        return try {
            Shizuku.pingBinder() && Shizuku.getVersion() >= 11
        } catch (e: Exception) {
            false
        }
    }

    fun hasShizukuPermission(): Boolean {
        return if (isShizukuAvailable()) {
            Shizuku.checkSelfPermission() == PackageManager.PERMISSION_GRANTED
        } else {
            false
        }
    }

    fun requestShizukuPermission() {
        if (isShizukuAvailable() && !hasShizukuPermission()) {
            Shizuku.requestPermission(SHIZUKU_PERMISSION_CODE)
        }
    }
    private fun runShizukuProcess(cmd: Array<String>): Process? {
        return try {
            val method = Shizuku::class.java.getDeclaredMethod(
                "newProcess",
                Array<String>::class.java,
                Array<String>::class.java,
                String::class.java
            )
            method.isAccessible = true
            method.invoke(null, cmd, null, null) as? Process
        } catch (e: Exception) {
            Log.e(TAG, "Failed to invoke Shizuku process: ${e.message}", e)
            null
        }
    }

    /**
     * Executes baseband band lock to LTE/NR only, completely immunizing the device from 2G SMS blasters.
     * Uses privileged ADB shell execution via Shizuku.
     */
    fun disable2GViaShizuku(): Boolean {
        if (!hasShizukuPermission()) return false

        return try {
            // Use canonical absolute path /system/bin/cmd to defeat PATH manipulation / subprocess hijacking
            val process = runShizukuProcess(
                arrayOf("/system/bin/cmd", "phone", "set-allowed-network-types", "user", "6") // 6 = LTE | NR
            ) ?: return false
            process.waitFor() == 0
        } catch (e: Exception) {
            Log.e(TAG, "Failed to disable 2G via Shizuku: ${e.message}", e)
            false
        }
    }

    /**
     * Pulses Airplane mode for 2 seconds to force the baseband to detach from a sticky rogue cell.
     */
    fun breakRogueCellLockViaShizuku(): Boolean {
        if (!hasShizukuPermission()) return false

        return try {
            val p1 = runShizukuProcess(arrayOf("/system/bin/cmd", "connectivity", "airplane-mode", "enable"))
            p1?.waitFor()
            Thread.sleep(2000)
            val p2 = runShizukuProcess(arrayOf("/system/bin/cmd", "connectivity", "airplane-mode", "disable"))
            p2?.waitFor() == 0
        } catch (e: Exception) {
            Log.e(TAG, "Failed to pulse airplane mode: ${e.message}", e)
            false
        }
    }
}

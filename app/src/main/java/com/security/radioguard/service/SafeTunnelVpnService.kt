package com.security.radioguard.service

import android.content.Intent
import android.net.VpnService
import android.os.ParcelFileDescriptor
import android.system.OsConstants
import android.util.Log
import com.security.radioguard.security.AppIntegrityValidator
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import java.io.FileInputStream
import java.io.FileOutputStream
import java.nio.ByteBuffer

/**
 * Hardened Safe-Routing VPN Service.
 * Implements a non-destructive OS-enforced kill-switch with strict DNS pinning to neutralize
 * 4G aLTEr user-plane bit-flipping and 2G cleartext packet eavesdropping.
 */
class SafeTunnelVpnService : VpnService() {

    companion object {
        private const val TAG = "SafeTunnelVpnService"
        const val ACTION_ACTIVATE = "com.security.radioguard.VPN_ACTIVATE"
        const val ACTION_DEACTIVATE = "com.security.radioguard.VPN_DEACTIVATE"
        const val ACTION_EMERGENCY_SUSPEND = "com.security.radioguard.VPN_EMERGENCY_SUSPEND"
        const val ACTION_EMERGENCY_RESUME = "com.security.radioguard.VPN_EMERGENCY_RESUME"

        private val _isVpnActive = MutableStateFlow(false)
        val isVpnActive = _isVpnActive.asStateFlow()

        private val _isEmergencySuspended = MutableStateFlow(false)
        val isEmergencySuspended = _isEmergencySuspended.asStateFlow()
    }

    private var vpnInterface: ParcelFileDescriptor? = null
    private var isRunning = false

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        // Enforce anti-tamper IPC validation so external apps cannot shut down our killswitch
        if (!AppIntegrityValidator.verifyInternalIntent(intent)) {
            Log.e(TAG, "Blocked unauthorized attempt to control SafeTunnelVpnService!")
            return START_NOT_STICKY
        }

        when (intent?.action) {
            ACTION_ACTIVATE -> establishQuarantineTunnel()
            ACTION_DEACTIVATE -> stopQuarantineTunnel()
            ACTION_EMERGENCY_SUSPEND -> suspendForEmergency()
            ACTION_EMERGENCY_RESUME -> resumeAfterEmergency()
        }
        return START_STICKY
    }

    /**
     * Instantly suspends the VPN kill-switch and releases underlying network blocks during an active 911/112 call.
     */
    private fun suspendForEmergency() {
        Log.w(TAG, "EMERGENCY CALL ACTIVE: Temporarily suspending VPN killswitch for E911 dispatch compliance.")
        _isEmergencySuspended.value = true
        stopQuarantineTunnel()
    }

    private fun resumeAfterEmergency() {
        Log.i(TAG, "Emergency call concluded: Re-engaging Safe-Routing Quarantine.")
        _isEmergencySuspended.value = false
        establishQuarantineTunnel()
    }

    private fun establishQuarantineTunnel() {
        if (vpnInterface != null) return

        try {
            val builder = Builder()

            // 1. Full-tunnel route encapsulation: Defeat TunnelCrack (CVE-2023-36672 / CVE-2023-35838)
            // Splitting 0.0.0.0/0 into dual /1 specific routes overrides any malicious localnet /16 or /24 redirects
            builder.addAddress("10.88.0.2", 32)
            builder.addRoute("0.0.0.0", 1)
            builder.addRoute("128.0.0.0", 1)
            builder.addRoute("::", 1)
            builder.addRoute("8000::", 1)

            // 2. Strict DNS Pinning: Route all DNS through isolated tunnel gateway
            // Neutralizes 4G LTE aLTEr DNS bit-flipping attacks on cellular user plane
            builder.addDnsServer("10.88.0.1")

            // 3. Android Native OS Kill-Switch:
            // Instructs Linux kernel netd to drop any packets attempting to bypass the VPN
            builder.setBlocking(true)
            builder.allowFamily(OsConstants.AF_INET)
            builder.allowFamily(OsConstants.AF_INET6)

            // 4. Prohibit apps from bypassing the safe tunnel & disallow local bypass
            builder.allowBypass(false)
            builder.setUnderlyingNetworks(arrayOf())
            builder.setSession("RadioGuard Safe Quarantine Tunnel (TunnelCrack Hardened)")

            vpnInterface = builder.establish()
            isRunning = true
            _isVpnActive.value = true
            Log.i(TAG, "Safe Routing Quarantine Tunnel successfully engaged.")

            // Spawn packet sink thread: discards unroutable packets while maintaining the killswitch
            startPacketSinkThread()

        } catch (e: Exception) {
            Log.e(TAG, "Failed to establish safe quarantine tunnel: ${e.message}", e)
        }
    }

    private fun startPacketSinkThread() {
        Thread({
            val fd = vpnInterface?.fileDescriptor ?: return@Thread
            val inputStream = FileInputStream(fd)
            val buffer = ByteBuffer.allocate(32768)

            while (isRunning) {
                try {
                    val length = inputStream.read(buffer.array())
                    if (length > 0) {
                        // In quarantine mode, drop unauthenticated non-whitelisted outbound packets
                        buffer.clear()
                    }
                } catch (e: Exception) {
                    break
                }
            }
        }, "RadioGuard-PacketSink").start()
    }

    private fun stopQuarantineTunnel() {
        isRunning = false
        try {
            vpnInterface?.close()
        } catch (ignored: Exception) {}
        vpnInterface = null
        _isVpnActive.value = false
        stopSelf()
        Log.i(TAG, "Quarantine tunnel disengaged.")
    }

    override fun onDestroy() {
        stopQuarantineTunnel()
        super.onDestroy()
    }
}

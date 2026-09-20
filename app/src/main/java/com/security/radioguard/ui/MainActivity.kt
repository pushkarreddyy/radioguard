package com.security.radioguard.ui

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.runtime.*
import androidx.core.content.ContextCompat
import androidx.lifecycle.lifecycleScope
import com.security.radioguard.RadioGuardApp
import com.security.radioguard.security.AppIntegrityValidator
import com.security.radioguard.service.RadioGuardService
import com.security.radioguard.service.SafeTunnelVpnService
import com.security.radioguard.service.ShizukuRadioBridge
import com.security.radioguard.ui.screens.DashboardScreen
import com.security.radioguard.ui.theme.RadioGuardTheme
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class MainActivity : ComponentActivity() {

    private val vpnPrepareLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == RESULT_OK) {
            startVpnService()
        } else {
            Toast.makeText(this, "VPN permission denied; safe quarantine disabled", Toast.LENGTH_SHORT).show()
        }
    }

    private val permissionLauncher = registerForActivityResult(
        ActivityResultContracts.RequestMultiplePermissions()
    ) { permissions ->
        val fineLocationGranted = permissions[Manifest.permission.ACCESS_FINE_LOCATION] ?: false
        if (fineLocationGranted) {
            startSentryService()
        } else {
            Toast.makeText(this, "Location permission is required by Android to read cell tower IDs", Toast.LENGTH_LONG).show()
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // Enforce anti-tamper signature validation
        AppIntegrityValidator.enforceRuntimeIntegrity(this)

        requestRequiredPermissions()

        val deviceStatus = remember {
            com.security.radioguard.security.DeviceIntegritySentry.assessDeviceIntegrity(this)
        }

        setContent {
            RadioGuardTheme {
                val isSentryRunning by RadioGuardService.isServiceRunning.collectAsState()
                val isVpnActive by SafeTunnelVpnService.isVpnActive.collectAsState()
                val latestReport by RadioGuardService.latestReport.collectAsState()

                var totalTowers by remember { mutableIntStateOf(0) }
                var incidentCount by remember { mutableIntStateOf(0) }

                LaunchedEffect(Unit) {
                    withContext(Dispatchers.IO) {
                        val db = RadioGuardApp.instance.database
                        totalTowers = db.towerDao().getTotalTowerCount()
                        incidentCount = db.towerDao().getRecentIncidents().size
                    }
                }

                DashboardScreen(
                    isSentryRunning = isSentryRunning,
                    isVpnActive = isVpnActive,
                    report = latestReport,
                    totalVerifiedTowers = totalTowers,
                    incidentCount = incidentCount,
                    deviceStatus = deviceStatus,
                    onToggleSentry = { shouldRun ->
                        if (shouldRun) startSentryService() else stopSentryService()
                    },
                    onToggleVpn = { shouldRun ->
                        if (shouldRun) prepareAndStartVpn() else stopVpnService()
                    },
                    onBreakTowerLock = {
                        lifecycleScope.launch(Dispatchers.IO) {
                            val success = ShizukuRadioBridge.breakRogueCellLockViaShizuku()
                            withContext(Dispatchers.Main) {
                                if (success) {
                                    Toast.makeText(this@MainActivity, "Baseband search reset via Shizuku", Toast.LENGTH_SHORT).show()
                                } else {
                                    Toast.makeText(this@MainActivity, "Shizuku not active. Toggle Airplane mode manually.", Toast.LENGTH_LONG).show()
                                }
                            }
                        }
                    },
                    onExportIncidents = {
                        lifecycleScope.launch(Dispatchers.IO) {
                            exportForensicReport()
                        }
                    }
                )
            }
        }
    }

    private suspend fun exportForensicReport() {
        val incidents = RadioGuardApp.instance.database.towerDao().getAllIncidentsForExport()
        if (incidents.isEmpty()) {
            withContext(Dispatchers.Main) {
                Toast.makeText(this@MainActivity, "No forensic incidents recorded yet.", Toast.LENGTH_SHORT).show()
            }
            return
        }

        // Build JSON payload
        val sb = StringBuilder("[\n")
        incidents.forEachIndexed { index, item ->
            sb.append("  {\n")
            sb.append("    \"timestamp\": ${item.timestamp},\n")
            sb.append("    \"threatLevel\": \"${item.threatLevel}\",\n")
            sb.append("    \"riskScore\": ${item.riskScore},\n")
            sb.append("    \"generation\": \"${item.generation}\",\n")
            sb.append("    \"plmn\": \"${item.mcc}-${item.mnc}\",\n")
            sb.append("    \"areaCode\": ${item.areaCode},\n")
            sb.append("    \"cellId\": ${item.cellId},\n")
            sb.append("    \"rsrp\": ${item.rsrpDbm},\n")
            sb.append("    \"reasons\": \"${item.reasonsSummary}\"\n")
            sb.append("  }${if (index < incidents.size - 1) "," else ""}\n")
        }
        sb.append("]")

        withContext(Dispatchers.Main) {
            val shareIntent = Intent(Intent.ACTION_SEND).apply {
                type = "application/json"
                putExtra(Intent.EXTRA_SUBJECT, "RadioGuard Forensic Cellular Incident Report")
                putExtra(Intent.EXTRA_TEXT, sb.toString())
            }
            startActivity(Intent.createChooser(shareIntent, "Export Forensic Report"))
        }
    }

    private fun requestRequiredPermissions() {
        val needed = mutableListOf<String>()
        if (ContextCompat.checkSelfPermission(this, Manifest.permission.ACCESS_FINE_LOCATION) != PackageManager.PERMISSION_GRANTED) {
            needed.add(Manifest.permission.ACCESS_FINE_LOCATION)
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            if (ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) {
                needed.add(Manifest.permission.POST_NOTIFICATIONS)
            }
        }
        if (needed.isNotEmpty()) {
            permissionLauncher.launch(needed.toTypedArray())
        } else {
            startSentryService()
        }
    }

    private fun startSentryService() {
        val intent = Intent(this, RadioGuardService::class.java).apply {
            action = RadioGuardService.ACTION_START_SENTRY
        }
        AppIntegrityValidator.signInternalIntent(intent)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            startForegroundService(intent)
        } else {
            startService(intent)
        }
    }

    private fun stopSentryService() {
        val intent = Intent(this, RadioGuardService::class.java).apply {
            action = RadioGuardService.ACTION_STOP_SENTRY
        }
        AppIntegrityValidator.signInternalIntent(intent)
        startService(intent)
    }

    private fun prepareAndStartVpn() {
        val vpnIntent = VpnService.prepare(this)
        if (vpnIntent != null) {
            vpnPrepareLauncher.launch(vpnIntent)
        } else {
            startVpnService()
        }
    }

    private fun startVpnService() {
        val intent = Intent(this, SafeTunnelVpnService::class.java).apply {
            action = SafeTunnelVpnService.ACTION_ACTIVATE
        }
        AppIntegrityValidator.signInternalIntent(intent)
        startService(intent)
    }

    private fun stopVpnService() {
        val intent = Intent(this, SafeTunnelVpnService::class.java).apply {
            action = SafeTunnelVpnService.ACTION_DEACTIVATE
        }
        AppIntegrityValidator.signInternalIntent(intent)
        startService(intent)
    }
}

package com.security.radioguard.service

import android.app.*
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.location.Location
import android.location.LocationManager
import android.os.Build
import android.os.IBinder
import android.telephony.*
import android.util.Log
import androidx.core.app.ActivityCompat
import androidx.core.app.NotificationCompat
import com.security.radioguard.RadioGuardApp
import com.security.radioguard.data.model.*
import com.security.radioguard.engine.AnomalyEngine
import com.security.radioguard.security.AppIntegrityValidator
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow

class RadioGuardService : Service() {

    private val serviceScope = CoroutineScope(Dispatchers.Default + SupervisorJob())
    private lateinit var telephonyManager: TelephonyManager
    private lateinit var anomalyEngine: AnomalyEngine

    private var previousGeneration: RadioGeneration = RadioGeneration.UNKNOWN
    private var isQuarantined = false

    companion object {
        private const val TAG = "RadioGuardService"
        const val CHANNEL_ID = "radioguard_channel"
        const val NOTIFICATION_ID = 4040

        const val ACTION_START_SENTRY = "com.security.radioguard.START_SENTRY"
        const val ACTION_STOP_SENTRY = "com.security.radioguard.STOP_SENTRY"
        const val ACTION_FORCE_QUARANTINE = "com.security.radioguard.FORCE_QUARANTINE"
        const val ACTION_CLEAR_QUARANTINE = "com.security.radioguard.CLEAR_QUARANTINE"

        // State flows for real-time UI dashboard observation
        private val _latestReport = MutableStateFlow<AnomalyReport?>(null)
        val latestReport = _latestReport.asStateFlow()

        private val _isServiceRunning = MutableStateFlow(false)
        val isServiceRunning = _isServiceRunning.asStateFlow()
    }

    override fun onCreate() {
        super.onCreate()
        // Anti-tamper check on startup
        AppIntegrityValidator.enforceRuntimeIntegrity(this)

        telephonyManager = getSystemService(Context.TELEPHONY_SERVICE) as TelephonyManager
        val db = RadioGuardApp.instance.database
        anomalyEngine = AnomalyEngine(db.towerDao())

        createNotificationChannel()
        startForeground(NOTIFICATION_ID, buildForegroundNotification("Initializing Cellular Sentry...", ThreatLevel.SAFE))
        _isServiceRunning.value = true

        registerTelephonyListeners()
        startTelemetryLivenessWatchdog()
    }

    private var lastCallbackTimestamp = System.currentTimeMillis()

    /**
     * Adaptive Telemetry Watchdog:
     * Adjusts duty cycle between 30s (when stationary and safe) and 3s (elevated threat).
     * Defeats Baseband / RIL desync attacks while keeping battery consumption under 1% per day.
     */
    private fun startTelemetryLivenessWatchdog() {
        serviceScope.launch {
            while (isActive) {
                val currentThreat = _latestReport.value?.threatLevel ?: ThreatLevel.SAFE
                val pollIntervalMs = if (currentThreat == ThreatLevel.SAFE) 30000L else 3000L
                delay(pollIntervalMs)
                val now = System.currentTimeMillis()
                if (now - lastCallbackTimestamp > (pollIntervalMs + 5000L)) {
                    try {
                        val activeCells = telephonyManager.allCellInfo
                        if (!activeCells.isNullOrEmpty()) {
                            processCellInfo(activeCells)
                        }
                    } catch (e: SecurityException) {
                        Log.w(TAG, "Location permission restricted during liveness poll: ${e.message}")
                    }
                }
            }
        }
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        // Enforce anti-tamper IPC validation on commands originating from UI or internal events
        if (intent != null && intent.action != null) {
            if (!AppIntegrityValidator.verifyInternalIntent(intent)) {
                Log.w(TAG, "Rejected unauthorized intent without verified program signature: ${intent.action}")
                return START_NOT_STICKY
            }

            when (intent.action) {
                ACTION_STOP_SENTRY -> {
                    stopForeground(STOP_FOREGROUND_REMOVE)
                    stopSelf()
                    return START_NOT_STICKY
                }
                ACTION_FORCE_QUARANTINE -> engageQuarantine("Manual User Override")
                ACTION_CLEAR_QUARANTINE -> disengageQuarantine()
            }
        }
        return START_STICKY
    }

    private fun registerTelephonyListeners() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            telephonyManager.registerTelephonyCallback(
                mainExecutor,
                object : TelephonyCallback(),
                    TelephonyCallback.CellInfoListener,
                    TelephonyCallback.DisplayInfoListener,
                    TelephonyCallback.CallStateListener {

                    override fun onCellInfoChanged(cellInfo: MutableList<CellInfo>) {
                        processCellInfo(cellInfo)
                    }

                    override fun onDisplayInfoChanged(telephonyDisplayInfo: TelephonyDisplayInfo) {
                        checkDisplayNetworkType(telephonyDisplayInfo.networkType)
                    }

                    override fun onCallStateChanged(state: Int) {
                        handleCallStateTransition(state)
                    }
                }
            )
        } else {
            // Fallback for Android 10-11
            @Suppress("DEPRECATION")
            telephonyManager.listen(object : PhoneStateListener() {
                @Deprecated("Deprecated in Java")
                override fun onCellInfoChanged(cellInfo: MutableList<CellInfo>?) {
                    cellInfo?.let { processCellInfo(it) }
                }
                @Deprecated("Deprecated in Java")
                override fun onCallStateChanged(state: Int, phoneNumber: String?) {
                    handleCallStateTransition(state)
                }
            }, PhoneStateListener.LISTEN_CELL_INFO or PhoneStateListener.LISTEN_CALL_STATE)
        }
    }

    private fun handleCallStateTransition(callState: Int) {
        if (callState == TelephonyManager.CALL_STATE_OFFHOOK || callState == TelephonyManager.CALL_STATE_RINGING) {
            // Instant emergency fail-safe: suspend VPN killswitch during active calls to guarantee E911 compliance
            val suspendIntent = Intent(this, SafeTunnelVpnService::class.java).apply {
                action = SafeTunnelVpnService.ACTION_EMERGENCY_SUSPEND
            }
            AppIntegrityValidator.signInternalIntent(suspendIntent)
            startService(suspendIntent)
        } else if (callState == TelephonyManager.CALL_STATE_IDLE && isQuarantined) {
            // Call completed: resume safe-routing quarantine
            val resumeIntent = Intent(this, SafeTunnelVpnService::class.java).apply {
                action = SafeTunnelVpnService.ACTION_EMERGENCY_RESUME
            }
            AppIntegrityValidator.signInternalIntent(resumeIntent)
            startService(resumeIntent)
        }
    }

    private fun processCellInfo(cellInfoList: List<CellInfo>) {
        lastCallbackTimestamp = System.currentTimeMillis()
        serviceScope.launch {
            val registeredCell = cellInfoList.firstOrNull { it.isRegistered } ?: return@launch
            val neighborCells = cellInfoList.filter { !it.isRegistered }
            val observation = parseCellInfo(registeredCell, neighborCells) ?: return@launch

            val isPrevHighGen = previousGeneration == RadioGeneration.LTE_4G || previousGeneration == RadioGeneration.NR_5G
            val userLocation = getLastKnownLocation()

            val report = anomalyEngine.analyzeObservation(observation, userLocation, isPrevHighGen)
            previousGeneration = observation.generation
            _latestReport.value = report

            updateNotificationForReport(report)

            // Forensic Incident Logging: persist suspicious or critical rogue events into local SQLite
            val dao = RadioGuardApp.instance.database.towerDao()
            if (report.threatLevel != ThreatLevel.SAFE) {
                val incident = com.security.radioguard.data.model.IncidentEntity(
                    threatLevel = report.threatLevel.name,
                    riskScore = report.riskScore,
                    generation = observation.generation.name,
                    mcc = observation.mcc,
                    mnc = observation.mnc,
                    areaCode = observation.areaCode,
                    cellId = observation.cellId,
                    rsrpDbm = observation.rsrpDbm,
                    reasonsSummary = report.reasons.joinToString("; "),
                    deviceLatitude = userLocation?.first,
                    deviceLongitude = userLocation?.second
                )
                dao.logIncident(incident)
                dao.pruneOldIncidents()
            }

            // Automated Active Countermeasure & Blacklisting on Critical Rogue Detection
            if (report.threatLevel == ThreatLevel.CRITICAL_ROGUE) {
                dao.quarantineCell(
                    com.security.radioguard.data.model.QuarantinedCellEntity(
                        mcc = observation.mcc,
                        mnc = observation.mnc,
                        areaCode = observation.areaCode,
                        cellId = observation.cellId,
                        threatScore = report.riskScore,
                        reason = report.reasons.firstOrNull() ?: "Rogue Cell Sentry"
                    )
                )

                if (ShizukuRadioBridge.hasShizukuPermission()) {
                    launch(Dispatchers.IO) {
                        Log.w(TAG, "CRITICAL ROGUE: Triggering automated Shizuku radio pulse to break lock...")
                        ShizukuRadioBridge.breakRogueCellLockViaShizuku()
                    }
                }
            }

            if (report.isQuarantined && !isQuarantined) {
                engageQuarantine(report.reasons.joinToString("; "))
            }
        }
    }

    private fun parseCellInfo(cellInfo: CellInfo, neighborCells: List<CellInfo>): CellObservation? {
        val maxNeighborRsrp = neighborCells.mapNotNull { cell ->
            when (cell) {
                is CellInfoLte -> cell.cellSignalStrength.rsrp
                is CellInfoGsm -> cell.cellSignalStrength.dbm
                is CellInfoNr -> cell.cellSignalStrength.dbm
                else -> null
            }
        }.maxOrNull()

        return when (cellInfo) {
            is CellInfoLte -> {
                val id = cellInfo.cellIdentity
                CellObservation(
                    generation = RadioGeneration.LTE_4G,
                    mcc = id.mccString?.toIntOrNull() ?: 0,
                    mnc = id.mncString?.toIntOrNull() ?: 0,
                    areaCode = id.tac,
                    cellId = id.ci.toLong(),
                    pci = id.pci,
                    rsrpDbm = cellInfo.cellSignalStrength.rsrp,
                    timingAdvance = if (cellInfo.cellSignalStrength.timingAdvance != Int.MAX_VALUE) cellInfo.cellSignalStrength.timingAdvance else null,
                    neighborCount = neighborCells.size,
                    maxNeighborRsrpDbm = maxNeighborRsrp
                )
            }
            is CellInfoGsm -> {
                val id = cellInfo.cellIdentity
                CellObservation(
                    generation = RadioGeneration.GSM_2G,
                    mcc = id.mccString?.toIntOrNull() ?: 0,
                    mnc = id.mncString?.toIntOrNull() ?: 0,
                    areaCode = id.lac,
                    cellId = id.cid.toLong(),
                    pci = null,
                    rsrpDbm = cellInfo.cellSignalStrength.dbm,
                    neighborCount = neighborCells.size,
                    maxNeighborRsrpDbm = maxNeighborRsrp
                )
            }
            is CellInfoNr -> {
                val id = cellInfo.cellIdentity as? CellIdentityNr ?: return null
                CellObservation(
                    generation = RadioGeneration.NR_5G,
                    mcc = id.mccString?.toIntOrNull() ?: 0,
                    mnc = id.mncString?.toIntOrNull() ?: 0,
                    areaCode = id.tac,
                    cellId = id.nci,
                    pci = id.pci,
                    rsrpDbm = cellInfo.cellSignalStrength.dbm,
                    neighborCount = neighborCells.size,
                    maxNeighborRsrpDbm = maxNeighborRsrp
                )
            }
            else -> null
        }
    }

    private fun checkDisplayNetworkType(networkType: Int) {
        if (networkType == TelephonyManager.NETWORK_TYPE_EDGE || networkType == TelephonyManager.NETWORK_TYPE_GPRS) {
            if (previousGeneration == RadioGeneration.LTE_4G || previousGeneration == RadioGeneration.NR_5G) {
                engageQuarantine("Involuntary 2G forced fallback detected!")
            }
        }
    }

    private fun engageQuarantine(reason: String) {
        isQuarantined = true
        Log.w(TAG, "QUARANTINE TRIGGERED: $reason")

        val vpnIntent = Intent(this, SafeTunnelVpnService::class.java).apply {
            action = SafeTunnelVpnService.ACTION_ACTIVATE
        }
        AppIntegrityValidator.signInternalIntent(vpnIntent)
        startService(vpnIntent)
    }

    private fun disengageQuarantine() {
        isQuarantined = false
        val vpnIntent = Intent(this, SafeTunnelVpnService::class.java).apply {
            action = SafeTunnelVpnService.ACTION_DEACTIVATE
        }
        AppIntegrityValidator.signInternalIntent(vpnIntent)
        startService(vpnIntent)
    }

    private fun getLastKnownLocation(): Pair<Double, Double>? {
        if (ActivityCompat.checkSelfPermission(this, android.Manifest.permission.ACCESS_FINE_LOCATION) != PackageManager.PERMISSION_GRANTED) {
            return null
        }
        val locManager = getSystemService(Context.LOCATION_SERVICE) as LocationManager
        val loc: Location? = locManager.getLastKnownLocation(LocationManager.PASSIVE_PROVIDER)
            ?: locManager.getLastKnownLocation(LocationManager.GPS_PROVIDER)
        return loc?.let { Pair(it.latitude, it.longitude) }
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                "RadioGuard Active Sentry",
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = "Cellular manipulation detection and safe routing"
            }
            val manager = getSystemService(NotificationManager::class.java)
            manager.createNotificationChannel(channel)
        }
    }

    private fun buildForegroundNotification(status: String, threat: ThreatLevel): Notification {
        val title = when (threat) {
            ThreatLevel.SAFE -> "RadioGuard: Cellular Link Secure"
            ThreatLevel.SUSPICIOUS -> "RadioGuard: Suspicious Cell Detected"
            ThreatLevel.CRITICAL_ROGUE -> "RadioGuard: ROGUE TOWER QUARANTINED"
        }

        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle(title)
            .setContentText(status)
            .setSmallIcon(android.R.drawable.ic_lock_idle_lock)
            .setOngoing(true)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .build()
    }

    private fun updateNotificationForReport(report: AnomalyReport) {
        val text = when (report.threatLevel) {
            ThreatLevel.SAFE -> "Connected: ${report.observation.generation} (TAC ${report.observation.areaCode}) - Score: %.2f".format(report.riskScore)
            ThreatLevel.SUSPICIOUS -> "Warning: Risk %.2f - %s".format(report.riskScore, report.reasons.firstOrNull() ?: "")
            ThreatLevel.CRITICAL_ROGUE -> "THREAT DETECTED: Killswitch active! (%s)".format(report.reasons.firstOrNull() ?: "")
        }
        val notification = buildForegroundNotification(text, report.threatLevel)
        val manager = getSystemService(NotificationManager::class.java)
        manager.notify(NOTIFICATION_ID, notification)
    }

    override fun onDestroy() {
        super.onDestroy()
        serviceScope.cancel()
        _isServiceRunning.value = false
    }

    override fun onBind(intent: Intent?): IBinder? = null
}

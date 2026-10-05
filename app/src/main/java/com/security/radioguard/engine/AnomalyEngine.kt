package com.security.radioguard.engine

import com.security.radioguard.data.db.TowerDao
import com.security.radioguard.data.model.*
import kotlin.math.*

/**
 * Multi-Factor Anomaly Scoring Engine (MFASE).
 * Aggregates independent cellular anomaly vectors into a normalized Bayesian risk score.
 */
class AnomalyEngine(private val towerDao: TowerDao) {

    companion object {
        const val THRESHOLD_SUSPICIOUS = 0.45f
        const val THRESHOLD_CRITICAL = 0.75f
    }

    suspend fun analyzeObservation(
        obs: CellObservation,
        userLocation: Pair<Double, Double>?,
        isPreviousConnection4GOr5G: Boolean
    ): AnomalyReport {
        val reasons = mutableListOf<String>()
        val probabilityFactors = mutableListOf<Float>()

        // 0. Active Quarantine Blacklist Guard (Immediate entrapment bypassing hysteresis)
        if (towerDao.isCellQuarantined(obs.mcc, obs.mnc, obs.areaCode, obs.cellId)) {
            return AnomalyReport(
                threatLevel = ThreatLevel.CRITICAL_ROGUE,
                riskScore = 0.99f,
                reasons = listOf("Active Quarantine: Tower signature is blacklisted in local rogue cell registry"),
                observation = obs,
                isQuarantined = true
            )
        }

        // 1. Sudden Involuntary 2G Downgrade Vector
        if (isPreviousConnection4GOr5G && obs.generation == RadioGeneration.GSM_2G) {
            probabilityFactors.add(0.70f)
            reasons.add("Abrupt forced downgrade from 4G/5G to legacy 2G (GSM) detected")
        }

        // 2. Missing Neighbor Cell List (Cellular Isolation Trap)
        // Legitimate 4G macro-cells broadcast SIB4/5 neighbor lists. Rogue towers omit them to trap UEs.
        if (obs.generation == RadioGeneration.LTE_4G && obs.neighborCount == 0) {
            probabilityFactors.add(0.40f)
            reasons.add("LTE Neighbor cell list is empty (Isolation trap indicator)")
        }

        // 2b. Extreme Neighbor RF Dominance Anomaly
        // In legitimate cell networks, adjacent sectors/towers are typically within 6-25 dB of each other.
        // A portable rogue transmitter close to the phone often exhibits extreme artificial dominance.
        if (obs.maxNeighborRsrpDbm != null && obs.neighborCount > 0) {
            val dominanceDelta = obs.rsrpDbm - obs.maxNeighborRsrpDbm
            if (dominanceDelta > 35) {
                probabilityFactors.add(0.65f)
                reasons.add("RF Dominance Anomaly: Serving cell abnormally overshadows neighboring grid (+${dominanceDelta} dB dominance)")
            }
        }

        // 3. Unnatural Signal Spike without nearby legitimate macro-sites
        if (obs.rsrpDbm > -60) {
            probabilityFactors.add(0.35f)
            reasons.add("Unusually high signal power (${obs.rsrpDbm} dBm) indicating localized RF transmitter")
        }

        // 3b. Macro-Cell Cloning / Shadow MitM Attack Detection:
        // A stationary or slow device cannot jump >25 dBm on the same cell ID instantly without an RF spoofer
        if (obs.cellId == previousCellId && previousCellId != 0L) {
            val deltaRsrp = obs.rsrpDbm - previousRsrpDbm
            val deltaTimeMs = System.currentTimeMillis() - previousRsrpTimestamp
            if (deltaRsrp > 25 && deltaTimeMs < 4000) {
                probabilityFactors.add(0.80f)
                reasons.add("Macro-Cell Shadow Clone: Rapid RSRP surge (+${deltaRsrp} dBm in ${deltaTimeMs}ms) on same CID")
            }
        }
        previousCellId = obs.cellId
        previousRsrpDbm = obs.rsrpDbm
        previousRsrpTimestamp = System.currentTimeMillis()

        // 3c. Timing Advance (TA) vs Physical Signal Propagation Model
        // d ≈ TA * 78.12m. If TA is large (> 1.5 km), RSRP cannot be -55 dBm under legal licensed power limits.
        if (obs.timingAdvance != null && obs.timingAdvance > 0 && obs.generation == RadioGeneration.LTE_4G) {
            val taDistKm = (obs.timingAdvance * 78.12) / 1000.0
            if ((obs.timingAdvance >= 10 && obs.rsrpDbm >= -55) || (obs.timingAdvance >= 25 && obs.rsrpDbm >= -68)) {
                probabilityFactors.add(0.75f)
                reasons.add("Physical Propagation Anomaly: High RSRP (${obs.rsrpDbm} dBm) violates Path Loss for TA distance (%.1f km)".format(taDistKm))
            }
        }

        // 4. Invalid or Bogus Area Identifiers (Reserved PLMN or zero LAC/TAC)
        if (obs.areaCode == 0 || obs.areaCode == 0xFFFF || obs.cellId == 0L || obs.cellId == 0xFFFFFFFFL) {
            probabilityFactors.add(0.85f)
            reasons.add("Invalid/Malformed Tracking Area or Cell ID (${obs.areaCode}/${obs.cellId})")
        }

        // 5. Offline Ground-Truth Spatial Verification
        val knownTower = towerDao.findTower(obs.mcc, obs.mnc, obs.areaCode, obs.cellId)

        // 4b. eNodeB / Sector Topology Bounds Check
        // In 3GPP LTE: ECI = eNodeB_ID * 256 + Sector_ID.
        if (obs.generation == RadioGeneration.LTE_4G && obs.cellId > 0 && knownTower == null) {
            val sectorId = (obs.cellId % 256).toInt()
            val eNodeBId = obs.cellId / 256
            if (sectorId > 31 || eNodeBId == 0L) {
                probabilityFactors.add(0.45f)
                reasons.add("eNodeB Sector Topology Anomaly: Sector ID $sectorId anomalous for licensed macro-site")
            }
        }

        // 4c. TAC (Tracking Area Code) Hopping Sentry
        // Detects rapid TAC oscillations while stationary (signature of IMSI identity harvesting traps)
        checkTacHopping(obs.areaCode, userLocation)?.let { tacAnomalyReason ->
            probabilityFactors.add(0.85f)
            reasons.add(tacAnomalyReason)
        }

        if (knownTower != null && userLocation != null) {
            val distKm = haversineDistanceKm(
                userLocation.first, userLocation.second,
                knownTower.latitude, knownTower.longitude
            )
            // If device location is > 10 km away from where this tower is physically registered
            if (distKm > 10.0) {
                probabilityFactors.add(0.80f)
                reasons.add("Spatial Discrepancy: Claimed tower identity is %.1f km away from device location".format(distKm))
            }

            // Timing Advance verification (only valid if TA is provided by modern baseband)
            if (obs.timingAdvance != null && obs.timingAdvance > 0 && obs.generation == RadioGeneration.LTE_4G) {
                val taDistKm = (obs.timingAdvance * 78.12) / 1000.0
                if (abs(distKm - taDistKm) > 4.0) {
                    probabilityFactors.add(0.50f)
                    reasons.add("Timing Advance distance (%.2f km) contradicts physical coordinates".format(taDistKm))
                }
            }
        } else if (knownTower == null && obs.areaCode != 0) {
            // Uncataloged tower in regional database
            probabilityFactors.add(0.20f)
            reasons.add("Cell tower not present in offline verified carrier database")
        }

        // 5b. Wi-Fi Anchor Geofence Cross-Correlation
        if (obs.wifiLatitude != null && obs.wifiLongitude != null && knownTower != null) {
            val wifiDistKm = haversineDistanceKm(
                obs.wifiLatitude, obs.wifiLongitude,
                knownTower.latitude, knownTower.longitude
            )
            if (wifiDistKm > 15.0) {
                probabilityFactors.add(0.80f)
                reasons.add("Wi-Fi Geofence Discrepancy: Cell claims location %.1f km away from verified Wi-Fi anchor".format(wifiDistKm))
            }
        }

        // Combine independent probabilities: P_total = 1 - Prod(1 - P_i)
        var complementProduct = 1.0f
        for (p in probabilityFactors) {
            complementProduct *= (1.0f - p)
        }
        val instantaneousRiskScore = (1.0f - complementProduct).coerceIn(0.0f, 1.0f)

        // Hysteresis Smoothing: Prevent momentary Carrier Aggregation (CA) / handoff false alarms
        val smoothedRiskScore = updateHysteresis(instantaneousRiskScore)

        val threatLevel = when {
            smoothedRiskScore >= THRESHOLD_CRITICAL -> ThreatLevel.CRITICAL_ROGUE
            smoothedRiskScore >= THRESHOLD_SUSPICIOUS -> ThreatLevel.SUSPICIOUS
            else -> ThreatLevel.SAFE
        }

        return AnomalyReport(
            threatLevel = threatLevel,
            riskScore = smoothedRiskScore,
            reasons = reasons,
            observation = obs,
            isQuarantined = threatLevel == ThreatLevel.CRITICAL_ROGUE
        )
    }

    private data class TacHistoryRecord(val tac: Int, val timestamp: Long, val location: Pair<Double, Double>?)
    private val tacHistory = mutableListOf<TacHistoryRecord>()

    private fun checkTacHopping(currentTac: Int, userLocation: Pair<Double, Double>?): String? {
        if (currentTac <= 0 || currentTac == 0xFFFF) return null
        val now = System.currentTimeMillis()
        tacHistory.removeAll { now - it.timestamp > 180000L }

        val lastRecord = tacHistory.lastOrNull()
        if (lastRecord != null && lastRecord.tac != currentTac) {
            tacHistory.add(TacHistoryRecord(currentTac, now, userLocation))
            val uniqueTacs = tacHistory.map { it.tac }.distinct()
            if (uniqueTacs.size >= 2) {
                val firstLoc = tacHistory.firstOrNull { it.location != null }?.location
                val currentLoc = userLocation
                val isStationary = if (firstLoc != null && currentLoc != null) {
                    haversineDistanceKm(firstLoc.first, firstLoc.second, currentLoc.first, currentLoc.second) < 0.35
                } else {
                    true
                }
                if (isStationary) {
                    return "TAC Hopping Sentry: Rapid Tracking Area Code oscillation (${uniqueTacs.size} distinct TACs in 3m) while stationary"
                }
            }
        } else if (lastRecord == null) {
            tacHistory.add(TacHistoryRecord(currentTac, now, userLocation))
        }
        return null
    }

    private var previousAnomalyTimestamp = 0L
    private var consecutiveAnomalyCount = 0

    // Shadow Macro-Cell Clone tracking variables
    private var previousCellId = 0L
    private var previousRsrpDbm = 0
    private var previousRsrpTimestamp = 0L

    private fun updateHysteresis(instantScore: Float): Float {
        val now = System.currentTimeMillis()
        if (instantScore >= THRESHOLD_SUSPICIOUS) {
            if (now - previousAnomalyTimestamp < 10000) {
                consecutiveAnomalyCount++
            } else {
                consecutiveAnomalyCount = 1
            }
            previousAnomalyTimestamp = now
        } else {
            consecutiveAnomalyCount = 0
        }

        // Require at least 2 consecutive anomalous cycles within 10s before full critical escalation
        return if (instantScore >= THRESHOLD_CRITICAL && consecutiveAnomalyCount < 2) {
            THRESHOLD_SUSPICIOUS + 0.1f // Held at elevated warning until confirmed
        } else {
            instantScore
        }
    }

    private fun haversineDistanceKm(lat1: Double, lon1: Double, lat2: Double, lon2: Double): Double {
        val r = 6371.0 // Earth radius in km
        val dLat = Math.toRadians(lat2 - lat1)
        val dLon = Math.toRadians(lon2 - lon1)
        val a = sin(dLat / 2).pow(2) +
                cos(Math.toRadians(lat1)) * cos(Math.toRadians(lat2)) *
                sin(dLon / 2).pow(2)
        val c = 2 * atan2(sqrt(a), sqrt(1 - a))
        return r * c
    }
}

package com.security.radioguard.data.model

import androidx.room.Entity
import androidx.room.Index
import androidx.room.PrimaryKey

enum class RadioGeneration {
    GSM_2G,
    UMTS_3G,
    LTE_4G,
    NR_5G,
    UNKNOWN
}

enum class ThreatLevel {
    SAFE,
    SUSPICIOUS,
    CRITICAL_ROGUE
}

data class CellObservation(
    val generation: RadioGeneration,
    val mcc: Int,
    val mnc: Int,
    val areaCode: Int, // LAC for 2G/3G, TAC for 4G/5G
    val cellId: Long,  // CID or ECI
    val pci: Int?,     // Physical Cell ID (LTE/5G)
    val rsrpDbm: Int,  // Signal power
    val timingAdvance: Int? = null,
    val neighborCount: Int = 0,
    val timestamp: Long = System.currentTimeMillis()
)

data class AnomalyReport(
    val threatLevel: ThreatLevel,
    val riskScore: Float, // 0.0 to 1.0
    val reasons: List<String>,
    val observation: CellObservation,
    val isQuarantined: Boolean,
    val timestamp: Long = System.currentTimeMillis()
)

/**
 * Offline verified tower record from OpenCelliD or BeaconDB.
 */
@Entity(
    tableName = "verified_towers",
    indices = [
        Index(value = ["mcc", "mnc", "areaCode", "cellId"], unique = true),
        Index(value = ["latitude", "longitude"])
    ]
)
data class TowerEntity(
    @PrimaryKey(autoGenerate = true)
    val id: Long = 0,
    val mcc: Int,
    val mnc: Int,
    val areaCode: Int,
    val cellId: Long,
    val radio: String, // "GSM", "LTE", "NR"
    val latitude: Double,
    val longitude: Double,
    val rangeMeters: Int,
    val verifiedSamples: Int
)

/**
 * Forensic Incident Audit Log Entity.
 * Preserves evidence of rogue tower interception, signal manipulation, and silent SMS pings.
 */
@Entity(
    tableName = "incident_logs",
    indices = [Index(value = ["timestamp"])]
)
data class IncidentEntity(
    @PrimaryKey(autoGenerate = true)
    val id: Long = 0,
    val timestamp: Long = System.currentTimeMillis(),
    val threatLevel: String,
    val riskScore: Float,
    val generation: String,
    val mcc: Int,
    val mnc: Int,
    val areaCode: Int,
    val cellId: Long,
    val rsrpDbm: Int,
    val reasonsSummary: String,
    val deviceLatitude: Double?,
    val deviceLongitude: Double?
)


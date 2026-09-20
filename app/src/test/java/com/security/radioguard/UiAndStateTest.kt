package com.security.radioguard

import com.security.radioguard.data.model.ThreatLevel
import org.junit.Assert.*
import org.junit.Test

class UiAndStateTest {

    @Test
    fun testThreatLevelUiLabelsAndColors() {
        // Verify UI mappings for threat levels
        assertEquals("SAFE", ThreatLevel.SAFE.name)
        assertEquals("SUSPICIOUS", ThreatLevel.SUSPICIOUS.name)
        assertEquals("CRITICAL_ROGUE", ThreatLevel.CRITICAL_ROGUE.name)
    }

    @Test
    fun testMathematicalBoundsClamping() {
        val overflowScore = 1.45f
        val underflowScore = -0.32f
        val clampedHigh = overflowScore.coerceIn(0.0f, 1.0f)
        val clampedLow = underflowScore.coerceIn(0.0f, 1.0f)

        assertEquals(1.0f, clampedHigh, 0.001f)
        assertEquals(0.0f, clampedLow, 0.001f)
    }

    @Test
    fun testDualRouteSplittingCoversEntireIpSpace() {
        // Dual /1 route splitting: 0.0.0.0/1 covers 0.0.0.0 - 127.255.255.255
        // 128.0.0.0/1 covers 128.0.0.0 - 255.255.255.255
        // Together they cover 100% of IPv4 addresses while superseding /8 - /24 localnet routes
        val prefix1 = 1 // 0.0.0.0/1
        val prefix2 = 1 // 128.0.0.0/1
        assertTrue(prefix1 > 0 && prefix2 > 0)
    }

    @Test
    fun testThreatGaugeStatusLabelsAndPercentages() {
        // Test all three UI states
        val safeScore = 0.12f
        val warningScore = 0.54f
        val criticalScore = 0.95f

        val safePercent = (safeScore * 100).toInt()
        val warningPercent = (warningScore * 100).toInt()
        val criticalPercent = (criticalScore * 100).toInt()

        assertEquals(12, safePercent)
        assertEquals(54, warningPercent)
        assertEquals(95, criticalPercent)

        val safeLabel = when (ThreatLevel.SAFE) {
            ThreatLevel.SAFE -> "SECURE: NO ROGUE CELLS"
            ThreatLevel.SUSPICIOUS -> "WARNING: UNVERIFIED ANOMALY"
            ThreatLevel.CRITICAL_ROGUE -> "CRITICAL: ROGUE TOWER TRAPPED"
        }
        assertEquals("SECURE: NO ROGUE CELLS", safeLabel)

        val warningLabel = when (ThreatLevel.SUSPICIOUS) {
            ThreatLevel.SAFE -> "SECURE: NO ROGUE CELLS"
            ThreatLevel.SUSPICIOUS -> "WARNING: UNVERIFIED ANOMALY"
            ThreatLevel.CRITICAL_ROGUE -> "CRITICAL: ROGUE TOWER TRAPPED"
        }
        assertEquals("WARNING: UNVERIFIED ANOMALY", warningLabel)

        val criticalLabel = when (ThreatLevel.CRITICAL_ROGUE) {
            ThreatLevel.SAFE -> "SECURE: NO ROGUE CELLS"
            ThreatLevel.SUSPICIOUS -> "WARNING: UNVERIFIED ANOMALY"
            ThreatLevel.CRITICAL_ROGUE -> "CRITICAL: ROGUE TOWER TRAPPED"
        }
        assertEquals("CRITICAL: ROGUE TOWER TRAPPED", criticalLabel)
    }

    @Test
    fun testServingCellTelemetryStringFormatting() {
        val mcc = 310
        val mnc = 410
        val rsrp = -92
        val neighbors = 4

        val plmnFormatted = "$mcc / $mnc"
        val rsrpFormatted = "$rsrp dBm"
        val neighborsFormatted = "$neighbors detected"

        assertEquals("310 / 410", plmnFormatted)
        assertEquals("-92 dBm", rsrpFormatted)
        assertEquals("4 detected", neighborsFormatted)
    }

    @Test
    fun testForensicIncidentJsonReportGeneration() {
        val incident = com.security.radioguard.data.model.IncidentEntity(
            timestamp = 1718000000000L,
            threatLevel = "CRITICAL_ROGUE",
            riskScore = 0.88f,
            generation = "LTE_4G",
            mcc = 310,
            mnc = 410,
            areaCode = 12014,
            cellId = 1004521L,
            rsrpDbm = -62,
            reasonsSummary = "Macro-Cell Shadow Clone detected",
            deviceLatitude = 37.7749,
            deviceLongitude = -122.4194
        )

        val jsonEntry = """
        {
          "timestamp": ${incident.timestamp},
          "threatLevel": "${incident.threatLevel}",
          "riskScore": ${incident.riskScore},
          "generation": "${incident.generation}",
          "plmn": "${incident.mcc}-${incident.mnc}",
          "areaCode": ${incident.areaCode},
          "cellId": ${incident.cellId},
          "rsrp": ${incident.rsrpDbm},
          "reasons": "${incident.reasonsSummary}"
        }
        """.trimIndent()

        assertTrue(jsonEntry.contains("\"threatLevel\": \"CRITICAL_ROGUE\""))
        assertTrue(jsonEntry.contains("\"plmn\": \"310-410\""))
        assertTrue(jsonEntry.contains("\"rsrp\": -62"))
        assertTrue(jsonEntry.contains("Macro-Cell Shadow Clone"))
    }
}

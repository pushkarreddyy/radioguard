package com.security.radioguard

import com.security.radioguard.data.db.TowerDao
import com.security.radioguard.data.model.*
import com.security.radioguard.engine.AnomalyEngine
import kotlinx.coroutines.runBlocking
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import org.mockito.Mockito.*

class AnomalyEngineTest {

    private lateinit var mockTowerDao: TowerDao
    private lateinit var anomalyEngine: AnomalyEngine

    @Before
    fun setup() {
        mockTowerDao = mock(TowerDao::class.java)
        anomalyEngine = AnomalyEngine(mockTowerDao)
    }

    @Test
    fun testNormalCellProducesSafeScore() = runBlocking {
        // Normal 4G cell with neighbors and matching database entry
        val obs = CellObservation(
            generation = RadioGeneration.LTE_4G,
            mcc = 310,
            mnc = 410,
            areaCode = 12014,
            cellId = 1004521L,
            pci = 42,
            rsrpDbm = -95,
            timingAdvance = 5,
            neighborCount = 4
        )
        val tower = TowerEntity(
            mcc = 310, mnc = 410, areaCode = 12014, cellId = 1004521L,
            radio = "LTE", latitude = 37.7749, longitude = -122.4194,
            rangeMeters = 2500, verifiedSamples = 150
        )
        `when`(mockTowerDao.findTower(310, 410, 12014, 1004521L)).thenReturn(tower)

        val report = anomalyEngine.analyzeObservation(obs, Pair(37.7749, -122.4194), isPreviousConnection4GOr5G = true)
        assertEquals(ThreatLevel.SAFE, report.threatLevel)
        assertTrue(report.riskScore < 0.45f)
        assertFalse(report.isQuarantined)
    }

    @Test
    fun testInvoluntary2GDowngradeTriggersAlert() = runBlocking {
        // Involuntary drop from LTE to 2G GSM
        val obs = CellObservation(
            generation = RadioGeneration.GSM_2G,
            mcc = 310,
            mnc = 410,
            areaCode = 9999,
            cellId = 5555L,
            pci = null,
            rsrpDbm = -65,
            neighborCount = 0
        )
        `when`(mockTowerDao.findTower(310, 410, 9999, 5555L)).thenReturn(null)

        val report = anomalyEngine.analyzeObservation(obs, Pair(37.7749, -122.4194), isPreviousConnection4GOr5G = true)
        assertTrue(report.reasons.any { it.contains("forced downgrade", ignoreCase = true) })
        assertTrue(report.riskScore >= 0.45f)
    }

    @Test
    fun testMacroCellShadowCloneTriggersHighRisk() = runBlocking {
        // First observation: normal signal
        val obs1 = CellObservation(
            generation = RadioGeneration.LTE_4G,
            mcc = 310, mnc = 410, areaCode = 12014, cellId = 1004521L,
            pci = 42, rsrpDbm = -98, neighborCount = 3
        )
        anomalyEngine.analyzeObservation(obs1, Pair(37.7749, -122.4194), isPreviousConnection4GOr5G = true)

        // Instantaneous power jump (+38 dBm) on the exact same Cell ID
        val obs2 = CellObservation(
            generation = RadioGeneration.LTE_4G,
            mcc = 310, mnc = 410, areaCode = 12014, cellId = 1004521L,
            pci = 42, rsrpDbm = -60, neighborCount = 3
        )
        val report2 = anomalyEngine.analyzeObservation(obs2, Pair(37.7749, -122.4194), isPreviousConnection4GOr5G = true)

        assertTrue(report2.reasons.any { it.contains("Macro-Cell Shadow Clone", ignoreCase = true) })
    }
}

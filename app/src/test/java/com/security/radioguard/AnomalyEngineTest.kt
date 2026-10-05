package com.security.radioguard

import com.security.radioguard.data.db.TowerDao
import com.security.radioguard.data.model.*
import com.security.radioguard.engine.AnomalyEngine
import kotlinx.coroutines.runBlocking
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test

class AnomalyEngineTest {

    private class FakeTowerDao : TowerDao {
        val towers = mutableMapOf<String, TowerEntity>()
        val incidents = mutableListOf<IncidentEntity>()

        val quarantinedCells = mutableMapOf<String, QuarantinedCellEntity>()

        override suspend fun findTower(mcc: Int, mnc: Int, areaCode: Int, cellId: Long): TowerEntity? {
            return towers["$mcc-$mnc-$areaCode-$cellId"]
        }

        override suspend fun findTowersInBoundingBox(minLat: Double, maxLat: Double, minLon: Double, maxLon: Double): List<TowerEntity> {
            return towers.values.filter { it.latitude in minLat..maxLat && it.longitude in minLon..maxLon }
        }

        override suspend fun getTotalTowerCount(): Int = towers.size

        override suspend fun insertTowers(towersList: List<TowerEntity>) {
            towersList.forEach { towers["${it.mcc}-${it.mnc}-${it.areaCode}-${it.cellId}"] = it }
        }

        override suspend fun clearDatabase() { towers.clear() }

        override suspend fun logIncident(incident: IncidentEntity) { incidents.add(incident) }

        override suspend fun getRecentIncidents(): List<IncidentEntity> = incidents.takeLast(50)

        override suspend fun getAllIncidentsForExport(): List<IncidentEntity> = incidents.toList()

        override suspend fun pruneOldIncidents() {
            if (incidents.size > 1000) {
                val toRemove = incidents.size - 1000
                repeat(toRemove) { incidents.removeAt(0) }
            }
        }

        override suspend fun clearIncidentLogs() { incidents.clear() }

        override suspend fun isCellQuarantined(mcc: Int, mnc: Int, areaCode: Int, cellId: Long): Boolean {
            return quarantinedCells.containsKey("$mcc-$mnc-$areaCode-$cellId")
        }

        override suspend fun quarantineCell(cell: QuarantinedCellEntity) {
            quarantinedCells["${cell.mcc}-${cell.mnc}-${cell.areaCode}-${cell.cellId}"] = cell
        }

        override suspend fun getAllQuarantinedCells(): List<QuarantinedCellEntity> = quarantinedCells.values.toList()

        override suspend fun unquarantineCell(mcc: Int, mnc: Int, areaCode: Int, cellId: Long) {
            quarantinedCells.remove("$mcc-$mnc-$areaCode-$cellId")
        }

        override suspend fun clearQuarantinedCells() {
            quarantinedCells.clear()
        }
    }

    private lateinit var fakeTowerDao: FakeTowerDao
    private lateinit var anomalyEngine: AnomalyEngine

    @Before
    fun setup() {
        fakeTowerDao = FakeTowerDao()
        anomalyEngine = AnomalyEngine(fakeTowerDao)
    }

    @Test
    fun testNormalCellProducesSafeScore() = runBlocking {
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
        fakeTowerDao.insertTowers(listOf(tower))

        val report = anomalyEngine.analyzeObservation(obs, Pair(37.7749, -122.4194), isPreviousConnection4GOr5G = true)
        assertEquals(ThreatLevel.SAFE, report.threatLevel)
        assertTrue(report.riskScore < 0.45f)
        assertFalse(report.isQuarantined)
    }

    @Test
    fun testInvoluntary2GDowngradeTriggersAlert() = runBlocking {
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

        val report = anomalyEngine.analyzeObservation(obs, Pair(37.7749, -122.4194), isPreviousConnection4GOr5G = true)
        assertTrue(report.reasons.any { it.contains("forced downgrade", ignoreCase = true) })
        assertTrue(report.riskScore >= 0.45f)
    }

    @Test
    fun testMacroCellShadowCloneTriggersHighRisk() = runBlocking {
        val obs1 = CellObservation(
            generation = RadioGeneration.LTE_4G,
            mcc = 310, mnc = 410, areaCode = 12014, cellId = 1004521L,
            pci = 42, rsrpDbm = -98, neighborCount = 3
        )
        anomalyEngine.analyzeObservation(obs1, Pair(37.7749, -122.4194), isPreviousConnection4GOr5G = true)

        val obs2 = CellObservation(
            generation = RadioGeneration.LTE_4G,
            mcc = 310, mnc = 410, areaCode = 12014, cellId = 1004521L,
            pci = 42, rsrpDbm = -60, neighborCount = 3
        )
        val report2 = anomalyEngine.analyzeObservation(obs2, Pair(37.7749, -122.4194), isPreviousConnection4GOr5G = true)

        assertTrue(report2.reasons.any { it.contains("Macro-Cell Shadow Clone", ignoreCase = true) })
    }

    @Test
    fun testQuarantinedCellTrappedImmediately() = runBlocking {
        fakeTowerDao.quarantineCell(
            QuarantinedCellEntity(
                mcc = 310, mnc = 410, areaCode = 12014, cellId = 999999L,
                threatScore = 0.99f,
                detectedTimestamp = System.currentTimeMillis(),
                reason = "Known IMSI Catcher Signature"
            )
        )

        val obs = CellObservation(
            generation = RadioGeneration.LTE_4G,
            mcc = 310, mnc = 410, areaCode = 12014, cellId = 999999L,
            rsrpDbm = -80
        )
        val report = anomalyEngine.analyzeObservation(obs, Pair(37.7749, -122.4194), isPreviousConnection4GOr5G = false)
        assertTrue(report.isQuarantined)
        assertEquals(ThreatLevel.CRITICAL_ROGUE, report.threatLevel)
        assertEquals(0.99f, report.riskScore, 0.01f)
    }

    @Test
    fun testExtremeNeighborRfDominanceAnomaly() = runBlocking {
        val obs = CellObservation(
            generation = RadioGeneration.LTE_4G,
            mcc = 310, mnc = 410, areaCode = 12014, cellId = 1004521L,
            rsrpDbm = -52,
            maxNeighborRsrpDbm = -96, // Dominance = 44 dB > 35 dB threshold
            neighborCount = 3
        )
        val report = anomalyEngine.analyzeObservation(obs, Pair(37.7749, -122.4194), isPreviousConnection4GOr5G = false)
        assertTrue(report.reasons.any { it.contains("RF Dominance Anomaly", ignoreCase = true) })
    }

    @Test
    fun testPhysicsTimingAdvanceRsrpViolation() = runBlocking {
        // High Timing Advance (12 => ~6.6km) but unusually high RSRP (-50 dBm)
        val obs = CellObservation(
            generation = RadioGeneration.LTE_4G,
            mcc = 310, mnc = 410, areaCode = 12014, cellId = 1004521L,
            rsrpDbm = -50,
            timingAdvance = 12
        )
        val report = anomalyEngine.analyzeObservation(obs, Pair(37.7749, -122.4194), isPreviousConnection4GOr5G = false)
        assertTrue(report.reasons.any { it.contains("Propagation Anomaly", ignoreCase = true) })
    }

    @Test
    fun testSectorTopologyAnomaly() = runBlocking {
        // Invalid sector ID: 1004521 % 256 = 41 (> 31)
        val obs = CellObservation(
            generation = RadioGeneration.LTE_4G,
            mcc = 310, mnc = 410, areaCode = 12014, cellId = 1004521L,
            rsrpDbm = -90
        )
        val report = anomalyEngine.analyzeObservation(obs, Pair(37.7749, -122.4194), isPreviousConnection4GOr5G = false)
        assertTrue(report.reasons.any { it.contains("Topology", ignoreCase = true) })
    }
}

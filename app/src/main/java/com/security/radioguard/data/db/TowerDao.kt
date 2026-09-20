package com.security.radioguard.data.db

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query
import com.security.radioguard.data.model.TowerEntity

@Dao
interface TowerDao {

    @Query("""
        SELECT * FROM verified_towers 
        WHERE mcc = :mcc AND mnc = :mnc AND areaCode = :areaCode AND cellId = :cellId 
        LIMIT 1
    """)
    suspend fun findTower(mcc: Int, mnc: Int, areaCode: Int, cellId: Long): TowerEntity?

    @Query("""
        SELECT * FROM verified_towers 
        WHERE latitude BETWEEN :minLat AND :maxLat 
          AND longitude BETWEEN :minLon AND :maxLon
    """)
    suspend fun findTowersInBoundingBox(
        minLat: Double, maxLat: Double,
        minLon: Double, maxLon: Double
    ): List<TowerEntity>

    @Query("SELECT COUNT(*) FROM verified_towers")
    suspend fun getTotalTowerCount(): Int

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertTowers(towers: List<TowerEntity>)

    @Query("DELETE FROM verified_towers")
    suspend fun clearDatabase()

    // --- Forensic Incident Audit Queries ---

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun logIncident(incident: com.security.radioguard.data.model.IncidentEntity)

    @Query("SELECT * FROM incident_logs ORDER BY timestamp DESC LIMIT 50")
    suspend fun getRecentIncidents(): List<com.security.radioguard.data.model.IncidentEntity>

    @Query("SELECT * FROM incident_logs ORDER BY timestamp DESC")
    suspend fun getAllIncidentsForExport(): List<com.security.radioguard.data.model.IncidentEntity>

    // Storage-Bounds Guard: Prune records exceeding 1,000 to prevent flash storage exhaustion DoS
    @Query("""
        DELETE FROM incident_logs WHERE id NOT IN (
            SELECT id FROM incident_logs ORDER BY timestamp DESC LIMIT 1000
        )
    """)
    suspend fun pruneOldIncidents()

    @Query("DELETE FROM incident_logs")
    suspend fun clearIncidentLogs()
}

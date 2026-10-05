package com.security.radioguard.data.db

import android.content.Context
import androidx.room.Database
import androidx.room.Room
import androidx.room.RoomDatabase
import androidx.sqlite.db.SupportSQLiteDatabase
import com.security.radioguard.data.model.QuarantinedCellEntity
import com.security.radioguard.data.model.TowerEntity
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch

@Database(
    entities = [TowerEntity::class, com.security.radioguard.data.model.IncidentEntity::class, QuarantinedCellEntity::class],
    version = 3,
    exportSchema = false
)
abstract class TowerDatabase : RoomDatabase() {

    abstract fun towerDao(): TowerDao

    companion object {
        @Volatile
        private var INSTANCE: TowerDatabase? = null

        fun getInstance(context: Context): TowerDatabase {
            return INSTANCE ?: synchronized(this) {
                val instance = Room.databaseBuilder(
                    context.applicationContext,
                    TowerDatabase::class.java,
                    "radioguard_towers.db"
                )
                .addCallback(object : Callback() {
                    override fun onCreate(db: SupportSQLiteDatabase) {
                        super.onCreate(db)
                        // Seed initial baseline verification records so database is operational out-of-the-box
                        CoroutineScope(Dispatchers.IO).launch {
                            seedStarterBaseline(getInstance(context).towerDao())
                        }
                    }

                    override fun onOpen(db: SupportSQLiteDatabase) {
                        super.onOpen(db)
                        // Run PRAGMA integrity_check to ensure offline data has not been corrupted or tampered with
                        val cursor = db.query("PRAGMA integrity_check")
                        if (cursor.moveToFirst()) {
                            val status = cursor.getString(0)
                            if (!status.equals("ok", ignoreCase = true)) {
                                android.util.Log.e("TowerDatabase", "Database integrity violation: $status")
                            }
                        }
                        cursor.close()
                    }
                })
                .fallbackToDestructiveMigration()
                .build()
                INSTANCE = instance
                instance
            }
        }

        private suspend fun seedStarterBaseline(dao: TowerDao) {
            val starterTowers = listOf(
                TowerEntity(mcc = 310, mnc = 410, areaCode = 12014, cellId = 1004521L, radio = "LTE", latitude = 37.7749, longitude = -122.4194, rangeMeters = 2500, verifiedSamples = 150),
                TowerEntity(mcc = 310, mnc = 260, areaCode = 24018, cellId = 2056112L, radio = "LTE", latitude = 40.7128, longitude = -74.0060, rangeMeters = 2000, verifiedSamples = 220),
                TowerEntity(mcc = 234, mnc = 15, areaCode = 8011, cellId = 3041920L, radio = "LTE", latitude = 51.5074, longitude = -0.1278, rangeMeters = 1800, verifiedSamples = 310),
                TowerEntity(mcc = 404, mnc = 45, areaCode = 5021, cellId = 4058190L, radio = "LTE", latitude = 28.6139, longitude = 77.2090, rangeMeters = 3000, verifiedSamples = 400)
            )
            dao.insertTowers(starterTowers)
        }

        suspend fun seedRegionalDataset(dao: TowerDao, regionCode: String): Int {
            val regionalTowers = when (regionCode.uppercase()) {
                "US" -> listOf(
                    TowerEntity(mcc = 310, mnc = 410, areaCode = 12014, cellId = 1004521L, radio = "LTE", latitude = 37.7749, longitude = -122.4194, rangeMeters = 2500, verifiedSamples = 150),
                    TowerEntity(mcc = 310, mnc = 260, areaCode = 24018, cellId = 2056112L, radio = "LTE", latitude = 40.7128, longitude = -74.0060, rangeMeters = 2000, verifiedSamples = 220),
                    TowerEntity(mcc = 311, mnc = 480, areaCode = 31050, cellId = 5123901L, radio = "LTE", latitude = 34.0522, longitude = -118.2437, rangeMeters = 1800, verifiedSamples = 340),
                    TowerEntity(mcc = 310, mnc = 410, areaCode = 15082, cellId = 8841920L, radio = "LTE", latitude = 41.8781, longitude = -87.6298, rangeMeters = 2200, verifiedSamples = 190)
                )
                "EU" -> listOf(
                    TowerEntity(mcc = 234, mnc = 15, areaCode = 8011, cellId = 3041920L, radio = "LTE", latitude = 51.5074, longitude = -0.1278, rangeMeters = 1800, verifiedSamples = 310),
                    TowerEntity(mcc = 262, mnc = 1, areaCode = 14201, cellId = 4402199L, radio = "LTE", latitude = 52.5200, longitude = 13.4050, rangeMeters = 1500, verifiedSamples = 410),
                    TowerEntity(mcc = 208, mnc = 10, areaCode = 9022, cellId = 6128033L, radio = "LTE", latitude = 48.8566, longitude = 2.3522, rangeMeters = 1700, verifiedSamples = 290)
                )
                "ASIA" -> listOf(
                    TowerEntity(mcc = 404, mnc = 45, areaCode = 5021, cellId = 4058190L, radio = "LTE", latitude = 28.6139, longitude = 77.2090, rangeMeters = 3000, verifiedSamples = 400),
                    TowerEntity(mcc = 405, mnc = 840, areaCode = 7712, cellId = 9120482L, radio = "LTE", latitude = 19.0760, longitude = 72.8777, rangeMeters = 2500, verifiedSamples = 520),
                    TowerEntity(mcc = 440, mnc = 20, areaCode = 1042, cellId = 7780193L, radio = "LTE", latitude = 35.6762, longitude = 139.6503, rangeMeters = 1200, verifiedSamples = 600)
                )
                else -> listOf(
                    TowerEntity(mcc = 310, mnc = 410, areaCode = 12014, cellId = 1004521L, radio = "LTE", latitude = 37.7749, longitude = -122.4194, rangeMeters = 2500, verifiedSamples = 150),
                    TowerEntity(mcc = 310, mnc = 260, areaCode = 24018, cellId = 2056112L, radio = "LTE", latitude = 40.7128, longitude = -74.0060, rangeMeters = 2000, verifiedSamples = 220),
                    TowerEntity(mcc = 234, mnc = 15, areaCode = 8011, cellId = 3041920L, radio = "LTE", latitude = 51.5074, longitude = -0.1278, rangeMeters = 1800, verifiedSamples = 310),
                    TowerEntity(mcc = 404, mnc = 45, areaCode = 5021, cellId = 4058190L, radio = "LTE", latitude = 28.6139, longitude = 77.2090, rangeMeters = 3000, verifiedSamples = 400)
                )
            }
            dao.insertTowers(regionalTowers)
            return regionalTowers.size
        }
    }
}

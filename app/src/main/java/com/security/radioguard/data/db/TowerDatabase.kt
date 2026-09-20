package com.security.radioguard.data.db

import android.content.Context
import androidx.room.Database
import androidx.room.Room
import androidx.room.RoomDatabase
import androidx.sqlite.db.SupportSQLiteDatabase
import com.security.radioguard.data.model.TowerEntity

@Database(
    entities = [TowerEntity::class, com.security.radioguard.data.model.IncidentEntity::class],
    version = 2,
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
                        kotlinx.coroutines.CoroutineScope(kotlinx.coroutines.Dispatchers.IO).launch {
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
    }
}

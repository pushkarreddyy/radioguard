package com.security.radioguard

import android.app.Application
import com.security.radioguard.data.db.TowerDatabase
import com.security.radioguard.security.AppIntegrityValidator

class RadioGuardApp : Application() {

    lateinit var database: TowerDatabase
        private set

    companion object {
        lateinit var instance: RadioGuardApp
            private set
    }

    override fun onCreate() {
        super.onCreate()
        instance = this

        // Validate program signature and anti-tamper constraints immediately on launch
        AppIntegrityValidator.enforceRuntimeIntegrity(this)

        database = TowerDatabase.getInstance(this)
    }
}

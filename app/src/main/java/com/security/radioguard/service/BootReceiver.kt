package com.security.radioguard.service

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.os.Build
import com.security.radioguard.security.AppIntegrityValidator

class BootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action == Intent.ACTION_BOOT_COMPLETED || 
            intent.action == Intent.ACTION_MY_PACKAGE_REPLACED) {
            
            val serviceIntent = Intent(context, RadioGuardService::class.java).apply {
                action = RadioGuardService.ACTION_START_SENTRY
            }
            AppIntegrityValidator.signInternalIntent(serviceIntent)

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                context.startForegroundService(serviceIntent)
            } else {
                context.startService(serviceIntent)
            }
        }
    }
}

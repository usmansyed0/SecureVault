package com.securevault

import android.app.Application
import com.securevault.security.DeadManSwitchWorker
import dagger.hilt.android.HiltAndroidApp

@HiltAndroidApp
class SecureVaultApplication : Application() {
    override fun onCreate() {
        super.onCreate()
        try {
            DeadManSwitchWorker.schedule(this)
        } catch (_: Exception) {
        }
    }
}

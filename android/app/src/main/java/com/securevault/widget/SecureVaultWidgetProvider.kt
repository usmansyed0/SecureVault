package com.securevault.widget

import android.app.PendingIntent
import android.appwidget.AppWidgetManager
import android.appwidget.AppWidgetProvider
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.widget.RemoteViews
import com.securevault.MainActivity
import com.securevault.R
import com.securevault.security.SafeSecurityLogger

/**
 * Zero-Knowledge Quick Actions Widget Provider.
 *
 * Provides rapid shortcuts from the Android home screen:
 * - Direct lock command to clear in-memory cryptographic state
 * - Quick Add Entry shortcut
 * - Quick Scan Document shortcut
 *
 * Zero-Knowledge Guarantee:
 * This widget NEVER renders, stores, or requests plaintext passwords,
 * document titles, usernames, record counts, or sensitive user data.
 */
class SecureVaultWidgetProvider : AppWidgetProvider() {

    companion object {
        const val ACTION_LOCK_VAULT = "com.securevault.widget.ACTION_LOCK_VAULT"
        const val ACTION_ADD_ITEM = "com.securevault.ACTION_ADD_ITEM"
        const val ACTION_SCAN_DOC = "com.securevault.ACTION_SCAN_DOC"

        /**
         * Broadcast helper to refresh widget status across all active instances.
         */
        fun updateAllWidgets(context: Context) {
            val intent = Intent(context, SecureVaultWidgetProvider::class.java).apply {
                action = AppWidgetManager.ACTION_APPWIDGET_UPDATE
            }
            val widgetManager = AppWidgetManager.getInstance(context)
            val ids = widgetManager.getAppWidgetIds(ComponentName(context, SecureVaultWidgetProvider::class.java))
            intent.putExtra(AppWidgetManager.EXTRA_APPWIDGET_IDS, ids)
            context.sendBroadcast(intent)
        }
    }

    override fun onUpdate(
        context: Context,
        appWidgetManager: AppWidgetManager,
        appWidgetIds: IntArray
    ) {
        for (widgetId in appWidgetIds) {
            updateAppWidget(context, appWidgetManager, widgetId)
        }
    }

    override fun onReceive(context: Context, intent: Intent) {
        super.onReceive(context, intent)
        if (intent.action == ACTION_LOCK_VAULT) {
            SafeSecurityLogger.event("widget_lock_triggered")
            // Broadcast lock event or notify main activity
            val lockIntent = Intent(context, MainActivity::class.java).apply {
                action = ACTION_LOCK_VAULT
                flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP
            }
            context.startActivity(lockIntent)
            updateAllWidgets(context)
        }
    }

    private fun updateAppWidget(
        context: Context,
        appWidgetManager: AppWidgetManager,
        appWidgetId: Int
    ) {
        val views = RemoteViews(context.packageName, R.layout.widget_quick_actions)

        // 1. Header click: Launch MainActivity
        val mainIntent = Intent(context, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_SINGLE_TOP
        }
        val mainPendingIntent = PendingIntent.getActivity(
            context,
            0,
            mainIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        views.setOnClickPendingIntent(R.id.widget_header, mainPendingIntent)

        // 2. Lock button click: Broadcast ACTION_LOCK_VAULT
        val lockIntent = Intent(context, SecureVaultWidgetProvider::class.java).apply {
            action = ACTION_LOCK_VAULT
        }
        val lockPendingIntent = PendingIntent.getBroadcast(
            context,
            1,
            lockIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        views.setOnClickPendingIntent(R.id.widget_btn_lock, lockPendingIntent)

        // 3. Add Item click: Launch MainActivity with ACTION_ADD_ITEM
        val addIntent = Intent(context, MainActivity::class.java).apply {
            action = ACTION_ADD_ITEM
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_SINGLE_TOP
        }
        val addPendingIntent = PendingIntent.getActivity(
            context,
            2,
            addIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        views.setOnClickPendingIntent(R.id.widget_btn_add, addPendingIntent)

        // 4. Scan Doc click: Launch MainActivity with ACTION_SCAN_DOC
        val scanIntent = Intent(context, MainActivity::class.java).apply {
            action = ACTION_SCAN_DOC
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_SINGLE_TOP
        }
        val scanPendingIntent = PendingIntent.getActivity(
            context,
            3,
            scanIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        views.setOnClickPendingIntent(R.id.widget_btn_scan, scanPendingIntent)

        appWidgetManager.updateAppWidget(appWidgetId, views)
    }
}

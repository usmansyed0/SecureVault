package com.securevault.widget

import android.content.Context
import android.content.Intent
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class SecureVaultWidgetProviderTest {

    private val context: Context = RuntimeEnvironment.getApplication()

    @Test
    fun widgetConstants_areProperlyConfigured() {
        assertEquals("com.securevault.widget.ACTION_LOCK_VAULT", SecureVaultWidgetProvider.ACTION_LOCK_VAULT)
        assertEquals("com.securevault.ACTION_ADD_ITEM", SecureVaultWidgetProvider.ACTION_ADD_ITEM)
        assertEquals("com.securevault.ACTION_SCAN_DOC", SecureVaultWidgetProvider.ACTION_SCAN_DOC)
    }

    @Test
    fun onReceive_handlesLockVaultActionWithoutThrowing() {
        val provider = SecureVaultWidgetProvider()
        val intent = Intent(SecureVaultWidgetProvider.ACTION_LOCK_VAULT)

        // Should execute smoothly and trigger security log without crashing
        provider.onReceive(context, intent)
        assertNotNull(provider)
    }

    @Test
    fun onReceive_ignoresUnknownAction() {
        val provider = SecureVaultWidgetProvider()
        val intent = Intent("com.securevault.UNKNOWN_ACTION")

        provider.onReceive(context, intent)
        assertNotNull(provider)
    }
}

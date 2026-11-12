package com.securevault.security

import android.content.Context
import android.util.Base64
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey

/** Stores only an encrypted refresh token; access token stays memory-only. */
interface RefreshTokenStorage { fun saveRefreshToken(token: String); fun refreshToken(): String?; fun clear() }

class SecureSessionStore(context: Context) : RefreshTokenStorage {
    private val prefs = EncryptedSharedPreferences.create(context, "session.enc", MasterKey.Builder(context).setKeyScheme(MasterKey.KeyScheme.AES256_GCM).build(), EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV, EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM)
    override fun saveRefreshToken(token: String) = prefs.edit().putString("refresh_token", token).apply()
    override fun refreshToken(): String? = prefs.getString("refresh_token", null)
    fun saveDisplayName(name: String) = prefs.edit().putString("display_name", name).apply()
    fun displayName(): String? = prefs.getString("display_name", null)
    fun saveUserEmail(email: String) = prefs.edit().putString("user_email", email).apply()
    fun userEmail(): String? = prefs.getString("user_email", null)
    fun saveDeviceId(deviceId: String) = prefs.edit().putString("device_id", deviceId).apply()
    fun deviceId(): String? = prefs.getString("device_id", null)
    fun saveLastServerContact(epochMillis: Long) = prefs.edit().putLong("last_server_contact", epochMillis).apply()
    fun lastServerContact(): Long = prefs.getLong("last_server_contact", 0L)
    fun saveDeadManSwitchDays(days: Int) = prefs.edit().putInt("dead_man_switch_days", days.coerceIn(1, 30)).apply()
    fun deadManSwitchDays(): Int = prefs.getInt("dead_man_switch_days", 7)
    override fun clear() = prefs.edit().clear().apply()
}

package com.securevault.auth

import com.securevault.network.SecureVaultApi
import com.securevault.network.model.RefreshRequestDto
import com.securevault.security.RefreshTokenStorage
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import retrofit2.HttpException

data class SessionTokens(
    val accessToken: String,
    val refreshToken: String,
    val userId: String? = null,
    val deviceId: String? = null,
    val sessionId: String? = null,
    val deviceStatus: String? = null
)

class DeviceRevokedException(val status: String) : Exception("Device has been $status")

interface SessionApi {
    suspend fun refresh(refreshToken: String): SessionTokens
    suspend fun logout(accessToken: String)
    suspend fun logoutAll(accessToken: String)
}

interface VaultAccountLifecycle {
    fun lockForAccountLogout()
    suspend fun wipeForRevokedDevice()
}

/** Access tokens are process-memory only; refresh serialization prevents self-triggered token reuse. */
class SessionCoordinator(
    private val api: SessionApi,
    private val storage: RefreshTokenStorage,
    private val vault: VaultAccountLifecycle
) {
    private val mutex = Mutex()
    @Volatile private var access: String? = null
    @Volatile var userId: String? = null; private set
    @Volatile var deviceId: String? = null; private set
    @Volatile var sessionId: String? = null; private set
    @Volatile var deviceStatus: String? = null; private set

    fun accessToken(): String? = access

    fun install(tokens: SessionTokens) {
        require(tokens.accessToken.isNotBlank() && tokens.refreshToken.length >= 64)
        storage.saveRefreshToken(tokens.refreshToken)
        access = tokens.accessToken
        tokens.userId?.let { userId = it }
        tokens.deviceId?.let {
            deviceId = it
            (storage as? com.securevault.security.SecureSessionStore)?.saveDeviceId(it)
        }
        tokens.sessionId?.let { sessionId = it }
        tokens.deviceStatus?.let { deviceStatus = it }
    }

    fun currentDeviceId(): String? = deviceId ?: (storage as? com.securevault.security.SecureSessionStore)?.deviceId()

    fun updateDeviceStatus(status: String) {
        deviceStatus = status
    }

    suspend fun refreshSingleFlight(): Boolean = mutex.withLock {
        val refresh = storage.refreshToken() ?: return@withLock false
        try {
            val tokens = api.refresh(refresh)
            install(tokens)
            if (tokens.deviceStatus == "revoked" || tokens.deviceStatus == "stolen") {
                handleDeviceState(tokens.deviceStatus)
                return@withLock false
            }
            true
        } catch (e: DeviceRevokedException) {
            handleDeviceState(e.status)
            false
        } catch (_: Exception) {
            clearAndLock()
            false
        }
    }

    suspend fun logout() {
        access?.let { runCatching { api.logout(it) } }
        clearAndLock()
    }

    suspend fun logoutAll() {
        access?.let { runCatching { api.logoutAll(it) } }
        clearAndLock()
    }

    suspend fun handleDeviceState(status: String) {
        if (status == "revoked" || status == "stolen") {
            access = null
            userId = null
            deviceId = null
            sessionId = null
            deviceStatus = status
            storage.clear()
            vault.wipeForRevokedDevice()
        }
    }

    /**
     * Inspects the fetched device list for the current device's status.
     * Triggers mandatory local cryptographic wipe if the current device is revoked or stolen.
     */
    suspend fun inspectDeviceList(devices: List<com.securevault.network.model.DeviceDto>) {
        val currentId = deviceId ?: return
        val currentDevice = devices.find { it.id == currentId } ?: return
        if (currentDevice.status == "revoked" || currentDevice.status == "stolen") {
            handleDeviceState(currentDevice.status)
        } else {
            deviceStatus = currentDevice.status
        }
    }

    private fun clearAndLock() {
        access = null
        storage.clear()
        vault.lockForAccountLogout()
    }
}

class NetworkSessionApi(private val api: SecureVaultApi) : SessionApi {
    override suspend fun refresh(refreshToken: String): SessionTokens {
        val response = try {
            api.refresh(RefreshRequestDto(refreshToken))
        } catch (e: HttpException) {
            if (e.code() == 403) {
                val errorBody = e.response()?.errorBody()?.string() ?: ""
                if (errorBody.contains("device_stolen")) throw DeviceRevokedException("stolen")
                if (errorBody.contains("device_revoked")) throw DeviceRevokedException("revoked")
            }
            throw e
        }
        return SessionTokens(
            accessToken = response.access_token,
            refreshToken = response.refresh_token,
            userId = response.user_id,
            deviceId = response.device_id,
            sessionId = response.session_id,
            deviceStatus = response.device_status
        )
    }

    override suspend fun logout(accessToken: String) {
        api.logout()
    }

    override suspend fun logoutAll(accessToken: String) {
        api.logoutAll()
    }
}

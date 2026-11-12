package com.securevault.auth

import com.securevault.security.RefreshTokenStorage
import kotlinx.coroutines.runBlocking
import org.junit.Assert.*
import org.junit.Test

class SessionCoordinatorTest {
    @Test fun refreshRotatesStoredTokenAndAccessRemainsMemoryOnly() = runBlocking {
        val storage = FakeStorage("old".padEnd(64, 'x'))
        val api = FakeApi()
        val vault = FakeVault()
        val session = SessionCoordinator(api, storage, vault)

        assertNull(session.accessToken())
        assertTrue(session.refreshSingleFlight())
        assertEquals("new".padEnd(64, 'y'), storage.value)
        assertEquals("access", session.accessToken())
        assertEquals("user-1", session.userId)
        assertEquals("device-1", session.deviceId)
        assertEquals("session-1", session.sessionId)
        assertEquals("trusted", session.deviceStatus)
        assertEquals(1, api.refreshes)
    }

    @Test fun logoutPreservesVaultButRevocationWipesIt() = runBlocking {
        val storage = FakeStorage("old".padEnd(64, 'x'))
        val vault = FakeVault()
        val session = SessionCoordinator(FakeApi(), storage, vault)

        session.install(SessionTokens("access", "new".padEnd(64, 'y'), "user-1", "device-1", "session-1", "trusted"))
        session.logout()

        assertNull(storage.value)
        assertNull(session.accessToken())
        assertEquals(1, vault.locks)
        assertEquals(0, vault.wipes)

        session.handleDeviceState("stolen")
        assertEquals(1, vault.wipes)
    }

    @Test fun refreshRevocationExceptionTriggersMandatoryLocalWipe() = runBlocking {
        val storage = FakeStorage("old".padEnd(64, 'x'))
        val vault = FakeVault()
        val api = FakeApi().apply { throwRevoked = true }
        val session = SessionCoordinator(api, storage, vault)

        val refreshed = session.refreshSingleFlight()
        assertFalse(refreshed)
        assertNull(storage.value)
        assertNull(session.accessToken())
        assertEquals(0, vault.locks)
        assertEquals(1, vault.wipes)
    }

    @Test fun refreshGenericErrorLocksVaultWithoutWiping() = runBlocking {
        val storage = FakeStorage("old".padEnd(64, 'x'))
        val vault = FakeVault()
        val api = FakeApi().apply { throwGenericError = true }
        val session = SessionCoordinator(api, storage, vault)

        val refreshed = session.refreshSingleFlight()
        assertFalse(refreshed)
        assertNull(storage.value)
        assertNull(session.accessToken())
        assertEquals(1, vault.locks)
        assertEquals(0, vault.wipes)
    }

    @Test fun currentDeviceRevokedInDeviceListTriggersImmediateWipe() = runBlocking {
        val storage = FakeStorage("refresh-token".padEnd(64, 'x'))
        val vault = FakeVault()
        val session = SessionCoordinator(FakeApi(), storage, vault)
        session.install(SessionTokens("access-token", "refresh-token".padEnd(64, 'x'), "u-1", "dev-current", "s-1", "trusted"))

        val devices = listOf(
            com.securevault.network.model.DeviceDto("dev-current", "Current Phone", "android", "revoked")
        )
        session.inspectDeviceList(devices)

        assertEquals(1, vault.wipes)
        assertNull(session.accessToken())
        assertNull(session.deviceId)
        assertNull(storage.value)
    }

    @Test fun currentDeviceStolenInDeviceListTriggersImmediateWipe() = runBlocking {
        val storage = FakeStorage("refresh-token".padEnd(64, 'x'))
        val vault = FakeVault()
        val session = SessionCoordinator(FakeApi(), storage, vault)
        session.install(SessionTokens("access-token", "refresh-token".padEnd(64, 'x'), "u-1", "dev-current", "s-1", "trusted"))

        val devices = listOf(
            com.securevault.network.model.DeviceDto("dev-current", "Current Phone", "android", "stolen")
        )
        session.inspectDeviceList(devices)

        assertEquals(1, vault.wipes)
        assertNull(session.accessToken())
        assertNull(session.deviceId)
        assertNull(storage.value)
    }

    @Test fun currentDeviceTrustedInDeviceListDoesNotWipe() = runBlocking {
        val storage = FakeStorage("refresh-token".padEnd(64, 'x'))
        val vault = FakeVault()
        val session = SessionCoordinator(FakeApi(), storage, vault)
        session.install(SessionTokens("access-token", "refresh-token".padEnd(64, 'x'), "u-1", "dev-current", "s-1", "pending"))

        val devices = listOf(
            com.securevault.network.model.DeviceDto("dev-current", "Current Phone", "android", "trusted")
        )
        session.inspectDeviceList(devices)

        assertEquals(0, vault.wipes)
        assertEquals(0, vault.locks)
        assertEquals("access-token", session.accessToken())
        assertEquals("dev-current", session.deviceId)
        assertEquals("trusted", session.deviceStatus)
    }

    @Test fun anotherDeviceRevokedOrStolenInDeviceListDoesNotWipeCurrentDevice() = runBlocking {
        val storage = FakeStorage("refresh-token".padEnd(64, 'x'))
        val vault = FakeVault()
        val session = SessionCoordinator(FakeApi(), storage, vault)
        session.install(SessionTokens("access-token", "refresh-token".padEnd(64, 'x'), "u-1", "dev-current", "s-1", "trusted"))

        val devices = listOf(
            com.securevault.network.model.DeviceDto("dev-current", "Current Phone", "android", "trusted"),
            com.securevault.network.model.DeviceDto("dev-other-1", "Stolen Tablet", "android", "stolen"),
            com.securevault.network.model.DeviceDto("dev-other-2", "Old Revoked Phone", "android", "revoked")
        )
        session.inspectDeviceList(devices)

        assertEquals(0, vault.wipes)
        assertEquals(0, vault.locks)
        assertEquals("access-token", session.accessToken())
        assertEquals("dev-current", session.deviceId)
        assertEquals("trusted", session.deviceStatus)
    }

    private class FakeStorage(var value: String?) : RefreshTokenStorage {
        override fun saveRefreshToken(token: String) { value = token }
        override fun refreshToken() = value
        override fun clear() { value = null }
    }

    private class FakeApi : SessionApi {
        var refreshes = 0
        var throwRevoked = false
        var throwGenericError = false

        override suspend fun refresh(refreshToken: String): SessionTokens {
            refreshes++
            if (throwRevoked) throw DeviceRevokedException("revoked")
            if (throwGenericError) throw RuntimeException("401 Unauthorized")
            return SessionTokens("access", "new".padEnd(64, 'y'), "user-1", "device-1", "session-1", "trusted")
        }

        override suspend fun logout(accessToken: String) {}
        override suspend fun logoutAll(accessToken: String) {}
    }

    private class FakeVault : VaultAccountLifecycle {
        var locks = 0
        var wipes = 0
        override fun lockForAccountLogout() { locks++ }
        override suspend fun wipeForRevokedDevice() { wipes++ }
    }
}

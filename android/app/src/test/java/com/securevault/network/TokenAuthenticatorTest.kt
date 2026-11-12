package com.securevault.network

import com.securevault.auth.DeviceRevokedException
import com.securevault.auth.SessionCoordinator
import com.securevault.auth.SessionTokens
import com.securevault.auth.SessionApi
import com.securevault.auth.VaultAccountLifecycle
import com.securevault.security.RefreshTokenStorage
import okhttp3.Protocol
import okhttp3.Request
import okhttp3.Response
import org.junit.Assert.*
import org.junit.Test

class TokenAuthenticatorTest {

    @Test
    fun on401RefreshesTokenAndRetriesWithNewBearer() {
        val storage = FakeStorage("refresh-initial".padEnd(64, 'a'))
        val api = FakeApi().apply {
            nextTokens = SessionTokens("fresh-access-token", "new-refresh-token".padEnd(64, 'b'))
        }
        val vault = FakeVault()
        val coordinator = SessionCoordinator(api, storage, vault)
        coordinator.install(SessionTokens("expired-access-token", "refresh-initial".padEnd(64, 'a')))

        val authenticator = TokenAuthenticator { coordinator }

        val request = Request.Builder()
            .url("https://example.test/v1/devices")
            .header("Authorization", "Bearer expired-access-token")
            .build()
        val response = Response.Builder()
            .request(request)
            .protocol(Protocol.HTTP_1_1)
            .code(401)
            .message("Unauthorized")
            .build()

        val retriedRequest = authenticator.authenticate(null, response)

        assertNotNull(retriedRequest)
        assertEquals("Bearer fresh-access-token", retriedRequest!!.header("Authorization"))
        assertEquals(1, api.refreshes)
        assertEquals(0, vault.wipes)
        assertEquals(0, vault.locks)
    }

    @Test
    fun doesNotInterceptAuthEndpointsToPreventLoops() {
        val storage = FakeStorage("refresh-token".padEnd(64, 'a'))
        val api = FakeApi()
        val vault = FakeVault()
        val coordinator = SessionCoordinator(api, storage, vault)
        val authenticator = TokenAuthenticator { coordinator }

        val refreshRequest = Request.Builder()
            .url("https://example.test/v1/auth/refresh")
            .build()
        val response = Response.Builder()
            .request(refreshRequest)
            .protocol(Protocol.HTTP_1_1)
            .code(401)
            .message("Unauthorized")
            .build()

        val result = authenticator.authenticate(null, response)
        assertNull(result)
        assertEquals(0, api.refreshes)
    }

    @Test
    fun preventsInfiniteRetryLoopAfterMaxRetries() {
        val storage = FakeStorage("refresh-token".padEnd(64, 'a'))
        val api = FakeApi()
        val vault = FakeVault()
        val coordinator = SessionCoordinator(api, storage, vault)
        val authenticator = TokenAuthenticator { coordinator }

        val request = Request.Builder()
            .url("https://example.test/v1/devices")
            .header("Authorization", "Bearer access")
            .build()
        val prior1 = Response.Builder()
            .request(request)
            .protocol(Protocol.HTTP_1_1)
            .code(401)
            .message("Unauthorized")
            .build()
        val response = Response.Builder()
            .request(request)
            .protocol(Protocol.HTTP_1_1)
            .code(401)
            .message("Unauthorized")
            .priorResponse(prior1)
            .build()

        val result = authenticator.authenticate(null, response)
        assertNull(result)
        assertEquals(0, api.refreshes)
    }

    @Test
    fun revokedOrStolenRefreshCausesMandatoryLocalWipeAndStopsRetry() {
        val storage = FakeStorage("refresh-token".padEnd(64, 'a'))
        val api = FakeApi().apply { throwRevoked = true }
        val vault = FakeVault()
        val coordinator = SessionCoordinator(api, storage, vault)
        coordinator.install(SessionTokens("expired-access", "refresh-token".padEnd(64, 'a')))

        val authenticator = TokenAuthenticator { coordinator }

        val request = Request.Builder()
            .url("https://example.test/v1/devices")
            .header("Authorization", "Bearer expired-access")
            .build()
        val response = Response.Builder()
            .request(request)
            .protocol(Protocol.HTTP_1_1)
            .code(401)
            .message("Unauthorized")
            .build()

        val result = authenticator.authenticate(null, response)
        assertNull(result)
        assertEquals(1, vault.wipes)
        assertNull(coordinator.accessToken())
    }

    private class FakeStorage(var token: String?) : RefreshTokenStorage {
        override fun saveRefreshToken(t: String) { token = t }
        override fun refreshToken(): String? = token
        override fun clear() { token = null }
    }

    private class FakeApi : SessionApi {
        var refreshes = 0
        var throwRevoked = false
        var nextTokens: SessionTokens? = null

        override suspend fun refresh(refreshToken: String): SessionTokens {
            refreshes++
            if (throwRevoked) throw DeviceRevokedException("revoked")
            return nextTokens ?: throw RuntimeException("401 Unauthorized")
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

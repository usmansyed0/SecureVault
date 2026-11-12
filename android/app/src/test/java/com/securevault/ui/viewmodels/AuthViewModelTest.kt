package com.securevault.ui.viewmodels

import com.securevault.auth.SessionCoordinator
import com.securevault.network.SecureVaultApi
import com.securevault.network.model.GoogleNonceResponseDto
import com.securevault.network.model.TokensDto
import com.securevault.security.DeviceSigningKey
import com.securevault.security.SecureSessionStore
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.*
import okhttp3.ResponseBody.Companion.toResponseBody
import org.junit.After
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import org.mockito.kotlin.any
import org.mockito.kotlin.mock
import org.mockito.kotlin.whenever
import retrofit2.HttpException
import retrofit2.Response
import java.io.IOException

@OptIn(ExperimentalCoroutinesApi::class)
class AuthViewModelTest {

    private val testDispatcher = UnconfinedTestDispatcher()
    private val api: SecureVaultApi = mock()
    private val sessionCoordinator: SessionCoordinator = mock()
    private val sessionStore: SecureSessionStore = mock()
    private val deviceSigningKey: DeviceSigningKey = mock()

    private lateinit var viewModel: AuthViewModel

    @Before
    fun setUp() {
        Dispatchers.setMain(testDispatcher)
        whenever(deviceSigningKey.publicKeyBase64()).thenReturn("fake-public-key")
        viewModel = AuthViewModel(api, sessionCoordinator, sessionStore, deviceSigningKey)
    }

    @After
    fun tearDown() {
        Dispatchers.resetMain()
    }

    @Test
    fun fetchGoogleNonce_returnsNullOnFailure() = runTest {
        whenever(api.getGoogleNonce()).thenThrow(RuntimeException("Network down"))
        val nonce = viewModel.fetchGoogleNonce()
        assertNull(nonce)
    }

    @Test
    fun fetchGoogleNonce_returnsNonceOnSuccess() = runTest {
        whenever(api.getGoogleNonce()).thenReturn(GoogleNonceResponseDto(nonce = "test-nonce-12345", expires_in_seconds = 300))
        val nonce = viewModel.fetchGoogleNonce()
        assertEquals("test-nonce-12345", nonce)
    }

    @Test
    fun onGoogleSignInCancelled_emitsCancellationEventAndClearsLoading() = runTest {
        var eventReceived: AuthEvent? = null
        val job = launch(testDispatcher) {
            viewModel.events.collect { eventReceived = it }
        }

        viewModel.onGoogleSignInCancelled()

        assertEquals(AuthEvent.GoogleSignInCancelled, eventReceived)
        assertFalse(viewModel.uiState.value.isLoading)
        assertNull(viewModel.uiState.value.errorMessage)
        job.cancel()
    }

    @Test
    fun completeGoogleSignIn_server401_mapsToAuthError() = runTest {
        val errorResponse = Response.error<TokensDto>(401, "{\"detail\":\"Unauthorized\"}".toResponseBody())
        whenever(api.googleAuth(any())).thenThrow(HttpException(errorResponse))

        var successCalled = false
        viewModel.completeGoogleSignIn("id-token", "server-nonce") {
            successCalled = true
        }

        assertFalse(successCalled)
        assertFalse(viewModel.uiState.value.isLoading)
        assertNotNull(viewModel.uiState.value.errorMessage)
        assertFalse(viewModel.uiState.value.errorMessage!!.contains("detail"))
    }

    @Test
    fun completeGoogleSignIn_serverUnreachable_mapsToNetworkError() = runTest {
        whenever(api.googleAuth(any())).thenThrow(IOException("Failed to connect to /api.securevault.app"))

        var successCalled = false
        viewModel.completeGoogleSignIn("id-token", "server-nonce") {
            successCalled = true
        }

        assertFalse(successCalled)
        assertFalse(viewModel.uiState.value.isLoading)
        assertNotNull(viewModel.uiState.value.errorMessage)
        assertFalse(viewModel.uiState.value.errorMessage!!.contains("api.securevault.app"))
    }
}

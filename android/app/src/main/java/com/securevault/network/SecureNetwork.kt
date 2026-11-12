package com.securevault.network

import com.securevault.auth.SessionCoordinator
import com.securevault.network.model.*
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import okhttp3.Authenticator
import okhttp3.Interceptor
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.Response
import okhttp3.Route
import retrofit2.Retrofit
import retrofit2.converter.kotlinx.serialization.asConverterFactory
import retrofit2.http.Body
import retrofit2.http.GET
import retrofit2.http.POST
import retrofit2.http.Path
import java.util.concurrent.TimeUnit

/** TLS is mandatory; this class deliberately has no trust-all or validation-bypass mode. */
class BearerInterceptor(private val token: () -> String?) : Interceptor {
    override fun intercept(chain: Interceptor.Chain): Response = chain.proceed(
        chain.request().newBuilder().apply {
            token()?.let { header("Authorization", "Bearer $it") }
        }.build()
    )
}

/**
 * Automatically handles 401 Unauthorized responses on protected endpoints by calling
 * SessionCoordinator.refreshSingleFlight() and retrying the request once with the new access token.
 */
class TokenAuthenticator(
    private val sessionCoordinatorProvider: () -> SessionCoordinator
) : Authenticator {
    override fun authenticate(route: Route?, response: Response): Request? {
        val path = response.request.url.encodedPath
        // Prevent refresh loops on auth endpoints
        if (path.endsWith("/auth/refresh") || path.endsWith("/auth/login") || path.endsWith("/auth/register")) {
            return null
        }

        // Prevent infinite retries: retry at most once
        if (responseCount(response) >= 2) {
            return null
        }

        val requestAuthHeader = response.request.header("Authorization")
        val coordinator = sessionCoordinatorProvider()

        val refreshed = runBlocking {
            val currentToken = coordinator.accessToken()
            val currentHeader = currentToken?.let { "Bearer $it" }
            // If another concurrent request already refreshed the token, use it immediately
            if (currentHeader != null && currentHeader != requestAuthHeader) {
                true
            } else {
                coordinator.refreshSingleFlight()
            }
        }

        if (!refreshed) {
            return null
        }

        val newToken = coordinator.accessToken() ?: return null
        return response.request.newBuilder()
            .header("Authorization", "Bearer $newToken")
            .build()
    }

    private fun responseCount(response: Response): Int {
        var count = 1
        var prior = response.priorResponse
        while (prior != null) {
            count++
            prior = prior.priorResponse
        }
        return count
    }
}

fun secureHttpClient(
    token: () -> String?,
    authenticator: Authenticator? = null,
    deviceSigningInterceptor: Interceptor? = null
): OkHttpClient = OkHttpClient.Builder()
    .addInterceptor(BearerInterceptor(token))
    .apply {
        if (deviceSigningInterceptor != null) {
            addInterceptor(deviceSigningInterceptor)
        }
        if (authenticator != null) {
            authenticator(authenticator)
        }
    }
    .connectTimeout(5, TimeUnit.SECONDS)
    .readTimeout(15, TimeUnit.SECONDS)
    .build()

interface SecureVaultApi {
    @POST("v1/auth/register")
    suspend fun register(@Body body: RegisterRequestDto): Map<String, String>

    @POST("v1/auth/login")
    suspend fun login(@Body body: LoginRequestDto): TokensDto

    @GET("v1/auth/google/nonce")
    suspend fun getGoogleNonce(): GoogleNonceResponseDto

    @POST("v1/auth/google")
    suspend fun googleAuth(@Body body: GoogleAuthRequestDto): TokensDto

    @POST("v1/auth/refresh")
    suspend fun refresh(@Body body: RefreshRequestDto): TokensDto

    @POST("v1/auth/logout")
    suspend fun logout(): retrofit2.Response<Unit>

    @POST("v1/auth/logout-all")
    suspend fun logoutAll(): retrofit2.Response<Unit>

    @POST("v1/auth/step-up/challenge")
    suspend fun requestStepUpChallenge(@Body body: StepUpChallengeRequestDto): StepUpChallengeResponseDto

    @POST("v1/auth/step-up/complete")
    suspend fun completeStepUp(@Body body: StepUpCompleteRequestDto): StepUpGrantResponseDto

    @POST("v1/auth/step-up/google")
    suspend fun completeStepUpGoogle(@Body body: StepUpGoogleRequestDto): StepUpGrantResponseDto

    @POST("v1/auth/bootstrap")
    suspend fun bootstrap(@Body body: StepUpGrantRequestDto): retrofit2.Response<Unit>

    @GET("v1/devices")
    suspend fun listDevices(): List<DeviceDto>

    @POST("v1/devices/{deviceId}/revoke")
    suspend fun revokeDevice(
        @Path("deviceId") deviceId: String,
        @Body body: StepUpGrantRequestDto
    ): retrofit2.Response<Unit>

    @POST("v1/devices/{deviceId}/mark-stolen")
    suspend fun markDeviceStolen(
        @Path("deviceId") deviceId: String,
        @Body body: StepUpGrantRequestDto
    ): retrofit2.Response<Unit>

    @POST("v1/devices/{deviceId}/end-sessions")
    suspend fun endDeviceSessions(
        @Path("deviceId") deviceId: String,
        @Body body: StepUpGrantRequestDto
    ): retrofit2.Response<Unit>

    @POST("v1/devices/sign-out-others")
    suspend fun signOutOtherDevices(
        @Body body: StepUpGrantRequestDto
    ): retrofit2.Response<Unit>

    @retrofit2.http.GET("v1/auth/salt")
    suspend fun getSalt(@retrofit2.http.Query("login") login: String): SaltResponseDto

    @retrofit2.http.GET("v1/vault/binding")
    suspend fun getVaultBinding(): VaultBindingDto

    @retrofit2.http.PUT("v1/vault/binding")
    suspend fun putVaultBinding(@Body body: VaultBindingDto): retrofit2.Response<Unit>

    @retrofit2.http.GET("v1/vault/changes")
    suspend fun getChanges(@retrofit2.http.Query("since_seq") sinceSeq: Long): SyncChangesResponseDto

    @retrofit2.http.PUT("v1/vault/records/{recordId}")
    suspend fun upsertRecord(
        @Path("recordId") recordId: String,
        @Body body: SyncRecordUpsertDto
    ): Map<String, String>

    @retrofit2.http.DELETE("v1/vault/records/{recordId}")
    suspend fun deleteRecord(@Path("recordId") recordId: String): Map<String, String>

    @POST("v1/shares")
    suspend fun createShare(@Body body: CreateShareRequestDto): CreateShareResponseDto

    @GET("v1/shares")
    suspend fun listShares(): List<ShareSummaryDto>

    @retrofit2.http.DELETE("v1/shares/{shareId}")
    suspend fun revokeShare(@Path("shareId") shareId: String): retrofit2.Response<Unit>

    @POST("v1/backups")
    suspend fun createBackup(@Body body: CreateBackupRequestDto): Map<String, String>

    @GET("v1/backups")
    suspend fun listBackups(): List<BackupSummaryDto>
}

fun createSecureVaultApi(baseUrl: String, client: OkHttpClient): SecureVaultApi {
    val json = Json {
        ignoreUnknownKeys = true
        encodeDefaults = true
    }
    return Retrofit.Builder()
        .baseUrl(baseUrl)
        .client(client)
        .addConverterFactory(json.asConverterFactory("application/json".toMediaType()))
        .build()
        .create(SecureVaultApi::class.java)
}

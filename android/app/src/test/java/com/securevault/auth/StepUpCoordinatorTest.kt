package com.securevault.auth

import com.securevault.network.SecureVaultApi
import com.securevault.network.model.*
import com.securevault.security.DeviceSigner
import com.securevault.security.RefreshTokenStorage
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Test
import retrofit2.Response
import java.security.KeyPairGenerator
import java.security.Signature

class StepUpCoordinatorTest {

    @Test
    fun canonicalStepUpMessageBuildsExactBackendFormat() {
        val storage = FakeStorage()
        val lifecycle = FakeLifecycle()
        val sessionApi = FakeSessionApi()
        val sessionCoordinator = SessionCoordinator(sessionApi, storage, lifecycle)
        sessionCoordinator.install(
            SessionTokens(
                accessToken = "test-access",
                refreshToken = "r".repeat(64),
                userId = "user-123",
                deviceId = "dev-456",
                sessionId = "sess-789",
                deviceStatus = "trusted"
            )
        )

        val api = FakeApi()
        val deviceSigningKey = FakeSigner()
        val coordinator = StepUpCoordinator(api, deviceSigningKey, sessionCoordinator)

        val messageBytes = coordinator.buildCanonicalMessage("chal-001", "device_revoke", "challenge-xyz")
        val expected = "securevault.step-up.v1|chal-001|device_revoke|user-123|dev-456|sess-789|challenge-xyz".encodeToByteArray()

        assertEquals(expected.decodeToString(), messageBytes.decodeToString())
    }

    @Test
    fun executeStepUpOrchestratesChallengeSigningAndCompletion() = runBlocking {
        val storage = FakeStorage()
        val lifecycle = FakeLifecycle()
        val sessionApi = FakeSessionApi()
        val sessionCoordinator = SessionCoordinator(sessionApi, storage, lifecycle)
        sessionCoordinator.install(
            SessionTokens(
                accessToken = "test-access",
                refreshToken = "r".repeat(64),
                userId = "u-1",
                deviceId = "d-1",
                sessionId = "s-1",
                deviceStatus = "pending"
            )
        )

        val api = FakeApi().apply {
            challengeResponse = StepUpChallengeResponseDto("c-id", "chal-secret", "bootstrap", 120)
            grantResponse = StepUpGrantResponseDto("grant-abc-123", "bootstrap", 120)
        }
        val deviceSigningKey = FakeSigner().apply {
            signatureBytes = byteArrayOf(1, 2, 3)
        }

        val coordinator = StepUpCoordinator(api, deviceSigningKey, sessionCoordinator)

        val kpg = KeyPairGenerator.getInstance("RSA")
        kpg.initialize(512)
        val kp = kpg.generateKeyPair()
        val dummySignature = Signature.getInstance("SHA256withRSA").apply {
            initSign(kp.private)
        }

        val grant = coordinator.executeStepUp("bootstrap", "correct-password-123", dummySignature)
        assertEquals("grant-abc-123", grant)
        assertEquals("c-id", api.lastCompleteRequest?.challenge_id)
        assertEquals("chal-secret", api.lastCompleteRequest?.challenge)
        assertEquals("correct-password-123", api.lastCompleteRequest?.auth_secret)
    }

    private class FakeStorage : RefreshTokenStorage {
        override fun saveRefreshToken(token: String) {}
        override fun refreshToken(): String? = null
        override fun clear() {}
    }

    private class FakeLifecycle : VaultAccountLifecycle {
        override fun lockForAccountLogout() {}
        override suspend fun wipeForRevokedDevice() {}
    }

    private class FakeSessionApi : SessionApi {
        override suspend fun refresh(refreshToken: String): SessionTokens = throw UnsupportedOperationException()
        override suspend fun logout(accessToken: String) {}
        override suspend fun logoutAll(accessToken: String) {}
    }

    private class FakeSigner : DeviceSigner {
        var signatureBytes: ByteArray = byteArrayOf()
        override fun createIfMissing() {}
        override fun publicKeyDer(): ByteArray = byteArrayOf()
        override fun publicKeyBase64(): String = "fake-pubkey"
        override fun exists(): Boolean = true
        override fun signatureForAuthentication(): Signature = throw UnsupportedOperationException()
        override fun signAuthenticated(signature: Signature, message: ByteArray): ByteArray = signatureBytes
        override fun sign(message: ByteArray): ByteArray = signatureBytes
        override fun delete() {}
    }

    private class FakeApi : SecureVaultApi {
        var challengeResponse: StepUpChallengeResponseDto? = null
        var grantResponse: StepUpGrantResponseDto? = null
        var lastCompleteRequest: StepUpCompleteRequestDto? = null

        override suspend fun register(body: RegisterRequestDto): Map<String, String> = emptyMap()
        override suspend fun login(body: LoginRequestDto): TokensDto = throw UnsupportedOperationException()
        override suspend fun getGoogleNonce(): GoogleNonceResponseDto = GoogleNonceResponseDto(nonce = "test-nonce", expires_in_seconds = 300)
        override suspend fun googleAuth(body: com.securevault.network.model.GoogleAuthRequestDto): TokensDto = throw UnsupportedOperationException()
        override suspend fun refresh(body: RefreshRequestDto): TokensDto = throw UnsupportedOperationException()
        override suspend fun logout(): Response<Unit> = Response.success(Unit)
        override suspend fun logoutAll(): Response<Unit> = Response.success(Unit)
        override suspend fun requestStepUpChallenge(body: StepUpChallengeRequestDto): StepUpChallengeResponseDto =
            challengeResponse ?: throw IllegalStateException("No challenge response configured")
        override suspend fun completeStepUp(body: StepUpCompleteRequestDto): StepUpGrantResponseDto {
            lastCompleteRequest = body
            return grantResponse ?: throw IllegalStateException("No grant response configured")
        }
        override suspend fun completeStepUpGoogle(body: StepUpGoogleRequestDto): StepUpGrantResponseDto {
            return grantResponse ?: throw IllegalStateException("No grant response configured")
        }
        override suspend fun bootstrap(body: StepUpGrantRequestDto): Response<Unit> = Response.success(Unit)
        override suspend fun listDevices(): List<DeviceDto> = emptyList()
        override suspend fun revokeDevice(deviceId: String, body: StepUpGrantRequestDto): Response<Unit> = Response.success(Unit)
        override suspend fun markDeviceStolen(deviceId: String, body: StepUpGrantRequestDto): Response<Unit> = Response.success(Unit)
        override suspend fun endDeviceSessions(deviceId: String, body: StepUpGrantRequestDto): Response<Unit> = Response.success(Unit)
        override suspend fun signOutOtherDevices(body: StepUpGrantRequestDto): Response<Unit> = Response.success(Unit)
        override suspend fun getSalt(login: String): com.securevault.network.model.SaltResponseDto = throw UnsupportedOperationException()
        override suspend fun getVaultBinding(): com.securevault.network.model.VaultBindingDto = throw UnsupportedOperationException()
        override suspend fun putVaultBinding(body: com.securevault.network.model.VaultBindingDto): Response<Unit> = Response.success(Unit)
        override suspend fun getChanges(sinceSeq: Long): com.securevault.network.model.SyncChangesResponseDto = throw UnsupportedOperationException()
        override suspend fun upsertRecord(recordId: String, body: com.securevault.network.model.SyncRecordUpsertDto): Map<String, String> = emptyMap()
        override suspend fun deleteRecord(recordId: String): Map<String, String> = emptyMap()
        override suspend fun createShare(body: com.securevault.network.model.CreateShareRequestDto): com.securevault.network.model.CreateShareResponseDto = throw UnsupportedOperationException()
        override suspend fun listShares(): List<com.securevault.network.model.ShareSummaryDto> = emptyList()
        override suspend fun revokeShare(shareId: String): Response<Unit> = Response.success(Unit)
        override suspend fun createBackup(body: com.securevault.network.model.CreateBackupRequestDto): Map<String, String> = emptyMap()
        override suspend fun listBackups(): List<com.securevault.network.model.BackupSummaryDto> = emptyList()
    }
}

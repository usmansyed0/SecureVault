package com.securevault.vault

import com.securevault.crypto.Argon2Kdf
import com.securevault.crypto.RecoveryKeyManager
import com.securevault.crypto.VaultPasswordManager
import com.securevault.network.SecureVaultApi
import com.securevault.network.model.*
import com.securevault.security.*
import com.securevault.vault.clipboard.ClipboardController
import com.securevault.vault.generator.PasswordGenerator
import com.securevault.vault.model.PasswordEntry
import com.securevault.vault.model.SecureNote
import com.securevault.vault.model.VaultItem
import com.securevault.vault.repository.VaultItemRepository
import com.securevault.vault.strength.PasswordStrengthMeter
import com.securevault.vault.ui.VaultCoordinator
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runTest
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import org.mockito.Mockito.mock
import retrofit2.Response
import java.util.UUID

@OptIn(ExperimentalCoroutinesApi::class)
class Phase7SharingAndRecoveryTest {

    private val testDispatcher = StandardTestDispatcher()
    private lateinit var itemRepository: VaultItemRepository
    private lateinit var keyManager: VaultKeyManager
    private lateinit var session: VaultSession
    private lateinit var clipboard: ClipboardController
    private lateinit var generator: PasswordGenerator
    private lateinit var strengthMeter: PasswordStrengthMeter
    private lateinit var fakeApi: FakeApi
    private lateinit var coordinator: VaultCoordinator

    private val recoveryKeyManager = RecoveryKeyManager()
    private val vaultPasswordManager = VaultPasswordManager(Argon2Kdf(), PasswordStrengthMeter())

    private class FakeApi : SecureVaultApi {
        var createShareResult: CreateShareResponseDto? = null
        var lastCreateShareRequest: CreateShareRequestDto? = null
        var revokedShareId: String? = null

        override suspend fun createShare(body: CreateShareRequestDto): CreateShareResponseDto {
            lastCreateShareRequest = body
            return createShareResult ?: CreateShareResponseDto("s-default", "tok-default", "exp", 1)
        }

        override suspend fun listShares(): List<ShareSummaryDto> = emptyList()

        override suspend fun revokeShare(shareId: String): Response<Unit> {
            revokedShareId = shareId
            return Response.success(Unit)
        }

        override suspend fun register(body: RegisterRequestDto): Map<String, String> = emptyMap()
        override suspend fun login(body: LoginRequestDto): TokensDto = throw UnsupportedOperationException()
        override suspend fun getGoogleNonce(): GoogleNonceResponseDto = throw UnsupportedOperationException()
        override suspend fun googleAuth(body: GoogleAuthRequestDto): TokensDto = throw UnsupportedOperationException()
        override suspend fun refresh(body: RefreshRequestDto): TokensDto = throw UnsupportedOperationException()
        override suspend fun logout(): Response<Unit> = Response.success(Unit)
        override suspend fun logoutAll(): Response<Unit> = Response.success(Unit)
        override suspend fun requestStepUpChallenge(body: StepUpChallengeRequestDto): StepUpChallengeResponseDto = throw UnsupportedOperationException()
        override suspend fun completeStepUp(body: StepUpCompleteRequestDto): StepUpGrantResponseDto = throw UnsupportedOperationException()
        override suspend fun completeStepUpGoogle(body: StepUpGoogleRequestDto): StepUpGrantResponseDto = throw UnsupportedOperationException()
        override suspend fun bootstrap(body: StepUpGrantRequestDto): Response<Unit> = Response.success(Unit)
        override suspend fun listDevices(): List<DeviceDto> = emptyList()
        override suspend fun revokeDevice(deviceId: String, body: StepUpGrantRequestDto): Response<Unit> = Response.success(Unit)
        override suspend fun markDeviceStolen(deviceId: String, body: StepUpGrantRequestDto): Response<Unit> = Response.success(Unit)
        override suspend fun endDeviceSessions(deviceId: String, body: StepUpGrantRequestDto): Response<Unit> = Response.success(Unit)
        override suspend fun signOutOtherDevices(body: StepUpGrantRequestDto): Response<Unit> = Response.success(Unit)
        override suspend fun getSalt(login: String): SaltResponseDto = throw UnsupportedOperationException()
        override suspend fun getVaultBinding(): VaultBindingDto = throw UnsupportedOperationException()
        override suspend fun putVaultBinding(body: VaultBindingDto): Response<Unit> = Response.success(Unit)
        override suspend fun getChanges(sinceSeq: Long): SyncChangesResponseDto = throw UnsupportedOperationException()
        override suspend fun upsertRecord(recordId: String, body: SyncRecordUpsertDto): Map<String, String> = emptyMap()
        override suspend fun deleteRecord(recordId: String): Map<String, String> = emptyMap()
        override suspend fun createBackup(body: CreateBackupRequestDto): Map<String, String> = emptyMap()
        override suspend fun listBackups(): List<BackupSummaryDto> = emptyList()
    }

    @Before
    fun setup() {
        itemRepository = mock(VaultItemRepository::class.java)
        keyManager = mock(VaultKeyManager::class.java)
        session = mock(VaultSession::class.java)
        clipboard = mock(ClipboardController::class.java)
        generator = mock(PasswordGenerator::class.java)
        strengthMeter = mock(PasswordStrengthMeter::class.java)
        fakeApi = FakeApi()

        coordinator = VaultCoordinator(
            itemRepository = itemRepository,
            keyManager = keyManager,
            session = session,
            clipboard = clipboard,
            generator = generator,
            strengthMeter = strengthMeter,
            blobManager = null,
            api = fakeApi,
            dispatcher = testDispatcher
        )
    }

    @Test
    fun testShareUrlPlacesKeyStrictlyInFragment() = runTest(testDispatcher) {
        val entry = PasswordEntry(
            id = UUID.randomUUID().toString(),
            vaultId = "vault-1",
            title = "Test Login",
            username = "alice",
            password = "secretPassword123!"
        )

        fakeApi.createShareResult = CreateShareResponseDto(
            share_id = "share-123",
            share_token = "tok-abc-456",
            expires_at = "2026-10-26T12:00:00Z",
            max_views = 1
        )

        var generatedUrl: String? = null
        coordinator.createShare(
            item = VaultItem.Password(entry),
            expiresInSeconds = 3600,
            maxViews = 1,
            includePassword = false,
            onSuccess = { url -> generatedUrl = url },
            onError = { fail("Should not fail: $it") }
        )

        advanceUntilIdle()

        assertNotNull(generatedUrl)
        assertTrue("URL must start with https://vault.secure/s/", generatedUrl!!.startsWith("https://vault.secure/s/tok-abc-456"))
        assertTrue("URL must contain #key= fragment", generatedUrl!!.contains("#key="))

        val parts = generatedUrl!!.split("#")
        assertEquals("URL must have exactly one fragment separator (#)", 2, parts.size)
        assertTrue("Key parameter must be inside fragment", parts[1].startsWith("key="))
        assertFalse("Key must NOT be in the HTTP path", parts[0].contains("key="))
    }

    @Test
    fun testPasswordSanitizationWhenIncludePasswordIsFalse() = runTest(testDispatcher) {
        val entry = PasswordEntry(
            id = UUID.randomUUID().toString(),
            vaultId = "vault-1",
            title = "Bank Account",
            username = "bob",
            password = "superSensitivePassword999!"
        )

        fakeApi.createShareResult = CreateShareResponseDto("s-1", "tok-1", "exp", 1)

        // includePassword = false (default)
        coordinator.createShare(
            item = VaultItem.Password(entry),
            includePassword = false,
            onSuccess = {},
            onError = { fail(it) }
        )

        advanceUntilIdle()

        val captured = fakeApi.lastCreateShareRequest
        assertNotNull(captured)
        assertEquals("password", captured!!.item_type)
        assertEquals(entry.id, captured.item_id)
    }

    @Test
    fun testBip39RecoveryPhraseRoundTrip() {
        val phrase = recoveryKeyManager.generateRecoveryPhrase()
        assertEquals(24, phrase.words.size)
        assertEquals(32, phrase.recoveryKey.size)

        // Decode back from phrase string
        val recoveredKey = recoveryKeyManager.phraseToRecoveryKey(phrase.phrase)
        assertArrayEquals(phrase.recoveryKey, recoveredKey)

        // VRK wrap and unwrap test
        val vrk = ByteArray(32) { (it * 3).toByte() }
        val wrappedBlob = recoveryKeyManager.wrapVrk(vrk, recoveredKey)
        val unwrappedVrk = recoveryKeyManager.unwrapVrk(wrappedBlob, recoveredKey)

        assertArrayEquals(vrk, unwrappedVrk)
    }

    @Test
    fun testVaultPasswordWrapAndUnwrap() {
        val password = "MyMasterVaultPassword2026!"
        val vrk = ByteArray(32) { (it * 7).toByte() }

        val wrapped = vaultPasswordManager.wrapVrk(vrk, password)
        val unwrappedVrk = vaultPasswordManager.unwrapVrk(
            password = password,
            salt = wrapped.salt,
            nonce = wrapped.nonce,
            ciphertext = wrapped.ciphertext
        )

        assertArrayEquals(vrk, unwrappedVrk)
    }

    @Test
    fun testNoteShareSupport() = runTest(testDispatcher) {
        val note = SecureNote(
            id = "note-1",
            vaultId = "vault-1",
            title = "My Secret Diary",
            content = "This is a private diary entry"
        )

        fakeApi.createShareResult = CreateShareResponseDto("s-2", "tok-2", "exp", 1)

        coordinator.createShare(
            item = VaultItem.Note(note),
            expiresInSeconds = 86400,
            maxViews = 3,
            onSuccess = {},
            onError = { fail(it) }
        )

        advanceUntilIdle()

        val captured = fakeApi.lastCreateShareRequest
        assertNotNull(captured)
        assertEquals("note", captured!!.item_type)
        assertEquals("note-1", captured.item_id)
        assertEquals(86400, captured.expires_in_seconds)
        assertEquals(3, captured.max_views)
    }
}

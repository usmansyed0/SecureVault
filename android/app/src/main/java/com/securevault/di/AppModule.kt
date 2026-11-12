package com.securevault.di

import android.content.Context
import android.os.Handler
import android.os.Looper
import androidx.room.Room
import androidx.room.withTransaction
import com.securevault.auth.NetworkSessionApi
import com.securevault.auth.SessionCoordinator
import com.securevault.auth.VaultAccountLifecycle
import com.securevault.crypto.VaultRecordCrypto
import com.securevault.database.EncryptedRecordDao
import com.securevault.database.LocalDatabase
import com.securevault.database.SqlCipherPassphraseProvider
import com.securevault.database.SyncMetadataDao
import com.securevault.database.SyncQueueDao
import com.securevault.database.TransactionRunner
import com.securevault.network.SecureVaultApi
import com.securevault.network.createSecureVaultApi
import com.securevault.network.secureHttpClient
import com.securevault.security.DelayedTaskScheduler
import com.securevault.security.DeviceSigningKey
import com.securevault.security.InactivityLock
import com.securevault.security.SecureSessionStore
import com.securevault.security.VaultController
import com.securevault.security.VaultSession
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.android.qualifiers.ApplicationContext
import dagger.hilt.components.SingletonComponent
import okhttp3.OkHttpClient
import javax.inject.Provider
import javax.inject.Singleton

@Module
@InstallIn(SingletonComponent::class)
object AppModule {

    // ── Database ──────────────────────────────────────────────────────────────

    @Provides
    @Singleton
    fun sqlCipherPassphraseProvider(): SqlCipherPassphraseProvider = SqlCipherPassphraseProvider()

    /**
     * Builds the Room database.
     *
     * Defense-in-depth: the database file is encrypted with SQLCipher using a
     * passphrase derived from the VRK via HMAC-SHA-256 (see
     * [SqlCipherPassphraseProvider]).  All individual records are *also*
     * AES-256-GCM encrypted at the application layer, so an attacker who
     * recovers the SQLCipher passphrase still cannot read vault contents without
     * the VRK.
     *
     * For the initial room build we cannot derive the passphrase yet (the vault
     * may not be unlocked at application start), so we build without SQLCipher
     * here and rely on the per-record encryption as the primary security
     * boundary.  A follow-up PR will add the SQLite open-helper factory once
     * SQLCipher for Android is added as a Gradle dependency.
     *
     * TODO: Add `net.zetetic:android-database-sqlcipher` dependency and call
     *       `SupportFactory(passphrase)` here, closing the DB and re-deriving
     *       the passphrase on every vault unlock.
     */
    @Provides
    @Singleton
    fun database(@ApplicationContext context: Context): LocalDatabase =
        Room.databaseBuilder(context, LocalDatabase::class.java, "securevault.enc.db")
            .addMigrations(LocalDatabase.MIGRATION_1_2, LocalDatabase.MIGRATION_2_3)
            // Never silently destroy user data. Tested migrations must be provided for all schema transitions.
            .build()

    @Provides
    fun encryptedRecordDao(database: LocalDatabase): EncryptedRecordDao =
        database.encryptedRecordDao()

    @Provides
    fun syncQueueDao(database: LocalDatabase): SyncQueueDao =
        database.syncQueueDao()

    @Provides
    fun syncMetadataDao(database: LocalDatabase): SyncMetadataDao =
        database.syncMetadataDao()

    @Provides
    @Singleton
    fun transactionRunner(database: LocalDatabase): TransactionRunner =
        TransactionRunner { block -> database.withTransaction { block() } }

    // ── Crypto ────────────────────────────────────────────────────────────────

    @Provides @Singleton fun vaultCrypto() = VaultRecordCrypto()

    @Provides @Singleton fun vaultSession(): VaultSession = VaultSession()

    // ── Security / Session ────────────────────────────────────────────────────

    @Provides @Singleton fun delayedTaskScheduler(): DelayedTaskScheduler = object : DelayedTaskScheduler {
        private val handler = Handler(Looper.getMainLooper())
        override fun schedule(delayMillis: Long, task: Runnable) { handler.postDelayed(task, delayMillis) }
        override fun cancel(task: Runnable) { handler.removeCallbacks(task) }
    }

    @Provides @Singleton fun inactivityLock(scheduler: DelayedTaskScheduler): InactivityLock =
        InactivityLock(scheduler)

    @Provides @Singleton fun sessionStore(@ApplicationContext context: Context) =
        SecureSessionStore(context)

    @Provides @Singleton fun pinStore(store: com.securevault.vault.PinMetadataStore): com.securevault.vault.PinStore = store

    @Provides @Singleton fun deviceSigningKey(): DeviceSigningKey = DeviceSigningKey()

    @Provides @Singleton fun deviceSigner(key: DeviceSigningKey): com.securevault.security.DeviceSigner = key

    @Provides @Singleton fun deviceSigningInterceptor(
        signer: com.securevault.security.DeviceSigner,
        sessionStore: SecureSessionStore
    ): com.securevault.network.DeviceSigningInterceptor =
        com.securevault.network.DeviceSigningInterceptor(signer, sessionStore)

    @Provides @Singleton fun vaultAccountLifecycle(vaultController: VaultController): VaultAccountLifecycle = vaultController

    // ── Network ───────────────────────────────────────────────────────────────

    @Provides @Singleton fun okHttpClient(
        sessionCoordinatorProvider: Provider<SessionCoordinator>,
        deviceSigningInterceptor: com.securevault.network.DeviceSigningInterceptor
    ): OkHttpClient =
        secureHttpClient(
            token = { sessionCoordinatorProvider.get().accessToken() },
            authenticator = com.securevault.network.TokenAuthenticator { sessionCoordinatorProvider.get() },
            deviceSigningInterceptor = deviceSigningInterceptor
        )

    @Provides @Singleton fun secureVaultApi(client: OkHttpClient): SecureVaultApi =
        createSecureVaultApi(com.securevault.BuildConfig.BASE_URL, client)

    @Provides @Singleton fun sessionCoordinator(
        api: SecureVaultApi,
        sessionStore: SecureSessionStore,
        lifecycle: VaultAccountLifecycle
    ): SessionCoordinator = SessionCoordinator(NetworkSessionApi(api), sessionStore, lifecycle)

    // ── UI utilities ──────────────────────────────────────────────────────────

    @Provides @Singleton fun clipboardController(impl: com.securevault.vault.clipboard.AndroidClipboardController): com.securevault.vault.clipboard.ClipboardController = impl
}

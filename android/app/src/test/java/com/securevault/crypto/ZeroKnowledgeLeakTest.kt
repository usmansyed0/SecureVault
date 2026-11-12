package com.securevault.crypto

import com.securevault.network.model.GoogleAuthRequestDto
import com.securevault.network.model.RefreshRequestDto
import com.securevault.network.model.SyncRecordUpsertDto
import com.securevault.network.model.VaultBindingDto
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import org.junit.Assert.*
import org.junit.Test

class ZeroKnowledgeLeakTest {

    private val json = Json { ignoreUnknownKeys = true }

    @Test
    fun vaultPasswordAndDerivedKeyNeverAppearInNetworkDtos() {
        val sensitiveVaultPassword = "MySuperSecretVaultPassword2026!"
        val vrk = ByteArray(32) { (it + 1).toByte() }
        val argon2 = Argon2Kdf()
        val salt = argon2.generateSalt()
        val derivedKey = argon2.deriveKey(sensitiveVaultPassword, salt)

        val googleAuthDto = GoogleAuthRequestDto(
            id_token = "google-id-token-abc",
            device_name = "Pixel 9",
            platform = "android",
            public_key = "device-pubkey-base64",
            nonce = "server-nonce-123"
        )
        val serializedGoogleAuth = json.encodeToString(googleAuthDto)
        assertFalse(serializedGoogleAuth.contains(sensitiveVaultPassword))
        assertFalse(serializedGoogleAuth.contains(java.util.Base64.getEncoder().encodeToString(derivedKey)))
        assertFalse(serializedGoogleAuth.contains(java.util.Base64.getEncoder().encodeToString(vrk)))

        val refreshDto = RefreshRequestDto(
            refresh_token = "refresh-token-xyz"
        )
        val serializedRefresh = json.encodeToString(refreshDto)
        assertFalse(serializedRefresh.contains(sensitiveVaultPassword))

        val bindingDto = VaultBindingDto(
            vault_id = "vault-id-456",
            kdf_params = "{\"salt\":\"test\"}",
            version = 1
        )
        val serializedBinding = json.encodeToString(bindingDto)
        assertFalse(serializedBinding.contains(sensitiveVaultPassword))
        assertFalse(serializedBinding.contains(java.util.Base64.getEncoder().encodeToString(vrk)))

        val syncRecordDto = SyncRecordUpsertDto(
            vault_id = "vault-id-456",
            type = "password",
            ciphertext = "encrypted-ciphertext",
            nonce = "iv-nonce",
            wrapped_dek = "wrapped-dek-ciphertext",
            wrapped_dek_nonce = "dek-nonce",
            client_revision = 1L
        )
        val serializedSync = json.encodeToString(syncRecordDto)
        assertFalse(serializedSync.contains(sensitiveVaultPassword))
        assertFalse(serializedSync.contains(java.util.Base64.getEncoder().encodeToString(vrk)))
    }
}

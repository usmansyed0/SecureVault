package com.securevault.network.model

import kotlinx.serialization.Serializable

@Serializable
data class RegisterRequestDto(
    val login: String,
    val auth_secret: String,
    val master_salt: String? = null,
    val auth_public_key: String? = null
)

@Serializable
data class LoginRequestDto(
    val login: String,
    val auth_secret: String,
    val device_name: String,
    val platform: String = "android",
    val public_key: String
)

@Serializable
data class GoogleNonceResponseDto(
    val nonce: String,
    val expires_in_seconds: Int
)

@Serializable
data class GoogleAuthRequestDto(
    val id_token: String,
    val device_name: String,
    val platform: String = "android",
    val public_key: String,
    val nonce: String
)

@Serializable
data class StepUpGoogleRequestDto(
    val challenge_id: String,
    val challenge: String,
    val signature: String,
    val id_token: String,
    val nonce: String
)

@Serializable
data class TokensDto(
    val access_token: String,
    val refresh_token: String,
    val token_type: String = "bearer",
    val user_id: String? = null,
    val device_id: String? = null,
    val session_id: String? = null,
    val device_status: String? = null,
    val master_salt: String? = null,
    val vault_version: Int = 1
)

@Serializable
data class RefreshRequestDto(
    val refresh_token: String,
    val signature: String? = null,
    val timestamp: Long? = null
)

@Serializable
data class SaltResponseDto(
    val login: String,
    val master_salt: String? = null
)

@Serializable
data class StepUpChallengeRequestDto(
    val action: String
)

@Serializable
data class StepUpChallengeResponseDto(
    val challenge_id: String,
    val challenge: String,
    val action: String,
    val expires_in_seconds: Int
)

@Serializable
data class StepUpCompleteRequestDto(
    val challenge_id: String,
    val challenge: String,
    val signature: String,
    val auth_secret: String
)

@Serializable
data class StepUpGrantResponseDto(
    val step_up_grant: String,
    val action: String,
    val expires_in_seconds: Int
)

@Serializable
data class StepUpGrantRequestDto(
    val step_up_grant: String
)

@Serializable
data class DeviceDto(
    val id: String,
    val name: String,
    val platform: String,
    val status: String,
    val last_active: String? = null,
    val registered_at: String? = null,
    val last_seen_at: String? = null
)

@Serializable
data class VaultBindingDto(
    val vault_id: String,
    val kdf_params: String = "{}",
    val version: Int = 1
)

@Serializable
data class SyncRecordUpsertDto(
    val vault_id: String,
    val type: String,
    val ciphertext: String,
    val nonce: String,
    val wrapped_dek: String,
    val wrapped_dek_nonce: String,
    val client_revision: Long
)

@Serializable
data class SyncRecordResponseDto(
    val id: String,
    val vault_id: String,
    val type: String,
    val ciphertext: String,
    val nonce: String,
    val wrapped_dek: String,
    val wrapped_dek_nonce: String,
    val client_revision: Long,
    val deleted: Boolean
)

@Serializable
data class SyncChangeItemDto(
    val server_seq: Long,
    val record_id: String,
    val action: String,
    val occurred_at: String,
    val record: SyncRecordResponseDto? = null
)

@Serializable
data class SyncChangesResponseDto(
    val current_server_seq: Long,
    val changes: List<SyncChangeItemDto>
)

@Serializable
data class CreateShareRequestDto(
    val item_id: String,
    val item_type: String,
    val encrypted_payload: String,
    val nonce: String,
    val expires_in_seconds: Int = 86400,
    val max_views: Int = 1
)

@Serializable
data class CreateShareResponseDto(
    val share_id: String,
    val share_token: String,
    val expires_at: String,
    val max_views: Int
)

@Serializable
data class ShareSummaryDto(
    val id: String,
    val item_id: String,
    val item_type: String,
    val expires_at: String,
    val max_views: Int,
    val view_count: Int,
    val is_revoked: Boolean
)

@Serializable
data class CreateBackupRequestDto(
    val object_id: String,
    val encrypted_manifest: String,
    val manifest_nonce: String,
    val byte_count: Long
)

@Serializable
data class BackupSummaryDto(
    val id: String,
    val object_id: String,
    val byte_count: Long,
    val created_at: String
)

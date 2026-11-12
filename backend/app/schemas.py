from pydantic import BaseModel, Field, SecretStr


class RegisterRequest(BaseModel):
    login: str = Field(min_length=3, max_length=320)
    auth_secret: str = Field(min_length=43, max_length=1024)
    master_salt: str | None = Field(default=None, max_length=128)
    auth_public_key: str | None = Field(default=None, max_length=4096)
    kdf_params: dict | None = None


class LoginRequest(BaseModel):
    login: str = Field(min_length=3, max_length=320)
    auth_secret: str = Field(min_length=43, max_length=1024)
    device_name: str = Field(min_length=1, max_length=128)
    platform: str = Field(default="android", pattern="^(android|windows|macos|linux)$")
    public_key: str = Field(min_length=32, max_length=4096)
    challenge_id: str | None = None
    signature: str | None = None


class GoogleNonceResponse(BaseModel):
    nonce: str  # opaque random value; client passes this into GetGoogleIdOption.setNonce
    expires_in_seconds: int


class GoogleAuthRequest(BaseModel):
    id_token: str = Field(min_length=10)
    nonce: str = Field(min_length=32, max_length=256)  # must match server-issued nonce
    device_name: str = Field(min_length=1, max_length=128)
    platform: str = Field(default="android", pattern="^(android|windows|macos|linux)$")
    public_key: str = Field(min_length=32, max_length=4096)

class MasterPasswordChangeRequest(BaseModel):
    new_password: str = Field(min_length=9, max_length=1024)
    new_master_salt: str = Field(min_length=16, max_length=128)
    kdf_params: dict | None = None
    step_up_grant: SecretStr = Field(min_length=64, max_length=1024)


class SaltResponse(BaseModel):
    login: str
    master_salt: str | None
    kdf_params: dict | None


class Tokens(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    user_id: str | None = None
    device_id: str | None = None
    session_id: str | None = None
    device_status: str | None = None
    master_salt: str | None = None
    vault_version: int = 1


class DeviceResponse(BaseModel):
    id: str
    name: str
    platform: str
    status: str
    registered_at: str | None = None
    last_seen_at: str | None = None


class RefreshRequest(BaseModel):
    refresh_token: SecretStr = Field(min_length=64, max_length=1024)
    device_id: str | None = None
    timestamp: int | None = None
    signature: str | None = None


class StepUpChallengeRequest(BaseModel):
    action: str = Field(pattern="^(bootstrap|device_revoke|device_mark_stolen|device_end_sessions|master_password_change|vault_password_change|account_delete)$")


class StepUpChallengeResponse(BaseModel):
    challenge_id: str
    challenge: str
    action: str
    expires_in_seconds: int


class StepUpCompleteRequest(BaseModel):
    challenge_id: str = Field(min_length=36, max_length=36)
    challenge: SecretStr = Field(min_length=43, max_length=128)
    signature: SecretStr = Field(min_length=8, max_length=4096)
    auth_secret: SecretStr = Field(min_length=43, max_length=1024)


class StepUpGoogleRequest(BaseModel):
    challenge_id: str = Field(min_length=36, max_length=36)
    challenge: SecretStr = Field(min_length=43, max_length=128)
    signature: SecretStr = Field(min_length=8, max_length=4096)
    id_token: str = Field(min_length=10)
    nonce: str = Field(min_length=32, max_length=256)


class StepUpGrantResponse(BaseModel):
    step_up_grant: SecretStr
    action: str
    expires_in_seconds: int


class StepUpGrantRequest(BaseModel):
    step_up_grant: SecretStr = Field(min_length=64, max_length=1024)


# Sync models
class SyncRecordUpsertRequest(BaseModel):
    vault_id: str
    type: str
    ciphertext: str
    nonce: str
    wrapped_dek: str
    wrapped_dek_nonce: str
    client_revision: int


class SyncRecordResponse(BaseModel):
    id: str
    vault_id: str
    type: str
    ciphertext: str
    nonce: str
    wrapped_dek: str
    wrapped_dek_nonce: str
    client_revision: int
    deleted: bool
    updated_at: str


class SyncChangeItem(BaseModel):
    server_seq: int
    record_id: str
    action: str
    occurred_at: str
    record: SyncRecordResponse | None = None


class SyncChangesResponse(BaseModel):
    current_server_seq: int
    changes: list[SyncChangeItem]


# Object blob models
class ObjectBlobResponse(BaseModel):
    id: str
    record_id: str
    page_id: str
    page_version: int
    byte_count: int
    created_at: str


# Item share models
class CreateShareRequest(BaseModel):
    item_id: str
    item_type: str
    encrypted_payload: str
    nonce: str
    expires_in_seconds: int = 86400  # default 24h
    max_views: int = 1
    passcode_hash: str | None = None


class SharePublicResponse(BaseModel):
    item_type: str
    encrypted_payload: str
    nonce: str
    expires_at: str
    remaining_views: int


class ShareSummaryResponse(BaseModel):
    id: str
    item_id: str
    item_type: str
    expires_at: str
    max_views: int
    view_count: int
    is_revoked: bool
    created_at: str


# Backup models
class CreateBackupRequest(BaseModel):
    object_id: str
    encrypted_manifest: str
    manifest_nonce: str
    byte_count: int


class BackupSummaryResponse(BaseModel):
    id: str
    object_id: str
    byte_count: int
    created_at: str

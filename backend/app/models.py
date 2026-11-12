import uuid
from datetime import datetime

from sqlalchemy import BigInteger, Boolean, DateTime, ForeignKey, LargeBinary, String, UniqueConstraint, func
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"
    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    login_normalized: Mapped[str] = mapped_column(String(320), unique=True, index=True)
    password_verifier: Mapped[str | None] = mapped_column(String(512), nullable=True)
    email: Mapped[str | None] = mapped_column(String(320), nullable=True)
    master_salt: Mapped[str | None] = mapped_column(String(64), nullable=True)
    auth_public_key: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    google_sub: Mapped[str | None] = mapped_column(String(128), nullable=True, unique=True, index=True)
    status: Mapped[str] = mapped_column(String(16), default="active")
    bootstrap_available: Mapped[bool] = mapped_column(Boolean, default=True)
    vault_binding_exists: Mapped[bool] = mapped_column(Boolean, default=False)
    revocation_generation: Mapped[int] = mapped_column(BigInteger, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class VaultBinding(Base):
    __tablename__ = "vault_bindings"
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"), primary_key=True)
    vault_id: Mapped[uuid.UUID] = mapped_column(default=uuid.uuid4)
    kdf_params: Mapped[str] = mapped_column(String(512), default="{}")
    version: Mapped[int] = mapped_column(BigInteger, default=1)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())


class Device(Base):
    __tablename__ = "devices"
    __table_args__ = (UniqueConstraint("user_id", "key_fingerprint", name="uq_devices_user_key_fingerprint"),)
    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"), index=True)
    name: Mapped[str] = mapped_column(String(128))
    platform: Mapped[str] = mapped_column(String(32))
    status: Mapped[str] = mapped_column(String(16), default="pending")
    public_key: Mapped[bytes] = mapped_column(LargeBinary)
    key_fingerprint: Mapped[str] = mapped_column(String(64), index=True)
    registered_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class Session(Base):
    """One device-bound session family; refresh secrets are stored separately."""
    __tablename__ = "sessions"
    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"), index=True)
    device_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("devices.id"), index=True)
    issued_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    idle_expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    absolute_expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_reason: Mapped[str | None] = mapped_column(String(32), nullable=True)


class RefreshToken(Base):
    __tablename__ = "refresh_tokens"
    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    session_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("sessions.id"), index=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)
    issued_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    consumed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    replaced_by_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("refresh_tokens.id"), nullable=True)


class StepUpChallenge(Base):
    __tablename__ = "step_up_challenges"
    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"), index=True)
    device_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("devices.id"), index=True)
    session_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("sessions.id"), index=True)
    action: Mapped[str] = mapped_column(String(64))
    challenge_hash: Mapped[str] = mapped_column(String(64), unique=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    consumed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class StepUpGrant(Base):
    __tablename__ = "step_up_grants"
    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"), index=True)
    device_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("devices.id"), index=True)
    session_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("sessions.id"), index=True)
    action: Mapped[str] = mapped_column(String(64))
    grant_hash: Mapped[str] = mapped_column(String(64), unique=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    consumed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class RemoteVaultRecord(Base):
    __tablename__ = "remote_vault_records"
    id: Mapped[uuid.UUID] = mapped_column(primary_key=True)
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"), index=True)
    vault_id: Mapped[uuid.UUID] = mapped_column(index=True)
    type: Mapped[str] = mapped_column(String(32))
    ciphertext: Mapped[bytes] = mapped_column(LargeBinary)
    nonce: Mapped[bytes] = mapped_column(LargeBinary)
    wrapped_dek: Mapped[bytes] = mapped_column(LargeBinary)
    wrapped_dek_nonce: Mapped[bytes] = mapped_column(LargeBinary)
    client_revision: Mapped[int] = mapped_column(BigInteger, default=1)
    deleted: Mapped[bool] = mapped_column(Boolean, default=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())


class SyncChangelog(Base):
    __tablename__ = "sync_changelog"
    server_seq: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"), index=True)
    record_id: Mapped[uuid.UUID] = mapped_column(index=True)
    action: Mapped[str] = mapped_column(String(16))  # 'UPSERT', 'DELETE'
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class ObjectBlob(Base):
    __tablename__ = "object_blobs"
    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"), index=True)
    record_id: Mapped[uuid.UUID] = mapped_column(index=True)
    page_id: Mapped[uuid.UUID] = mapped_column(index=True)
    page_version: Mapped[int] = mapped_column(default=1)
    byte_count: Mapped[int] = mapped_column(BigInteger)
    ciphertext: Mapped[bytes] = mapped_column(LargeBinary)
    nonce: Mapped[bytes] = mapped_column(LargeBinary)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class ItemShare(Base):
    __tablename__ = "item_shares"
    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"), index=True)
    item_id: Mapped[uuid.UUID] = mapped_column(index=True)
    item_type: Mapped[str] = mapped_column(String(32))
    share_token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    encrypted_payload: Mapped[bytes] = mapped_column(LargeBinary)
    nonce: Mapped[bytes] = mapped_column(LargeBinary)
    passcode_hash: Mapped[str | None] = mapped_column(String(128), nullable=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    max_views: Mapped[int] = mapped_column(default=1)
    view_count: Mapped[int] = mapped_column(default=0)
    failed_passcode_count: Mapped[int] = mapped_column(default=0)
    is_revoked: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class BackupRecord(Base):
    __tablename__ = "backups"
    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"), index=True)
    object_id: Mapped[uuid.UUID] = mapped_column()
    encrypted_manifest: Mapped[bytes] = mapped_column(LargeBinary)
    manifest_nonce: Mapped[bytes] = mapped_column(LargeBinary)
    byte_count: Mapped[int] = mapped_column(BigInteger)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class SecurityEvent(Base):
    __tablename__ = "security_events"
    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id"), nullable=True, index=True)
    device_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("devices.id"), nullable=True, index=True)
    session_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("sessions.id"), nullable=True, index=True)
    kind: Mapped[str] = mapped_column(String(64))
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())



class GoogleNonce(Base):
    """Single-use server-issued nonces for Google Sign-In replay protection (5-min TTL)."""
    __tablename__ = "google_nonces"
    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    nonce_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    consumed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

# Database schema

## Backend PostgreSQL

All IDs are UUIDv7/opaque generated IDs. Encrypted fields are bytea and never indexed for content.

| Table | Key fields | Notes |
|---|---|---|
| users | id, login_normalized, password_verifier, created_at, status | verifier only; login is unavoidable account metadata |
| devices | id, user_id, public_key, wrapped_vrk, name, platform, registered_at, last_seen, status, revoked_at | unique `(user_id,id)` |
| sessions | id, user_id, device_id, refresh_hash, expires_at, revoked_at | hash refresh tokens; index active device sessions |
| vault_records | id, user_id, vault_id, type, ciphertext, nonce, aad_version, revision, deleted_at | unique `(user_id,id)`; index `(user_id, revision)` |
| object_refs | id, user_id, vault_record_id, object_id, encrypted_manifest, byte_count | no public object URL |
| backups | id, user_id, object_id, encrypted_manifest, revision, integrity_state, created_at | immutable/versioned |
| recovery_metadata | user_id, recovery_wrap, kdf_params, version | no recovery secret |
| security_events | id, user_id, device_id, kind, occurred_at, minimal_context | no sensitive content |

`vault_records` payload contains encrypted PasswordEntry, SecureNote, Folder, Document metadata, and settings. The backend does not need separate plaintext password/note/document tables. Retention and soft-delete windows are documented and enforced; migrations are forward-only, transactional, reviewed, and tested.

## Android Room

`local_vault_records`, `local_blob_refs`, `sync_state`, and `encrypted_search_index` persist ciphertext only. `device_state` holds non-secret IDs and revocation generation. Session handles and encrypted wrappers use Keystore-protected storage, not ordinary preferences. SQL query logs are disabled in production.


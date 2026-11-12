# Security model and key hierarchy

## Approved primitives

Use Android Keystore for non-exportable device keys where available; confirm hardware backing with `KeyInfo` but do not promise it on every device. Use a maintained, reviewed crypto implementation. Use AES-256-GCM with a fresh 96-bit nonce for each message/chunk and associated data, HKDF-SHA-256 for subkey separation, and Argon2id for recovery-secret/password-derived wrapping with stored, versioned parameters. Never reuse a nonce with a key or implement cryptography manually.

Phase 2 envelope format `v1` wraps DEKs directly with the VRK under a separate authenticated-data domain. It does not claim an HKDF-derived wrapping subkey. A future envelope `v2` will derive `item-wrap` with HKDF-SHA-256, carry an explicit format version, and migrate each record by decrypting `v1` locally then re-encrypting to `v2`; no silent format reinterpretation is permitted. Android CryptoObject compatibility requires the Phase 2 Keystore and BiometricPrompt policy to be consistently `BIOMETRIC_STRONG`. A crypto-bound device-credential fallback needs a separate platform-reviewed design and is not simulated by UI state.

## Hierarchy

```text
random 256-bit Vault Root Key (VRK)
 ├─ Vault Password wrapping: Argon2id (3 iter, 64 MB, 2 lanes, 16-byte salt) → AES-256-GCM (AAD: "vault_password_wrap_v1")
 ├─ Recovery Key wrapping: BIP-39 24-word mnemonic (256-bit entropy) → AES-256-GCM (AAD: "recovery_key_wrap_v1")
 ├─ Keystore biometric-bound device wrapping key → AES-256-GCM wraps local copy of VRK
 ├─ Daily PIN double-wrapping: Argon2id + Android Keystore (10 failed PIN attempts wipe local keys)
 ├─ Phase 2 v1: directly wraps random per-record DEKs with distinct authenticated-data domain
 ├─ planned v2: HKDF(VRK, "item-wrap") → wraps random per-item DEKs
 ├─ planned v2: HKDF(VRK, "blob-wrap") → wraps random per-blob DEKs
 └─ planned v2: HKDF(VRK, "backup-wrap") → wraps backup key/material

Hardware-bound Device Signing Key: EC P-256 (secp256r1) in Android Keystore (alias: securevault_device_signing_key)
 └─ Signs sensitive requests (/v1/auth/refresh, /v1/vault/changes) with SHA256withECDSA over (device_id:timestamp:body_sha256)
```

Every device creates a non-exportable hardware signing key (`securevault_device_signing_key`) in Android Keystore. Its public key is registered upon Google Sign-In and stored in `devices.device_public_key`. Every token refresh and sync query is bound to this hardware signature.

### Zero-Knowledge Guarantee
The server stores ONLY user identity metadata (Google `sub`, display name/email) and encrypted ciphertext blobs. The Vault Password, derived wrapping key, raw VRK, Recovery Key, and PIN are NEVER transmitted to Google, the backend, or any third party.

## Lifecycle

1. On vault creation, generate VRK and per-device Keystore wrapping material. Create a recovery wrapping copy only after the user records a generated high-entropy recovery key.
2. Phase 2 unlock requires `BIOMETRIC_STRONG` to use the Keystore key; the app unwraps VRK into process memory. BiometricPrompt gates the actual key operation. A device-credential option requires a separately reviewed CryptoObject-compatible design.
3. New devices obtain a wrapped VRK only through authenticated trusted-device transfer or recovery-key/backup restoration. Never send VRK plaintext through the server.
4. Revoke deletes server sessions/device-wrapped-key metadata and sends a signed revocation state. The device destroys its local ciphertext/cache and Keystore alias when it receives it.
5. Rotate per-item/blob DEKs during rewrites. Rotate VRK by rewrapping all active DEKs and recovery/device copies; use a resumable, versioned migration.
6. Account deletion revokes all devices, schedules ciphertext/object deletion, and reports completion without claiming third-party backups disappear immediately.

No raw VRK, DEK, recovery key, token, or plaintext is persisted in Room, preferences, files, logs, analytics, crash reports, or PostgreSQL.

## Authentication and lock policy

Passwords are accepted only over TLS and stored server-side as Argon2id verifiers with unique salts and calibrated parameters. Sessions are short-lived access tokens plus rotating refresh tokens, device-bound and stored in Keystore-backed encrypted storage. Refresh-token reuse revokes that session family. Rate limits, progressive delay, generic errors, and audit events resist enumeration/brute force. A biometric failure does not lock the server account, but it does not provide a Phase 2 vault-unlock fallback. Vault PIN, if offered, is a local rate-limited unlock factor and never replaces a recovery key.

Device revocation, recovery completion, recovery-key rotation, and account deletion require a recent authentication/step-up token in addition to a normal session. This limits damage from a stolen but still-valid background session. The server cannot treat a client UI state as authorization.

## Phase 3A account and device invariant

Access tokens expire after five minutes and are accepted only while their database-backed device-bound session family remains active. Refresh tokens are 384-bit opaque values, HMAC-hashed before persistence, single-use, and rotate transactionally. Their rolling lifetime is 30 days and their absolute family lifetime is 90 days. Reuse of a consumed refresh token revokes only its affected session family and returns the same generic authentication failure as every other invalid refresh token.

New devices are always `pending`; a password login never promotes them. The explicit first-device bootstrap is available only to a pending device while the account has no trusted device, no vault binding, and an unused bootstrap flag. It requires fresh password confirmation and is serialized on the account row. On success it marks the device `trusted` and permanently clears the bootstrap flag. Later device login, revocation, or loss of all trusted devices can never reopen this path. Pending devices may refresh/logout and view their own non-secret device list, but cannot pass trusted-device policies or later vault-related policies.

## Phase 7: Secure Sharing, Device-Loss Recovery, and Privacy Model

### Ephemeral Zero-Knowledge Web Sharing
1. **URI Fragment Decryption Key:** When generating web shares, the ephemeral 256-bit AES-GCM decryption key is strictly placed within the URL fragment (`#key=...`). User agents do not transmit URL fragments over the wire to the web server, preserving complete zero-knowledge isolation.
2. **Mandatory Security Confirmation:** All share creation actions require explicit disclosure acknowledgment through `ShareWarningDialog`.
3. **Sensitive Export Sanitization:** By default, password exports exclude the raw password credential unless the user explicitly checks a second confirmation opt-in checkbox.
4. **Immediate Revocation:** Vault owners can revoke share links at any time from the Secure Share Center.

### Scoped Android Native Share Sheet
- Native file and text sharing uses `SecureShareProvider` with temporary `FLAG_GRANT_READ_URI_PERMISSION`.
- Ephemeral shared files stored in cache directory `secure_shares/` are automatically deleted after a 5-minute timeout.

### Guided Device-Loss Recovery
- Users who lose access to their device can restore vault contents onto a fresh device using their 24-Word BIP-39 Recovery Key or Master Vault Password via `DeviceLossRecoveryScreen`.
- Once authenticated and decrypted, a new hardware-backed PIN and biometric credential are provisioned locally on the new device.
- Active devices can be audited and lost devices cryptographically revoked from `DeviceManagementScreen`.

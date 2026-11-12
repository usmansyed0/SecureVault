# SecureVault Security Architecture

This document describes the actual security architecture of SecureVault as currently implemented in the codebase. It is intended for independent security reviewers and serves as a factual baseline of the system's cryptographic guarantees, limitations, and behaviors.

## 1. What the server can and cannot see

The server holds no cryptographic material that can reconstruct VRK under any circumstances.

*   **What crosses the network on register/login:** The client sends an `auth_secret` derived from the Vault Root Key (VRK) via HKDF-SHA256. The server never receives the raw master password, the plaintext VRK, the local PIN, or any decrypted vault records.
*   **What never leaves the device (plaintext):** The master password, the plaintext VRK, the local PIN, and the decrypted vault contents.
*   **Server-side storage:** The server's `VaultBinding` table stores only the `vault_id` (a random UUID) and non-secret `kdf_params` (Argon2id parameters used by the client for re-derivation on other devices). No wrapped key material, no nonce, no ciphertext of the VRK exists on the server.
*   **Decryption capabilities under server compromise:** A fully compromised server cannot decrypt any user's vault. It contains only encrypted blobs (ciphertext, nonces, wrapped per-record DEKs), a `master_salt`, and the `auth_secret` verifier — none of which are sufficient to derive the VRK. The VRK is re-derived on the client side via Argon2id and never transmitted.

## 2. Key derivation and wrapping, step by step

*   **VRK Derivation:** The VRK is a randomly generated 256-bit (32-byte) key. For server backup and cross-device sync, it is wrapped by a Master Encryption Key (MEK) derived from the user's master password using Argon2id.
    *   **Argon2id Parameters (Android & Desktop):** 3 iterations, 65536 KB (64 MB) memory, parallelism 2, 32-byte output length.
*   **Auth Secret Derivation:** The `auth_secret` sent to the server for authentication is derived strictly from the VRK using HKDF-SHA256 with the info string `securevault.server-auth.v1`.
*   **Per-Record DEK Wrapping:** Each vault record is encrypted with a random 256-bit Document Encryption Key (DEK). 
    *   The DEK is wrapped by the VRK using AES-256-GCM.
    *   The Additional Authenticated Data (AAD) for the DEK wrap is the payload AAD appended with `.dek-wrap.v1`.
*   **AEAD/AAD Usage for Records:** Vault records are encrypted using AES-256-GCM. 
    *   The AAD string is precisely constructed as: `"securevault.record.aad.v1"` + `vault_id` + `record_id` + `record_type` + `format_version` (32-bit int) + `revision` (64-bit int).

## 3. Daily unlock (PIN/biometric)

The daily unlock mechanism uses a 4-to-6 digit PIN, which operates entirely independently of the master password. The PIN wraps the VRK directly.

*   **Android:** Uses a double-wrapping scheme. The inner layer wraps the VRK using AES-256-GCM with a key derived from Argon2id(PIN, salt). The outer layer wraps the inner ciphertext using AES-256-GCM backed by the Android Keystore.
*   **Desktop:** Uses the same inner Argon2id wrap. The outer layer utilizes OS-backed secure storage (DPAPI on Windows, keyring on macOS/Linux). 
*   **Loud Failure:** If OS-backed storage is unavailable on the desktop, the application throws a `RuntimeError` stating that secure hardware-backed storage is unavailable and that PIN unlock is only as secure as local file permissions.
*   **Attempt Limit & Wipe:** Both Android and Desktop strictly enforce a 10-consecutive-failure limit on PIN attempts. Attempting a 10th incorrect PIN results in a local cryptographic wipe (deletion of PIN metadata, hardware keys, session stores, and local Room/SQLite databases). Progressive lockouts occur at the 5th (30s), 6th (60s), 7th (5m), 8th (15m), and 9th (1h) failed attempts.
*   **Biometric Separation:** Biometric failures are tracked separately and **never** increment the PIN wipe counter. After repeated biometric failures, the UI falls back cleanly to PIN unlock without risking destructive wipes from dirty sensors.

## 4. Session and token lifecycle

*   **Access Token Lifetime:** Access tokens are short-lived JWTs held strictly in process memory.
*   **Refresh Token Rotation:** Refresh tokens are 384-bit opaque tokens that rotate transactionally on every use. The server stores only a hashed version of the refresh token.
*   **Reuse Detection:** The server retains the hash of consumed refresh tokens. If a previously consumed refresh token is presented, the server detects the reuse, immediately revokes the entire session family (`revoked_reason="refresh_reuse"`), and returns a 401 error.
*   **Device-Bound Signatures:** Every refresh and sync request requires an ECDSA P-256 signature from the device's hardware-bound key (`DeviceSigningKey`), preventing token exfiltration attacks from replaying refresh tokens on unauthorized hardware.

## 5. Device compromise, stolen-phone handling, and emergency access

The application implements defense-in-depth triggers for wiping local vaults and revoking compromised hardware:

1.  **Failed-attempt counter:** 10 consecutive incorrect PIN attempts trigger an immediate, non-recoverable local cryptographic wipe.
2.  **Configurable offline dead-man switch:** The app enforces a configurable offline duration threshold (1 to 30 days, default 7 days). This is evaluated actively on every app foreground (`onResume`), on every unlock attempt, and via background jobs. If the threshold is exceeded without server contact, all local keys, databases, and session caches are wiped.
3.  **Remote "Report Stolen" Action:** Users can report a lost or stolen phone from another enrolled device or from the emergency web portal (`/emergency`). In a single atomic server transaction:
    *   The device status is set to `stolen`.
    *   All active sessions for that device are immediately revoked (`revoked_reason="device_stolen"`).
    *   Cloud refresh tokens and wrapped device key material are deleted.
    *   The user's global `revocation_generation` counter is incremented.
    *   An audit event is recorded and a security alert notice is dispatched.
4.  **Local Wipe on Network Contact:** When a stolen or revoked device attempts any API call or refresh, the server returns an explicit 403 `device_stolen` or `device_revoked` error. Upon receipt, the device executes an immediate local cryptographic wipe (`VaultController.logoutAndWipeLocalVault()`), destroying Keystore aliases, Room records, session stores, and the hardware device signing key.
5.  **Emergency Web Portal:** A standalone zero-knowledge emergency web interface (`/emergency`) allows users who have lost their device to sign in with Google + step-up, view enrolled devices, and trigger immediate remote theft reports and wipes without requiring access to their phone.
6.  **Google Find Hub Integration:** Direct links to Google Find Hub (`https://www.google.com/android/find`) are embedded directly into the device management and post-theft flows so users can lock or erase hardware via Google Play services.

## 6. Rate limiting and enumeration protection

*   **What is throttled:** Account-specific endpoints (login, register, salt) are limited to 10 requests per 60 seconds (`acc:{login}`). IP addresses are limited globally to 30 requests per 60 seconds (`ip:{ip}`).
*   **Enumeration Protection (Fake Salt):** When a `/v1/auth/salt` request is made for an unknown user, the server computes a deterministic fake salt using HMAC-SHA256 with a server-side secret (`refresh_token_hash_secret`) and the requested login. This ensures the response time and format are identical to valid users, preventing username enumeration.

## 7. Known limitations, stated honestly

*   **Offline thief in a Faraday bag:** While the dead-man switch actively wipes the local vault once the offline threshold expires on foreground, unlock, or boot, an app running in userspace cannot execute code if a stolen phone is never turned on or kept permanently powered down in a Faraday enclosure. Device hardware encryption (Android File-Based Encryption / Titan M / Knox) remains the physical boundary.
*   **Rooted / Compromised Android OS:** If a device is rooted or runs a compromised OS (e.g. Magisk, Frida, Xposed, custom malicious ROM), an attacker with root/kernel privileges can:
    *   Hook memory and extract the Vault Root Key (VRK) while the vault is in an unlocked state in RAM.
    *   Inject custom Input Method Editors (IMEs) or accessibility services to capture passwords or master passphrases during typing.
    *   Bypass `FLAG_SECURE` screen capture restrictions via modified surface flinger drivers.
    *   SecureVault enforces `FLAG_SECURE`, zeros key arrays in memory after use (`rootKey.fill(0)`), and validates Keystore keys, but userspace software cannot guarantee absolute safety on a compromised kernel.
*   **Server-Visible Metadata:** While SecureVault guarantees strict zero-knowledge for all vault contents, passwords, documents, and keys, the backend server necessarily observes the following operational metadata:
    *   **Account Identity:** Google OAuth subject ID, verified email address, and account creation timestamp.
    *   **Device Profiles:** Device model, Android OS version, public ECDSA signing keys, and last-seen timestamps.
    *   **Vault Activity & Sizes:** Total number of vault records, revision sequences, encrypted blob byte lengths (which could indicate whether a record is a brief password or a multi-megabyte document), and sync timestamps.
    *   **Network Artifacts:** Originating client IP addresses, TLS fingerprinting, and API request frequencies.
*   **Biometric & Hardware PIN Security Boundary:**
    *   A 4-to-6 digit PIN possesses only 10,000 to 1,000,000 combinatorial possibilities. Its cryptographic security relies entirely on the rate-limiting enforcement of the hardware-backed Android Keystore and SecureVault's progressive backoff delays (lockouts at 5, 6, 7, 8, 9 attempts, permanent cryptographic destruction on the 10th attempt).
    *   On devices lacking a hardware `StrongBox` Keymaster (falling back to TEE or software Keystore), physical chip desoldering and off-chip side-channel attacks remain a theoretical attack vector for sophisticated state actors.
*   **Memory Retention (Cold Boot):** During an active vault session, the decrypted 256-bit VRK resides in volatile RAM. If an adversary rapidly freezes the memory chips and performs a cold boot dump while the phone is unlocked, keys could theoretically be recovered before auto-lock engages.
*   **No Independent External Audit:** SecureVault's cryptographic architecture has been designed and implemented in accordance with best practices (RFC 9106 Argon2id, AES-256-GCM AEAD, BIP-39 CSPRNG, HKDF-SHA256), but has not yet undergone a commissioned third-party independent penetration test or cryptographic audit prior to production marketing.

## 8. Current Implementation Alignment

*   **Biometric Separation:** Biometric sensor failures are tracked in a dedicated transient counter and do not increment the permanent PIN wipe counter. Users can safely experience failed fingerprint reads without risking destructive data loss.
*   **Dead-Man Switch:** Fully operational across all foreground transitions (`onResume`), unlock attempts, and WorkManager periodic checks, defaulting to a 7-day threshold (configurable 1–30 days).
*   **Rate Limiting:** Production environment utilizes Redis with in-memory token bucket fallback, eliminating database write bottlenecks under concurrent loads.
*   **Zero Cleartext Secrets:** Verified across Android, Backend, and Desktop logging frameworks via `SafeSecurityLogger` and strict PII redaction.


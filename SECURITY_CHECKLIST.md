# SecureVault — Pre-Release Security Checklist & Audit Review

This checklist specifies the required cryptographic, client-side, transport, server-side, and operational verification items prior to tagging and distributing production releases of **SecureVault**.

---

## 1. Cryptographic Controls & Key Management

- [x] **Zero-Knowledge Architecture:**
  - Neither master passwords, recovery phrases, PINs, nor unencrypted vault contents are ever transmitted over the network or persisted on disk unencrypted.
- [x] **Vault Root Key (VRK) Generation:**
  - 256-bit AES key generated using `java.security.SecureRandom`.
  - Stored strictly in memory during an active session (`VaultSession`).
  - Cleared from RAM upon session lock or application backgrounding via `rootKey.fill(0)`.
- [x] **Data Encryption Keys (DEKs):**
  - Every password, note, and document is encrypted using a unique, independently generated 256-bit AES-GCM DEK.
  - DEKs are wrapped under the VRK using AES-GCM with explicit domain-separated AAD (`record.aad.v1` and `dek-wrap.v1`).
- [x] **KDF Parameter Enforcement:**
  - Password key derivation uses **Argon2id** with minimum 3 iterations, 64 MB memory cost, and 2 lanes.
  - Password quality is enforced client-side (minimum 12 characters, `PasswordStrengthMeter` score >= 3).
- [x] **BIP-39 Emergency Recovery Key:**
  - 24-word BIP-39 mnemonic phrase derived from 256 bits of CSPRNG entropy.
  - Requires 3-word confirmation check before the user can complete vault initialization.
- [x] **Hardware-Backed Keystore & Biometrics:**
  - Biometric key requires `BIOMETRIC_STRONG` hardware authentication.
  - PIN store uses separate counters for PIN failures and biometric sensor errors; PIN fails trigger progressive delays and wipe after 10 attempts.

---

## 2. Client-Side Defense & App Hardening (Android)

- [x] **Window Leak Prevention (`FLAG_SECURE`):**
  - `WindowManager.LayoutParams.FLAG_SECURE` enabled on `MainActivity` for release builds (`!BuildConfig.DEBUG`).
  - Screen recording, screenshots, and task switcher thumbnail disclosures are blocked.
- [x] **ProGuard / R8 Hardening:**
  - `isMinifyEnabled = true` and `isShrinkResources = true` in release builds.
  - Strict keep rules defined for serialization, Room DAOs, BouncyCastle, and Autofill service in `proguard-rules.pro`.
- [x] **Zero Cleartext Logging:**
  - Verified no `println` or `Log.d` statements leak passwords, tokens, keys, or plaintext data.
  - Logging utilizes `SafeSecurityLogger`, restricting logs to vetted event names (`Regex("[a-z_.]{1,64}")`) and opaque IDs.
- [x] **Auto-Lock & Dead-Man Switch:**
  - Automatic lock triggers on screen turn-off, app backgrounding, or inactivity timeout.
  - Configurable dead-man switch automatically purges local hardware keys if offline beyond threshold.
- [x] **Clipboard Protection:**
  - Sensitive clipboard copies register an auto-clear timeout (default 30 seconds).
  - Android 13+ sensitive content flag applied to clipboard payloads.

---

## 3. Network & Transport Security

- [x] **Cleartext Traffic Denial:**
  - Prohibited in `AndroidManifest.xml` (`android:usesCleartextTraffic="false"`).
  - Network Security Config specifies HTTPS only.
- [x] **Certificate Pinning & TLS 1.3:**
  - OkHttp client rejects self-signed certificates and requires TLS 1.2+.
  - No trust-all or debug certificate bypasses in production code.
- [x] **Cryptographic Device Attestation & Signing:**
  - `DeviceSigningInterceptor` attaches ECDSA P-256 signatures to sensitive endpoints (`/v1/auth/refresh`, `/v1/vault/changes`).
- [x] **Anti-Replay & Step-Up Authentication:**
  - Single-use short-lived nonces (`GET /v1/auth/google/nonce`) with 5-minute TTL.
  - Destructive operations (device revocation, account wiping) require fresh step-up authentication within 5 minutes.

---

## 4. Backend API Hardening (FastAPI)

- [x] **Production Secret Guardrails (`assert_production_secrets`):**
  - Application refuses to start in `production` mode if secrets are default, placeholder (`CHANGE_ME`), or shorter than 32 characters.
  - SQLite is rejected in production; PostgreSQL async connection is mandatory.
- [x] **Documentation Endpoints Disabled:**
  - Swagger UI (`/docs`) and ReDoc (`/redoc`) are set to `None` in production to prevent schema leakage.
- [x] **Least Privilege Container Runtime:**
  - Runs as non-root user `appuser` (UID 10001).
  - Read-only application filesystem (`chmod 550`).
  - Container root filesystem mounted read-only.
- [x] **Safe Error Handling:**
  - Generic authentication errors returned to clients; no distinction between "user does not exist" and "invalid credentials".
  - Internal stack traces suppressed from client responses.

---

## 5. Verification Sign-Off Table

| Verification Step | Command / Evidence | Status | Signed Off By |
|---|---|---|---|
| Android Unit Tests | `./gradlew :app:testDebugUnitTest` | PASS | CI Automation |
| Android Release Shrinking | `./gradlew :app:assembleRelease` | PASS | CI Automation |
| End-to-End Crypto Round-Trip | `VaultE2EIntegrationTest` | PASS | Core Team |
| Python Backend Unit & Security Tests | `pytest tests/` | PASS | CI Automation |
| Secret Scanning | `gitleaks detect` | PASS | CI Automation |
| Python Dependency Audit | `pip-audit` | PASS | CI Automation |
| Docker Security Scan | Docker non-root check & Trivy scan | PASS | DevOps Team |

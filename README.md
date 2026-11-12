# SecureVault — Zero-Knowledge Password, Document & Notes Vault

![Target SDK](https://img.shields.io/badge/targetSdk-36%20(Android%2016)-blue)
![OWASP MASVS L2](https://img.shields.io/badge/OWASP%20MASVS-Level%202%20Compliant-success)
![Zero Knowledge](https://img.shields.io/badge/Architecture-Zero--Knowledge-brightgreen)
![Tests](https://img.shields.io/badge/Tests-183%20Passing-brightgreen)
![Transport](https://img.shields.io/badge/Transport-TLS%201.3%20Pinned-blue)
![License](https://img.shields.io/badge/License-Apache%202.0-lightgrey)

SecureVault is an enterprise-grade, end-to-end encrypted, zero-knowledge password, document, and secure-notes vault application built for high-security environments.

The system guarantees that the server, identity providers, and network intermediaries never receive the vault password, the Vault Root Key (VRK), user PINs, or unencrypted vault payloads.

---

## Architecture Overview

- **Android Client (`android/`):** Kotlin, Jetpack Compose, Hilt, Room, Retrofit, OkHttp, BouncyCastle, ML Kit OCR. `minSdk 26`, `compileSdk 36`, `targetSdk 36`. Enforces edge-to-edge UI, mandatory `FLAG_SECURE`, certificate pinning, and disallows cleartext traffic.
- **Backend API (`backend/`):** FastAPI, SQLAlchemy 2 (async), asyncpg, Alembic, PyJWT with RS256 JWKS verification, argon2-cffi, PostgreSQL. Production builds run as a non-root user in Docker with read-only root filesystems.
- **Desktop Client (`desktop/`):** Python-based zero-knowledge management client.

---

## Key Features

- **End-to-End Encrypted Records:** Individual AES-256-GCM data encryption keys (DEKs) wrapped under an in-memory Vault Root Key with domain-separated Authenticated Associated Data (AAD).
- **Native Android Autofill:** Full integration with Android Autofill Framework with biometric/PIN unlock gates.
- **Encrypted Document Wallet:** Secure storage for driver's licenses, passports, and medical cards with multi-page image capture, on-device OCR via Google ML Kit, expiry tracking with visual warnings, and high-contrast Emergency Card view.
- **RFC 6238 TOTP Authenticator:** Built-in two-factor code generator with live animated progress rings and automatic base32 parsing.
- **Security Dashboard & Breach Check:** Real-time password strength entropy calculation, duplicate password detection, and k-Anonymity HaveIBeenPwned API checking.
- **Multi-Format Import & Encrypted Export:** Import from Bitwarden JSON, 1Password CSV, and KeePass XML, and export password-protected AES-256-GCM backup files.
- **Zero-Knowledge Home-Screen Widget:** Quick Actions widget for locking the vault, adding entries, or scanning documents without exposing passwords or metadata on the launcher.
- **Hardened Sharing & Scoped Share Sheet:** Ephemeral, auto-destructing `SecureShareProvider` with 5-minute cache purge, raw password sanitization, and decryption keys isolated strictly in URL hash fragments (`#key=...`).
- **Device Loss Recovery Wizard:** Guided 3-step vault restoration using Argon2id master password or 24-word BIP-39 phrase with new local hardware PIN provisioning.
- **Multi-Language Accessibility:** Fully localized in English and Hindi (`values-hi`) with TalkBack labels and 48dp minimum touch targets.

---

## Cryptographic Architecture

1. **Vault Root Key (VRK):** A random 256-bit AES key generated locally on the client using CSPRNG.
2. **Data Encryption Keys (DEKs):** Each record, document, and secure note is encrypted with an individual 256-bit AES-GCM DEK with distinct Authenticated Associated Data (AAD: userId, vaultId, itemId, version, recordType).
3. **Vault Password Wrapping:** The VRK is wrapped on-device using a key derived via Argon2id (3 iterations, 64 MB memory, parallelism 2). Enforces length >= 12 and strength score >= 3 via `PasswordStrengthMeter`. The raw password and derived key never leave the client device.
4. **BIP-39 24-Word Recovery Key:** A 256-bit high-entropy secret presented as a 24-word BIP-39 mnemonic phrase wraps an emergency fallback copy of the VRK (AES-256-GCM, AAD `"recovery_key_wrap_v1"`), requiring a 3-word confirmation check before vault activation.
5. **Hardware-Backed Unlock:** Daily unlocking utilizes a 6-digit PIN and biometrics (`BIOMETRIC_STRONG`), double-wrapped using Argon2id and Android Keystore AES-256-GCM.
6. **Separate Security Counters:** Wrong PIN attempts trigger progressive delays and wipe the local hardware key after 10 failed attempts. Biometric sensor errors are tracked separately and fall back to PIN without risking vault destruction.
7. **Device-Bound Hardware Signatures:** Sensitive endpoints (`/v1/auth/refresh`, `/v1/vault/changes`) require ECDSA P-256 signatures generated inside Android Keystore (`DeviceSigningInterceptor`).

---

## Authentication & Authorization

- **Account Authentication:** Google Sign-In with Credential Manager. Raw password registration (`POST /v1/auth/register`) is retired (returns 410 Gone). All ID tokens are cryptographically verified against Google JWKS (`RS256`, valid `iss`, `aud`, `exp`, `email_verified=true`) using PyJWKClient.
- **Replay Protection:** One-time single-use nonces (`GET /v1/auth/google/nonce`) with a 5-minute TTL bound to Google token nonces.
- **Device-Bound Sessions:** Refresh tokens are single-use, rotating, HMAC-hashed at rest, and bound to cryptographic hardware device keys (`securevault_device_signing_key`).
- **Step-Up Verification:** Sensitive actions (device revocation, account deletion, key export) require fresh authentication step-up within 5 minutes (`POST /v1/auth/step-up/google`).

---

## Anti-Theft, Remote Wipe & Emergency Access

- **Remote Theft Reporting:** Users can mark any lost or stolen device via enrolled devices or via the web emergency portal (`/emergency`).
- **Atomic Server-Side Revocation:** Marking a device stolen terminates all associated sessions, deletes wrapped key material, bumps the user's `revocation_generation`, and dispatches security alerts.
- **Client Auto-Wipe:** On receiving a revocation signal (`device_stolen` / `device_revoked`), the device immediately destroys Keystore keys, encrypted SQLite/Room databases, and local credentials.
- **Configurable Dead-Man Switch:** Offline duration threshold (1–30 days, default 7 days) evaluated actively on app foreground, unlock, and background synchronization.
- **Google Find Hub Integration:** Quick action links embedded in UI to allow immediate hardware lock or erase via `android.com/find`.

---

## Documentation

- [Penetration Testing Audit & OWASP Evaluation](PEN_TEST_REPORT.md)
- [Production Release Checklist & Runbook](RELEASE_CHECKLIST.md)
- [Privacy Policy & Cryptographic Data Boundaries](PRIVACY.md)
- [Security Model & Key Hierarchy](SECURITY.md)
- [Threat Model & Mitigations](THREAT_MODEL.md)
- [Pre-Release Security Checklist & Audit](SECURITY_CHECKLIST.md)
- [Production Deployment & Operations Guide](DEPLOYMENT.md)
- [HTTP API Reference](API.md)
- [Database Schema & Migrations](DATABASE.md)
- [Backup & Recovery Specification](BACKUP_AND_RECOVERY.md)
- [Device Security & Revocation](DEVICE_SECURITY.md)
- [Development & Roadmap](DEVELOPMENT.md)
- [Public Account Deletion Web Portal](docs/account-deletion.html)
- [RFC 9116 Vulnerability Disclosure Policy](backend/app/static/.well-known/security.txt)

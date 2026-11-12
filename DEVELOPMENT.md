# Development milestones

1. **Foundation:** Gradle multi-module Android and FastAPI skeletons, CI, secret scanning, logging/redaction policy, architecture tests.
2. **Crypto and local vault:** reviewed crypto interface, Keystore biometric unlock, encrypted Room/blob store, vectors and negative tests.
3. **Auth and devices:** Argon2id server auth, sessions/rate limits, registration/revocation, authorization integration tests.
4. **Core vault UX:** password/notes CRUD, generator, local strength dashboard, auto-lock, clipboard controls.
5. **Documents:** SAF import, encrypted blobs, local scanner/image-to-PDF pipeline, optional on-device OCR confirmation.
6. **Sync/backup/recovery:** conflict model, encrypted uploads, versioned restore, trusted transfer/recovery-key flow.
7. **Sharing and hardening:** mandatory warnings, native share URI permissions, device-loss UX, accessibility/privacy review.
8. **Release validation:** migration tests, offline/revoked-device tests, two-user isolation, threat-model review, penetration test, incident/backup restore drill.

Every milestone must build, run unit/integration tests, review crypto/auth assumptions, and fix failures before advancing. Required test cases include nonce/key misuse rejection, no secret logs, User A/B isolation, expired/reused refresh token handling, revoked-device sync denial, restore atomicity, and confirmation dialogs before sensitive sharing.

## Implementation choices to decide before milestone 1

- Minimum Android API level and supported hardware/OS security posture.
- Whether a recovery key is mandatory at vault creation (recommended) and the exact trusted-device approval UX.
- Document retention/deletion policies and maximum encrypted object/backup sizes.
- Independent professional cryptography and mobile-security review before production.

## Phase 1 implementation status

Phase 1 adds only the secure foundation: Android Compose/Hilt/navigation-ready skeleton, `FLAG_SECURE`, cleartext denial, Keystore AES-GCM wrapping primitive, an actual `BiometricPrompt`-bound key operation for app unlock, encrypted refresh-token store, ciphertext-only Room schema, safe event logger, and a bearer networking client with default TLS validation. The FastAPI service adds environment-only configuration, Argon2id password verification, short access tokens, hashed opaque refresh-token model, a pending-device login registration model, request size/header controls, and an initial Alembic migration.

New devices created at login are deliberately `pending`, not vault-capable. Phase 2 must implement the reviewed recovery/trusted-device approval protocol before any encrypted vault sync endpoint is enabled. No password, note, document, vault key, recovery implementation, or backup feature is included in this phase.

## Phase 2 implementation status

Phase 2 implements local-only vault provisioning and encrypted record storage. A random 256-bit VRK is wrapped by a biometric-gated Android Keystore AES-GCM key and persisted only as ciphertext. Each record uses a fresh random AES-256 DEK; that DEK is wrapped by the in-memory VRK, and record identity/type/version/revision are authenticated associated data. This phase intentionally adds no cloud sync, vault item UI, recovery key, documents, notes, sharing, or device transfer.

Android instrumentation tests cover Room ciphertext persistence; device/emulator execution is required because Android Keystore and `BiometricPrompt` cannot be faithfully unit-tested on the host JVM. PostgreSQL migration integration is intentionally an explicit suite: start `docker compose -f docker-compose.integration.yml up -d`, set `SECUREVAULT_TEST_DATABASE_URL`, and run `pytest -m postgres`. It fails clearly if no PostgreSQL URL is supplied rather than silently replacing PostgreSQL with SQLite.

## Phase 3A implementation status

Phase 3A adds backend-only account/session/device authorization: five-minute database-checked access tokens, device-bound session families, 30-day rolling and 90-day absolute single-use refresh rotation, refresh-reuse revocation, generic authentication errors, pending/trusted/revoked policy enforcement, device listing, logout, and logout-all. The only trust transition is the documented one-time first-device bootstrap.

## Phase 3B implementation status

Phase 3B completes client-side device authorization and cryptographic hardware signing. Enrolled Android devices create an ECDSA P-256 key pair inside Android Keystore (`securevault_device_signing_key`). The `DeviceSigningInterceptor` computes SHA-256 signatures over sensitive request payloads and headers, preventing replay attacks. The `StepUpCoordinator` governs elevated actions (device revocation, remote theft reporting, session clearing) requiring fresh re-authentication within a 5-minute validity window.

## Phase 4 implementation status

Phase 4 implements the core vault user experience, item management, and local cryptographic defense:
- **Password & Secure Notes CRUD:** Full lifecycle management with search, category filtering, favorites, archive, and sensitive field masking.
- **Configurable Password Generator:** High-entropy character pool generator with length, digits, symbols, uppercase, and ambiguous character exclusion.
- **RFC 6238 TOTP Engine:** Native zero-dependency RFC 6238 HMAC-SHA1/SHA256/SHA512 time-based one-time password calculator with progress ring countdown and base32 secret parsing.
- **Security Dashboard & HIBP Breach Checker:** Offline entropy and strength analysis via `PasswordStrengthMeter`, duplicate password detection, compromised password check via HaveIBeenPwned k-Anonymity SHA-1 API.
- **Multi-Format Import / Export:** Bitwarden JSON, 1Password CSV, and KeePass XML parsing into native envelopes, plus password-protected AES-256-GCM encrypted backup exports.
- **Protected Clipboard Controller:** Timed auto-clear (default 30 seconds) and Android 13+ sensitive content flag to prevent clipboard manager snooping.

## Phase 5 implementation status

Phase 5 delivers advanced productivity, platform integration, and internationalization:
- **Android AutofillService:** Native credential autofill integrated with Android Autofill Framework. Prompts user for biometric/PIN unlock when matching domain records are discovered.
- **Document Wallet:** Encrypted document storage for government IDs, passports, cards, and medical records. Includes multi-page image capture, on-device OCR text extraction via Google ML Kit, expiry tracking with color-coded warning chips, and high-contrast Emergency Card view.
- **Anti-Theft & Dead-Man Switch:** Configurable offline inactivity threshold (1–30 days) that triggers automatic local cryptographic key destruction if disconnected beyond the allowed limit.
- **Internationalization (Hindi Localization):** Full localization covering all user-facing strings in `values-hi/strings.xml`, ensuring seamless native language accessibility.

## Phase 6 implementation status

Phase 6 hardens the codebase for enterprise release, establishes continuous integration, and validates end-to-end reliability:
- **ProGuard / R8 Hardening:** Full consumer and app minification rules preserving Room DAOs, BouncyCastle reflection, Kotlin serialization, and Autofill service entry points.
- **Automated CI/CD Workflows:** GitHub Actions pipelines for Android (`android-ci.yml`), backend testing & container build (`backend-ci.yml`), and secret scanning & dependency audit (`security-scan.yml`).
- **End-to-End Integration Testing (`VaultE2EIntegrationTest`):** Comprehensive integration test validating real AES-256-GCM encryption, DEK wrapping, sync push, pull, decryption, and tamper resistance without mocking the cryptographic core.
- **Deployment & Production Operations Guide (`DEPLOYMENT.md`):** Complete guide covering container orchestration, Kubernetes manifests, zero-downtime database rollout, health probes, and disaster recovery.
- **Pre-Release Security Review (`SECURITY_CHECKLIST.md`):** Structured sign-off verification confirming `FLAG_SECURE`, zero secret logs, disabled interactive docs, and defense-in-depth enforcement.


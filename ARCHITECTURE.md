# Architecture

## Scope and trust boundaries

Android is the trusted encryption endpoint after the user unlocks the vault. FastAPI/PostgreSQL/object storage are untrusted with respect to vault plaintext. TLS protects transport but does not replace application encryption. The backend may see account, device, ciphertext sizes, timestamps, and opaque IDs; minimizing even this metadata is a product requirement.

```text
Compose UI → feature use-cases → VaultCrypto → encrypted Room/blob cache
                 │                      │
                 └→ authenticated API ←─┴→ FastAPI → PostgreSQL + private object storage
```

The app has feature modules for auth, passwords, notes, documents, PDF/scanner, sharing, backup, devices, recovery, and settings. `core` owns errors, time and IDs; `security` owns session/lock policy; `crypto` is the sole encryption interface; `database` persists only encrypted payloads; `network` has no plaintext vault DTOs.

## Client data flow

Each vault item is serialized to a versioned plaintext envelope, encrypted locally with a unique random content key, then stored/synchronized as ciphertext plus authenticated non-sensitive routing metadata. Documents are encrypted as chunked blobs before local persistence or upload. Decryption occurs only in memory after an explicit vault unlock; use short-lived buffers and clear references promptly. UI prevents screenshots on sensitive screens (`FLAG_SECURE`), subject to platform limits.

## Server components

- API gateway: TLS termination, request limit, rate limit, correlation ID.
- Auth/device service: opaque sessions, device records, revocation.
- Sync service: authorization, version/conflict coordination, opaque encrypted records.
- Backup service: immutable/versioned encrypted manifests and blobs.
- Storage adapter: interface for private object storage; generated object IDs only.
- Audit service: minimal non-secret security events.

PostgreSQL data and object storage use independent service credentials and encryption at rest. Internal service authorization is least privilege.

## Navigation and sensitive workflows

Bottom-level navigation is Passwords & IDs, Documents, Secure Notes, Image → PDF, Security & Backup, and Settings. Password/detail actions require an unlocked vault; password visibility is momentary and hidden by default. Password sharing always opens a blocking warning with entry identity, masked secret, cancel as the safe default, and an additional severity warning for marked sensitive categories. Document sharing similarly requires acknowledgement before a read-only, time-scoped `FileProvider` URI is passed to Android's native share sheet. Copying a password displays an acknowledgement and clears the matching clipboard content after the configured short timeout where Android permits it.

Image → PDF runs entirely on device: Android Photo Picker/Storage Access Framework → in-memory/downsampled page work area → reorder/crop/rotate/perspective correction → preview → `PdfDocument` generation → encrypted vault blob. Scanner capture follows the same flow using CameraX and must not upload a raw camera image. Optional OCR is on-device, output is user-confirmed, and confirmed fields are encrypted in the document payload.

## Design decisions and contradictions

“Sign in from a new phone” cannot itself decrypt a zero-knowledge vault. It requires an already-trusted device transfer, a high-entropy recovery key, or an encrypted backup whose key the user can derive. Email/password reset must restore account access only, never vault decryption ability.

Remote wipe is eventually delivered, not guaranteed. A thief with an already-unlocked app can read what was already decrypted until automatic lock/OS protection intervenes. Android malware or a compromised OS cannot be fully defeated by an ordinary app.

Server-side search, password breach checks, and plaintext document previews are incompatible with this model and are out of scope. Local search indexes must themselves be encrypted.

# SecureVault Privacy Policy & Data Architecture Review

> **Zero-Knowledge Architecture:** SecureVault is architected so that neither the operators of SecureVault, nor server hosting providers, nor network intermediaries possess the ability to decrypt your vault items.

---

## 1. Zero-Knowledge Cryptographic Boundaries

### Data at Rest (Client Device)
* **Vault Root Key (VRK):** A 256-bit cryptographically secure random key that is the master secret for all item and document encryption. The raw VRK is **never persisted in unencrypted form** on disk, database, or shared preferences.
* **Dual Local Wrapping:** The VRK is wrapped via:
  1. **Argon2id Vault Password Wrapping:** Derived using 3 iterations, 64 MB memory, 2 parallelism lanes, and a 16-byte random salt, encrypted with AES-256-GCM.
  2. **BIP-39 24-Word Recovery Key:** 256-bit entropy converted to 24 standard BIP-39 mnemonic words and wrapped via AES-256-GCM.
  3. **Android Keystore Hardware Key:** Stored inside the device hardware security module (Secure Element / StrongBox / TEE) and bound to `BIOMETRIC_STRONG` authentication.
  4. **Daily PIN:** Double-wrapped with Argon2id and Keystore. Ten consecutive incorrect PIN attempts permanently wipe local key copies.

### Data in Transit
* **All Network Traffic:** Encrypted using TLS 1.3 with Certificate Pinning (SPKI pins defined in `network_security_config.xml`). Cleartext HTTP is strictly blocked.
* **Server Payload Isolation:** All passwords, diary notes, document images, and OCR text are encrypted client-side using AES-256-GCM *prior* to network transmission.
* **Metadata Only:** The server only sees:
  * User identification: Google `sub` (or account ID), email, and display name.
  * Device hardware records: Random Device UUID, public signing key (secp256r1), and enrollment status.
  * Opaque encrypted blobs: Ciphertext and random 12-byte initialization vectors (nonces).

---

## 2. Secure Sharing Architecture & Threat Model

### Zero-Knowledge Web Share Links
* **Key Placement in URL Fragment:** When a share link is generated (`https://vault.secure/s/{token}#key={b64Key}`), the decryption key is located strictly within the URI fragment identifier (after the `#`).
* **RFC 3986 Compliance:** Per browser specifications, HTTP user agents **never transmit the fragment identifier** to the web server in HTTP `GET` request headers or query strings.
* **Server Isolation:** The backend server stores only the ciphertext, expiry timestamp, and access counters. The server has no mathematical ability to decrypt the shared item.
* **Mandatory Disclosures:** Users are presented with an explicit security warning dialog with mandatory acknowledgment before any link can be created.
* **Configurable Expiry & Views:** Links support durations (1 hour, 24 hours, 7 days, 30 days) and view caps (1-view burn-on-read, 3 views, 10 views).
* **Immediate Revocation:** Owners can revoke active share links on demand from the Secure Share Center.

### Native Android Share Sheet Integration
* **Scoped Ephemeral Content:** File sharing uses `SecureShareProvider` (extending `FileProvider`) with scoped `FLAG_GRANT_READ_URI_PERMISSION`.
* **Automatic Cache Revocation:** Ephemeral share files written to `secure_shares/` are automatically deleted after 5 minutes by background coroutines and cleanup sweeps on each share creation.
* **Sensitive Data Sanitization:** By default, password records shared via Android Share Sheet or web links contain **only** the username, website, and title. The actual plaintext password is excluded unless the user explicitly checks a second confirmation opt-in checkbox.

---

## 3. Device Loss & Recovery Privacy

### Device Loss Recovery Wizard
* If a primary device is lost, stolen, or destroyed, the vault can be reconstructed on a clean secondary device without server operator intervention.
* **Recovery Prerequisites:** Requires (1) Master Vault Password OR (2) 24-Word BIP-39 Recovery Phrase.
* **Server Role in Recovery:** The server acts strictly as an encrypted backup repository. It validates device credentials but cannot bypass vault decryption.
* **Local Re-enrollment:** Upon successful recovery key decryption, the wizard guides the user to set a fresh local hardware PIN and enroll biometrics specifically for the new device.
* **Remote Device Revocation:** Users can view all active devices from Settings and issue cryptographic revocation to immediately sign out lost devices.

---

## 4. On-Device Privacy & Screen Hardening

### Screen Capture & Task Switcher Protection
* **`FLAG_SECURE` Enforcement:** Prevents Android OS screen recording, screenshots, and visual preview capture in Android Recents / App Switcher.
* **Exclusion from Recents:** Sensitive authentication and sharing flows prevent leakages into multi-tasking thumbnail caches.

### Clipboard Privacy & Auto-Clear
* **Timed Clipboard Purge:** Any credentials or share links copied to the clipboard are automatically overwritten and purged after 30 seconds via `ClipboardController`.
* **Clipboard Notice:** Users receive a visual countdown banner informing them that the sensitive data will auto-clear.

### Inactivity Auto-Lock & Dead-Man Switch
* **Idle Lock Policy:** The vault locks automatically after 60 seconds of touch inactivity.
* **Offline Dead-Man Switch:** If the app remains offline without server contact past the configured dead-man threshold (default: 30 days), local keys and plaintext caches are permanently purged from hardware storage to protect against offline forensic attacks.

---

## 5. Accessibility & Semantics Audit

* **Assistive Technology Support:** All buttons, icons, and interactive elements provide explicit `contentDescription` properties for TalkBack and screen readers.
* **Custom Semantic Actions:** Accessible actions (`Modifier.semantics`) are exposed for copy, toggle visibility, and deletion without leaking raw secrets into accessibility logs.
* **Touch Targets & Visual Contrast:** Minimum 48dp touch targets are enforced across all navigation and interactive components to satisfy WCAG 2.1 AA accessibility guidelines.
* **Multi-Language Accessibility:** Accessibility labels are localized in English (`values/strings.xml`) and Hindi (`values-hi/strings.xml`).

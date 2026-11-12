# SecureVault — Google Play Store Assets Specification & Copy

This document outlines the required visual and textual assets needed to publish SecureVault to the Google Play Store, along with honest, compliant descriptions that reflect the actual zero-knowledge implementation without hyperbolic claims.

---

## 1. Required Visual Assets Checklist

The developer/operator must produce and place the following files into this directory:

- [ ] **App Icon:**
  - **Dimensions:** 512 × 512 px
  - **Format:** 32-bit PNG (with alpha)
  - **Max file size:** 1024 KB
  - **Current status:** Provided at `store_assets/icon_512.png`.

- [ ] **Feature Graphic:**
  - **Dimensions:** 1024 × 500 px
  - **Format:** JPEG or 24-bit PNG (no alpha)
  - **Max file size:** 15 MB
  - **Guidance:** Showcase the app brand and tagline ("Zero-Knowledge Password & Document Vault"). Keep focal elements centered to avoid cutoffs across various display form factors.

- [ ] **Phone Screenshots:**
  - **Quantity:** Minimum 2, maximum 8 screenshots
  - **Format:** 16:9 or 9:16 aspect ratio (e.g., 1080 × 1920 or 1080 × 2400 px), JPEG or 24-bit PNG
  - **Critical Rule:** Use strictly realistic placeholder / demo data (e.g. `example.com`, `user@example.com`). **NEVER** use real accounts, authentic emails, production passwords, or sensitive keys.
  - **Recommended Screens:**
    1. Lock / Unlock screen (PIN & Biometric authentication)
    2. Passwords list with categories and search
    3. Password detail with copy-to-clipboard action and countdown
    4. Secure Document scanner and encrypted preview
    5. Zero-Knowledge share creation with expiry options
    6. Device management and active session controls

---

## 2. Store Copy Drafts

### Short Description (≤ 80 characters)
```text
Zero-knowledge password and document vault with client-side encryption.
```
*(Exact length: 71 characters)*

### Full Description (≤ 4,000 characters)
```text
SecureVault is an open, zero-knowledge password and sensitive document manager built on proven client-side cryptography. Your credentials, private notes, and scanned documents are encrypted on your device before they ever touch the network or cloud storage.

Zero-Knowledge by Design
• Client-Side Encryption: Vault items are encrypted using AES-256-GCM authenticated encryption.
• Argon2id Key Derivation: Master keys are derived on-device using the memory-hard RFC 9106 Argon2id algorithm, resisting specialized GPU/ASIC cracking hardware.
• Server Isolation: The backend server holds no passwords, decryption keys, or plaintext data. Even in the event of a full server compromise, stored blobs remain unreadable ciphertext.

Core Features
• Secure Passwords: Store unlimited accounts, logins, and passwords with custom categorization and search.
• Encrypted Document Vault: Capture or import private documents, receipts, and IDs with on-device OCR search. Documents are encrypted and split client-side.
• Fast Daily Unlock: Unlock conveniently using your device's biometric sensor (fingerprint/face) or a 4-to-6 digit PIN backed by hardware rate-limiting.
• Zero-Knowledge Sharing: Share selected passwords or documents via temporary links where the decryption key stays in the URL fragment (#) and is never transmitted to any web server.
• Autofill Service: Seamlessly autofill credentials into recognized apps and websites without exposing passwords to untrusted apps.
• Stolen Device Protection: Configurable offline dead-man switch and remote theft reporting from trusted secondary devices.
• Clipboard Auto-Clear: Sensitive copied passwords are automatically cleared from the Android clipboard after 30 seconds.
• Screen Protection: FLAG_SECURE protects against unauthorized screenshots and hides vault previews in the Android recent apps switcher.

Privacy & Transparency
• Sign in using your Google account for authentication and cross-device sync.
• Only encrypted ciphertext, minimal operational metadata (device models, timestamps), and opaque identifiers are stored on the server.
• No analytics tracking, no third-party advertising SDKs, and no background profiling.

Note on Security:
Security depends on choosing a strong, unique Vault Password and keeping your 24-word recovery phrase safe. An app cannot protect data on a rooted operating system or a device compromised by kernel-level malware.
```
*(Honest, accurate, no forbidden buzzwords like "unhackable", "military-grade", or "audited".)*

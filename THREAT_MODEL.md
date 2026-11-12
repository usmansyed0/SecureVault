# Threat model

| Threat | Mitigation | Residual risk |
|---|---|---|
| Stolen locked phone | Encrypted Room/blobs; Keystore-gated VRK; fast auto-lock; no plaintext cache | Device/OS exploit or weak device lock |
| Stolen unlocked phone | background lock, sensitive-screen protection, local wipe on revocation | attacker can view data while app remains unlocked |
| Offline stolen device | local encryption independent of server; no persistent VRK | remote revocation cannot reach it until online |
| Credential brute force | Argon2id verifier, rate limit, delay, generic replies | phishing and password reuse |
| Backend/database/object-store breach | client-side AEAD, separated random keys, private objects | metadata, ciphertext size and timing exposed |
| MITM/session theft | TLS, certificate/network security config, rotating device-bound refresh tokens | compromised endpoint/device |
| Malicious Android app | Keystore, no exports, least permissions, no plaintext intents | rooted/compromised OS lies outside app guarantee |
| Backup/recovery-key theft | high-entropy recovery key, Argon2id wrapping, explicit display once | user disclosure of recovery key |
| Cross-user API access | authenticated ownership checks on every query/object; UUIDs are not authorization | implementation defects; mandatory tests |
| Malicious upload | authenticated encrypted upload, size caps, magic/content validation for intake, generated IDs | denial of service within quotas |
| Clipboard/share/screenshot leak | timed clipboard clearing, confirmations, `FLAG_SECURE`, native share sheet | receiving app/user controls copied/shared data |
| Password weakness/reuse | offline local analysis; no third-party disclosure | cannot prove a password is safe |
| Recovery/account takeover | account reset does not unwrap VRK; trusted transfer/recovery key required | compromised recovery key |
| Dirty biometric sensor / false rejections | Biometric failures separated from PIN wipe counter; falls back to PIN without risking data loss | Temporary inconvenience falling back to PIN |
| Google token forgery or replay | RS256 JWKS cryptographic verification, sub-only identity mapping, server-issued single-use nonces | Compromised Google account (still protected by zero-knowledge Vault Password) |
| MITM or rogue CA certificate | Release network security config forbids cleartext; SPKI certificate pinning with active + backup pins | Compromised device trust root |
| Server database/backup breach | Zero-knowledge VRK: server stores only ciphertext; VRK wrapped locally with Argon2id Vault Password and BIP-39 Recovery Key | User forgets both Vault Password and 24-word Recovery Phrase |
| Background session theft / API replay | Refresh and sync requests bound to Keystore EC P-256 hardware signature (`X-Device-Signature`) | Malware with root OS exploitation |
| Shared link data leak to server | Ephemeral key in URL fragment (#key=...) never sent to server; mandatory warning dialog before link creation | Recipient forwards link to unauthorized third party |
| Password credential leakage via share | Default export strips raw password (username/URL only); requires explicit confirmation checkbox | User chooses to share actual password |
| Ephemeral share file lingering in cache | `SecureShareProvider` with scoped URI and automatic 5-minute file self-destruction | Malicious app with root filesystem access |
| Lost or stolen hardware device | Guided device-loss wizard restores vault on new device via BIP-39 recovery key/vault password, followed by remote device revocation | Physical possession of device before PIN/biometric lockout |

Security review gates all crypto/auth/storage changes. Penetration testing, dependency scanning, mobile threat testing, server authorization tests, and log redaction tests are release criteria.


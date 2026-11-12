# Device revocation and stolen-device response

Each device owns a Keystore-protected local VRK wrapper and registered public key/device identifier. The server keeps a monotonically increasing per-user revocation generation. Sync and refresh require an active device and current generation. Push notification is only a wake-up hint; the next authenticated API call is authoritative.

Revocation is a high-risk action: it requires recent step-up authentication and is audited. Server-side authorization evaluates the target's ownership and status; device IDs are never accepted as proof of ownership. The client independently verifies the registered recipient device key before a trusted-device transfer and signs the transfer context, preventing the service from silently substituting a new recipient key.

“Secure & Wipe Device” immediately revokes sessions, marks the device stolen, removes server-side device authorization and prevents sync. The server records the security event and issues revocation notifications. When the target app next receives/observes revocation, it locks first, deletes encrypted databases/blob cache/session material, deletes its Keystore aliases where permitted, and unregisters background work. This is cryptographic erasure of the local ability to decrypt, not guaranteed remote deletion.

Local app startup checks revocation before sync, and auto-locks on timeout/background. A new device needs normal account authentication plus recovery key/backup decryption or trusted-device approval before it gains a VRK wrapper. Account-password reset alone grants no vault access.

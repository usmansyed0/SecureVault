# Backup and recovery

Backup creation snapshots encrypted record/blob manifests locally, encrypts the manifest and backup payload with unique backup DEKs, wraps those with a backup subkey of VRK, verifies AEAD tags and manifest hashes locally, then uploads a new immutable version. The server stores ciphertext and opaque object IDs only. Automatic backups require Wi-Fi/charging/user policy and report status without plaintext details. Never overwrite the only confirmed backup; retain a configurable version window.

Restore downloads ciphertext, verifies size/hash/AEAD before committing, decrypts locally only after VRK recovery, and imports transactionally. A failed restore leaves the existing vault untouched. Recovery key presentation uses an OS-protected screen, requires acknowledgement, is never logged, and is not re-displayable; users may rotate it after unlock.

Recovery paths: (1) encrypted trusted-device transfer after user approval, or (2) recovery key unwraps VRK then restores a backup. Email verification can protect the account workflow but does not decrypt vault material. Recovery-key loss plus no trusted device/backups is intentionally unrecoverable.


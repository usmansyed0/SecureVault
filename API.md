# API design

Base path: `/v1`. Every endpoint uses TLS, JSON limits (1 MiB unless stated), strict schemas, and generic errors. Bearer access tokens identify a user and device; server authorization scopes every row/object by the token user ID. Object upload/download uses authenticated streaming endpoints or short-lived single-use private URLs bound to user, object and method.

| Method/path | Purpose |
|---|---|
| Method/path | Purpose |
|---|---|
| `GET /auth/google/nonce` | Server-issued single-use cryptographic nonce (5-min TTL) for Google Sign-In replay protection |
| `POST /auth/google` | Verifies Google ID token via RS256 JWKS; registers/authenticates account by `sub` + device public key |
| `POST /auth/register` | Deprecated (410 Gone) — new accounts require Google Sign-In with server nonce |
| `POST /auth/refresh` | Rotates refresh token; requires hardware `X-Device-Signature`, `X-Timestamp`, `X-Device-Id` |
| `POST /auth/step-up/google` | Validates recent Google ID token + device signature for sensitive administrative step-up actions |
| `POST /auth/logout`, `/auth/logout-all` | Account/session revocation; rate limited |
| `POST /devices/register` | Registers public device signing keys in `devices.device_public_key` |
| `GET /devices`, `POST /devices/{id}/revoke` | Device view/revocation; requires recent step-up |
| `GET /vault/changes` | Returns opaque encrypted record changes; requires hardware `X-Device-Signature` |
| `GET /vault/binding`, `PUT /vault/binding` | Opaque recovery-wrapped VRK envelope and Argon2id parameters |
| `PUT /vault/records/{id}` | Conditional encrypted record upsert (`If-Match` revision) |
| `DELETE /vault/records/{id}` | Tombstone, conditional revision |
| `POST /objects`, `GET /objects/{id}` | authorized bounded encrypted blob stream |
| `POST /backups`, `GET /backups`, `GET /backups/{id}` | immutable encrypted backup operations |
| `POST /recovery/start`, `/recovery/complete` | account/device recovery orchestration; completion requires proof/recent step-up and no VRK plaintext |
| `GET /security-events` | minimal authenticated event history |

Uploads declare encrypted length and content suite; server enforces quotas, max object size, streaming limits, and rejects unexpected types. It treats uploaded vault blobs as opaque ciphertext—not user supplied file paths. Pagination cursors are signed and user-scoped. Audit logs record route/status/opaque IDs, never headers, bodies, tokens, or secrets.

Trusted-device transfer packages are opaque relay objects addressed to a registered recipient public key. The server enforces ownership and device state but cannot generate, inspect, or replace cryptographic transfer contents. Revocation, recovery completion, recovery-key rotation and deletion consume a short-lived step-up token minted only after fresh password plus approved local factor where available.

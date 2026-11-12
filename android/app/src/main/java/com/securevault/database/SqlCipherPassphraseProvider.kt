package com.securevault.database

import android.content.Context
import com.securevault.security.VaultSession
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * Derives a stable 32-byte SQLCipher database passphrase from the Vault Root
 * Key (VRK) using HMAC-SHA-256.
 *
 * ### Design rationale
 *
 * Room already stores only encrypted ciphertext (AES-256-GCM envelopes), so
 * this is a **defense-in-depth** layer: if an attacker extracts the raw SQLite
 * file they still cannot read the schema, metadata, or ciphertext without also
 * recovering the VRK.
 *
 * The domain-separation label `"securevault.sqlcipher.passphrase.v1"` is
 * prepended to the HMAC input so this key cannot be confused with or reused as
 * any other key material derived from the VRK.
 *
 * ### Lifecycle
 *
 * - [derive] is called once during database open, immediately after the vault
 *   is unlocked.
 * - [wipe] must be called as part of logout / vault destruction so the
 *   passphrase is not cached beyond the session.
 *
 * ### Threat model note
 *
 * If the VRK is wiped from [VaultSession] (lock / logout), no new database
 * connection can be opened because the passphrase cannot be re-derived.
 * Existing SQLCipher connections held by Room's connection pool are closed by
 * calling `db.close()` in [com.securevault.di.AppModule] during logout.
 */
class SqlCipherPassphraseProvider {

    /**
     * Derives the SQLCipher passphrase as `HMAC-SHA-256(vrk, label)` and
     * returns it as a hex string (SQLCipher's expected format when using
     * `PRAGMA key = "x'<hex>'"` via the SupportSQLiteOpenHelper factory).
     *
     * The returned ByteArray is 32 bytes.  Callers must [fill(0)] it once the
     * database is open.
     */
    fun derive(vrk: ByteArray): ByteArray {
        require(vrk.size == 32) { "VRK must be 32 bytes" }
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(vrk, "HmacSHA256"))
        mac.update(LABEL)
        return mac.doFinal()  // 32 bytes
    }

    private companion object {
        private val LABEL = "securevault.sqlcipher.passphrase.v1".toByteArray(Charsets.UTF_8)
    }
}

/**
 * Converts a 32-byte raw key to a lowercase hex string suitable for passing to
 * SQLCipher's `PRAGMA key` via the `openHelperFactory` parameter of Room.
 *
 * `"x'<64 hex chars>'"` is the raw-key format accepted by SQLCipher 4.x.
 */
fun ByteArray.toSqlCipherHexKey(): String {
    require(size == 32) { "Expected 32-byte key, got $size" }
    val hex = StringBuilder(64)
    for (b in this) hex.append(String.format("%02x", b))
    return "x'$hex'"
}

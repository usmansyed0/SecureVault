package com.securevault.vault.io

import com.securevault.crypto.Argon2Kdf
import com.securevault.util.SecureBuffer.useAndWipe
import com.securevault.vault.model.PasswordEntry
import com.securevault.vault.model.SecureNote
import com.securevault.vault.model.VaultItem
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import java.io.BufferedReader
import java.io.StringReader
import java.nio.charset.StandardCharsets
import java.security.SecureRandom
import java.util.Base64
import java.util.UUID
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

@Serializable
data class EncryptedExportPackage(
    val format: String = "securevault-backup-v1",
    val saltBase64: String,
    val nonceBase64: String,
    val ciphertextBase64: String,
    val itemCount: Int,
    val createdAtEpochMs: Long = System.currentTimeMillis()
)

@Serializable
data class PlaintextExportPayload(
    val passwords: List<ExportPasswordItem>,
    val notes: List<ExportNoteItem>
)

@Serializable
data class ExportPasswordItem(
    val title: String,
    val username: String,
    val password: String,
    val website: String = "",
    val notes: String = "",
    val category: String = "General",
    val totpSecret: String = ""
)

@Serializable
data class ExportNoteItem(
    val title: String,
    val content: String,
    val category: String = "General"
)

object VaultImportExportManager {

    private val json = Json { ignoreUnknownKeys = true; encodeDefaults = true }
    private val random = SecureRandom()

    // ── Import Parsers ────────────────────────────────────────────────────────

    /**
     * Parses CSV text exported from Chrome, Bitwarden, 1Password, LastPass, or KeePass.
     * Maps extracted records into [PasswordEntry] items for import into the vault.
     */
    fun importFromCsv(csvContent: String, vaultId: String): List<PasswordEntry> {
        val reader = BufferedReader(StringReader(csvContent))
        val headerLine = reader.readLine() ?: return emptyList()
        val headers = parseCsvRow(headerLine).map { it.trim().lowercase() }

        val entries = mutableListOf<PasswordEntry>()
        var line: String? = reader.readLine()

        while (line != null) {
            if (line.isNotBlank()) {
                val row = parseCsvRow(line)
                if (row.isNotEmpty()) {
                    val entry = parseRowToPasswordEntry(headers, row, vaultId)
                    if (entry != null) {
                        entries.add(entry)
                    }
                }
            }
            line = reader.readLine()
        }

        return entries
    }

    private fun parseRowToPasswordEntry(headers: List<String>, row: List<String>, vaultId: String): PasswordEntry? {
        fun getCol(vararg candidates: String): String {
            for (candidate in candidates) {
                val idx = headers.indexOf(candidate.lowercase())
                if (idx in row.indices) {
                    val value = row[idx].trim()
                    if (value.isNotEmpty()) return value
                }
            }
            return ""
        }

        val title = getCol("name", "title", "account", "login_name").ifEmpty {
            getCol("url", "website", "login_uri")
        }
        val username = getCol("username", "login_username", "login name", "user", "email")
        val password = getCol("password", "login_password", "pass")
        val website = getCol("url", "website", "login_uri", "web site")
        val notes = getCol("notes", "extra", "comments")
        val totp = getCol("login_totp", "totp", "otp", "secret")

        // Must at least have title or password or username
        if (title.isEmpty() && password.isEmpty() && username.isEmpty()) return null

        return PasswordEntry(
            id = UUID.randomUUID().toString(),
            vaultId = vaultId,
            title = title.ifEmpty { "Imported Account" },
            username = username,
            password = password,
            website = website,
            notes = notes,
            category = "Imported",
            totpSecret = totp
        )
    }

    // ── Export Generators ─────────────────────────────────────────────────────

    /**
     * Creates an encrypted backup file package using AES-256-GCM.
     * The encryption key is derived from [exportPassword] using Argon2id.
     */
    fun exportEncryptedPackage(items: List<VaultItem>, exportPassword: String): String {
        require(exportPassword.length >= 8) { "Export password must be at least 8 characters" }

        val passwords = items.filterIsInstance<VaultItem.Password>().map {
            ExportPasswordItem(
                title = it.entry.title,
                username = it.entry.username,
                password = it.entry.password,
                website = it.entry.website,
                notes = it.entry.notes,
                category = it.entry.category,
                totpSecret = it.entry.totpSecret
            )
        }
        val notes = items.filterIsInstance<VaultItem.Note>().map {
            ExportNoteItem(
                title = it.note.title,
                content = it.note.content,
                category = it.note.category
            )
        }

        val payload = PlaintextExportPayload(passwords, notes)
        val plaintextBytes = json.encodeToString(payload).toByteArray(StandardCharsets.UTF_8)

        val salt = ByteArray(16).also(random::nextBytes)
        val nonce = ByteArray(12).also(random::nextBytes)

        val kdf = Argon2Kdf()
        val derivedKey = kdf.deriveKey(exportPassword, salt)

        val ciphertext = try {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(derivedKey, "AES"), GCMParameterSpec(128, nonce))
            cipher.updateAAD("securevault-export-v1".toByteArray(StandardCharsets.UTF_8))
            cipher.doFinal(plaintextBytes)
        } finally {
            derivedKey.useAndWipe {}
        }

        val pkg = EncryptedExportPackage(
            saltBase64 = Base64.getEncoder().encodeToString(salt),
            nonceBase64 = Base64.getEncoder().encodeToString(nonce),
            ciphertextBase64 = Base64.getEncoder().encodeToString(ciphertext),
            itemCount = items.size
        )
        return json.encodeToString(pkg)
    }

    /**
     * Decrypts an encrypted export package using [exportPassword].
     */
    fun decryptExportPackage(packageJson: String, exportPassword: String): PlaintextExportPayload {
        val pkg = json.decodeFromString<EncryptedExportPackage>(packageJson)
        val salt = Base64.getDecoder().decode(pkg.saltBase64)
        val nonce = Base64.getDecoder().decode(pkg.nonceBase64)
        val ciphertext = Base64.getDecoder().decode(pkg.ciphertextBase64)

        val kdf = Argon2Kdf()
        val derivedKey = kdf.deriveKey(exportPassword, salt)

        val plaintextBytes = try {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(derivedKey, "AES"), GCMParameterSpec(128, nonce))
            cipher.updateAAD("securevault-export-v1".toByteArray(StandardCharsets.UTF_8))
            cipher.doFinal(ciphertext)
        } finally {
            derivedKey.useAndWipe {}
        }

        return json.decodeFromString(String(plaintextBytes, StandardCharsets.UTF_8))
    }

    /**
     * Exports password items to standard CSV format.
     */
    fun exportPlaintextCsv(items: List<VaultItem.Password>): String {
        val sb = StringBuilder()
        sb.append("name,url,username,password,notes,totp\n")
        for (item in items) {
            val e = item.entry
            sb.append(escapeCsv(e.title)).append(",")
            sb.append(escapeCsv(e.website)).append(",")
            sb.append(escapeCsv(e.username)).append(",")
            sb.append(escapeCsv(e.password)).append(",")
            sb.append(escapeCsv(e.notes)).append(",")
            sb.append(escapeCsv(e.totpSecret)).append("\n")
        }
        return sb.toString()
    }

    private fun escapeCsv(value: String): String {
        if (value.contains(",") || value.contains("\"") || value.contains("\n")) {
            return "\"" + value.replace("\"", "\"\"") + "\""
        }
        return value
    }

    private fun parseCsvRow(line: String): List<String> {
        val cells = mutableListOf<String>()
        val sb = StringBuilder()
        var inQuotes = false
        var i = 0

        while (i < line.length) {
            val c = line[i]
            when {
                c == '\"' -> {
                    if (inQuotes && i + 1 < line.length && line[i + 1] == '\"') {
                        sb.append('\"')
                        i++
                    } else {
                        inQuotes = !inQuotes
                    }
                }
                c == ',' && !inQuotes -> {
                    cells.add(sb.toString())
                    sb.clear()
                }
                else -> sb.append(c)
            }
            i++
        }
        cells.add(sb.toString())
        return cells
    }
}

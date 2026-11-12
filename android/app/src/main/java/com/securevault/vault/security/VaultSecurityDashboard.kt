package com.securevault.vault.security

import com.securevault.vault.model.PasswordEntry
import com.securevault.vault.strength.PasswordStrengthMeter
import java.io.BufferedReader
import java.io.InputStreamReader
import java.net.HttpURLConnection
import java.net.URL
import java.security.MessageDigest
import java.util.Locale

data class PasswordHealthReport(
    val totalPasswords: Int,
    val strongCount: Int,
    val weakItems: List<PasswordEntry>,
    val reusedGroups: Map<String, List<PasswordEntry>>,
    val oldItems: List<PasswordEntry>,
    val overallScorePercent: Int
)

data class BreachCheckResult(
    val isPwned: Boolean,
    val breachCount: Int
)

object VaultSecurityDashboard {

    private const val OLD_PASSWORD_THRESHOLD_MS = 90L * 24 * 3600 * 1000 // 90 days

    /**
     * Performs a complete on-device health check across all stored password entries.
     * Evaluates strength, password reuse, and age without any network calls.
     */
    fun analyzePasswords(entries: List<PasswordEntry>): PasswordHealthReport {
        if (entries.isEmpty()) {
            return PasswordHealthReport(
                totalPasswords = 0,
                strongCount = 0,
                weakItems = emptyList(),
                reusedGroups = emptyMap(),
                oldItems = emptyList(),
                overallScorePercent = 100
            )
        }

        val weak = mutableListOf<PasswordEntry>()
        val old = mutableListOf<PasswordEntry>()
        val byPassword = mutableMapOf<String, MutableList<PasswordEntry>>()
        val now = System.currentTimeMillis()

        for (e in entries) {
            val pass = e.password
            // Check password strength
            val strength = PasswordStrengthMeter.estimate(pass)
            if (pass.length < 12 || strength.score < 3) {
                weak.add(e)
            }

            // Check age
            if (now - e.updatedAtEpochMs > OLD_PASSWORD_THRESHOLD_MS) {
                old.add(e)
            }

            // Group by password to detect reuse
            if (pass.isNotEmpty()) {
                byPassword.getOrPut(pass) { mutableListOf() }.add(e)
            }
        }

        val reused = byPassword.filter { it.value.size > 1 }
        val strongCount = entries.size - weak.size

        // Calculate 0..100 composite security score
        val weakPenalty = (weak.size.toFloat() / entries.size) * 50
        val reusePenalty = (reused.values.sumOf { it.size }.toFloat() / entries.size) * 35
        val oldPenalty = (old.size.toFloat() / entries.size) * 15
        val score = maxOf(0, (100 - weakPenalty - reusePenalty - oldPenalty).toInt())

        return PasswordHealthReport(
            totalPasswords = entries.size,
            strongCount = maxOf(0, strongCount),
            weakItems = weak,
            reusedGroups = reused,
            oldItems = old,
            overallScorePercent = score
        )
    }

    /**
     * K-Anonymity breach check against Have I Been Pwned.
     *
     * Privacy invariant:
     * - Only the first 5 characters of the SHA-1 hash leave the device.
     * - The full password and remaining 35 characters are evaluated entirely on-device.
     */
    fun checkPwnedKAnonymity(password: String): BreachCheckResult {
        if (password.isEmpty()) return BreachCheckResult(isPwned = false, breachCount = 0)

        val sha1Hex = sha1(password).uppercase(Locale.ROOT)
        val prefix = sha1Hex.substring(0, 5)
        val suffix = sha1Hex.substring(5)

        val url = URL("https://api.pwnedpasswords.com/range/$prefix")
        val conn = url.openConnection() as HttpURLConnection
        conn.requestMethod = "GET"
        conn.setRequestProperty("User-Agent", "SecureVault-Android-App")
        conn.connectTimeout = 5000
        conn.readTimeout = 5000

        try {
            if (conn.responseCode != 200) {
                return BreachCheckResult(isPwned = false, breachCount = 0)
            }

            BufferedReader(InputStreamReader(conn.inputStream)).use { reader ->
                var line = reader.readLine()
                while (line != null) {
                    val parts = line.trim().split(":")
                    if (parts.size == 2 && parts[0].equals(suffix, ignoreCase = true)) {
                        val count = parts[1].toIntOrNull() ?: 1
                        return BreachCheckResult(isPwned = true, breachCount = count)
                    }
                    line = reader.readLine()
                }
            }
        } catch (_: Exception) {
            // Fail open on network / timeout errors
        } finally {
            conn.disconnect()
        }

        return BreachCheckResult(isPwned = false, breachCount = 0)
    }

    private fun sha1(input: String): String {
        val md = MessageDigest.getInstance("SHA-1")
        val bytes = md.digest(input.toByteArray(Charsets.UTF_8))
        return bytes.joinToString("") { "%02x".format(it) }
    }
}

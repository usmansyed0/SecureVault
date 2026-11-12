package com.securevault.vault.totp

import java.net.URI
import java.net.URLDecoder
import java.nio.ByteBuffer
import java.nio.charset.StandardCharsets
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import kotlin.math.floor

/**
 * TOTP code snapshot.
 *
 * @property code Formatted 6-digit or 8-digit OTP string.
 * @property secondsRemaining Seconds remaining in the current 30-second window (1..30).
 * @property progressFraction Floating progress (0.0 to 1.0) for circular/linear UI timers.
 */
data class TotpCode(
    val code: String,
    val secondsRemaining: Int,
    val progressFraction: Float
)

/**
 * Zero-knowledge on-device RFC 6238 TOTP Authenticator.
 *
 * Supports:
 * - Base32 encoded secrets (RFC 4648).
 * - Standard 30-second intervals and 6/8 digit outputs.
 * - Parsing standard `otpauth://totp/...` QR-code URIs.
 */
object TotpGenerator {

    private const val DEFAULT_TIME_STEP_SECONDS = 30L
    private const val DEFAULT_DIGITS = 6

    fun generateCode(
        base32Secret: String,
        epochSeconds: Long = System.currentTimeMillis() / 1000L,
        timeStepSeconds: Long = DEFAULT_TIME_STEP_SECONDS,
        digits: Int = DEFAULT_DIGITS,
        algorithm: String = "HmacSHA1"
    ): TotpCode? {
        val cleanSecret = base32Secret.trim().replace(" ", "").replace("-", "").uppercase()
        if (cleanSecret.isEmpty()) return null

        val secretBytes = try {
            decodeBase32(cleanSecret)
        } catch (_: Exception) {
            return null
        }
        if (secretBytes.isEmpty()) return null

        val counter = epochSeconds / timeStepSeconds
        val elapsed = (epochSeconds % timeStepSeconds).toInt()
        val remaining = (timeStepSeconds - elapsed).toInt()
        val progress = remaining.toFloat() / timeStepSeconds.toFloat()

        val mac = Mac.getInstance(algorithm)
        mac.init(SecretKeySpec(secretBytes, algorithm))

        val buffer = ByteBuffer.allocate(8)
        buffer.putLong(counter)
        val hash = mac.doFinal(buffer.array())

        // Dynamic truncation (RFC 4226 Section 5.4)
        val offset = (hash[hash.size - 1].toInt() and 0x0F)
        val truncatedHash = ((hash[offset].toInt() and 0x7F) shl 24) or
                ((hash[offset + 1].toInt() and 0xFF) shl 16) or
                ((hash[offset + 2].toInt() and 0xFF) shl 8) or
                (hash[offset + 3].toInt() and 0xFF)

        val modulo = when (digits) {
            8 -> 100_000_000
            7 -> 10_000_000
            else -> 1_000_000
        }
        val otpValue = (truncatedHash % modulo).toString().padStart(digits, '0')

        return TotpCode(
            code = otpValue,
            secondsRemaining = remaining,
            progressFraction = progress
        )
    }

    /**
     * Extracts the raw secret from an `otpauth://totp/` URI.
     */
    fun parseOtpAuthUri(uriString: String): String? {
        try {
            val uri = URI(uriString)
            if (uri.scheme?.lowercase() != "otpauth") return null
            val query = uri.query ?: return null
            val pairs = query.split("&")
            for (pair in pairs) {
                val parts = pair.split("=", limit = 2)
                if (parts.size == 2 && parts[0].equals("secret", ignoreCase = true)) {
                    return URLDecoder.decode(parts[1], StandardCharsets.UTF_8.name())
                }
            }
        } catch (_: Exception) {}
        return null
    }

    /**
     * RFC 4648 Base32 decoder.
     */
    fun decodeBase32(input: String): ByteArray {
        val base32Chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
        var buffer = 0
        var bitsLeft = 0
        val out = mutableListOf<Byte>()

        for (c in input) {
            if (c == '=') break
            val charIndex = base32Chars.indexOf(c)
            if (charIndex < 0) continue

            buffer = (buffer shl 5) or charIndex
            bitsLeft += 5

            if (bitsLeft >= 8) {
                val byteVal = (buffer shr (bitsLeft - 8)) and 0xFF
                out.add(byteVal.toByte())
                bitsLeft -= 8
            }
        }
        return out.toByteArray()
    }
}

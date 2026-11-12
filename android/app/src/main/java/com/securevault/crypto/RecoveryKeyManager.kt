package com.securevault.crypto

import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import javax.inject.Inject
import javax.inject.Singleton

@Singleton
class RecoveryKeyManager @Inject constructor() {
    private val random = SecureRandom()

    companion object {
        const val ENTROPY_BYTES = 32 // 256 bits
        const val WORD_COUNT = 24
        const val GCM_IV_LENGTH = 12
        const val GCM_TAG_LENGTH_BITS = 128
        val AAD_RECOVERY_KEY_WRAP = "recovery_key_wrap_v1".toByteArray(Charsets.UTF_8)
    }

    data class RecoveryPhrase(
        val words: List<String>,
        val phrase: String,
        val recoveryKey: ByteArray
    ) {
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other !is RecoveryPhrase) return false
            return phrase == other.phrase && recoveryKey.contentEquals(other.recoveryKey)
        }

        override fun hashCode(): Int = 31 * phrase.hashCode() + recoveryKey.contentHashCode()
    }

    /**
     * Generates a fresh 256-bit Recovery Key and converts it to a 24-word BIP-39 mnemonic phrase.
     */
    fun generateRecoveryPhrase(): RecoveryPhrase {
        val entropy = ByteArray(ENTROPY_BYTES)
        random.nextBytes(entropy)
        val words = entropyToWords(entropy)
        val phrase = words.joinToString(" ")
        return RecoveryPhrase(words = words, phrase = phrase, recoveryKey = entropy)
    }

    /**
     * Converts 32-byte (256-bit) entropy into 24 BIP-39 words.
     */
    fun entropyToWords(entropy: ByteArray): List<String> {
        require(entropy.size == ENTROPY_BYTES) { "Entropy must be exactly $ENTROPY_BYTES bytes" }
        val hash = MessageDigest.getInstance("SHA-256").digest(entropy)
        val checksum = hash[0].toInt() and 0xFF

        val words = ArrayList<String>(WORD_COUNT)
        var bitBuffer = 0
        var bitsInBuffer = 0
        var byteIndex = 0

        for (i in 0 until WORD_COUNT) {
            while (bitsInBuffer < 11) {
                val nextByte = if (byteIndex < ENTROPY_BYTES) {
                    entropy[byteIndex].toInt() and 0xFF
                } else {
                    checksum
                }
                byteIndex++
                bitBuffer = (bitBuffer shl 8) or nextByte
                bitsInBuffer += 8
            }
            bitsInBuffer -= 11
            val wordIndex = (bitBuffer ushr bitsInBuffer) and 0x7FF
            words.add(Bip39WordList.getWord(wordIndex))
        }
        return words
    }

    /**
     * Converts a 24-word BIP-39 recovery phrase back into the 32-byte Recovery Key.
     * Validates word count, dictionary presence, and SHA-256 checksum.
     */
    fun phraseToRecoveryKey(phrase: String): ByteArray {
        val words = phrase.trim().lowercase().split(Regex("\\s+")).filter { it.isNotBlank() }
        require(words.size == WORD_COUNT) { "Recovery phrase must contain exactly $WORD_COUNT words (found ${words.size})" }

        val result = ByteArray(33)
        var bitBuffer = 0
        var bitsInBuffer = 0
        var byteIndex = 0

        for (word in words) {
            val wordIndex = Bip39WordList.indexOf(word)
                ?: throw IllegalArgumentException("Invalid BIP-39 word: $word")
            bitBuffer = (bitBuffer shl 11) or (wordIndex and 0x7FF)
            bitsInBuffer += 11
            while (bitsInBuffer >= 8) {
                bitsInBuffer -= 8
                result[byteIndex++] = ((bitBuffer ushr bitsInBuffer) and 0xFF).toByte()
            }
        }

        val entropy = result.copyOfRange(0, ENTROPY_BYTES)
        val expectedChecksum = result[32].toInt() and 0xFF
        val computedHash = MessageDigest.getInstance("SHA-256").digest(entropy)
        val actualChecksum = computedHash[0].toInt() and 0xFF

        if (expectedChecksum != actualChecksum) {
            throw IllegalArgumentException("Invalid recovery phrase checksum")
        }
        return entropy
    }

    /**
     * Wraps the VRK (AES-256-GCM) with the 256-bit Recovery Key.
     * Output format: 12-byte IV + 48-byte Ciphertext/Tag = 60 bytes.
     */
    fun wrapVrk(vrk: ByteArray, recoveryKey: ByteArray): ByteArray {
        require(vrk.size == 32) { "VRK must be exactly 32 bytes" }
        require(recoveryKey.size == 32) { "Recovery Key must be exactly 32 bytes" }

        val iv = ByteArray(GCM_IV_LENGTH)
        random.nextBytes(iv)

        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        val keySpec = SecretKeySpec(recoveryKey, "AES")
        val gcmSpec = GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv)
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmSpec)
        cipher.updateAAD(AAD_RECOVERY_KEY_WRAP)
        val ciphertext = cipher.doFinal(vrk)

        val output = ByteArray(iv.size + ciphertext.size)
        System.arraycopy(iv, 0, output, 0, iv.size)
        System.arraycopy(ciphertext, 0, output, iv.size, ciphertext.size)
        return output
    }

    /**
     * Unwraps the VRK using the 256-bit Recovery Key.
     */
    fun unwrapVrk(wrappedBlob: ByteArray, recoveryKey: ByteArray): ByteArray {
        require(wrappedBlob.size >= GCM_IV_LENGTH + 16) { "Invalid wrapped VRK blob length" }
        require(recoveryKey.size == 32) { "Recovery Key must be exactly 32 bytes" }

        val iv = wrappedBlob.copyOfRange(0, GCM_IV_LENGTH)
        val ciphertext = wrappedBlob.copyOfRange(GCM_IV_LENGTH, wrappedBlob.size)

        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        val keySpec = SecretKeySpec(recoveryKey, "AES")
        val gcmSpec = GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv)
        cipher.init(Cipher.DECRYPT_MODE, keySpec, gcmSpec)
        cipher.updateAAD(AAD_RECOVERY_KEY_WRAP)
        val vrk = cipher.doFinal(ciphertext)
        if (vrk.size != 32) {
            throw SecurityException("Decrypted VRK has invalid length: ${vrk.size}")
        }
        return vrk
    }

    /**
     * Selects 3 random 1-indexed word positions (e.g. 3, 11, 19) for confirmation check.
     */
    fun pickConfirmationPositions(count: Int = 3): List<Int> {
        return (1..WORD_COUNT).shuffled(random).take(count).sorted()
    }

    /**
     * Validates user confirmation input against the original words.
     */
    fun validateConfirmation(words: List<String>, confirmations: Map<Int, String>): Boolean {
        if (confirmations.isEmpty()) return false
        for ((pos, inputWord) in confirmations) {
            if (pos !in 1..WORD_COUNT) return false
            val expected = words[pos - 1]
            if (!expected.equals(inputWord.trim(), ignoreCase = true)) {
                return false
            }
        }
        return true
    }

    fun encodeBase64(bytes: ByteArray): String = Base64.getEncoder().encodeToString(bytes)
    fun decodeBase64(str: String): ByteArray = Base64.getDecoder().decode(str)
}

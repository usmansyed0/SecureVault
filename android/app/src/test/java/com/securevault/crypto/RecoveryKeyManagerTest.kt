package com.securevault.crypto

import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import java.security.SecureRandom

class RecoveryKeyManagerTest {

    private lateinit var manager: RecoveryKeyManager

    @Before
    fun setUp() {
        manager = RecoveryKeyManager()
    }

    @Test
    fun generateRecoveryPhraseProduces24ValidBip39Words() {
        val result = manager.generateRecoveryPhrase()
        assertEquals(24, result.words.size)
        assertEquals(32, result.recoveryKey.size)

        // Verify each word exists in BIP-39 dictionary
        for (word in result.words) {
            assertNotNull("Word '$word' should be in BIP-39 word list", Bip39WordList.indexOf(word))
        }

        // Verify round-trip conversion from phrase back to recovery key
        val recoveredKey = manager.phraseToRecoveryKey(result.phrase)
        assertArrayEquals(result.recoveryKey, recoveredKey)
    }

    @Test
    fun phraseToRecoveryKeyRejectsCorruptedChecksum() {
        val result = manager.generateRecoveryPhrase()
        val words = result.words.toMutableList()
        // Tamper with the last word (which includes the checksum bits)
        val lastIndex = Bip39WordList.indexOf(words.last())!!
        val differentIndex = (lastIndex + 1) % 2048
        words[words.size - 1] = Bip39WordList.getWord(differentIndex)

        val tamperedPhrase = words.joinToString(" ")
        try {
            manager.phraseToRecoveryKey(tamperedPhrase)
            fail("Expected IllegalArgumentException for tampered recovery phrase checksum")
        } catch (e: IllegalArgumentException) {
            assertTrue(e.message!!.contains("checksum", ignoreCase = true))
        }
    }

    @Test
    fun phraseToRecoveryKeyRejectsInvalidWord() {
        val result = manager.generateRecoveryPhrase()
        val words = result.words.toMutableList()
        words[0] = "notabipword123"
        val invalidPhrase = words.joinToString(" ")

        try {
            manager.phraseToRecoveryKey(invalidPhrase)
            fail("Expected IllegalArgumentException for non-BIP word")
        } catch (e: IllegalArgumentException) {
            assertTrue(e.message!!.contains("Invalid BIP-39 word", ignoreCase = true))
        }
    }

    @Test
    fun phraseToRecoveryKeyRejectsWrongWordCount() {
        try {
            manager.phraseToRecoveryKey("abandon ability able")
            fail("Expected IllegalArgumentException for 3 words instead of 24")
        } catch (e: IllegalArgumentException) {
            assertTrue(e.message!!.contains("24 words", ignoreCase = true))
        }
    }

    @Test
    fun wrapAndUnwrapVrkRoundTripsCorrectly() {
        val random = SecureRandom()
        val vrk = ByteArray(32).also(random::nextBytes)
        val recoveryKey = ByteArray(32).also(random::nextBytes)

        val wrappedBlob = manager.wrapVrk(vrk, recoveryKey)
        // 12 bytes IV + 32 bytes VRK + 16 bytes GCM tag = 60 bytes
        assertEquals(60, wrappedBlob.size)

        val unwrappedVrk = manager.unwrapVrk(wrappedBlob, recoveryKey)
        assertArrayEquals(vrk, unwrappedVrk)
    }

    @Test
    fun unwrapVrkFailsWithWrongRecoveryKey() {
        val random = SecureRandom()
        val vrk = ByteArray(32).also(random::nextBytes)
        val recoveryKey = ByteArray(32).also(random::nextBytes)
        val wrongRecoveryKey = ByteArray(32).also(random::nextBytes)

        val wrappedBlob = manager.wrapVrk(vrk, recoveryKey)

        try {
            manager.unwrapVrk(wrappedBlob, wrongRecoveryKey)
            fail("Expected AEAD tag mismatch exception with wrong recovery key")
        } catch (e: Exception) {
            // Expected AEAD auth failure
            assertTrue(e is javax.crypto.AEADBadTagException || e is java.security.GeneralSecurityException)
        }
    }

    @Test
    fun pickConfirmationPositionsReturnsThreeUniqueSortedIndices() {
        val positions = manager.pickConfirmationPositions(3)
        assertEquals(3, positions.size)
        assertEquals(positions.sorted(), positions)
        for (pos in positions) {
            assertTrue("Position $pos should be in 1..24", pos in 1..24)
        }
        assertEquals(3, positions.distinct().size)
    }

    @Test
    fun validateConfirmationVerifiesAccurately() {
        val phrase = manager.generateRecoveryPhrase()
        val positions = listOf(3, 11, 19)

        val validConfirmations = mapOf(
            3 to phrase.words[2],
            11 to phrase.words[10].uppercase(), // case-insensitive
            19 to "  " + phrase.words[18] + "  " // trimmed
        )
        assertTrue(manager.validateConfirmation(phrase.words, validConfirmations))

        val invalidConfirmations = mapOf(
            3 to phrase.words[2],
            11 to "wrongword",
            19 to phrase.words[18]
        )
        assertFalse(manager.validateConfirmation(phrase.words, invalidConfirmations))
    }
}

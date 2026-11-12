package com.securevault.crypto

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertFalse
import org.junit.Test
import java.security.SecureRandom

class VaultRecordCryptoTest {
    private val crypto = VaultRecordCrypto(SecureRandom())
    private val key = ByteArray(32).also { SecureRandom().nextBytes(it) }
    private val address = RecordAddress("vault-a", "record-a", "test", 1, 1)
    @Test fun roundTripUsesCiphertextAndDistinctNonces() {
        val one = crypto.encrypt(key, address, "secret".encodeToByteArray())
        val two = crypto.encrypt(key, address, "secret".encodeToByteArray())
        assertArrayEquals("secret".encodeToByteArray(), crypto.decrypt(key, address, one))
        assertFalse(one.nonce.contentEquals(two.nonce)); assertFalse(one.wrappedDekNonce.contentEquals(two.wrappedDekNonce))
        assertFalse(one.ciphertext.contentEquals("secret".encodeToByteArray()))
    }
    @Test(expected = VaultDecryptionException::class) fun alteredCiphertextFailsClosed() {
        val value = crypto.encrypt(key, address, "secret".encodeToByteArray())
        value.ciphertext[0] = (value.ciphertext[0].toInt() xor 1).toByte(); crypto.decrypt(key, address, value)
    }
    @Test(expected = VaultDecryptionException::class) fun alteredAssociatedDataFailsClosed() {
        val value = crypto.encrypt(key, address, "secret".encodeToByteArray())
        crypto.decrypt(key, address.copy(revision = 2), value)
    }
    @Test(expected = VaultDecryptionException::class) fun alteredWrappedDekFailsClosed() {
        val value = crypto.encrypt(key, address, "secret".encodeToByteArray())
        value.wrappedDek[0] = (value.wrappedDek[0].toInt() xor 1).toByte(); crypto.decrypt(key, address, value)
    }
    @Test(expected = VaultDecryptionException::class) fun malformedNonceFailsClosed() {
        val value = crypto.encrypt(key, address, "secret".encodeToByteArray())
        crypto.decrypt(key, address, value.copy(nonce = byteArrayOf(1)))
    }
}

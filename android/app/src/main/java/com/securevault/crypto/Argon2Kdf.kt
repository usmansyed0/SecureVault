package com.securevault.crypto

import org.bouncycastle.crypto.generators.Argon2BytesGenerator
import org.bouncycastle.crypto.params.Argon2Parameters
import java.security.SecureRandom
import javax.inject.Inject
import javax.inject.Singleton

@Singleton
class Argon2Kdf @Inject constructor() {
    private val random = SecureRandom()

    fun generateSalt(lengthBytes: Int = 16): ByteArray {
        val salt = ByteArray(lengthBytes)
        random.nextBytes(salt)
        return salt
    }

    /**
     * Derives a 32-byte (256-bit) cryptographic key using Argon2id.
     * Default parameters: 3 iterations, 32MB memory, parallelism 2 for mobile balance of speed and resistance.
     */
    fun deriveKey(
        secretChars: CharArray,
        salt: ByteArray,
        iterations: Int = 3,
        memoryKb: Int = 65536,
        parallelism: Int = 2,
        outputLengthBytes: Int = 32
    ): ByteArray {
        val secretBytes = secretChars.map { it.code.toByte() }.toByteArray()
        try {
            val builder = Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
                .withVersion(Argon2Parameters.ARGON2_VERSION_13)
                .withIterations(iterations)
                .withMemoryAsKB(memoryKb)
                .withParallelism(parallelism)
                .withSalt(salt)

            val generator = Argon2BytesGenerator()
            generator.init(builder.build())

            val result = ByteArray(outputLengthBytes)
            generator.generateBytes(secretBytes, result, 0, result.size)
            return result
        } finally {
            secretBytes.fill(0)
        }
    }

    fun deriveKey(
        secret: String,
        salt: ByteArray,
        iterations: Int = 3,
        memoryKb: Int = 65536,
        parallelism: Int = 2,
        outputLengthBytes: Int = 32
    ): ByteArray = deriveKey(secret.toCharArray(), salt, iterations, memoryKb, parallelism, outputLengthBytes)
}

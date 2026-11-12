package com.securevault.util

/**
 * Memory-safety utilities for zeroing sensitive material after use.
 *
 * Kotlin/JVM does not guarantee that String contents are ever wiped from the
 * heap, so all secret values (PINs, master passwords, derived keys) should be
 * handled as CharArray or ByteArray and zeroed via these helpers as soon as
 * they are no longer needed.
 */
object SecureBuffer {

    /** Overwrite every element of a ByteArray with 0x00. */
    fun wipe(buf: ByteArray?) {
        buf?.fill(0x00)
    }

    /** Overwrite every element of a CharArray with the null character. */
    fun wipe(buf: CharArray?) {
        buf?.fill('\u0000')
    }

    /**
     * Execute [block] with the receiver ByteArray, then immediately zero it.
     *
     * Usage:
     * ```
     * myByteArray.useAndWipe { bytes ->
     *     // use bytes here
     * }
     * // bytes are now zeroed
     * ```
     */
    inline fun ByteArray.useAndWipe(block: (ByteArray) -> Unit) {
        try {
            block(this)
        } finally {
            wipe(this)
        }
    }

    /**
     * Execute [block] with the receiver CharArray, then immediately zero it.
     */
    inline fun CharArray.useAndWipe(block: (CharArray) -> Unit) {
        try {
            block(this)
        } finally {
            wipe(this)
        }
    }

    /**
     * Convert a String to a CharArray, execute [block], then zero the array.
     *
     * The original String still exists in the JVM String pool, but at least
     * the working copy is cleared from heap after use.
     */
    inline fun String.asCharArrayAndWipe(block: (CharArray) -> Unit) {
        val chars = this.toCharArray()
        try {
            block(chars)
        } finally {
            wipe(chars)
        }
    }
}

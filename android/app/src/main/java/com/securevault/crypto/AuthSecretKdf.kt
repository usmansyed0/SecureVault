package com.securevault.crypto

import android.util.Base64
import org.bouncycastle.crypto.digests.SHA256Digest
import org.bouncycastle.crypto.generators.HKDFBytesGenerator
import org.bouncycastle.crypto.params.HKDFParameters

object AuthSecretKdf {
    fun derive(vrk: ByteArray): String {
        val generator = HKDFBytesGenerator(SHA256Digest())
        val params = HKDFParameters(vrk, null, "securevault.server-auth.v1".toByteArray())
        generator.init(params)
        val result = ByteArray(32)
        generator.generateBytes(result, 0, 32)
        return Base64.encodeToString(result, Base64.NO_WRAP)
    }
}

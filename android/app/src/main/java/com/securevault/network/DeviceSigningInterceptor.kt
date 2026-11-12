package com.securevault.network

import com.securevault.security.DeviceSigner
import com.securevault.security.SecureSessionStore
import okhttp3.Interceptor
import okhttp3.Response
import okio.Buffer
import java.security.MessageDigest
import java.util.Base64

/**
 * Intercepts sensitive requests (/v1/auth/refresh, /v1/vault/changes) and signs them
 * using the hardware-backed EC P-256 device key.
 *
 * Headers added:
 * - X-Device-Id: <uuid>
 * - X-Timestamp: <unix_epoch_ms>
 * - X-Device-Signature: base64(ECDSA.sign(device_id + ":" + timestamp + ":" + body_sha256))
 */
class DeviceSigningInterceptor(
    private val signer: DeviceSigner,
    private val deviceIdProvider: () -> String?
) : Interceptor {

    constructor(
        signer: DeviceSigner,
        sessionStore: SecureSessionStore
    ) : this(signer, { sessionStore.deviceId() })

    override fun intercept(chain: Interceptor.Chain): Response {
        val request = chain.request()
        val path = request.url.encodedPath

        val isTarget = path.endsWith("/auth/refresh") || path.contains("/vault/changes")
        if (!isTarget) {
            return chain.proceed(request)
        }

        val deviceId = deviceIdProvider() ?: return chain.proceed(request)
        if (!signer.exists()) {
            signer.createIfMissing()
        }

        val timestamp = System.currentTimeMillis().toString()

        val reqBody = request.body
        val bodyBytes = if (reqBody != null) {
            val buffer = Buffer()
            reqBody.writeTo(buffer)
            buffer.readByteArray()
        } else {
            ByteArray(0)
        }

        val sha256 = MessageDigest.getInstance("SHA-256").digest(bodyBytes)
        val bodySha256 = sha256.joinToString("") { "%02x".format(it) }

        val message = "$deviceId:$timestamp:$bodySha256".toByteArray(Charsets.UTF_8)
        val signature = try {
            signer.sign(message)
        } catch (_: Exception) {
            return chain.proceed(request)
        }
        val sigB64 = Base64.getEncoder().encodeToString(signature)

        val newRequest = request.newBuilder()
            .header("X-Device-Id", deviceId)
            .header("X-Timestamp", timestamp)
            .header("X-Device-Signature", sigB64)
            .build()

        return chain.proceed(newRequest)
    }
}

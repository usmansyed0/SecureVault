package com.securevault.network

import com.securevault.security.DeviceSigner
import okhttp3.*
import okhttp3.RequestBody.Companion.toRequestBody
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import java.security.Signature
import java.util.concurrent.TimeUnit

class DeviceSigningInterceptorTest {

    private lateinit var signer: TestSigner
    private lateinit var interceptor: DeviceSigningInterceptor

    private class TestSigner : DeviceSigner {
        var signCallCount = 0
        var lastSignedMessage: ByteArray? = null

        override fun createIfMissing() {}
        override fun publicKeyDer(): ByteArray = byteArrayOf(1, 2, 3)
        override fun publicKeyBase64(): String = "test-pubkey"
        override fun exists(): Boolean = true
        override fun signatureForAuthentication(): Signature = throw UnsupportedOperationException()
        override fun signAuthenticated(signature: Signature, message: ByteArray): ByteArray = byteArrayOf()
        override fun sign(message: ByteArray): ByteArray {
            signCallCount++
            lastSignedMessage = message
            return "mock-signature-bytes".toByteArray()
        }
        override fun delete() {}
    }

    @Before
    fun setUp() {
        signer = TestSigner()
        interceptor = DeviceSigningInterceptor(signer) { "device-uuid-1234" }
    }

    private class FakeChain(private val currentRequest: Request) : Interceptor.Chain {
        var interceptedRequest: Request? = null

        override fun request(): Request = currentRequest
        override fun proceed(request: Request): Response {
            interceptedRequest = request
            return Response.Builder()
                .request(request)
                .protocol(Protocol.HTTP_1_1)
                .code(200)
                .message("OK")
                .build()
        }

        override fun call(): Call = throw UnsupportedOperationException()
        override fun connectTimeoutMillis(): Int = 5000
        override fun connection(): Connection? = null
        override fun readTimeoutMillis(): Int = 15000
        override fun withConnectTimeout(timeout: Int, unit: TimeUnit): Interceptor.Chain = this
        override fun withReadTimeout(timeout: Int, unit: TimeUnit): Interceptor.Chain = this
        override fun withWriteTimeout(timeout: Int, unit: TimeUnit): Interceptor.Chain = this
        override fun writeTimeoutMillis(): Int = 15000
    }

    @Test
    fun refreshEndpointIncludesDeviceSigningHeaders() {
        val request = Request.Builder()
            .url("https://example.test/v1/auth/refresh")
            .post("{\"refresh_token\":\"sample_token\"}".toRequestBody())
            .build()

        val chain = FakeChain(request)
        interceptor.intercept(chain)

        val processed = chain.interceptedRequest
        assertNotNull(processed)
        assertEquals("device-uuid-1234", processed!!.header("X-Device-Id"))
        assertNotNull(processed.header("X-Timestamp"))
        assertNotNull(processed.header("X-Device-Signature"))

        assertEquals(1, signer.signCallCount)
        assertNotNull(signer.lastSignedMessage)
        val msgStr = signer.lastSignedMessage!!.decodeToString()
        assertTrue(msgStr.startsWith("device-uuid-1234:"))
    }

    @Test
    fun vaultChangesEndpointIncludesDeviceSigningHeaders() {
        val request = Request.Builder()
            .url("https://example.test/v1/vault/changes?since_seq=0")
            .get()
            .build()

        val chain = FakeChain(request)
        interceptor.intercept(chain)

        val processed = chain.interceptedRequest
        assertNotNull(processed)
        assertEquals("device-uuid-1234", processed!!.header("X-Device-Id"))
        assertNotNull(processed.header("X-Timestamp"))
        assertNotNull(processed.header("X-Device-Signature"))

        assertEquals(1, signer.signCallCount)
    }

    @Test
    fun nonSensitiveEndpointDoesNotIncludeDeviceSigningHeaders() {
        val request = Request.Builder()
            .url("https://example.test/v1/devices")
            .get()
            .build()

        val chain = FakeChain(request)
        interceptor.intercept(chain)

        val processed = chain.interceptedRequest
        assertNotNull(processed)
        assertNull(processed!!.header("X-Device-Id"))
        assertNull(processed.header("X-Timestamp"))
        assertNull(processed.header("X-Device-Signature"))

        assertEquals(0, signer.signCallCount)
    }
}

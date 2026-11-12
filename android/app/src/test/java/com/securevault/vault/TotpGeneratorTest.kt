package com.securevault.vault

import com.securevault.vault.totp.TotpGenerator
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Test

class TotpGeneratorTest {

    // RFC 6238 Section B test vector secret: "12345678901234567890"
    // In Base32: GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ
    private val rfcSecret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"

    @Test
    fun generateCode_rfc6238TestVectors() {
        // T0 = 59s -> count = 1
        val code1 = TotpGenerator.generateCode(rfcSecret, epochSeconds = 59L)
        assertNotNull(code1)
        assertEquals("287082", code1!!.code)

        // T1 = 1111111109s
        val code2 = TotpGenerator.generateCode(rfcSecret, epochSeconds = 1111111109L)
        assertNotNull(code2)
        assertEquals("081804", code2!!.code)

        // T2 = 1111111111s
        val code3 = TotpGenerator.generateCode(rfcSecret, epochSeconds = 1111111111L)
        assertNotNull(code3)
        assertEquals("050471", code3!!.code)

        // T3 = 1234567890s
        val code4 = TotpGenerator.generateCode(rfcSecret, epochSeconds = 1234567890L)
        assertNotNull(code4)
        assertEquals("005924", code4!!.code)

        // T4 = 2000000000s
        val code5 = TotpGenerator.generateCode(rfcSecret, epochSeconds = 2000000000L)
        assertNotNull(code5)
        assertEquals("279037", code5!!.code)
    }

    @Test
    fun parseOtpAuthUri_extractsSecretCorrectly() {
        val uri = "otpauth://totp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&issuer=Example"
        val secret = TotpGenerator.parseOtpAuthUri(uri)
        assertEquals("JBSWY3DPEHPK3PXP", secret)
    }

    @Test
    fun generateCode_handlesSpacesAndHyphens() {
        val formattedSecret = "GEZD-GNBV GY3T-QOJQ GEZD-GNBV GY3T-QOJQ"
        val code = TotpGenerator.generateCode(formattedSecret, epochSeconds = 59L)
        assertNotNull(code)
        assertEquals("287082", code!!.code)
    }

    @Test
    fun generateCode_invalidSecretReturnsNull() {
        val invalid = "111999!!!"
        val code = TotpGenerator.generateCode(invalid)
        assertNull(code)
    }
}

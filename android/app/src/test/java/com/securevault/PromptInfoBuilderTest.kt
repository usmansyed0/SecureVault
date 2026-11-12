package com.securevault

import android.text.TextUtils
import androidx.biometric.BiometricManager
import org.junit.Assert.*
import org.junit.Test
import org.mockito.Mockito.*

class PromptInfoBuilderTest {

    @Test
    fun buildPromptInfoWithValidNegativeButtonTextSucceeds() {
        mockStatic(TextUtils::class.java).use { mocked ->
            mocked.`when`<Boolean> { TextUtils.isEmpty(any()) }.thenAnswer { invocation ->
                val cs = invocation.getArgument<CharSequence?>(0)
                cs == null || cs.isEmpty()
            }

            val promptInfo = MainActivity.buildPromptInfo(
                title = "Unlock SecureVault",
                negativeButtonText = "Cancel"
            )
            assertEquals("Unlock SecureVault", promptInfo.title)
            assertEquals("Cancel", promptInfo.negativeButtonText)
            assertEquals(BiometricManager.Authenticators.BIOMETRIC_STRONG, promptInfo.allowedAuthenticators)
        }
    }

    @Test
    fun buildPromptInfoWithSubtitleSucceeds() {
        mockStatic(TextUtils::class.java).use { mocked ->
            mocked.`when`<Boolean> { TextUtils.isEmpty(any()) }.thenAnswer { invocation ->
                val cs = invocation.getArgument<CharSequence?>(0)
                cs == null || cs.isEmpty()
            }

            val promptInfo = MainActivity.buildPromptInfo(
                title = "Step-Up Authentication",
                subtitle = "Confirm action: device_revoke",
                negativeButtonText = "Cancel"
            )
            assertEquals("Step-Up Authentication", promptInfo.title)
            assertEquals("Confirm action: device_revoke", promptInfo.subtitle)
            assertEquals("Cancel", promptInfo.negativeButtonText)
            assertEquals(BiometricManager.Authenticators.BIOMETRIC_STRONG, promptInfo.allowedAuthenticators)
        }
    }

    @Test
    fun buildPromptInfoRejectsBlankNegativeButtonText() {
        assertThrows(IllegalArgumentException::class.java) {
            MainActivity.buildPromptInfo(
                title = "Unlock SecureVault",
                negativeButtonText = ""
            )
        }
        assertThrows(IllegalArgumentException::class.java) {
            MainActivity.buildPromptInfo(
                title = "Unlock SecureVault",
                negativeButtonText = "   "
            )
        }
    }
}

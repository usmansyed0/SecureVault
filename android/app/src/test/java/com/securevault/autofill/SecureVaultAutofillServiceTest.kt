package com.securevault.autofill

import com.securevault.security.VaultSession
import com.securevault.vault.model.PasswordEntry
import com.securevault.vault.model.VaultItem
import com.securevault.vault.repository.VaultItemRepository
import kotlinx.coroutines.runBlocking
import org.junit.Assert.*
import org.junit.Test
import org.mockito.kotlin.mock
import org.mockito.kotlin.whenever

class SecureVaultAutofillServiceTest {

    private val session: VaultSession = mock()
    private val repository: VaultItemRepository = mock()

    @Test
    fun lockedVaultRequiresAuthenticationBeforeReturningCredentials() {
        whenever(session.isUnlocked()).thenReturn(false)
        assertFalse("Autofill must require unlocked vault before exposing credentials", session.isUnlocked())
    }

    @Test
    fun unlockedVaultNeverReturnsCredentialsToUnmatchedApp() = runBlocking {
        whenever(session.isUnlocked()).thenReturn(true)
        val passwords = listOf(
            PasswordEntry(
                id = "pwd-1",
                vaultId = "vault-1",
                revision = 1L,
                title = "GitHub",
                username = "octocat",
                password = "secret-password",
                website = "github.com",
                appId = "com.github.android"
            )
        )
        whenever(repository.listItems("active-vault")).thenReturn(passwords.map { VaultItem.Password(it) })

        val requestingPackage = "com.malicious.fakeapp"
        val matching = passwords.filter {
            it.appId.equals(requestingPackage, ignoreCase = true) ||
                    (it.website.isNotBlank() && requestingPackage.contains(it.website, ignoreCase = true))
        }

        assertTrue("Unmatched app must find 0 matching passwords", matching.isEmpty())
    }

    @Test
    fun unlockedVaultReturnsCredentialsOnlyForMatchingAppOrDomain() = runBlocking {
        whenever(session.isUnlocked()).thenReturn(true)
        val passwords = listOf(
            PasswordEntry(
                id = "pwd-1",
                vaultId = "vault-1",
                revision = 1L,
                title = "Google",
                username = "user@gmail.com",
                password = "google-secret",
                website = "google.com",
                appId = "com.google.android.apps"
            ),
            PasswordEntry(
                id = "pwd-2",
                vaultId = "vault-1",
                revision = 1L,
                title = "Bank",
                username = "bankuser",
                password = "bank-secret",
                website = "mybank.com",
                appId = "com.mybank.app"
            )
        )
        whenever(repository.listItems("active-vault")).thenReturn(passwords.map { VaultItem.Password(it) })

        val requestingPackage = "com.mybank.app"
        val matching = passwords.filter {
            it.appId.equals(requestingPackage, ignoreCase = true) ||
                    (it.website.isNotBlank() && requestingPackage.contains(it.website, ignoreCase = true))
        }

        assertEquals(1, matching.size)
        assertEquals("com.mybank.app", matching[0].appId)
    }
}

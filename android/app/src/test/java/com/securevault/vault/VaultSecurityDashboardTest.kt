package com.securevault.vault

import com.securevault.vault.model.PasswordEntry
import com.securevault.vault.security.VaultSecurityDashboard
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class VaultSecurityDashboardTest {

    private val vaultId = "test-vault"

    @Test
    fun analyzePasswords_emptyList_returnsPerfectScore() {
        val report = VaultSecurityDashboard.analyzePasswords(emptyList())
        assertEquals(0, report.totalPasswords)
        assertEquals(100, report.overallScorePercent)
        assertTrue(report.weakItems.isEmpty())
        assertTrue(report.reusedGroups.isEmpty())
    }

    @Test
    fun analyzePasswords_identifiesWeakReusedAndOldPasswords() {
        val now = System.currentTimeMillis()
        val oneHundredDaysAgo = now - (100L * 24 * 3600 * 1000)

        // Weak password (<12 chars)
        val p1 = PasswordEntry(
            id = "p-1",
            vaultId = vaultId,
            title = "Site 1",
            username = "user1",
            password = "short",
            updatedAtEpochMs = now
        )

        // Strong password, but reused
        val p2 = PasswordEntry(
            id = "p-2",
            vaultId = vaultId,
            title = "Site 2",
            username = "user2",
            password = "CorrectHorseBatteryStaple!2026",
            updatedAtEpochMs = now
        )

        // Same password as p2 (reuse) + old (>90 days)
        val p3 = PasswordEntry(
            id = "p-3",
            vaultId = vaultId,
            title = "Site 3",
            username = "user3",
            password = "CorrectHorseBatteryStaple!2026",
            updatedAtEpochMs = oneHundredDaysAgo
        )

        // Strong, unique, fresh password
        val p4 = PasswordEntry(
            id = "p-4",
            vaultId = vaultId,
            title = "Site 4",
            username = "user4",
            password = "Unique&UltraSecurePassword#987",
            updatedAtEpochMs = now
        )

        val report = VaultSecurityDashboard.analyzePasswords(listOf(p1, p2, p3, p4))

        assertEquals(4, report.totalPasswords)
        assertEquals(1, report.weakItems.size)
        assertEquals("p-1", report.weakItems[0].id)

        assertEquals(1, report.reusedGroups.size)
        assertEquals(2, report.reusedGroups["CorrectHorseBatteryStaple!2026"]?.size)

        assertEquals(1, report.oldItems.size)
        assertEquals("p-3", report.oldItems[0].id)

        // Score should reflect penalties
        assertTrue(report.overallScorePercent < 100)
        assertTrue(report.overallScorePercent > 0)
    }
}

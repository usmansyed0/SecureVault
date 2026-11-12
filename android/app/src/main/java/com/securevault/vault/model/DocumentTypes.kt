package com.securevault.vault.model

/**
 * Standard document types with metadata and icons for the SecureVault Document Wallet.
 * Tailored for high-frequency offline document access (Passports, Driving Licences,
 * Aadhaar Cards, PAN Cards, Insurance Policies, and Vehicle Papers).
 */
object DocumentTypes {
    const val PASSPORT = "Passport"
    const val DRIVING_LICENCE = "Driving Licence"
    const val AADHAAR_CARD = "Aadhaar Card"
    const val PAN_CARD = "PAN Card"
    const val INSURANCE_POLICY = "Insurance Policy"
    const val VEHICLE_PAPERS = "Vehicle Registration"
    const val EMERGENCY_CARD = "Emergency Card"
    const val GENERAL = "General Document"

    val ALL = listOf(
        PASSPORT,
        DRIVING_LICENCE,
        AADHAAR_CARD,
        PAN_CARD,
        INSURANCE_POLICY,
        VEHICLE_PAPERS,
        EMERGENCY_CARD,
        GENERAL
    )

    /**
     * Checks if a document is expired or expiring within [thresholdDays] (default: 30 days).
     */
    fun checkExpiryStatus(expiryDateEpochMs: Long?, thresholdDays: Int = 30): ExpiryStatus {
        if (expiryDateEpochMs == null || expiryDateEpochMs == 0L) return ExpiryStatus.NO_EXPIRY
        val now = System.currentTimeMillis()
        val diffMs = expiryDateEpochMs - now
        val diffDays = diffMs / (24 * 3600 * 1000)

        return when {
            diffMs < 0 -> ExpiryStatus.EXPIRED
            diffDays <= thresholdDays -> ExpiryStatus.EXPIRING_SOON(diffDays.toInt())
            else -> ExpiryStatus.VALID(diffDays.toInt())
        }
    }
}

sealed class ExpiryStatus {
    object NO_EXPIRY : ExpiryStatus()
    object EXPIRED : ExpiryStatus()
    data class EXPIRING_SOON(val daysRemaining: Int) : ExpiryStatus()
    data class VALID(val daysRemaining: Int) : ExpiryStatus()
}

package com.securevault.security

import android.util.Log

object SafeSecurityLogger {
    private const val TAG = "SecureVault"
    /** Event names and opaque IDs only. Callers must never pass request bodies, errors or secrets. */
    fun event(name: String, opaqueId: String? = null) { require(name.matches(Regex("[a-z_.]{1,64}"))); Log.i(TAG, if (opaqueId == null) name else "$name id=$opaqueId") }
}

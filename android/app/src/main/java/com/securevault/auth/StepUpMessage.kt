package com.securevault.auth

/** Must exactly match the backend canonical signature payload. No vault data is included. */
fun stepUpMessage(challengeId: String, action: String, userId: String, deviceId: String, sessionId: String, challenge: String): ByteArray =
    "securevault.step-up.v1|$challengeId|$action|$userId|$deviceId|$sessionId|$challenge".encodeToByteArray()

package com.securevault.auth

import com.securevault.network.SecureVaultApi
import com.securevault.network.model.StepUpChallengeRequestDto
import com.securevault.network.model.StepUpChallengeResponseDto
import com.securevault.network.model.StepUpCompleteRequestDto
import com.securevault.security.DeviceSigner
import java.security.Signature
import java.util.Base64
import javax.inject.Inject
import javax.inject.Singleton

@Singleton
class StepUpCoordinator @Inject constructor(
    private val api: SecureVaultApi,
    private val deviceSigningKey: DeviceSigner,
    private val sessionCoordinator: SessionCoordinator
) {
    fun prepareSignature(): Signature {
        deviceSigningKey.createIfMissing()
        return deviceSigningKey.signatureForAuthentication()
    }

    suspend fun requestChallenge(action: String): StepUpChallengeResponseDto {
        return api.requestStepUpChallenge(StepUpChallengeRequestDto(action))
    }

    fun buildCanonicalMessage(challengeId: String, action: String, challenge: String): ByteArray {
        val uId = sessionCoordinator.userId ?: throw IllegalStateException("Active user context required")
        val dId = sessionCoordinator.deviceId ?: throw IllegalStateException("Active device context required")
        val sId = sessionCoordinator.sessionId ?: throw IllegalStateException("Active session context required")
        return stepUpMessage(challengeId, action, uId, dId, sId, challenge)
    }

    fun signMessage(authenticatedSignature: Signature, message: ByteArray): String {
        val signatureBytes = deviceSigningKey.signAuthenticated(authenticatedSignature, message)
        return Base64.getEncoder().encodeToString(signatureBytes)
    }

    suspend fun complete(challengeId: String, challenge: String, signatureBase64: String, authSecret: String): String {
        val result = api.completeStepUp(
            StepUpCompleteRequestDto(
                challenge_id = challengeId,
                challenge = challenge,
                signature = signatureBase64,
                auth_secret = authSecret
            )
        )
        return result.step_up_grant
    }

    /**
     * Completes a full cryptographic step-up exchange using an authenticated BiometricPrompt Signature.
     */
    suspend fun executeStepUp(action: String, authSecret: String, authenticatedSignature: Signature): String {
        val challenge = requestChallenge(action)
        val message = buildCanonicalMessage(challenge.challenge_id, action, challenge.challenge)
        val signatureBase64 = signMessage(authenticatedSignature, message)
        return complete(challenge.challenge_id, challenge.challenge, signatureBase64, authSecret)
    }
}

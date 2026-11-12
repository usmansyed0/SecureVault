package com.securevault.util

/**
 * Strongly-typed application errors.
 *
 * Ensures no raw exception messages, tokens, or cryptographic internals
 * are displayed in the UI or leaked to logs.
 */
sealed class AppError(open val userMessage: String) {
    data class NetworkError(
        override val userMessage: String = "Cannot connect to server. Please verify your network connection."
    ) : AppError(userMessage)

    data class AuthenticationError(
        override val userMessage: String = "Authentication failed. Please verify your credentials."
    ) : AppError(userMessage)

    data class DeviceRevokedError(
        override val userMessage: String = "This device has been revoked or marked stolen. Local vault has been wiped."
    ) : AppError(userMessage)

    data class VaultLockedError(
        override val userMessage: String = "Vault is locked. Unlock required."
    ) : AppError(userMessage)

    data class CryptoError(
        override val userMessage: String = "Cryptographic operation failed."
    ) : AppError(userMessage)

    data class ValidationError(
        override val userMessage: String
    ) : AppError(userMessage)

    data class ServerError(
        val code: Int,
        override val userMessage: String = "Server error ($code). Please try again later."
    ) : AppError(userMessage)

    data class UnexpectedError(
        override val userMessage: String = "An unexpected error occurred. Please try again."
    ) : AppError(userMessage)

    companion object {
        fun fromThrowable(t: Throwable, defaultMessage: String? = null): AppError {
            android.util.Log.e("SecureVault", "AppError mapped from: ${t.javaClass.simpleName}")
            return when (t) {
                is java.net.ConnectException,
                is java.net.SocketTimeoutException,
                is java.net.UnknownHostException -> NetworkError()
                is retrofit2.HttpException -> {
                    when (t.code()) {
                        400 -> ValidationError("Invalid request. Please check your input.")
                        401 -> AuthenticationError("Invalid credentials or session expired.")
                        403 -> {
                            val body = try { t.response()?.errorBody()?.string() } catch (_: Exception) { null }
                            if (body?.contains("device_stolen") == true || body?.contains("device_revoked") == true) {
                                DeviceRevokedError()
                            } else {
                                AuthenticationError("Access denied.")
                            }
                        }
                        404 -> ValidationError("Requested resource was not found.")
                        409 -> ValidationError("An account with this email already exists.")
                        422 -> ValidationError("Validation failed. Please verify the format and requirements.")
                        else -> ServerError(t.code())
                    }
                }
                is IllegalStateException -> ValidationError(defaultMessage ?: t.message ?: "Invalid state.")
                else -> if (defaultMessage != null) ValidationError(defaultMessage) else UnexpectedError()
            }
        }
    }
}

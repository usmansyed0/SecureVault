package com.securevault.ui.viewmodels

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.securevault.auth.SessionCoordinator
import com.securevault.network.SecureVaultApi
import com.securevault.network.model.DeviceDto
import com.securevault.network.model.StepUpGrantRequestDto
import com.securevault.util.AppError
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import javax.inject.Inject

data class DevicesUiState(
    val devices: List<DeviceDto> = emptyList(),
    val isLoading: Boolean = false,
    val errorMessage: String? = null,
    val successMessage: String? = null
)

@HiltViewModel
class DevicesViewModel @Inject constructor(
    private val api: SecureVaultApi,
    private val session: SessionCoordinator
) : ViewModel() {

    private val _uiState = MutableStateFlow(DevicesUiState())
    val uiState: StateFlow<DevicesUiState> = _uiState.asStateFlow()

    fun refreshDevices() {
        viewModelScope.launch {
            _uiState.value = _uiState.value.copy(isLoading = true, errorMessage = null)
            try {
                val devices = api.listDevices()
                session.inspectDeviceList(devices)
                _uiState.value = _uiState.value.copy(
                    devices = devices,
                    isLoading = false
                )
            } catch (t: Throwable) {
                val err = AppError.fromThrowable(t, "Failed to load enrolled devices")
                _uiState.value = _uiState.value.copy(
                    isLoading = false,
                    errorMessage = err.userMessage
                )
            }
        }
    }

    fun revokeDevice(deviceId: String, grant: String, onSuccess: () -> Unit = {}) {
        viewModelScope.launch {
            _uiState.value = _uiState.value.copy(isLoading = true, errorMessage = null)
            try {
                val res = api.revokeDevice(deviceId, StepUpGrantRequestDto(grant))
                if (res.isSuccessful) {
                    refreshDevices()
                    _uiState.value = _uiState.value.copy(successMessage = "Device revoked successfully.")
                    onSuccess()
                } else {
                    _uiState.value = _uiState.value.copy(
                        isLoading = false,
                        errorMessage = "Server rejected revocation request (${res.code()})."
                    )
                }
            } catch (t: Throwable) {
                val err = AppError.fromThrowable(t, "Failed to revoke device")
                _uiState.value = _uiState.value.copy(
                    isLoading = false,
                    errorMessage = err.userMessage
                )
            }
        }
    }

    fun markDeviceStolen(deviceId: String, grant: String, onSuccess: () -> Unit = {}) {
        viewModelScope.launch {
            _uiState.value = _uiState.value.copy(isLoading = true, errorMessage = null)
            try {
                val res = api.markDeviceStolen(deviceId, StepUpGrantRequestDto(grant))
                if (res.isSuccessful) {
                    refreshDevices()
                    _uiState.value = _uiState.value.copy(successMessage = "Device reported stolen. Remote wipe signal dispatched.")
                    onSuccess()
                } else {
                    _uiState.value = _uiState.value.copy(
                        isLoading = false,
                        errorMessage = "Server rejected report stolen request (${res.code()})."
                    )
                }
            } catch (t: Throwable) {
                val err = AppError.fromThrowable(t, "Failed to mark device stolen")
                _uiState.value = _uiState.value.copy(
                    isLoading = false,
                    errorMessage = err.userMessage
                )
            }
        }
    }

    fun endDeviceSessions(deviceId: String, grant: String, onSuccess: () -> Unit = {}) {
        viewModelScope.launch {
            _uiState.value = _uiState.value.copy(isLoading = true, errorMessage = null)
            try {
                val res = api.endDeviceSessions(deviceId, StepUpGrantRequestDto(grant))
                if (res.isSuccessful) {
                    refreshDevices()
                    _uiState.value = _uiState.value.copy(successMessage = "Device sessions terminated.")
                    onSuccess()
                } else {
                    _uiState.value = _uiState.value.copy(
                        isLoading = false,
                        errorMessage = "Server rejected session termination (${res.code()})."
                    )
                }
            } catch (t: Throwable) {
                val err = AppError.fromThrowable(t, "Failed to terminate device sessions")
                _uiState.value = _uiState.value.copy(
                    isLoading = false,
                    errorMessage = err.userMessage
                )
            }
        }
    }

    fun signOutOtherDevices(grant: String, onSuccess: () -> Unit = {}) {
        viewModelScope.launch {
            _uiState.value = _uiState.value.copy(isLoading = true, errorMessage = null)
            try {
                val res = api.signOutOtherDevices(StepUpGrantRequestDto(grant))
                if (res.isSuccessful) {
                    refreshDevices()
                    _uiState.value = _uiState.value.copy(successMessage = "All other devices signed out.")
                    onSuccess()
                } else {
                    _uiState.value = _uiState.value.copy(
                        isLoading = false,
                        errorMessage = "Server rejected sign out request (${res.code()})."
                    )
                }
            } catch (t: Throwable) {
                val err = AppError.fromThrowable(t, "Failed to sign out other devices")
                _uiState.value = _uiState.value.copy(
                    isLoading = false,
                    errorMessage = err.userMessage
                )
            }
        }
    }

    fun clearMessages() {
        _uiState.value = _uiState.value.copy(errorMessage = null, successMessage = null)
    }
}

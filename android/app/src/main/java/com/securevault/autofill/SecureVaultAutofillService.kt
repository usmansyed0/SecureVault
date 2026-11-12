package com.securevault.autofill

import android.app.PendingIntent
import android.app.assist.AssistStructure
import android.content.Intent
import android.os.Build
import android.os.CancellationSignal
import android.service.autofill.AutofillService
import android.service.autofill.Dataset
import android.service.autofill.FillCallback
import android.service.autofill.FillContext
import android.service.autofill.FillRequest
import android.service.autofill.FillResponse
import android.view.autofill.AutofillId
import android.view.autofill.AutofillValue
import android.widget.RemoteViews
import androidx.annotation.RequiresApi
import com.securevault.MainActivity
import com.securevault.R
import com.securevault.security.VaultSession
import com.securevault.vault.model.PasswordEntry
import com.securevault.vault.repository.VaultItemRepository
import dagger.hilt.android.AndroidEntryPoint
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * Android AutofillService provider for SecureVault.
 *
 * Implements password autofill for apps and web browsers.
 * Enforces zero-knowledge security: credentials are never filled into forms
 * without explicit user authentication (Biometric or PIN unlock).
 */
@AndroidEntryPoint
class SecureVaultAutofillService : AutofillService() {

    @Inject lateinit var session: VaultSession
    @Inject lateinit var repository: VaultItemRepository

    private val serviceScope = CoroutineScope(Dispatchers.IO + SupervisorJob())

    override fun onFillRequest(
        request: FillRequest,
        cancellationSignal: android.os.CancellationSignal,
        callback: FillCallback
    ) {
        val structure = request.fillContexts.lastOrNull()?.structure ?: run {
            callback.onSuccess(null)
            return
        }

        val fields = AutofillFieldFinder.findFields(structure)
        if (fields.usernameId == null && fields.passwordId == null) {
            callback.onSuccess(null)
            return
        }

        // If vault is locked, present an "Unlock SecureVault" authentication dataset
        if (!session.isUnlocked()) {
            val response = buildUnlockPromptResponse(fields, structure.activityComponent.packageName)
            callback.onSuccess(response)
            return
        }

        // Vault is unlocked — query matching items in background
        serviceScope.launch {
            try {
                val packageName = structure.activityComponent.packageName
                val allItems = repository.listItems("active-vault")
                val passwords = allItems.mapNotNull { (it as? com.securevault.vault.model.VaultItem.Password)?.entry }

                val matching = passwords.filter {
                    it.appId.equals(packageName, ignoreCase = true) ||
                            (it.website.isNotBlank() && packageName.contains(it.website, ignoreCase = true))
                }

                if (matching.isEmpty()) {
                    callback.onSuccess(null)
                    return@launch
                }

                val fillResponse = buildDatasets(matching, fields)
                callback.onSuccess(fillResponse)
            } catch (e: Exception) {
                callback.onFailure("Autofill request could not be completed.")
            }
        }
    }

    private fun buildUnlockPromptResponse(fields: AutofillFields, packageName: String): FillResponse {
        val authIntent = Intent(this, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP
        }
        val pendingIntent = PendingIntent.getActivity(
            this,
            1001,
            authIntent,
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_CANCEL_CURRENT
        )

        val presentation = RemoteViews(packageName, android.R.layout.simple_list_item_1).apply {
            setTextViewText(android.R.id.text1, "🔒 Unlock SecureVault to Autofill")
        }

        val responseBuilder = FillResponse.Builder()
        if (fields.passwordId != null) {
            responseBuilder.setAuthentication(
                arrayOf(fields.passwordId),
                pendingIntent.intentSender,
                presentation
            )
        } else if (fields.usernameId != null) {
            responseBuilder.setAuthentication(
                arrayOf(fields.usernameId),
                pendingIntent.intentSender,
                presentation
            )
        }
        return responseBuilder.build()
    }

    private fun buildDatasets(items: List<PasswordEntry>, fields: AutofillFields): FillResponse {
        val responseBuilder = FillResponse.Builder()

        for (item in items) {
            val presentation = RemoteViews(packageName, android.R.layout.simple_list_item_2).apply {
                setTextViewText(android.R.id.text1, item.title)
                setTextViewText(android.R.id.text2, item.username)
            }

            val datasetBuilder = Dataset.Builder(presentation)
            if (fields.usernameId != null && item.username.isNotEmpty()) {
                datasetBuilder.setValue(fields.usernameId, AutofillValue.forText(item.username))
            }
            if (fields.passwordId != null && item.password.isNotEmpty()) {
                datasetBuilder.setValue(fields.passwordId, AutofillValue.forText(item.password))
            }
            responseBuilder.addDataset(datasetBuilder.build())
        }

        return responseBuilder.build()
    }

    override fun onSaveRequest(request: android.service.autofill.SaveRequest, callback: android.service.autofill.SaveCallback) {
        callback.onSuccess()
    }
}

data class AutofillFields(
    val usernameId: AutofillId? = null,
    val passwordId: AutofillId? = null
)

object AutofillFieldFinder {
    fun findFields(structure: AssistStructure): AutofillFields {
        var usernameId: AutofillId? = null
        var passwordId: AutofillId? = null

        fun traverse(node: AssistStructure.ViewNode) {
            val hints = node.autofillHints
            val isPassword = hints?.any { it.contains("password", ignoreCase = true) } == true ||
                    node.hint?.contains("password", ignoreCase = true) == true ||
                    node.className?.contains("password", ignoreCase = true) == true

            val isUsername = hints?.any { it.contains("username", ignoreCase = true) || it.contains("email", ignoreCase = true) } == true ||
                    node.hint?.contains("username", ignoreCase = true) == true ||
                    node.hint?.contains("email", ignoreCase = true) == true

            if (isPassword && passwordId == null) {
                passwordId = node.autofillId
            } else if (isUsername && usernameId == null) {
                usernameId = node.autofillId
            }

            for (i in 0 until node.childCount) {
                traverse(node.getChildAt(i))
            }
        }

        for (i in 0 until structure.windowNodeCount) {
            traverse(structure.getWindowNodeAt(i).rootViewNode)
        }

        return AutofillFields(usernameId, passwordId)
    }
}

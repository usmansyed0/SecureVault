package com.securevault.vault.ui

import android.content.Context
import androidx.compose.runtime.State
import androidx.compose.runtime.mutableStateOf
import com.securevault.vault.SecureShareProvider
import com.securevault.network.SecureVaultApi
import com.securevault.network.model.CreateBackupRequestDto
import com.securevault.network.model.CreateShareRequestDto
import com.securevault.network.model.ShareSummaryDto
import com.securevault.network.model.SyncRecordUpsertDto
import com.securevault.security.VaultKeyManager
import com.securevault.security.VaultSession
import com.securevault.vault.clipboard.ClipboardController
import com.securevault.vault.document.DocumentBlobManager
import com.securevault.vault.generator.PasswordGenerator
import com.securevault.vault.model.*
import com.securevault.vault.repository.VaultItemRepository
import com.securevault.vault.strength.PasswordStrengthMeter
import kotlinx.coroutines.*
import java.security.SecureRandom
import java.util.Base64
import java.util.UUID
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import javax.inject.Inject
import javax.inject.Singleton

@Singleton
class VaultCoordinator(
    private val itemRepository: VaultItemRepository,
    private val keyManager: VaultKeyManager,
    private val session: VaultSession,
    val clipboard: ClipboardController,
    val generator: PasswordGenerator,
    val strengthMeter: PasswordStrengthMeter,
    val blobManager: DocumentBlobManager? = null,
    val api: SecureVaultApi? = null,
    dispatcher: CoroutineDispatcher = Dispatchers.Default
) {
    @Inject
    constructor(
        itemRepository: VaultItemRepository,
        keyManager: VaultKeyManager,
        session: VaultSession,
        clipboard: ClipboardController,
        generator: PasswordGenerator,
        strengthMeter: PasswordStrengthMeter,
        blobManager: DocumentBlobManager,
        api: SecureVaultApi
    ) : this(
        itemRepository,
        keyManager,
        session,
        clipboard,
        generator,
        strengthMeter,
        blobManager,
        api,
        Dispatchers.Default
    )

    private val scope = CoroutineScope(dispatcher + SupervisorJob())
    private val random = SecureRandom()

    var onLockDetected: (() -> Unit)? = null
    var onUserActivity: (() -> Unit)? = null

    private val _items = mutableStateOf<List<VaultItem>>(emptyList())
    val items: State<List<VaultItem>> = _items

    private val _searchQuery = mutableStateOf("")
    val searchQuery: State<String> = _searchQuery

    private val _selectedCategory = mutableStateOf("All")
    val selectedCategory: State<String> = _selectedCategory

    private val _revealedPasswordIds = mutableStateOf<Set<String>>(emptySet())
    val revealedPasswordIds: State<Set<String>> = _revealedPasswordIds

    private val _clipboardNotice = mutableStateOf<String?>(null)
    val clipboardNotice: State<String?> = _clipboardNotice

    private val _activeShares = mutableStateOf<List<ShareSummaryDto>>(emptyList())
    val activeShares: State<List<ShareSummaryDto>> = _activeShares

    private val _syncStatus = mutableStateOf("Ready")
    val syncStatus: State<String> = _syncStatus

    private val revealJobs = mutableMapOf<String, Job>()

    fun setSearchQuery(query: String) {
        _searchQuery.value = query
    }

    fun setSelectedCategory(category: String) {
        _selectedCategory.value = category
    }

    fun clearClipboardNotice() {
        _clipboardNotice.value = null
    }

    fun clearDecryptedState() {
        _items.value = emptyList()
        _revealedPasswordIds.value = emptySet()
        revealJobs.values.forEach { it.cancel() }
        revealJobs.clear()
        _searchQuery.value = ""
    }

    fun loadItems(onError: ((String) -> Unit)? = null) {
        val vaultId = keyManager.vaultId() ?: return
        if (!session.isUnlocked()) {
            clearDecryptedState()
            onLockDetected?.invoke()
            return
        }
        scope.launch {
            try {
                _items.value = itemRepository.listItems(vaultId)
            } catch (e: IllegalStateException) {
                if (!session.isUnlocked()) {
                    clearDecryptedState()
                    onLockDetected?.invoke()
                    onError?.invoke("Vault is locked")
                } else {
                    onError?.invoke("Error loading items")
                }
            } catch (_: Exception) {
                _items.value = emptyList()
            }
        }
    }

    fun filteredItems(): List<VaultItem> {
        val query = _searchQuery.value.trim().lowercase()
        val category = _selectedCategory.value

        return _items.value.filter { item ->
            val matchesCategory = when (category) {
                "All" -> true
                "Passwords" -> item is VaultItem.Password
                "Documents" -> item is VaultItem.Document
                "Notes" -> item is VaultItem.Note
                "Favorites" -> item.isFavorite
                else -> item.category.equals(category, ignoreCase = true)
            }

            val matchesQuery = if (query.isEmpty()) true else {
                item.title.lowercase().contains(query) ||
                        item.category.lowercase().contains(query) ||
                        when (item) {
                            is VaultItem.Password -> item.entry.username.lowercase().contains(query) || item.entry.website.lowercase().contains(query)
                            is VaultItem.Note -> item.note.content.lowercase().contains(query)
                            is VaultItem.Document -> item.entry.ocrText.lowercase().contains(query)
                        }
            }

            matchesCategory && matchesQuery
        }
    }

    fun passwordCount(): Int = _items.value.count { it is VaultItem.Password }
    fun documentCount(): Int = _items.value.count { it is VaultItem.Document }
    fun noteCount(): Int = _items.value.count { it is VaultItem.Note }

    fun touch() {
        onUserActivity?.invoke()
    }

    fun savePassword(
        existingId: String?,
        existingRevision: Long?,
        title: String,
        username: String,
        password: String,
        website: String,
        notes: String,
        category: String,
        isSensitive: Boolean,
        isFavorite: Boolean = false,
        iconUri: String = "",
        appId: String = "",
        onError: ((String) -> Unit)? = null,
        onComplete: () -> Unit
    ) {
        touch()
        val vaultId = keyManager.vaultId() ?: run {
            onError?.invoke("Vault not initialized")
            return
        }
        if (!session.isUnlocked()) {
            clearDecryptedState()
            onLockDetected?.invoke()
            onError?.invoke("Vault is locked. Please unlock again.")
            return
        }
        scope.launch {
            try {
                val entry = PasswordEntry(
                    id = existingId ?: UUID.randomUUID().toString(),
                    vaultId = vaultId,
                    revision = (existingRevision ?: 0L) + 1L,
                    title = title.trim(),
                    username = username.trim(),
                    password = password,
                    website = website.trim(),
                    notes = notes.trim(),
                    category = category.trim().ifEmpty { "General" },
                    isSensitive = isSensitive,
                    isFavorite = isFavorite,
                    iconUri = iconUri,
                    appId = appId,
                    updatedAtEpochMs = System.currentTimeMillis()
                )
                itemRepository.savePassword(entry)
                _items.value = itemRepository.listItems(vaultId)
                onComplete()
            } catch (e: IllegalStateException) {
                if (!session.isUnlocked()) {
                    clearDecryptedState()
                    onLockDetected?.invoke()
                    onError?.invoke("Vault is locked. Please unlock again.")
                } else {
                    onError?.invoke("Failed to save password")
                }
            } catch (e: Exception) {
                onError?.invoke("Failed to save password")
            }
        }
    }

    fun saveNote(
        existingId: String?,
        existingRevision: Long?,
        title: String,
        content: String,
        category: String,
        isSensitive: Boolean,
        theme: String = "Classic",
        isFavorite: Boolean = false,
        onError: ((String) -> Unit)? = null,
        onComplete: () -> Unit
    ) {
        val vaultId = keyManager.vaultId() ?: run {
            onError?.invoke("Vault not initialized")
            return
        }
        if (!session.isUnlocked()) {
            clearDecryptedState()
            onLockDetected?.invoke()
            onError?.invoke("Vault is locked. Please unlock again.")
            return
        }
        scope.launch {
            try {
                val note = SecureNote(
                    id = existingId ?: UUID.randomUUID().toString(),
                    vaultId = vaultId,
                    revision = (existingRevision ?: 0L) + 1L,
                    title = title.trim(),
                    content = content.trim(),
                    category = category.trim().ifEmpty { "General" },
                    isSensitive = isSensitive,
                    theme = theme,
                    isFavorite = isFavorite,
                    updatedAtEpochMs = System.currentTimeMillis()
                )
                itemRepository.saveNote(note)
                _items.value = itemRepository.listItems(vaultId)
                onComplete()
            } catch (e: IllegalStateException) {
                if (!session.isUnlocked()) {
                    clearDecryptedState()
                    onLockDetected?.invoke()
                    onError?.invoke("Vault is locked. Please unlock again.")
                } else {
                    onError?.invoke("Failed to save note")
                }
            } catch (e: Exception) {
                onError?.invoke("Failed to save note")
            }
        }
    }

    fun saveDocument(
        existingId: String?,
        existingRevision: Long?,
        title: String,
        category: String,
        pages: List<DocumentPage>,
        ocrText: String = "",
        isFavorite: Boolean = false,
        onError: ((String) -> Unit)? = null,
        onComplete: () -> Unit
    ) {
        val vaultId = keyManager.vaultId() ?: run {
            onError?.invoke("Vault not initialized")
            return
        }
        if (!session.isUnlocked()) {
            clearDecryptedState()
            onLockDetected?.invoke()
            onError?.invoke("Vault is locked. Please unlock again.")
            return
        }
        scope.launch {
            try {
                val doc = DocumentEntry(
                    id = existingId ?: UUID.randomUUID().toString(),
                    vaultId = vaultId,
                    revision = (existingRevision ?: 0L) + 1L,
                    title = title.trim(),
                    category = category.trim().ifEmpty { "Personal Documents" },
                    isFavorite = isFavorite,
                    ocrText = ocrText.trim(),
                    pages = pages,
                    updatedAtEpochMs = System.currentTimeMillis()
                )
                itemRepository.saveDocument(doc)
                _items.value = itemRepository.listItems(vaultId)
                onComplete()
            } catch (e: IllegalStateException) {
                if (!session.isUnlocked()) {
                    clearDecryptedState()
                    onLockDetected?.invoke()
                    onError?.invoke("Vault is locked. Please unlock again.")
                } else {
                    onError?.invoke("Failed to save document")
                }
            } catch (e: Exception) {
                onError?.invoke("Failed to save document")
            }
        }
    }

    fun toggleFavorite(item: VaultItem, onError: ((String) -> Unit)? = null) {
        val vaultId = keyManager.vaultId() ?: run {
            onError?.invoke("Vault not initialized")
            return
        }
        if (!session.isUnlocked()) {
            clearDecryptedState()
            onLockDetected?.invoke()
            onError?.invoke("Vault is locked. Please unlock again.")
            return
        }
        scope.launch {
            try {
                itemRepository.toggleFavorite(item)
                _items.value = itemRepository.listItems(vaultId)
            } catch (e: Exception) {
                onError?.invoke("Failed to update favorite status")
            }
        }
    }

    fun deleteItem(id: String, onError: ((String) -> Unit)? = null, onComplete: () -> Unit = {}) {
        val vaultId = keyManager.vaultId() ?: run {
            onError?.invoke("Vault not initialized")
            return
        }
        if (!session.isUnlocked()) {
            clearDecryptedState()
            onLockDetected?.invoke()
            onError?.invoke("Vault is locked. Please unlock again.")
            return
        }
        scope.launch {
            try {
                itemRepository.deleteItem(id, vaultId)
                _items.value = itemRepository.listItems(vaultId)
                onComplete()
            } catch (e: Exception) {
                onError?.invoke("Failed to delete item")
            }
        }
    }

    fun togglePasswordVisibility(id: String) {
        if (_revealedPasswordIds.value.contains(id)) {
            hidePassword(id)
        } else {
            showPasswordTimed(id)
        }
    }

    private fun showPasswordTimed(id: String) {
        _revealedPasswordIds.value = _revealedPasswordIds.value + id
        revealJobs[id]?.cancel()
        revealJobs[id] = scope.launch {
            delay(15_000L)
            hidePassword(id)
        }
    }

    private fun hidePassword(id: String) {
        revealJobs[id]?.cancel()
        revealJobs.remove(id)
        _revealedPasswordIds.value = _revealedPasswordIds.value - id
    }

    fun copyToClipboard(text: String, label: String, isSensitive: Boolean = true) {
        if (isSensitive) {
            clipboard.copySensitive(label, text)
        } else {
            clipboard.copyPlain(label, text)
        }
        _clipboardNotice.value = "$label copied. Clipboard will auto-clear in 30 seconds."
        scope.launch {
            delay(4_000L)
            _clipboardNotice.value = null
        }
    }

    /**
     * Creates an encrypted zero-knowledge share link for an item:
     * - Derives an ephemeral AES-256 key
     * - Encrypts the plaintext payload
     * - Uploads ciphertext to backend
     * - Embeds ephemeral decryption key strictly in the URL fragment (#key=...)
     */
    fun createShare(
        item: VaultItem,
        expiresInSeconds: Int = 86400,
        maxViews: Int = 1,
        includePassword: Boolean = false,
        onSuccess: (String) -> Unit,
        onError: (String) -> Unit
    ) {
        val backendApi = api ?: run {
            onError("Sync service unavailable")
            return
        }
        scope.launch {
            try {
                val plaintext = when (item) {
                    is VaultItem.Password -> {
                        val toShare = if (includePassword) item.entry else item.entry.copy(password = "")
                        toShare.toEnvelopeBytes()
                    }
                    is VaultItem.Note -> item.note.toEnvelopeBytes()
                    is VaultItem.Document -> item.entry.toEnvelopeBytes()
                }

                val ephemeralKey = ByteArray(32).also(random::nextBytes)
                val nonce = ByteArray(12).also(random::nextBytes)

                val cipher = Cipher.getInstance("AES/GCM/NoPadding")
                cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(ephemeralKey, "AES"), GCMParameterSpec(128, nonce))
                cipher.updateAAD(item.id.toByteArray())
                val ciphertext = cipher.doFinal(plaintext)

                val b64Payload = Base64.getUrlEncoder().withoutPadding().encodeToString(ciphertext)
                val b64Nonce = Base64.getUrlEncoder().withoutPadding().encodeToString(nonce)
                val b64Key = Base64.getUrlEncoder().withoutPadding().encodeToString(ephemeralKey)

                val itemType = when (item) {
                    is VaultItem.Password -> "password"
                    is VaultItem.Note -> "note"
                    is VaultItem.Document -> "document"
                }

                val req = CreateShareRequestDto(
                    item_id = item.id,
                    item_type = itemType,
                    encrypted_payload = b64Payload,
                    nonce = b64Nonce,
                    expires_in_seconds = expiresInSeconds,
                    max_views = maxViews
                )

                val res = backendApi.createShare(req)
                // Privacy Guarantee: Key is strictly placed in URL fragment (#) so server never sees it
                val shareUrl = "https://vault.secure/s/${res.share_token}#key=$b64Key"
                onSuccess(shareUrl)
                loadShares()
            } catch (e: Exception) {
                onError("Failed to generate secure share")
            }
        }
    }

    /**
     * Native Android Share Sheet integration with scoped URI permissions and content sanitization.
     * Passwords default to username/URL only unless includePassword is true.
     */
    fun shareViaSystemSheet(
        context: Context,
        item: VaultItem,
        includePassword: Boolean = false
    ) {
        when (item) {
            is VaultItem.Password -> {
                val builder = StringBuilder()
                builder.append("Title: ").append(item.entry.title).append("\n")
                if (item.entry.username.isNotBlank()) {
                    builder.append("Username: ").append(item.entry.username).append("\n")
                }
                if (item.entry.website.isNotBlank()) {
                    builder.append("Website: ").append(item.entry.website).append("\n")
                }
                if (includePassword && item.entry.password.isNotBlank()) {
                    builder.append("Password: ").append(item.entry.password).append("\n")
                }
                if (item.entry.notes.isNotBlank()) {
                    builder.append("Notes: ").append(item.entry.notes).append("\n")
                }
                SecureShareProvider.shareTextViaSystem(
                    context = context,
                    title = item.entry.title,
                    content = builder.toString().trimEnd()
                )
            }
            is VaultItem.Note -> {
                val content = if (item.note.content.isNotBlank()) {
                    "${item.note.title}\n\n${item.note.content}"
                } else {
                    item.note.title
                }
                SecureShareProvider.shareTextViaSystem(
                    context = context,
                    title = item.note.title,
                    content = content
                )
            }
            is VaultItem.Document -> {
                val doc = item.entry
                if (doc.pages.isNotEmpty() && blobManager != null) {
                    val firstPage = doc.pages.first()
                    val data = try {
                        blobManager.loadPageBlob(doc.vaultId, doc.id, firstPage.pageId, 1, firstPage.blobId)
                    } catch (_: Exception) { null }
                    if (data != null) {
                        val ext = if (firstPage.mimeType.contains("pdf")) "pdf" else "jpg"
                        val fileName = "${doc.title}.$ext"
                        val uri = SecureShareProvider.createEphemeralShareUri(
                            context = context,
                            fileName = fileName,
                            data = data,
                            mimeType = firstPage.mimeType
                        )
                        SecureShareProvider.shareFileViaSystem(
                            context = context,
                            title = doc.title,
                            uri = uri,
                            mimeType = firstPage.mimeType
                        )
                        return
                    }
                }
                SecureShareProvider.shareTextViaSystem(
                    context = context,
                    title = doc.title,
                    content = "Document: ${doc.title}\nCategory: ${doc.category}"
                )
            }
        }
    }

    fun loadShares() {
        val backendApi = api ?: return
        scope.launch {
            try {
                _activeShares.value = backendApi.listShares()
            } catch (_: Exception) {
                // Ignore transient network errors
            }
        }
    }

    fun revokeShare(shareId: String, onComplete: () -> Unit) {
        val backendApi = api ?: return
        scope.launch {
            try {
                backendApi.revokeShare(shareId)
                loadShares()
                onComplete()
            } catch (_: Exception) {}
        }
    }

    /**
     * Creates an encrypted backup manifest of all local vault items.
     */
    fun createCloudBackup(onSuccess: () -> Unit, onError: (String) -> Unit) {
        val backendApi = api ?: run { onError("Cloud backup unavailable"); return }
        val vaultId = keyManager.vaultId() ?: run { onError("Vault not initialized"); return }
        if (!session.isUnlocked()) { onError("Vault is locked"); return }

        scope.launch {
            try {
                val manifestPayload = "{\"vaultId\":\"$vaultId\",\"itemCount\":${_items.value.size}}".toByteArray()
                val nonce = ByteArray(12).also(random::nextBytes)

                val encryptedManifest = session.withRootKey { vrk ->
                    val cipher = Cipher.getInstance("AES/GCM/NoPadding")
                    cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(vrk, "AES"), GCMParameterSpec(128, nonce))
                    cipher.doFinal(manifestPayload)
                }

                // Verify backup manifest decrypts and passes AEAD authentication before upload
                session.withRootKey { vrk ->
                    val verifyCipher = Cipher.getInstance("AES/GCM/NoPadding")
                    verifyCipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(vrk, "AES"), GCMParameterSpec(128, nonce))
                    val decrypted = verifyCipher.doFinal(encryptedManifest)
                    check(decrypted.contentEquals(manifestPayload)) { "Backup manifest integrity check failed" }
                }

                val req = CreateBackupRequestDto(
                    object_id = UUID.randomUUID().toString(),
                    encrypted_manifest = Base64.getUrlEncoder().withoutPadding().encodeToString(encryptedManifest),
                    manifest_nonce = Base64.getUrlEncoder().withoutPadding().encodeToString(nonce),
                    byte_count = encryptedManifest.size.toLong()
                )
                backendApi.createBackup(req)
                onSuccess()
            } catch (e: Exception) {
                onError("Failed to upload encrypted backup")
            }
        }
    }
}

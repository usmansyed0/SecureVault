package com.securevault.vault.model

import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import java.nio.charset.StandardCharsets

private val vaultJson = Json {
    ignoreUnknownKeys = true
    encodeDefaults = true
}

@Serializable
data class PasswordEnvelope(
    val formatVersion: Int = 1,
    val title: String,
    val username: String,
    val password: String,
    val website: String = "",
    val notes: String = "",
    val category: String = "General",
    val isSensitive: Boolean = false,
    val isFavorite: Boolean = false,
    val isArchived: Boolean = false,
    val appId: String = "",
    val iconUri: String = "",
    val totpSecret: String = "",
    val createdAtEpochMs: Long,
    val updatedAtEpochMs: Long
)

@Serializable
data class NoteEnvelope(
    val formatVersion: Int = 1,
    val title: String,
    val content: String,
    val category: String = "General",
    val isSensitive: Boolean = false,
    val isFavorite: Boolean = false,
    val isArchived: Boolean = false,
    val theme: String = "Classic",
    val createdAtEpochMs: Long,
    val updatedAtEpochMs: Long
)

@Serializable
data class DocumentPageEnvelope(
    val pageId: String,
    val pageNumber: Int,
    val mimeType: String,
    val blobId: String,
    val rotationDegrees: Int = 0,
    val filter: String = "Original",
    val width: Int = 0,
    val height: Int = 0
)

@Serializable
data class DocumentEnvelope(
    val formatVersion: Int = 1,
    val title: String,
    val category: String = "Personal Documents",
    val documentType: String = "General Document",
    val expiryDateEpochMs: Long? = null,
    val isEmergencyCard: Boolean = false,
    val isFavorite: Boolean = false,
    val isArchived: Boolean = false,
    val ocrText: String = "",
    val pages: List<DocumentPageEnvelope> = emptyList(),
    val createdAtEpochMs: Long,
    val updatedAtEpochMs: Long
)

data class PasswordEntry(
    val id: String,
    val vaultId: String,
    val revision: Long = 1L,
    val title: String,
    val username: String,
    val password: String,
    val website: String = "",
    val notes: String = "",
    val category: String = "General",
    val isSensitive: Boolean = false,
    val isFavorite: Boolean = false,
    val isArchived: Boolean = false,
    val appId: String = "",
    val iconUri: String = "",
    val totpSecret: String = "",
    val createdAtEpochMs: Long = System.currentTimeMillis(),
    val updatedAtEpochMs: Long = System.currentTimeMillis()
) {
    fun toEnvelopeBytes(): ByteArray {
        val envelope = PasswordEnvelope(
            formatVersion = 1,
            title = title,
            username = username,
            password = password,
            website = website,
            notes = notes,
            category = category,
            isSensitive = isSensitive,
            isFavorite = isFavorite,
            isArchived = isArchived,
            appId = appId,
            iconUri = iconUri,
            totpSecret = totpSecret,
            createdAtEpochMs = createdAtEpochMs,
            updatedAtEpochMs = updatedAtEpochMs
        )
        return vaultJson.encodeToString(PasswordEnvelope.serializer(), envelope).toByteArray(StandardCharsets.UTF_8)
    }

    companion object {
        fun fromEnvelopeBytes(id: String, vaultId: String, revision: Long, bytes: ByteArray): PasswordEntry {
            val jsonStr = String(bytes, StandardCharsets.UTF_8)
            val envelope = vaultJson.decodeFromString(PasswordEnvelope.serializer(), jsonStr)
            require(envelope.formatVersion == 1) { "Unsupported envelope format version: ${envelope.formatVersion}" }
            return PasswordEntry(
                id = id,
                vaultId = vaultId,
                revision = revision,
                title = envelope.title,
                username = envelope.username,
                password = envelope.password,
                website = envelope.website,
                notes = envelope.notes,
                category = envelope.category,
                isSensitive = envelope.isSensitive,
                isFavorite = envelope.isFavorite,
                isArchived = envelope.isArchived,
                appId = envelope.appId,
                iconUri = envelope.iconUri,
                totpSecret = envelope.totpSecret,
                createdAtEpochMs = envelope.createdAtEpochMs,
                updatedAtEpochMs = envelope.updatedAtEpochMs
            )
        }
    }
}

data class SecureNote(
    val id: String,
    val vaultId: String,
    val revision: Long = 1L,
    val title: String,
    val content: String,
    val category: String = "General",
    val isSensitive: Boolean = false,
    val isFavorite: Boolean = false,
    val isArchived: Boolean = false,
    val theme: String = "Classic",
    val createdAtEpochMs: Long = System.currentTimeMillis(),
    val updatedAtEpochMs: Long = System.currentTimeMillis()
) {
    fun toEnvelopeBytes(): ByteArray {
        val envelope = NoteEnvelope(
            formatVersion = 1,
            title = title,
            content = content,
            category = category,
            isSensitive = isSensitive,
            isFavorite = isFavorite,
            isArchived = isArchived,
            theme = theme,
            createdAtEpochMs = createdAtEpochMs,
            updatedAtEpochMs = updatedAtEpochMs
        )
        return vaultJson.encodeToString(NoteEnvelope.serializer(), envelope).toByteArray(StandardCharsets.UTF_8)
    }

    companion object {
        fun fromEnvelopeBytes(id: String, vaultId: String, revision: Long, bytes: ByteArray): SecureNote {
            val jsonStr = String(bytes, StandardCharsets.UTF_8)
            val envelope = vaultJson.decodeFromString(NoteEnvelope.serializer(), jsonStr)
            require(envelope.formatVersion == 1) { "Unsupported envelope format version: ${envelope.formatVersion}" }
            return SecureNote(
                id = id,
                vaultId = vaultId,
                revision = revision,
                title = envelope.title,
                content = envelope.content,
                category = envelope.category,
                isSensitive = envelope.isSensitive,
                isFavorite = envelope.isFavorite,
                isArchived = envelope.isArchived,
                theme = envelope.theme,
                createdAtEpochMs = envelope.createdAtEpochMs,
                updatedAtEpochMs = envelope.updatedAtEpochMs
            )
        }
    }
}

data class DocumentPage(
    val pageId: String,
    val pageNumber: Int,
    val mimeType: String,
    val blobId: String,
    val rotationDegrees: Int = 0,
    val filter: String = "Original",
    val width: Int = 0,
    val height: Int = 0
)

data class DocumentEntry(
    val id: String,
    val vaultId: String,
    val revision: Long = 1L,
    val title: String,
    val category: String = "Personal Documents",
    val documentType: String = "General Document",
    val expiryDateEpochMs: Long? = null,
    val isEmergencyCard: Boolean = false,
    val isFavorite: Boolean = false,
    val isArchived: Boolean = false,
    val ocrText: String = "",
    val pages: List<DocumentPage> = emptyList(),
    val createdAtEpochMs: Long = System.currentTimeMillis(),
    val updatedAtEpochMs: Long = System.currentTimeMillis()
) {
    fun toEnvelopeBytes(): ByteArray {
        val pageEnvelopes = pages.map {
            DocumentPageEnvelope(
                pageId = it.pageId,
                pageNumber = it.pageNumber,
                mimeType = it.mimeType,
                blobId = it.blobId,
                rotationDegrees = it.rotationDegrees,
                filter = it.filter,
                width = it.width,
                height = it.height
            )
        }
        val envelope = DocumentEnvelope(
            formatVersion = 1,
            title = title,
            category = category,
            documentType = documentType,
            expiryDateEpochMs = expiryDateEpochMs,
            isEmergencyCard = isEmergencyCard,
            isFavorite = isFavorite,
            isArchived = isArchived,
            ocrText = ocrText,
            pages = pageEnvelopes,
            createdAtEpochMs = createdAtEpochMs,
            updatedAtEpochMs = updatedAtEpochMs
        )
        return vaultJson.encodeToString(DocumentEnvelope.serializer(), envelope).toByteArray(StandardCharsets.UTF_8)
    }

    companion object {
        fun fromEnvelopeBytes(id: String, vaultId: String, revision: Long, bytes: ByteArray): DocumentEntry {
            val jsonStr = String(bytes, StandardCharsets.UTF_8)
            val envelope = vaultJson.decodeFromString(DocumentEnvelope.serializer(), jsonStr)
            require(envelope.formatVersion == 1) { "Unsupported envelope format version: ${envelope.formatVersion}" }
            val pages = envelope.pages.map {
                DocumentPage(
                    pageId = it.pageId,
                    pageNumber = it.pageNumber,
                    mimeType = it.mimeType,
                    blobId = it.blobId,
                    rotationDegrees = it.rotationDegrees,
                    filter = it.filter,
                    width = it.width,
                    height = it.height
                )
            }
            return DocumentEntry(
                id = id,
                vaultId = vaultId,
                revision = revision,
                title = envelope.title,
                category = envelope.category,
                documentType = envelope.documentType,
                expiryDateEpochMs = envelope.expiryDateEpochMs,
                isEmergencyCard = envelope.isEmergencyCard,
                isFavorite = envelope.isFavorite,
                isArchived = envelope.isArchived,
                ocrText = envelope.ocrText,
                pages = pages,
                createdAtEpochMs = envelope.createdAtEpochMs,
                updatedAtEpochMs = envelope.updatedAtEpochMs
            )
        }
    }
}

sealed interface VaultItem {
    val id: String
    val vaultId: String
    val revision: Long
    val title: String
    val category: String
    val isSensitive: Boolean
    val isFavorite: Boolean
    val isArchived: Boolean
    val updatedAtEpochMs: Long

    data class Password(val entry: PasswordEntry) : VaultItem {
        override val id: String get() = entry.id
        override val vaultId: String get() = entry.vaultId
        override val revision: Long get() = entry.revision
        override val title: String get() = entry.title
        override val category: String get() = entry.category
        override val isSensitive: Boolean get() = entry.isSensitive
        override val isFavorite: Boolean get() = entry.isFavorite
        override val isArchived: Boolean get() = entry.isArchived
        override val updatedAtEpochMs: Long get() = entry.updatedAtEpochMs
    }

    data class Note(val note: SecureNote) : VaultItem {
        override val id: String get() = note.id
        override val vaultId: String get() = note.vaultId
        override val revision: Long get() = note.revision
        override val title: String get() = note.title
        override val category: String get() = note.category
        override val isSensitive: Boolean get() = note.isSensitive
        override val isFavorite: Boolean get() = note.isFavorite
        override val isArchived: Boolean get() = note.isArchived
        override val updatedAtEpochMs: Long get() = note.updatedAtEpochMs
    }

    data class Document(val entry: DocumentEntry) : VaultItem {
        override val id: String get() = entry.id
        override val vaultId: String get() = entry.vaultId
        override val revision: Long get() = entry.revision
        override val title: String get() = entry.title
        override val category: String get() = entry.category
        override val isSensitive: Boolean get() = false
        override val isFavorite: Boolean get() = entry.isFavorite
        override val isArchived: Boolean get() = entry.isArchived
        override val updatedAtEpochMs: Long get() = entry.updatedAtEpochMs
    }
}

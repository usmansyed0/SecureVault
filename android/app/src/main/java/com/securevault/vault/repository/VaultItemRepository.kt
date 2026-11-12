package com.securevault.vault.repository

import com.securevault.crypto.RecordAddress
import com.securevault.database.EncryptedRecordDao
import com.securevault.database.VaultRecordRepository
import com.securevault.security.VaultKeyManager
import com.securevault.vault.model.DocumentEntry
import com.securevault.vault.model.PasswordEntry
import com.securevault.vault.model.SecureNote
import com.securevault.vault.model.VaultItem
import javax.inject.Inject
import javax.inject.Singleton

@Singleton
class VaultItemRepository @Inject constructor(
    private val records: VaultRecordRepository,
    private val recordDao: EncryptedRecordDao,
    private val keys: VaultKeyManager
) {
    companion object {
        const val TYPE_PASSWORD = "password"
        const val TYPE_NOTE = "note"
        const val TYPE_DOCUMENT = "document"
    }

    suspend fun savePassword(entry: PasswordEntry): PasswordEntry {
        val vaultId = if (entry.vaultId.isNotEmpty()) entry.vaultId else {
            keys.vaultId() ?: throw IllegalStateException("Vault not initialized")
        }
        val address = RecordAddress(
            vaultId = vaultId,
            recordId = entry.id,
            type = TYPE_PASSWORD,
            formatVersion = 1,
            revision = entry.revision
        )
        records.store(address, entry.toEnvelopeBytes())
        return entry.copy(vaultId = vaultId)
    }

    suspend fun getPassword(id: String, vaultId: String): PasswordEntry? {
        val pair = records.loadRecord(id, vaultId) ?: return null
        require(pair.first.type == TYPE_PASSWORD) { "Expected type $TYPE_PASSWORD, found ${pair.first.type}" }
        return PasswordEntry.fromEnvelopeBytes(id, vaultId, pair.first.revision, pair.second)
    }

    suspend fun saveNote(note: SecureNote): SecureNote {
        val vaultId = if (note.vaultId.isNotEmpty()) note.vaultId else {
            keys.vaultId() ?: throw IllegalStateException("Vault not initialized")
        }
        val address = RecordAddress(
            vaultId = vaultId,
            recordId = note.id,
            type = TYPE_NOTE,
            formatVersion = 1,
            revision = note.revision
        )
        records.store(address, note.toEnvelopeBytes())
        return note.copy(vaultId = vaultId)
    }

    suspend fun getNote(id: String, vaultId: String): SecureNote? {
        val pair = records.loadRecord(id, vaultId) ?: return null
        require(pair.first.type == TYPE_NOTE) { "Expected type $TYPE_NOTE, found ${pair.first.type}" }
        return SecureNote.fromEnvelopeBytes(id, vaultId, pair.first.revision, pair.second)
    }

    suspend fun saveDocument(doc: DocumentEntry): DocumentEntry {
        val vaultId = if (doc.vaultId.isNotEmpty()) doc.vaultId else {
            keys.vaultId() ?: throw IllegalStateException("Vault not initialized")
        }
        val address = RecordAddress(
            vaultId = vaultId,
            recordId = doc.id,
            type = TYPE_DOCUMENT,
            formatVersion = 1,
            revision = doc.revision
        )
        records.store(address, doc.toEnvelopeBytes())
        return doc.copy(vaultId = vaultId)
    }

    suspend fun getDocument(id: String, vaultId: String): DocumentEntry? {
        val pair = records.loadRecord(id, vaultId) ?: return null
        require(pair.first.type == TYPE_DOCUMENT) { "Expected type $TYPE_DOCUMENT, found ${pair.first.type}" }
        return DocumentEntry.fromEnvelopeBytes(id, vaultId, pair.first.revision, pair.second)
    }

    suspend fun toggleFavorite(item: VaultItem) {
        when (item) {
            is VaultItem.Password -> {
                savePassword(item.entry.copy(isFavorite = !item.entry.isFavorite, revision = item.entry.revision + 1))
            }
            is VaultItem.Note -> {
                saveNote(item.note.copy(isFavorite = !item.note.isFavorite, revision = item.note.revision + 1))
            }
            is VaultItem.Document -> {
                saveDocument(item.entry.copy(isFavorite = !item.entry.isFavorite, revision = item.entry.revision + 1))
            }
        }
    }

    /**
     * Soft-deletes the item and enqueues the delete operation for server sync.
     * The record is retained locally as a tombstone until the server confirms deletion.
     */
    suspend fun deleteItem(id: String, vaultId: String) {
        records.delete(id, vaultId)
    }

    /**
     * Permanently removes the item from local storage (hard-delete tombstone).
     * Only call this after the server has confirmed the deletion.
     * For normal UI-triggered deletes, use [deleteItem] instead.
     */
    suspend fun purgeItem(id: String, vaultId: String) {
        recordDao.hardDelete(id, vaultId)
    }

    suspend fun listItems(vaultId: String): List<VaultItem> {
        val pairs = records.loadAll(vaultId)
        val items = mutableListOf<VaultItem>()
        for ((address, plaintext) in pairs) {
            try {
                when (address.type) {
                    TYPE_PASSWORD -> {
                        val entry = PasswordEntry.fromEnvelopeBytes(address.recordId, address.vaultId, address.revision, plaintext)
                        items.add(VaultItem.Password(entry))
                    }
                    TYPE_NOTE -> {
                        val note = SecureNote.fromEnvelopeBytes(address.recordId, address.vaultId, address.revision, plaintext)
                        items.add(VaultItem.Note(note))
                    }
                    TYPE_DOCUMENT -> {
                        val doc = DocumentEntry.fromEnvelopeBytes(address.recordId, address.vaultId, address.revision, plaintext)
                        items.add(VaultItem.Document(doc))
                    }
                }
            } catch (_: Exception) {
                // Ignore corrupt or unreadable records rather than aborting entire vault list
            }
        }
        return items.sortedByDescending { it.updatedAtEpochMs }
    }
}

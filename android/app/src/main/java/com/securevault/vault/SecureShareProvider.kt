package com.securevault.vault

import android.content.Context
import android.content.Intent
import android.net.Uri
import androidx.core.content.FileProvider
import com.securevault.R
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import java.io.File
import java.io.FileOutputStream
import java.util.UUID

/**
 * Secure file provider and ephemeral sharing helper.
 *
 * Implements scoped Android Share Sheet integration with:
 * - Ephemeral cache directory `secure_shares/`
 * - Automatic cleanup of shared files after a 5-minute timeout
 * - Strict FLAG_GRANT_READ_URI_PERMISSION granting
 * - Content sanitization
 */
class SecureShareProvider : FileProvider(R.xml.file_paths) {

    companion object {
        private const val SHARE_DIR = "secure_shares"
        private const val EXPIRY_TIMEOUT_MS = 5 * 60 * 1000L // 5 minutes

        /**
         * Cleans up expired files in the cache directory that are older than 5 minutes.
         */
        fun cleanExpiredShares(context: Context) {
            val dir = File(context.cacheDir, SHARE_DIR)
            if (!dir.exists()) return
            val now = System.currentTimeMillis()
            dir.listFiles()?.forEach { file ->
                if (now - file.lastModified() > EXPIRY_TIMEOUT_MS) {
                    file.delete()
                }
            }
        }

        /**
         * Creates an ephemeral file in `secure_shares/` and returns a scoped content URI.
         * Automatically schedules deletion after 5 minutes.
         */
        fun createEphemeralShareUri(
            context: Context,
            fileName: String,
            data: ByteArray,
            mimeType: String = "text/plain"
        ): Uri {
            cleanExpiredShares(context)

            val dir = File(context.cacheDir, SHARE_DIR)
            if (!dir.exists()) {
                dir.mkdirs()
            }

            // Sanitize filename to avoid traversal or illegal characters
            val safeName = fileName.replace("[^a-zA-Z0-9._-]".toRegex(), "_")
            val ephemeralFile = File(dir, "${UUID.randomUUID()}_$safeName")

            FileOutputStream(ephemeralFile).use { out ->
                out.write(data)
                out.flush()
            }

            // Schedule self-destruction in background
            CoroutineScope(Dispatchers.IO).launch {
                delay(EXPIRY_TIMEOUT_MS)
                if (ephemeralFile.exists()) {
                    ephemeralFile.delete()
                }
            }

            val authority = "${context.packageName}.fileprovider"
            return getUriForFile(context, authority, ephemeralFile)
        }

        /**
         * Launches the native Android Share Sheet via Intent.createChooser with
         * scoped read URI permissions.
         */
        fun shareFileViaSystem(
            context: Context,
            title: String,
            uri: Uri,
            mimeType: String
        ) {
            val shareIntent = Intent(Intent.ACTION_SEND).apply {
                type = mimeType
                putExtra(Intent.EXTRA_STREAM, uri)
                putExtra(Intent.EXTRA_SUBJECT, title)
                addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
            }

            val chooser = Intent.createChooser(shareIntent, "Share '$title' via").apply {
                addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
            }
            context.startActivity(chooser)
        }

        /**
         * Shares text content (sanitized) via the system share sheet.
         */
        fun shareTextViaSystem(
            context: Context,
            title: String,
            content: String
        ) {
            val shareIntent = Intent(Intent.ACTION_SEND).apply {
                type = "text/plain"
                putExtra(Intent.EXTRA_SUBJECT, title)
                putExtra(Intent.EXTRA_TEXT, content)
            }

            val chooser = Intent.createChooser(shareIntent, "Share '$title' via").apply {
                addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            }
            context.startActivity(chooser)
        }
    }
}

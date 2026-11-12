package com.securevault.vault.document

import android.graphics.Bitmap
import android.graphics.BitmapFactory
import com.google.mlkit.vision.common.InputImage
import com.google.mlkit.vision.text.TextRecognition
import com.google.mlkit.vision.text.latin.TextRecognizerOptions
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException
import kotlin.coroutines.suspendCoroutine

/**
 * On-device OCR helper using Google ML Kit Text Recognition (Latin script).
 *
 * All processing is local — no network call is made, no image data leaves the device.
 * This matches the "nothing sensitive leaves the device" security model of SecureVault.
 *
 * The raw extracted text is returned as a plain String and is only ever stored after it
 * has been folded into the DocumentEnvelope and encrypted by VaultItemRepository /
 * VaultRecordRepository — exactly the same path as every other document field.
 */
object OcrHelper {

    private val recognizer by lazy {
        TextRecognition.getClient(TextRecognizerOptions.DEFAULT_OPTIONS)
    }

    /**
     * Runs on-device text recognition on a JPEG/PNG byte array (a single document page).
     *
     * @return extracted text trimmed of excess whitespace, or an empty string if
     *         recognition produced no text or [bytes] could not be decoded as a bitmap.
     */
    suspend fun extractText(bytes: ByteArray): String {
        val bitmap: Bitmap = BitmapFactory.decodeByteArray(bytes, 0, bytes.size)
            ?: return ""
        return extractText(bitmap)
    }

    /**
     * Runs on-device text recognition on an already-decoded [Bitmap].
     */
    suspend fun extractText(bitmap: Bitmap): String = suspendCoroutine { cont ->
        val image = InputImage.fromBitmap(bitmap, 0)
        recognizer.process(image)
            .addOnSuccessListener { visionText ->
                cont.resume(visionText.text.trim())
            }
            .addOnFailureListener { e ->
                // Do not crash the import flow — return empty string on failure
                cont.resume("")
            }
    }

    /**
     * Aggregates OCR results from multiple pages into a single text block separated
     * by double newlines, which keeps page boundaries visible in search results.
     */
    suspend fun extractTextFromPages(pageBytesList: List<ByteArray>): String {
        return pageBytesList
            .mapIndexed { _, bytes -> extractText(bytes) }
            .filter { it.isNotEmpty() }
            .joinToString("\n\n")
    }
}

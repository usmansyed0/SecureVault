package com.securevault.vault.document

import android.graphics.*
import android.graphics.pdf.PdfDocument
import java.io.ByteArrayOutputStream

object DocumentScannerUtils {

    fun rotateBitmap(source: Bitmap, degrees: Int): Bitmap {
        if (degrees % 360 == 0) return source
        val matrix = Matrix().apply { postRotate(degrees.toFloat()) }
        return Bitmap.createBitmap(source, 0, 0, source.width, source.height, matrix, true)
    }

    fun applyFilter(source: Bitmap, filterName: String): Bitmap {
        val result = Bitmap.createBitmap(source.width, source.height, Bitmap.Config.ARGB_8888)
        val canvas = Canvas(result)
        val paint = Paint()

        when (filterName.lowercase()) {
            "vivid" -> {
                val cm = ColorMatrix()
                cm.setSaturation(1.6f)
                val scale = 1.2f
                val translate = (-0.1f * 255)
                val contrastCm = ColorMatrix(
                    floatArrayOf(
                        scale, 0f, 0f, 0f, translate,
                        0f, scale, 0f, 0f, translate,
                        0f, 0f, scale, 0f, translate,
                        0f, 0f, 0f, 1f, 0f
                    )
                )
                cm.postConcat(contrastCm)
                paint.colorFilter = ColorMatrixColorFilter(cm)
                canvas.drawBitmap(source, 0f, 0f, paint)
            }
            "light" -> {
                val cm = ColorMatrix(
                    floatArrayOf(
                        1.2f, 0f, 0f, 0f, 30f,
                        0f, 1.2f, 0f, 0f, 30f,
                        0f, 0f, 1.2f, 0f, 30f,
                        0f, 0f, 0f, 1f, 0f
                    )
                )
                paint.colorFilter = ColorMatrixColorFilter(cm)
                canvas.drawBitmap(source, 0f, 0f, paint)
            }
            "b&w", "bw", "black & white" -> {
                val cm = ColorMatrix()
                cm.setSaturation(0f)
                // Boost contrast for sharp text readability
                val scale = 1.8f
                val translate = (-0.4f * 255)
                val contrastCm = ColorMatrix(
                    floatArrayOf(
                        scale, 0f, 0f, 0f, translate,
                        0f, scale, 0f, 0f, translate,
                        0f, 0f, scale, 0f, translate,
                        0f, 0f, 0f, 1f, 0f
                    )
                )
                cm.postConcat(contrastCm)
                paint.colorFilter = ColorMatrixColorFilter(cm)
                canvas.drawBitmap(source, 0f, 0f, paint)
            }
            else -> {
                // "Original"
                canvas.drawBitmap(source, 0f, 0f, paint)
            }
        }
        return result
    }

    data class Dimensions(val width: Int, val height: Int)

    /**
     * Calculates proportional dimensions constrained to [maxDimension].
     */
    fun calculateDownsampledDimensions(width: Int, height: Int, maxDimension: Int = 2048): Dimensions {
        if (width <= maxDimension && height <= maxDimension) return Dimensions(width, height)
        val ratio = minOf(maxDimension.toFloat() / width, maxDimension.toFloat() / height)
        val newWidth = maxOf(1, (width * ratio).toInt())
        val newHeight = maxOf(1, (height * ratio).toInt())
        return Dimensions(newWidth, newHeight)
    }

    /**
     * Safely downsamples a bitmap so that neither width nor height exceeds [maxDimension].
     * Preserves aspect ratio and prevents OutOfMemoryError on high-megapixel camera shots.
     */
    fun downsampleBitmap(source: Bitmap, maxDimension: Int = 2048): Bitmap {
        val target = calculateDownsampledDimensions(source.width, source.height, maxDimension)
        if (target.width == source.width && target.height == source.height) return source
        return Bitmap.createScaledBitmap(source, target.width, target.height, true)
    }

    /**
     * Converts an ordered list of scanned Bitmaps into a multi-page PDF document.
     * Downsamples excessively large images and handles memory pressure gracefully.
     */
    fun createPdfFromBitmaps(bitmaps: List<Bitmap>): ByteArray {
        val document = PdfDocument()
        try {
            bitmaps.forEachIndexed { index, rawBitmap ->
                val bitmap = try {
                    downsampleBitmap(rawBitmap, maxDimension = 2048)
                } catch (_: OutOfMemoryError) {
                    System.gc()
                    downsampleBitmap(rawBitmap, maxDimension = 1024)
                }
                val pageInfo = PdfDocument.PageInfo.Builder(bitmap.width, bitmap.height, index + 1).create()
                val page = document.startPage(pageInfo)
                val canvas = page.canvas
                canvas.drawBitmap(bitmap, 0f, 0f, null)
                document.finishPage(page)
            }
            val out = ByteArrayOutputStream()
            document.writeTo(out)
            return out.toByteArray()
        } catch (e: OutOfMemoryError) {
            System.gc()
            throw IllegalStateException("Device low on memory while assembling PDF. Reduce page count or resolution.", e)
        } finally {
            document.close()
        }
    }
}

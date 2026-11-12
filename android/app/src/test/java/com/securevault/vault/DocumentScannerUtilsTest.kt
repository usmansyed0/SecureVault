package com.securevault.vault

import com.securevault.vault.document.DocumentScannerUtils
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class DocumentScannerUtilsTest {

    @Test
    fun calculateDownsampledDimensions_withinBounds_leavesDimensionsUnchanged() {
        val target = DocumentScannerUtils.calculateDownsampledDimensions(800, 600, maxDimension = 2048)

        assertEquals(800, target.width)
        assertEquals(600, target.height)
    }

    @Test
    fun calculateDownsampledDimensions_exceedingBounds_scalesDownPreservingRatio() {
        // High resolution 4000 x 3000 (4:3 aspect ratio)
        val target = DocumentScannerUtils.calculateDownsampledDimensions(4000, 3000, maxDimension = 2048)

        assertTrue(target.width <= 2048)
        assertTrue(target.height <= 2048)
        assertEquals(2048, target.width)
        assertEquals(1536, target.height)
        val ratio = target.width.toFloat() / target.height.toFloat()
        assertEquals(4f / 3f, ratio, 0.01f)
    }

    @Test
    fun calculateDownsampledDimensions_tallImage_scalesHeightToMax() {
        // Tall image 1500 x 6000
        val target = DocumentScannerUtils.calculateDownsampledDimensions(1500, 6000, maxDimension = 2048)

        assertTrue(target.width <= 2048)
        assertTrue(target.height <= 2048)
        assertEquals(2048, target.height)
        assertEquals(512, target.width)
    }
}

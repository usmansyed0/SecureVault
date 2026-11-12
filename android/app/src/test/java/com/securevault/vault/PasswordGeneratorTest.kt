package com.securevault.vault

import com.securevault.vault.generator.*
import org.junit.Assert.*
import org.junit.Test

class PasswordGeneratorTest {

    private val generator = PasswordGenerator()

    @Test
    fun generatesDefaultLengthPassword() {
        val password = generator.generate()
        assertEquals(DEFAULT_PASSWORD_LENGTH, password.length)
        assertEquals(20, password.length)
    }

    @Test
    fun generatesPasswordAtExactBounds() {
        val minPassword = generator.generate(PasswordGeneratorConfig(length = MIN_PASSWORD_LENGTH))
        assertEquals(8, minPassword.length)

        val maxPassword = generator.generate(PasswordGeneratorConfig(length = MAX_PASSWORD_LENGTH))
        assertEquals(64, maxPassword.length)
    }

    @Test
    fun rejectsLengthLessThanEight() {
        val exception = assertThrows(IllegalArgumentException::class.java) {
            generator.generate(PasswordGeneratorConfig(length = 7))
        }
        assertTrue(exception.message!!.contains("between 8 and 64"))
    }

    @Test
    fun rejectsLengthGreaterThanSixtyFour() {
        val exception65 = assertThrows(IllegalArgumentException::class.java) {
            generator.generate(PasswordGeneratorConfig(length = 65))
        }
        assertTrue(exception65.message!!.contains("between 8 and 64"))

        val exception128 = assertThrows(IllegalArgumentException::class.java) {
            generator.generate(PasswordGeneratorConfig(length = 128))
        }
        assertTrue(exception128.message!!.contains("between 8 and 64"))
    }

    @Test
    fun guaranteesAllRequestedCharacterClassesAreIncluded() {
        for (i in 0 until 50) {
            val password = generator.generate(
                PasswordGeneratorConfig(
                    length = 16,
                    includeUppercase = true,
                    includeLowercase = true,
                    includeDigits = true,
                    includeSymbols = true
                )
            )
            assertTrue("Must contain uppercase", password.any { it.isUpperCase() })
            assertTrue("Must contain lowercase", password.any { it.isLowerCase() })
            assertTrue("Must contain digit", password.any { it.isDigit() })
            assertTrue("Must contain symbol", password.any { PasswordGenerator.SYMBOLS.contains(it) })
        }
    }

    @Test
    fun supportsSingleCharacterClassSelection() {
        val digitsOnly = generator.generate(
            PasswordGeneratorConfig(
                length = 10,
                includeUppercase = false,
                includeLowercase = false,
                includeDigits = true,
                includeSymbols = false
            )
        )
        assertEquals(10, digitsOnly.length)
        assertTrue(digitsOnly.all { it.isDigit() })

        val upperOnly = generator.generate(
            PasswordGeneratorConfig(
                length = 12,
                includeUppercase = true,
                includeLowercase = false,
                includeDigits = false,
                includeSymbols = false
            )
        )
        assertEquals(12, upperOnly.length)
        assertTrue(upperOnly.all { it.isUpperCase() })
    }

    @Test
    fun rejectsEmptyCharacterClasses() {
        assertThrows(IllegalArgumentException::class.java) {
            generator.generate(
                PasswordGeneratorConfig(
                    length = 16,
                    includeUppercase = false,
                    includeLowercase = false,
                    includeDigits = false,
                    includeSymbols = false
                )
            )
        }
    }

    @Test
    fun generatedPasswordsAreUniqueAcrossIterations() {
        val generatedSet = mutableSetOf<String>()
        for (i in 0 until 100) {
            val pass = generator.generate(PasswordGeneratorConfig(length = 24))
            assertTrue("Generated duplicate password!", generatedSet.add(pass))
        }
    }
}

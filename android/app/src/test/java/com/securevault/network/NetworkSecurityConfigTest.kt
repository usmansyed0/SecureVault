package com.securevault.network

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.w3c.dom.Element
import java.io.File
import javax.xml.parsers.DocumentBuilderFactory

class NetworkSecurityConfigTest {

    private fun findProjectRoot(): File {
        var dir = File(System.getProperty("user.dir") ?: ".")
        while (dir.exists()) {
            if (File(dir, "android").exists() || File(dir, "app").exists()) {
                val appDir = if (File(dir, "app").exists()) File(dir, "app") else File(dir, "android/app")
                if (appDir.exists()) return appDir
            }
            dir = dir.parentFile ?: break
        }
        return File("android/app").takeIf { it.exists() } ?: File("app")
    }

    @Test
    fun releaseNetworkSecurityConfig_forbidsCleartext() {
        val appDir = findProjectRoot()
        val releaseConfig = File(appDir, "src/main/res/xml/network_security_config.xml")
        assertTrue("Release network security config must exist", releaseConfig.exists())

        val doc = DocumentBuilderFactory.newInstance().newDocumentBuilder().parse(releaseConfig)
        val baseConfig = doc.getElementsByTagName("base-config").item(0) as? Element
        assertTrue("<base-config> must be present", baseConfig != null)
        assertEquals("false", baseConfig?.getAttribute("cleartextTrafficPermitted"))

        val domainConfigs = doc.getElementsByTagName("domain-config")
        for (i in 0 until domainConfigs.length) {
            val element = domainConfigs.item(i) as Element
            assertFalse(
                "No domain-config in release should permit cleartext",
                element.getAttribute("cleartextTrafficPermitted").equals("true", ignoreCase = true)
            )
        }
    }

    @Test
    fun releaseNetworkSecurityConfig_hasCertificatePinning() {
        val appDir = findProjectRoot()
        val releaseConfig = File(appDir, "src/main/res/xml/network_security_config.xml")
        val doc = DocumentBuilderFactory.newInstance().newDocumentBuilder().parse(releaseConfig)

        val pinSets = doc.getElementsByTagName("pin-set")
        assertTrue("Release config must have at least one <pin-set>", pinSets.length > 0)

        val pinSet = pinSets.item(0) as Element
        val pins = pinSet.getElementsByTagName("pin")
        assertTrue("Must have at least 2 pins (current + backup)", pins.length >= 2)
    }

    @Test
    fun manifest_disallowsCleartextTraffic() {
        val appDir = findProjectRoot()
        val manifest = File(appDir, "src/main/AndroidManifest.xml")
        assertTrue("AndroidManifest.xml must exist", manifest.exists())

        val content = manifest.readText()
        assertTrue(
            "AndroidManifest.xml must set android:usesCleartextTraffic=\"false\"",
            content.contains("android:usesCleartextTraffic=\"false\"")
        )
    }
}

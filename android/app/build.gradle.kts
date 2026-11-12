import org.jetbrains.kotlin.gradle.dsl.JvmTarget
import java.util.Properties
import java.util.Base64

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.compose")
    id("com.google.dagger.hilt.android")
    id("com.google.devtools.ksp")
    id("org.jetbrains.kotlin.plugin.serialization")
}

android {
    namespace = "com.securevault"
    compileSdk = 36

    defaultConfig {
        applicationId = "com.securevault"
        minSdk = 26
        targetSdk = 36
        versionCode = 1
        versionName = "0.1.0"
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        val googleWebClientId = (project.findProperty("googleWebClientId") as? String)
            ?: System.getenv("SECUREVAULT_GOOGLE_WEB_CLIENT_ID")
            ?: ""
        resValue("string", "google_web_client_id", googleWebClientId)
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    val devApiUrl = (project.findProperty("devApiUrl") as? String) ?: "http://10.0.2.2:8000/"
    val stagingApiUrl = (project.findProperty("stagingApiUrl") as? String) ?: "https://staging-api.securevault.app/"
    val prodApiUrl = (project.findProperty("prodApiUrl") as? String)
        ?: (project.findProperty("apiUrl") as? String)
        ?: System.getenv("SECUREVAULT_PROD_API_URL")
        ?: "https://api.securevault.app/"

    signingConfigs {
        create("release") {
            val keystorePropertiesFile = rootProject.file("keystore.properties")
            if (keystorePropertiesFile.exists()) {
                val properties = Properties()
                keystorePropertiesFile.inputStream().use { properties.load(it) }
                val storePath = properties.getProperty("storeFile")
                if (!storePath.isNullOrBlank()) {
                    storeFile = rootProject.file(storePath)
                }
                storePassword = properties.getProperty("storePassword")
                keyAlias = properties.getProperty("keyAlias")
                keyPassword = properties.getProperty("keyPassword")
            } else {
                val envStorePath = System.getenv("SECUREVAULT_KEYSTORE_PATH")
                if (!envStorePath.isNullOrBlank()) {
                    storeFile = rootProject.file(envStorePath)
                }
                storePassword = System.getenv("SECUREVAULT_KEYSTORE_PASSWORD")
                keyAlias = System.getenv("SECUREVAULT_KEY_ALIAS")
                keyPassword = System.getenv("SECUREVAULT_KEY_PASSWORD")
            }
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
            signingConfig = signingConfigs.getByName("release")
            buildConfigField("String", "BASE_URL", "\"$prodApiUrl\"")
        }
        debug {
            isMinifyEnabled = false
            isShrinkResources = false
            buildConfigField("String", "BASE_URL", "\"$devApiUrl\"")
        }
        create("staging") {
            initWith(getByName("release"))
            matchingFallbacks += "release"
            buildConfigField("String", "BASE_URL", "\"$stagingApiUrl\"")
        }
        create("releaseTest") {
            initWith(getByName("release"))
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
            signingConfig = signingConfigs.getByName("debug")
            isDebuggable = false
            matchingFallbacks += "release"
            val testApiUrl = (project.findProperty("testApiUrl") as? String) ?: "https://api.example.invalid/"
            buildConfigField("String", "BASE_URL", "\"$testApiUrl\"")
        }
    }
    buildFeatures { compose = true; buildConfig = true }
    packaging {
        resources {
            excludes += setOf(
                "/META-INF/{AL2.0,LGPL2.1}",
                "META-INF/versions/**",
                "META-INF/INDEX.LIST",
                "META-INF/DEPENDENCIES"
            )
        }
        jniLibs {
            useLegacyPackaging = false
        }
    }
}

tasks.register("verifyReleaseSafety") {
    group = "verification"
    description = "Enforces zero-knowledge release safety checks: secrets, certificate pinning, and prod URLs."
    doLast {
        // 1. Validate prodApiUrl
        val url = (project.findProperty("prodApiUrl") as? String)
            ?: (project.findProperty("apiUrl") as? String)
            ?: System.getenv("SECUREVAULT_PROD_API_URL")
            ?: "https://api.securevault.app/"
        if (url.isBlank()) {
            throw GradleException("Release build failed: 'prodApiUrl' is missing or empty. Provide -PprodApiUrl=https://... or SECUREVAULT_PROD_API_URL.")
        }
        if (!url.startsWith("https://")) {
            throw GradleException("Release build failed: 'prodApiUrl' must start with 'https://'. Got: '$url'")
        }
        val lowerUrl = url.lowercase()
        for (forbidden in listOf("example", "invalid", "localhost", "127.0.0.1", "10.0.2.2")) {
            if (lowerUrl.contains(forbidden)) {
                throw GradleException("Release build failed: 'prodApiUrl' cannot contain test or local domain ($forbidden). Got: '$url'")
            }
        }

        // 2. Validate googleWebClientId
        val gClientId = (project.findProperty("googleWebClientId") as? String)
            ?: System.getenv("SECUREVAULT_GOOGLE_WEB_CLIENT_ID")
            ?: ""
        if (gClientId.isBlank()) {
            throw GradleException("Release build failed: 'googleWebClientId' is missing or empty. Provide -PgoogleWebClientId=... or SECUREVAULT_GOOGLE_WEB_CLIENT_ID.")
        }

        // 3. Validate release signing credentials
        val releaseSigning = android.signingConfigs.getByName("release")
        val store = releaseSigning.storeFile
        if (store == null || !store.exists() ||
            releaseSigning.storePassword.isNullOrBlank() ||
            releaseSigning.keyAlias.isNullOrBlank() ||
            releaseSigning.keyPassword.isNullOrBlank()
        ) {
            throw GradleException(
                "Release build failed: Release signing configuration is missing or invalid.\n" +
                "Provide a valid keystore.properties file in the android/ directory or set the environment variables:\n" +
                "  SECUREVAULT_KEYSTORE_PATH, SECUREVAULT_KEYSTORE_PASSWORD, SECUREVAULT_KEY_ALIAS, SECUREVAULT_KEY_PASSWORD."
            )
        }

        // 4. Validate Network Security Config pins
        val nscFile = file("src/main/res/xml/network_security_config.xml")
        if (!nscFile.exists()) {
            throw GradleException("Release build failed: Release network security config missing at ${nscFile.absolutePath}")
        }
        val nscContent = nscFile.readText()
        if (nscContent.contains("cleartextTrafficPermitted=\"true\"")) {
            throw GradleException("Release build failed: Release NSC permits cleartext traffic.")
        }
        val pinRegex = Regex("""<pin\s+digest="SHA-256"\s*>([^<]+)</pin>""", RegexOption.IGNORE_CASE)
        val pins = pinRegex.findAll(nscContent).map { it.groupValues[1].trim() }.toList()
        if (pins.size < 2) {
            throw GradleException("Release build failed: Release NSC must contain at least 2 <pin> elements (current and backup). Found: ${pins.size}")
        }
        for (pin in pins) {
            if (pin.startsWith("REPLACE_WITH_")) {
                throw GradleException("Release build failed: Certificate pin is still a placeholder: '$pin'. Replace with real SHA-256 SPKI pin.")
            }
            try {
                val decoded = Base64.getDecoder().decode(pin)
                if (decoded.size != 32) {
                    throw GradleException("Release build failed: Pin '$pin' decodes to ${decoded.size} bytes, expected 32 bytes (SHA-256).")
                }
            } catch (e: Exception) {
                throw GradleException("Release build failed: Pin '$pin' is not valid base64.")
            }
        }
        if (pins.toSet().size < pins.size) {
            throw GradleException("Release build failed: Duplicate certificate pins detected in release NSC. Current and backup pins must differ.")
        }
    }
}

tasks.configureEach {
    if (name in listOf("assembleRelease", "bundleRelease", "packageRelease")) {
        dependsOn("verifyReleaseSafety")
    }
}

kotlin {
    jvmToolchain(17)
    compilerOptions { jvmTarget.set(JvmTarget.JVM_17) }
}

ksp {
    arg("room.schemaLocation", "$projectDir/schemas")
}

dependencies {
    implementation(platform("androidx.compose:compose-bom:2025.05.00"))
    implementation("androidx.core:core-ktx:1.13.1")
    implementation("androidx.activity:activity-compose:1.9.2")
    implementation("androidx.compose.ui:ui"); implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.material:material-icons-extended")
    implementation("androidx.navigation:navigation-compose:2.8.0")
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.8.6")
    implementation("androidx.biometric:biometric:1.1.0")
    implementation("androidx.security:security-crypto:1.1.0-alpha06")
    implementation("androidx.work:work-runtime-ktx:2.9.1")
    implementation("androidx.room:room-runtime:2.6.1"); implementation("androidx.room:room-ktx:2.6.1"); ksp("androidx.room:room-compiler:2.6.1")
    implementation("com.google.dagger:hilt-android:2.52"); ksp("com.google.dagger:hilt-compiler:2.52")
    implementation("com.squareup.okhttp3:okhttp:4.12.0"); implementation("com.squareup.retrofit2:retrofit:2.11.0"); implementation("com.squareup.retrofit2:converter-kotlinx-serialization:2.11.0")
    implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.7.3")
    implementation("org.bouncycastle:bcprov-jdk18on:1.78.1")
    implementation("androidx.credentials:credentials:1.3.0")
    implementation("androidx.credentials:credentials-play-services-auth:1.3.0")
    implementation("com.google.android.libraries.identity.googleid:googleid:1.1.1")
    implementation("com.google.mlkit:text-recognition:16.0.1")
    testImplementation("junit:junit:4.13.2"); testImplementation("androidx.room:room-testing:2.6.1"); testImplementation("org.mockito:mockito-core:5.13.0"); testImplementation("org.mockito.kotlin:mockito-kotlin:5.4.0"); testImplementation("org.jetbrains.kotlinx:kotlinx-coroutines-test:1.8.1")
    androidTestImplementation("androidx.test.ext:junit:1.2.1"); androidTestImplementation("androidx.test:runner:1.6.2"); androidTestImplementation("androidx.test:core:1.6.1"); androidTestImplementation("androidx.room:room-testing:2.6.1")
}

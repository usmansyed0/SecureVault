# ═══════════════════════════════════════════════════════════════════════════════
# SecureVault — ProGuard / R8 Rules for Release Minification
# ═══════════════════════════════════════════════════════════════════════════════
# These rules ensure that all encryption, authentication, serialization,
# autofill, and Hilt injection entry points survive R8 tree-shaking and
# minification. Every section maps to an application module.
# ═══════════════════════════════════════════════════════════════════════════════

# ── General ───────────────────────────────────────────────────────────────────
-keepattributes *Annotation*, InnerClasses, Signature, Exceptions, EnclosingMethod

# ── Kotlin Serialization ─────────────────────────────────────────────────────
-dontnote kotlinx.serialization.SerializationKt
-keepclassmembers class * {
    *** Companion;
}
-keepclasseswithmembers class * {
    kotlinx.serialization.KSerializer serializer(...);
}
-keepclassmembers class * {
    @kotlinx.serialization.Serializable <fields>;
}
-keepclassmembers class * {
    @kotlinx.serialization.SerialName <fields>;
}
# Network DTOs must survive for JSON deserialization
-keep class com.securevault.network.model.** { *; }

# ── Room Database, DAOs & Entities ────────────────────────────────────────────
-keep class * extends androidx.room.RoomDatabase
-dontwarn androidx.room.paging.**
-keep class com.securevault.database.** { *; }

# ── Vault Data Models (entities, envelopes, enums) ────────────────────────────
-keep class com.securevault.vault.model.** { *; }

# ── Cryptography — BouncyCastle ───────────────────────────────────────────────
# BouncyCastle providers are loaded by reflection; preserve everything.
-keep class org.bouncycastle.** { *; }
-dontwarn org.bouncycastle.**

# ── Cryptography — SecureVault Crypto Layer ───────────────────────────────────
# VaultRecordCrypto, Argon2Kdf, KeystoreAead use reflection-sensitive APIs
-keep class com.securevault.crypto.** { *; }

# ── Security — VaultSession, VaultIntegrity, DeviceSigning ────────────────────
-keep class com.securevault.security.** { *; }

# ── TOTP Generator (RFC 6238) ────────────────────────────────────────────────
-keep class com.securevault.vault.totp.** { *; }

# ── Import / Export Engine ────────────────────────────────────────────────────
# CSV/JSON parsers and AES-GCM backup packaging
-keep class com.securevault.vault.io.** { *; }

# ── Security Dashboard & Password Strength ────────────────────────────────────
-keep class com.securevault.vault.security.** { *; }
-keep class com.securevault.vault.strength.** { *; }

# ── Document Wallet — Types, Expiry, Emergency ────────────────────────────────
-keep class com.securevault.vault.document.** { *; }

# ── Autofill Service ─────────────────────────────────────────────────────────
# The AutofillService is declared in AndroidManifest and instantiated by the OS
-keep class com.securevault.autofill.** { *; }

# ── PIN & Clipboard ──────────────────────────────────────────────────────────
-keep class com.securevault.vault.PinManager { *; }
-keep class com.securevault.vault.PinMetadataStore { *; }
-keep class com.securevault.vault.clipboard.** { *; }

# ── Dagger / Hilt ────────────────────────────────────────────────────────────
-keep class * extends dagger.hilt.internal.UnsafeCasts
-keep class com.securevault.di.** { *; }
-dontwarn com.google.errorprone.annotations.**

# ── Biometric & AndroidX Security ────────────────────────────────────────────
-keep class androidx.biometric.** { *; }

# ── OkHttp / Retrofit ────────────────────────────────────────────────────────
# Retrofit uses reflection on interface method annotations
-keepattributes RuntimeVisibleAnnotations, RuntimeVisibleParameterAnnotations
-keepclassmembers,allowshrinking,allowobfuscation interface * {
    @retrofit2.http.* <methods>;
}
-dontwarn okhttp3.internal.platform.**
-dontwarn org.conscrypt.**
-dontwarn org.bouncycastle.jsse.**
-dontwarn org.openjsse.**

# ── ML Kit Text Recognition ──────────────────────────────────────────────────
-keep class com.google.mlkit.** { *; }
-dontwarn com.google.mlkit.**

# ── Google Credentials / Identity ─────────────────────────────────────────────
-keep class com.google.android.libraries.identity.** { *; }
-dontwarn com.google.android.libraries.identity.**

package com.securevault.security

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.util.Base64

interface DeviceSigner {
    fun createIfMissing()
    fun publicKeyDer(): ByteArray
    fun publicKeyBase64(): String
    fun exists(): Boolean
    fun signatureForAuthentication(): Signature
    fun signAuthenticated(signature: Signature, message: ByteArray): ByteArray
    fun sign(message: ByteArray): ByteArray
    fun delete()
}

/** P-256 private signing key is non-exportable and bound to Android Keystore. */
class DeviceSigningKey(private val alias: String = "securevault_device_signing_key") : DeviceSigner {
    private val store by lazy { KeyStore.getInstance("AndroidKeyStore").apply { load(null) } }

    private fun resolvedAlias(): String {
        return if (store.containsAlias(alias)) {
            alias
        } else if (store.containsAlias("securevault.device.sign.v1")) {
            "securevault.device.sign.v1"
        } else {
            alias
        }
    }

    override fun createIfMissing() {
        if (store.containsAlias(alias) || store.containsAlias("securevault.device.sign.v1")) return
        val spec = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
            .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
            .setDigests(KeyProperties.DIGEST_SHA256)
            .setUserAuthenticationRequired(false)
            .build()
        KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore").apply {
            initialize(spec)
            generateKeyPair()
        }
    }

    override fun publicKeyDer(): ByteArray =
        store.getCertificate(resolvedAlias())?.publicKey?.encoded
            ?: throw IllegalStateException("Device signing key unavailable")

    override fun publicKeyBase64(): String = Base64.getEncoder().encodeToString(publicKeyDer())

    override fun exists(): Boolean =
        store.containsAlias(alias) || store.containsAlias("securevault.device.sign.v1")

    override fun signatureForAuthentication(): Signature {
        val entry = store.getEntry(resolvedAlias(), null) as? KeyStore.PrivateKeyEntry
            ?: throw IllegalStateException("Device private key unavailable for alias ${resolvedAlias()}")
        return Signature.getInstance("SHA256withECDSA").also {
            it.initSign(entry.privateKey)
        }
    }

    override fun signAuthenticated(signature: Signature, message: ByteArray): ByteArray {
        signature.update(message)
        return signature.sign()
    }

    override fun sign(message: ByteArray): ByteArray {
        createIfMissing()
        val entry = store.getEntry(resolvedAlias(), null) as? KeyStore.PrivateKeyEntry
            ?: throw IllegalStateException("Private key not available for alias ${resolvedAlias()}")
        val sig = Signature.getInstance("SHA256withECDSA")
        sig.initSign(entry.privateKey)
        sig.update(message)
        return sig.sign()
    }

    override fun delete() {
        if (store.containsAlias(alias)) store.deleteEntry(alias)
        if (store.containsAlias("securevault.device.sign.v1")) store.deleteEntry("securevault.device.sign.v1")
    }
}

package com.securevault.security

import javax.inject.Inject
import javax.inject.Singleton

/** Holds VRK bytes only while unlocked. Call lock() on every lock, logout, and app background event. */
@Singleton
class VaultSession @Inject constructor() {
    private val monitor = Any()
    @Volatile private var rootKey: ByteArray? = null
    fun unlock(key: ByteArray) = synchronized(monitor) { require(key.size == 32); rootKey?.fill(0); rootKey = key.copyOf() }
    fun isUnlocked(): Boolean = rootKey != null
    /** Lease is held only during key use. After lock returns, no key operation can still run. */
    fun <T> withRootKey(action: (ByteArray) -> T): T = synchronized(monitor) {
        action(rootKey ?: throw IllegalStateException("Vault is locked"))
    }
    fun lock() = synchronized(monitor) { rootKey?.fill(0); rootKey = null }
}

package com.securevault.vault.clipboard

import android.content.ClipData
import android.content.ClipDescription
import android.content.ClipboardManager
import android.content.Context
import android.os.Build
import android.os.PersistableBundle
import com.securevault.security.DelayedTaskScheduler
import dagger.hilt.android.qualifiers.ApplicationContext
import javax.inject.Inject
import javax.inject.Singleton

interface ClipboardBackend {
    fun setPrimaryClip(label: String, text: String, isSensitive: Boolean)
    fun getPrimaryClipText(): String?
    fun clearPrimaryClip()
}

class SystemClipboardBackend(private val context: Context) : ClipboardBackend {
    private val manager: ClipboardManager? by lazy {
        context.getSystemService(Context.CLIPBOARD_SERVICE) as? ClipboardManager
    }

    override fun setPrimaryClip(label: String, text: String, isSensitive: Boolean) {
        val mgr = manager ?: return
        val clip = ClipData.newPlainText(label, text)
        if (isSensitive && Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            clip.description.extras = PersistableBundle().apply {
                putBoolean(ClipDescription.EXTRA_IS_SENSITIVE, true)
            }
        }
        mgr.setPrimaryClip(clip)
    }

    override fun getPrimaryClipText(): String? {
        val clip = manager?.primaryClip ?: return null
        if (clip.itemCount == 0) return null
        return clip.getItemAt(0).text?.toString()
    }

    override fun clearPrimaryClip() {
        val mgr = manager ?: return
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            mgr.clearPrimaryClip()
        } else {
            mgr.setPrimaryClip(ClipData.newPlainText("", ""))
        }
    }
}

interface ClipboardController {
    fun copySensitive(label: String, text: String, timeoutMs: Long = DEFAULT_CLEAR_TIMEOUT_MS)
    fun copyPlain(label: String, text: String)
    fun cancelPendingClear()

    companion object {
        const val DEFAULT_CLEAR_TIMEOUT_MS = 30_000L
    }
}

@Singleton
class AndroidClipboardController(
    private val backend: ClipboardBackend,
    private val scheduler: DelayedTaskScheduler
) : ClipboardController {

    @Inject
    constructor(
        @ApplicationContext context: Context,
        scheduler: DelayedTaskScheduler
    ) : this(
        SystemClipboardBackend(context),
        scheduler
    )

    private var pendingTask: Runnable? = null

    override fun copySensitive(label: String, text: String, timeoutMs: Long) {
        backend.setPrimaryClip(label, text, isSensitive = true)
        scheduleAutoClear(text, timeoutMs)
    }

    override fun copyPlain(label: String, text: String) {
        cancelPendingClear()
        backend.setPrimaryClip(label, text, isSensitive = false)
    }

    override fun cancelPendingClear() {
        pendingTask?.let { scheduler.cancel(it) }
        pendingTask = null
    }

    private fun scheduleAutoClear(expectedText: String, timeoutMs: Long) {
        cancelPendingClear()
        val task = Runnable {
            try {
                // Only clear if the user hasn't copied something else in the meantime
                if (backend.getPrimaryClipText() == expectedText) {
                    backend.clearPrimaryClip()
                }
            } catch (_: Exception) {
                // Ignore any security/clipboard access exceptions on background clear
            }
        }
        pendingTask = task
        scheduler.schedule(timeoutMs, task)
    }
}

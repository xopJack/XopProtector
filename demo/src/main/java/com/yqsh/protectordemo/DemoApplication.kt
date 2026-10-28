package com.yqsh.protectordemo

import android.app.Application
import android.util.Log
import dalvik.system.DexFile

/**
 * Real application used before packing / restored after shell init.
 */
class DemoApplication : Application() {
    override fun onCreate() {
        super.onCreate()
        Log.i(TAG, "DemoApplication.onCreate native=" + safeNativeVersion()
                + " this=" + javaClass.name)
        // Register on the real Application after shell replace — mirrors customer
        // ProcessLifecycleOwner / ActivityLifecycleCallbacks usage.
        LifecycleProbe.installAppActivityCallbacks(this)
        LifecycleProbe.installProcess(this)
        probeDexFileApkScan()
    }

    /**
     * Smoke test for dex_scan_compat: XPage-style {@code DexFile(sourceDir).entries()}
     * must see business classes after encrypt-first packing.
     */
    private fun probeDexFileApkScan() {
        if (!isProtectorPacked()) {
            Log.i(TAG, "dexScan: skip (unpacked)")
            return
        }
        try {
            val apk = applicationInfo.sourceDir
            @Suppress("DEPRECATION")
            val dex = DexFile(apk)
            try {
                var total = 0
                var biz = 0
                val en = dex.entries()
                while (en.hasMoreElements()) {
                    total++
                    val name = en.nextElement()
                    if (name != null && name.startsWith("com.yqsh.protectordemo")) {
                        biz++
                    }
                }
                Log.i(TAG, "dexScan: total=$total biz=$biz apk=$apk")
            } finally {
                try {
                    dex.close()
                } catch (_: Throwable) {
                }
            }
        } catch (t: Throwable) {
            Log.w(TAG, "dexScan: failed", t)
        }
    }

    private fun safeNativeVersion(): String {
        if (!isProtectorPacked()) {
            return "unpacked"
        }
        return try {
            ProtectorShell.nativeVersion()
        } catch (t: Throwable) {
            "unavailable: ${t.message}"
        }
    }

    companion object {
        private const val TAG = "protector.DemoApp"
    }
}

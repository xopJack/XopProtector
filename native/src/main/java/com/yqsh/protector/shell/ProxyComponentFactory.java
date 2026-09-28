package com.yqsh.protector.shell;

import android.annotation.TargetApi;
import android.app.AppComponentFactory;
import android.app.Application;
import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.util.Log;

import androidx.annotation.Keep;
import androidx.annotation.NonNull;

import java.io.File;

@Keep
@TargetApi(28)
public class ProxyComponentFactory extends AppComponentFactory {
    private static final String TAG = "protector.ProxyACF";
    private static volatile boolean bootstrapped;

    /** True after {@link FileBootstrap} completed (Application path can skip heavy work). */
    static boolean isBootstrapped() {
        return bootstrapped;
    }

    @NonNull
    @Override
    public ClassLoader instantiateClassLoader(@NonNull ClassLoader cl, @NonNull ApplicationInfo aInfo) {
        Log.d(TAG, "instantiateClassLoader");
        // Finalize PathClassLoader (all classesN.dex including junk) BEFORE shell
        // init — otherwise ART hooks may run junk integrity checks against an
        // incomplete loader and false-positive hang.
        ClassLoader ready = super.instantiateClassLoader(cl, aInfo);
        try {
            FileBootstrap.bootstrap(aInfo, ready);
            bootstrapped = true;
        } catch (Throwable t) {
            Log.e(TAG, "early init failed", t);
            // Fail closed — same rationale as ProxyApplication.attachBaseContext.
            throw new ExceptionInInitializerError(t);
        }
        return ready;
    }

    @NonNull
    @Override
    public Application instantiateApplication(@NonNull ClassLoader cl, @NonNull String className)
            throws InstantiationException, IllegalAccessException, ClassNotFoundException {
        Log.d(TAG, "instantiateApplication " + className);
        Application app = super.instantiateApplication(cl, className);
        // Heartbeat JNI only needs the Application instance, not a base Context.
        ProxyApplication.onShellInstantiated(app);
        // Prefer verifying here once a Context exists (ACF early path may lack one).
        tryVerifySignature(app);
        return app;
    }

    static void tryVerifySignature(Context context) {
        if (context == null) return;
        // Application from instantiateApplication() often has no base Context yet;
        // calling into JNI here trips CheckJNI fatally. Defer until attachBaseContext.
        try {
            if (context.getPackageManager() == null) return;
        } catch (Throwable ignored) {
            return;
        }
        try {
            JniBridge.verifySignature(context);
        } catch (Throwable t) {
            Log.e(TAG, "verifySignature failed", t);
        }
    }

    /**
     * Bootstrap without a Context — uses ApplicationInfo.dataDir/code cache conventions.
     */
    static final class FileBootstrap {
        static void bootstrap(ApplicationInfo aInfo, ClassLoader cl) throws Exception {
            if (bootstrapped) return;
            File codeCache = new File(aInfo.dataDir, "code_cache/" + StrEnc.d(new byte[]{
                    0x2a, 0x33, 0x03, 0x7f, 0x53, (byte)0xbe, (byte)0x8c, (byte)0x88, (byte)0xf0
            }));
            if (!codeCache.exists()) codeCache.mkdirs();

            File apk = new File(aInfo.sourceDir);
            ProxyApplication.invalidateIfApkChanged(codeCache, apk);

            // Warm: classes*.dex already prepatched — skip re-copying/decrypting dexes.zip.
            boolean warm = DexMerger.hasWarmCache(codeCache);
            if (!warm) {
                extractFromApk(apk, "assets/protector/dexes.zip", new File(codeCache,
                        StrEnc.d(new byte[]{
                                0x3e, 0x24, 0x14, 0x6e, 0x45, (byte)0xf3, (byte)0x82, (byte)0x8e, (byte)0xf2
                        })), true);
            } else {
                Log.i(TAG, "warm cache: skip dexes.zip extract");
            }
            File codeBin = new File(codeCache,
                    StrEnc.d(new byte[]{
                            0x39, 0x2e, 0x08, 0x6e, 0x18, (byte)0xbf, (byte)0x91, (byte)0x89
                    }));
            File configJson = new File(codeCache,
                    StrEnc.d(new byte[]{
                            0x39, 0x2e, 0x02, 0x6d, 0x5f, (byte)0xba, (byte)0xd6, (byte)0x8d, (byte)0xf1,
                            (byte)0xc6, 0x3a
                    }));
            if (!warm || !codeBin.isFile() || codeBin.length() == 0) {
                extractFromApk(apk, "assets/protector/code.bin", codeBin);
            }
            if (!warm || !configJson.isFile() || configJson.length() == 0) {
                extractFromApk(apk, "assets/protector/config.json", configJson);
            }
            // Optional — present when packer used --protect-so (needed each launch for keys).
            try {
                extractFromApk(apk, "assets/protector/sokeys.bin", new File(codeCache,
                        StrEnc.d(new byte[]{
                                0x29, 0x2e, 0x07, 0x6e, 0x4f, (byte)0xae, (byte)0xd6, (byte)0x85,
                                (byte)0xeb, (byte)0xc7
                        })));
            } catch (Throwable ignored) {
                // missing sokeys.bin is fine when --protect-so was not used
            }
            // Optional — Phase 3 NetGuard
            try {
                extractFromApk(apk, "assets/protector/netguard.json", new File(codeCache,
                        StrEnc.d(new byte[]{
                                0x34, 0x24, 0x18, 0x6c, 0x43, (byte)0xbc, (byte)0x8a, (byte)0x83,
                                (byte)0xac, (byte)0xc3, 0x27, 0x1c, 0x70
                        })));
            } catch (Throwable ignored) {
            }
            // Optional — packer so_text_diag for runtime .text integrity checks
            try {
                extractFromApk(apk, "assets/protector/so_text_diag.json", new File(codeCache,
                        StrEnc.d(new byte[]{
                                0x29, 0x2e, 0x33, 0x7f, 0x53, (byte)0xa5, (byte)0x8c, (byte)0xb8,
                                (byte)0xe6, (byte)0xc0, 0x35, 0x14, 0x30, 0x6f, 0x53, (byte)0xa0,
                                (byte)0x84
                        })));
            } catch (Throwable ignored) {
            }
            ProxyApplication.writeStamp(codeCache, apk);

            System.loadLibrary("protector");
            // Packaged extract dir — must be set before initApp materialize (before redirect).
            if (aInfo.nativeLibraryDir != null) {
                JniBridge.setNativeLibraryDir(aInfo.nativeLibraryDir);
            }
            JniBridge.initApp(codeCache.getAbsolutePath(), aInfo.packageName, aInfo.sourceDir);
            // Keep ApplicationInfo.nativeLibraryDir on packaged extract (path-sensitive
            // OSG/Teigha). ClassLoader: plaintext helper first so keyed SOs are not
            // mapped from extract ciphertext (libxcrash JNI_OnLoad SIGILL).
            String packaged = aInfo.nativeLibraryDir;
            File helper = NativeLibDirRedirect.apply(aInfo, codeCache);
            if (helper != null) {
                NativeLibDirRedirect.patchClassLoader(cl,
                        helper.getAbsolutePath(), packaged);
            }
            DexMerger.merge(cl, codeCache);
            JniBridge.finishBusinessSoDecrypt();
            JniBridge.enableJunkVerify();

            // Application may not exist yet; try ActivityThread.currentApplication().
            try {
                Class<?> at = Class.forName("android.app.ActivityThread");
                Object cur = at.getMethod("currentApplication").invoke(null);
                if (cur instanceof Context) {
                    tryVerifySignature((Context) cur);
                }
            } catch (Throwable ignored) {
            }
        }

        private static void extractFromApk(File apk, String entryName, File out) throws Exception {
            extractFromApk(apk, entryName, out, false);
        }

        /**
         * @param forceOverwrite when true, replace any leftover (needed for
         *        {@code dexes.zip}: a prior launch may have left plaintext PDX1
         *        fallback bytes that would fail {@code dex_hmac}).
         */
        private static void extractFromApk(File apk, String entryName, File out, boolean forceOverwrite)
                throws Exception {
            if (!forceOverwrite && out.exists() && out.length() > 0) return;
            try (java.util.zip.ZipFile zf = new java.util.zip.ZipFile(apk)) {
                java.util.zip.ZipEntry e = zf.getEntry(entryName);
                if (e == null) {
                    if (entryName.endsWith("sokeys.bin") || entryName.endsWith("netguard.json")) {
                        return; // optional
                    }
                    throw new IllegalStateException("missing " + entryName);
                }
                try (java.io.InputStream in = zf.getInputStream(e);
                     java.io.FileOutputStream fos = new java.io.FileOutputStream(out)) {
                    byte[] buf = new byte[256 * 1024];
                    int n;
                    while ((n = in.read(buf)) > 0) fos.write(buf, 0, n);
                }
            }
        }
    }
}

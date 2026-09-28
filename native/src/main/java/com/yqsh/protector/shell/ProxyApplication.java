package com.yqsh.protector.shell;

import android.app.Application;
import android.content.ComponentCallbacks;
import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.os.Build;
import android.text.TextUtils;
import android.util.Log;

import androidx.annotation.Keep;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

@Keep
public class ProxyApplication extends Application {
    // Rolling-XOR encoded (Phase 4 StrEnc) — "protector.ProxyApp"
    private static final String TAG = StrEnc.d(new byte[]{
            0x2a, 0x33, 0x03, 0x7f, 0x53, (byte)0xbe, (byte)0x8c, (byte)0x88, (byte)0xf0, (byte)0x87,
            0x04, 0x01, 0x71, 0x7d, 0x59, (byte)0x8e, (byte)0x9a, (byte)0xe1
    });
    // "protector/dexes.zip"
    private static final String DEXES_ASSET = StrEnc.d(new byte[]{
            0x2a, 0x33, 0x03, 0x7f, 0x53, (byte)0xbe, (byte)0x8c, (byte)0x88, (byte)0xf0, (byte)0x86,
            0x30, 0x16, 0x66, 0x60, 0x53, (byte)0xe1, (byte)0x90, (byte)0xf8, (byte)0xcc
    });
    // "protector/code.bin"
    private static final String CODE_ASSET = StrEnc.d(new byte[]{
            0x2a, 0x33, 0x03, 0x7f, 0x53, (byte)0xbe, (byte)0x8c, (byte)0x88, (byte)0xf0, (byte)0x86,
            0x37, 0x1c, 0x7a, 0x60, 0x0e, (byte)0xad, (byte)0x83, (byte)0xff
    });
    // "protector/config.json"
    private static final String CONFIG_ASSET = StrEnc.d(new byte[]{
            0x2a, 0x33, 0x03, 0x7f, 0x53, (byte)0xbe, (byte)0x8c, (byte)0x88, (byte)0xf0, (byte)0x86,
            0x37, 0x1c, 0x70, 0x63, 0x49, (byte)0xa8, (byte)0xc4, (byte)0xfb, (byte)0xcf, 0x34, 0x28
    });
    // "protector/sokeys.bin"
    private static final String SOKEYS_ASSET = StrEnc.d(new byte[]{
            0x2a, 0x33, 0x03, 0x7f, 0x53, (byte)0xbe, (byte)0x8c, (byte)0x88, (byte)0xf0, (byte)0x86,
            0x27, 0x1c, 0x75, 0x60, 0x59, (byte)0xbc, (byte)0xc4, (byte)0xf3, (byte)0xd5, 0x35
    });
    private static final String STAMP_FILE = ".apk_stamp";
    // "protector"
    private static final String CACHE_DIR = StrEnc.d(new byte[]{
            0x2a, 0x33, 0x03, 0x7f, 0x53, (byte)0xbe, (byte)0x8c, (byte)0x88, (byte)0xf0
    });
    // "code.bin"
    private static final String CODE_BIN = StrEnc.d(new byte[]{
            0x39, 0x2e, 0x08, 0x6e, 0x18, (byte)0xbf, (byte)0x91, (byte)0x89
    });
    // "dexes.zip"
    private static final String DEXES_ZIP = StrEnc.d(new byte[]{
            0x3e, 0x24, 0x14, 0x6e, 0x45, (byte)0xf3, (byte)0x82, (byte)0x8e, (byte)0xf2
    });
    // "config.json"
    private static final String CONFIG_JSON = StrEnc.d(new byte[]{
            0x39, 0x2e, 0x02, 0x6d, 0x5f, (byte)0xba, (byte)0xd6, (byte)0x8d, (byte)0xf1, (byte)0xc6, 0x3a
    });
    // "sokeys.bin"
    private static final String SOKEYS_BIN = StrEnc.d(new byte[]{
            0x29, 0x2e, 0x07, 0x6e, 0x4f, (byte)0xae, (byte)0xd6, (byte)0x85, (byte)0xeb, (byte)0xc7
    });
    // "protector/netguard.json"
    private static final String NETGUARD_ASSET = StrEnc.d(new byte[]{
            0x2a, 0x33, 0x03, 0x7f, 0x53, (byte)0xbe, (byte)0x8c, (byte)0x88, (byte)0xf0, (byte)0x86,
            0x3a, 0x16, 0x6a, 0x62, 0x55, (byte)0xae, (byte)0x98, (byte)0xf5, (byte)0x92, 0x31, 0x35, 0x02, 0x66
    });
    // "netguard.json"
    private static final String NETGUARD_JSON = StrEnc.d(new byte[]{
            0x34, 0x24, 0x18, 0x6c, 0x43, (byte)0xbc, (byte)0x8a, (byte)0x83, (byte)0xac, (byte)0xc3, 0x27, 0x1c, 0x70
    });
    // "protector/so_text_diag.json"
    private static final String SO_TEXT_DIAG_ASSET = StrEnc.d(new byte[]{
            0x2a, 0x33, 0x03, 0x7f, 0x53, (byte)0xbe, (byte)0x8c, (byte)0x88, (byte)0xf0, (byte)0x86,
            0x27, 0x1c, 0x41, 0x71, 0x45, (byte)0xb7, (byte)0x9e, (byte)0xce, (byte)0xd8, 0x32,
            0x27, 0x0a, 0x26, 0x5d, (byte)0xa1, (byte)0x96, (byte)0x8a
    });
    // "so_text_diag.json"
    private static final String SO_TEXT_DIAG_JSON = StrEnc.d(new byte[]{
            0x29, 0x2e, 0x33, 0x7f, 0x53, (byte)0xa5, (byte)0x8c, (byte)0xb8, (byte)0xe6, (byte)0xc0,
            0x35, 0x14, 0x30, 0x6f, 0x53, (byte)0xa0, (byte)0x84
    });

    private String realApplicationName = "";
    private Application realApplication;
    private boolean classLoaderReady;
    /** True after ActivityThread/LoadedApk point at the real Application (attach done). */
    private boolean replaced;
    /** True after real Application.onCreate(); must not run during ContentProvider install. */
    private boolean realOnCreateCalled;
    private static volatile boolean heartbeatStarted;

    /** Registrations received while this Proxy is still the live Application. */
    private final List<ActivityLifecycleCallbacks> pendingActivityLifecycleCallbacks = new ArrayList<>();
    private final List<ComponentCallbacks> pendingComponentCallbacks = new ArrayList<>();
    private final List<OnProvideAssistDataListener> pendingAssistCallbacks = new ArrayList<>();

    @Override
    public void registerActivityLifecycleCallbacks(ActivityLifecycleCallbacks callback) {
        super.registerActivityLifecycleCallbacks(callback);
        if (callback == null) {
            return;
        }
        synchronized (pendingActivityLifecycleCallbacks) {
            pendingActivityLifecycleCallbacks.add(callback);
        }
    }

    @Override
    public void unregisterActivityLifecycleCallbacks(ActivityLifecycleCallbacks callback) {
        super.unregisterActivityLifecycleCallbacks(callback);
        if (callback == null) {
            return;
        }
        synchronized (pendingActivityLifecycleCallbacks) {
            pendingActivityLifecycleCallbacks.remove(callback);
        }
    }

    @Override
    public void registerComponentCallbacks(ComponentCallbacks callback) {
        super.registerComponentCallbacks(callback);
        if (callback == null) {
            return;
        }
        synchronized (pendingComponentCallbacks) {
            pendingComponentCallbacks.add(callback);
        }
    }

    @Override
    public void unregisterComponentCallbacks(ComponentCallbacks callback) {
        super.unregisterComponentCallbacks(callback);
        if (callback == null) {
            return;
        }
        synchronized (pendingComponentCallbacks) {
            pendingComponentCallbacks.remove(callback);
        }
    }

    @Override
    public void registerOnProvideAssistDataListener(OnProvideAssistDataListener callback) {
        super.registerOnProvideAssistDataListener(callback);
        if (callback == null) {
            return;
        }
        synchronized (pendingAssistCallbacks) {
            pendingAssistCallbacks.add(callback);
        }
    }

    @Override
    public void unregisterOnProvideAssistDataListener(OnProvideAssistDataListener callback) {
        super.unregisterOnProvideAssistDataListener(callback);
        if (callback == null) {
            return;
        }
        synchronized (pendingAssistCallbacks) {
            pendingAssistCallbacks.remove(callback);
        }
    }

    /**
     * Move callbacks registered on this Proxy onto {@code real} via public APIs
     * (works when hidden-API reflection to {@code mCallbacksController} is blocked).
     */
    void transferCallbacksTo(Application real) {
        if (real == null || real == this) {
            return;
        }
        transferActivityLifecycle(real);
        transferComponentCallbacks(real);
        transferAssistCallbacks(real);
    }

    private void transferActivityLifecycle(Application real) {
        List<ActivityLifecycleCallbacks> moved;
        synchronized (pendingActivityLifecycleCallbacks) {
            if (pendingActivityLifecycleCallbacks.isEmpty()) {
                return;
            }
            moved = new ArrayList<>(pendingActivityLifecycleCallbacks);
            pendingActivityLifecycleCallbacks.clear();
        }
        int added = 0;
        for (ActivityLifecycleCallbacks cb : moved) {
            try {
                unregisterActivityLifecycleCallbacks(cb);
            } catch (Throwable ignored) {
            }
            try {
                real.registerActivityLifecycleCallbacks(cb);
                added++;
            } catch (Throwable t) {
                Log.w(TAG, "transfer ActivityLifecycleCallbacks failed", t);
            }
        }
        Log.i(TAG, "transferred ActivityLifecycleCallbacks count=" + added
                + " to=" + real.getClass().getName());
    }

    private void transferComponentCallbacks(Application real) {
        List<ComponentCallbacks> moved;
        synchronized (pendingComponentCallbacks) {
            if (pendingComponentCallbacks.isEmpty()) {
                return;
            }
            moved = new ArrayList<>(pendingComponentCallbacks);
            pendingComponentCallbacks.clear();
        }
        int added = 0;
        for (ComponentCallbacks cb : moved) {
            try {
                unregisterComponentCallbacks(cb);
            } catch (Throwable ignored) {
            }
            try {
                real.registerComponentCallbacks(cb);
                added++;
            } catch (Throwable t) {
                Log.w(TAG, "transfer ComponentCallbacks failed", t);
            }
        }
        Log.i(TAG, "transferred ComponentCallbacks count=" + added
                + " to=" + real.getClass().getName());
    }

    private void transferAssistCallbacks(Application real) {
        List<OnProvideAssistDataListener> moved;
        synchronized (pendingAssistCallbacks) {
            if (pendingAssistCallbacks.isEmpty()) {
                return;
            }
            moved = new ArrayList<>(pendingAssistCallbacks);
            pendingAssistCallbacks.clear();
        }
        int added = 0;
        for (OnProvideAssistDataListener cb : moved) {
            try {
                unregisterOnProvideAssistDataListener(cb);
            } catch (Throwable ignored) {
            }
            try {
                real.registerOnProvideAssistDataListener(cb);
                added++;
            } catch (Throwable t) {
                Log.w(TAG, "transfer AssistCallbacks failed", t);
            }
        }
        Log.i(TAG, "transferred AssistCallbacks count=" + added
                + " to=" + real.getClass().getName());
    }

    @Override
    protected void attachBaseContext(Context base) {
        super.attachBaseContext(base);
        try {
            bootstrap(base, this);
            classLoaderReady = true;
            realApplicationName = safe(JniBridge.readApplicationName());
            Log.i(TAG, "shell init done, realApp=" + realApplicationName);
            // Replace before ContentProvider install / DCloud path setup.
            // Returning "" from getPackageName() (legacy dpt-shell trick) breaks
            // UniApp (empty sPackageName, Android/data//). Early replace makes
            // Providers attach to the real Application without that trick.
            replaceApplication(false);
        } catch (Throwable t) {
            Log.e(TAG, "shell init failed", t);
            // Fail closed: a half-initialized shell leaves hollow stubs / missing
            // business Application and is harder to diagnose than a hard crash.
            throw new ExceptionInInitializerError(t);
        }
    }

    /** Shared bootstrap used by Application and AppComponentFactory. */
    public static void bootstrap(Context context, Application shell) throws Exception {
        HiddenApiBypass.exemptAll();
        if (!hasProtectionAssets(context)) {
            Log.i(TAG, "no protection assets, skip shell init");
            return;
        }
        File dir = ensureDexesOnDisk(context);
        // ACF already ran heavy init — only bind Context + signature/heartbeat.
        // AppComponentFactory (API 28+). Do not touch ProxyComponentFactory on older
        // APIs — loading it fails verification (superclass AppComponentFactory missing).
        if (Build.VERSION.SDK_INT >= 28 && ProxyComponentFactory.isBootstrapped()) {
            NativeLibDirRedirect.apply(context, dir);
            JniBridge.verifySignature(context);
            startHeartbeat(shell);
            try {
                NetGuard.install(context);
            } catch (Throwable t) {
                Log.w(TAG, "NetGuard.install skipped", t);
            }
            try {
                CrashGuard.install();
            } catch (Throwable t) {
                Log.w(TAG, "CrashGuard.install skipped", t);
            }
            return;
        }
        ApplicationInfo ai = context.getApplicationInfo();
        // Packaged extract dir for JNI materialize (ciphertext source).
        // ApplicationInfo.nativeLibraryDir stays on extract (path-sensitive OSG).
        String packagedLib = ai != null ? ai.nativeLibraryDir : null;
        if (packagedLib != null) {
            JniBridge.setNativeLibraryDir(packagedLib);
        }
        String pkg = context.getPackageName();
        String apkPath = ai != null ? ai.sourceDir : null;
        JniBridge.initApp(dir.getAbsolutePath(), pkg, apkPath);
        // Ping before DexMerger / SO decrypt — init_app already armed the timer.
        startHeartbeat(shell);
        NativeLibDirRedirect.apply(context, dir);
        DexMerger.merge(context.getClassLoader(), dir);
        // API≤24 x86: defer SO preload — L2/L3 verneed is flaky; ensureBusinessSo decrypts later.
        if (Build.VERSION.SDK_INT > 24) {
            JniBridge.finishBusinessSoDecrypt();
        } else {
            Log.i(TAG, "skip finishBusinessSoDecrypt on API " + Build.VERSION.SDK_INT);
        }
        JniBridge.enableJunkVerify();
        JniBridge.verifySignature(context);
        try {
            NetGuard.install(context);
        } catch (Throwable t) {
            Log.w(TAG, "NetGuard.install skipped", t);
        }
        try {
            CrashGuard.install();
        } catch (Throwable t) {
            Log.w(TAG, "CrashGuard.install skipped", t);
        }
    }

    /** ACF: start pings as soon as the shell Application exists (after FileBootstrap). */
    static void onShellInstantiated(Application app) {
        if (app instanceof ProxyApplication) {
            startHeartbeat(app);
        }
    }

    /** Periodic Java→Native heartbeat so the native risk thread
     *  can detect Java-layer tampering. Pass the live {@code ProxyApplication}
     *  ({@code this} in {@link #attachBaseContext}); do not use
     *  {@code ActivityThread.currentApplication()} after replace. */
    private static void startHeartbeat(Application shell) {
        if (heartbeatStarted) return;
        heartbeatStarted = true;
        Thread t = new Thread(() -> {
            while (true) {
                try {
                    JniBridge.heartbeat(shell);
                    Thread.sleep(5000);
                } catch (Throwable ignored) {
                    // If heartbeat fails the native side will notice the
                    // missing ping and crash the process itself.
                }
            }
        }, "protector-hb");
        t.setDaemon(true);
        t.start();
    }

    @Override
    public void onCreate() {
        super.onCreate();
        replaceApplication(true);
    }

    @Override
    public Context createPackageContext(String packageName, int flags)
            throws PackageManager.NameNotFoundException {
        if (!TextUtils.isEmpty(realApplicationName)) {
            // Attach real Application for ContentProviders; defer onCreate to Application.onCreate.
            replaceApplication(false);
            if (realApplication != null) {
                return realApplication;
            }
        }
        return super.createPackageContext(packageName, flags);
    }

    /**
     * Always return the real package name.
     * <p>Legacy shells returned {@code ""} before replace so Provider install went through
     * {@link #createPackageContext} (dpt-shell). That breaks UniApp/DCloud
     * ({@code sPackageName=} empty, {@code Android/data//} paths). We now
     * {@link #replaceApplication(boolean) replace early} in {@link #attachBaseContext},
     * and keep {@link #createPackageContext} as a fallback if replace was deferred.
     */
    @Override
    public String getPackageName() {
        return super.getPackageName();
    }

    private void replaceApplication(boolean invokeOnCreate) {
        if (!classLoaderReady || TextUtils.isEmpty(realApplicationName)) {
            return;
        }
        try {
            if (!replaced) {
                // Mark replaced BEFORE makeApplication/attach so Sophix/real APP
                // attachBaseContext sees a consistent Application identity.
                replaced = true;
                realApplication = ApplicationReplacer.replace(realApplicationName);
                if (realApplication == null) {
                    replaced = false;
                }
            } else if (invokeOnCreate && realApplication != null) {
                // Outer LoadedApk.makeApplication overwrote mApplication /
                // mInitialApplication back to this Proxy after early replace.
                // Re-pin so Activity.getApplication() is the real Application.
                ApplicationReplacer.reattach(realApplication, this);
            }
            if (invokeOnCreate && realApplication != null && !realOnCreateCalled) {
                // Providers already ran under the replaced Application. Clear the
                // pending list so Sophix does not re-install (AutoSize InitProvider etc.).
                ApplicationReplacer.markProvidersAlreadyInstalled();
                invokeRealApplicationOnCreate(realApplication);
                realOnCreateCalled = true;
            }
        } catch (Throwable t) {
            Log.e(TAG, "replace real Application failed", t);
        }
    }

    /**
     * Invoke Application.onCreate with Sophix-compatible recovery: if Sophix
     * still abandons on installProviders, call the business Application.onCreate
     * that Sophix already attached (keeps packer path unified — no --application).
     */
    private void invokeRealApplicationOnCreate(Application app) {
        try {
            app.onCreate();
            Log.i(TAG, "real Application.onCreate called: " + app.getClass().getName());
            return;
        } catch (Throwable t) {
            if (!isSophixProvidersAbandon(t)) {
                Log.e(TAG, "real Application.onCreate failed", t);
                return;
            }
            Log.w(TAG, "Sophix abandoned installProviders; calling business Application.onCreate", t);
        }
        Application business = ApplicationReplacer.findBusinessApplication(app);
        if (business == null) {
            Log.e(TAG, "no business Application found after Sophix abandon");
            return;
        }
        try {
            ApplicationReplacer.reattach(business, this);
            realApplication = business;
            business.onCreate();
            Log.i(TAG, "business Application.onCreate called: " + business.getClass().getName());
        } catch (Throwable t) {
            Log.e(TAG, "business Application.onCreate failed", t);
        }
    }

    private static boolean isSophixProvidersAbandon(Throwable t) {
        for (Throwable c = t; c != null; c = c.getCause()) {
            String msg = c.getMessage();
            if (msg != null && msg.contains("abandon initialization") && msg.contains("installProviders")) {
                return true;
            }
            if (msg != null && msg.contains("AutoSizeConfig#init() can only be called once")) {
                return true;
            }
        }
        return false;
    }

    private static boolean hasProtectionAssets(Context context) {
        try {
            String[] names = context.getAssets().list(CACHE_DIR);
            if (names == null) return false;
            boolean hasCode = false;
            boolean hasDexes = false;
            for (String n : names) {
                if (CODE_BIN.equals(n)) hasCode = true;
                if (DEXES_ZIP.equals(n)) hasDexes = true;
            }
            return hasCode && hasDexes;
        } catch (Exception e) {
            return false;
        }
    }

    static File ensureDexesOnDisk(Context context) throws Exception {
        ApplicationInfo info = context.getApplicationInfo();
        File outDir = new File(context.getCodeCacheDir(), CACHE_DIR);
        if (!outDir.exists() && !outDir.mkdirs()) {
            throw new IllegalStateException("cannot create " + outDir);
        }
        invalidateIfApkChanged(outDir, new File(info.sourceDir));

        File outZip = new File(outDir, DEXES_ZIP);
        // Warm: reuse prepatched classes*.dex; skip re-copying PDX1/dexes.zip.
        boolean warm = DexMerger.hasWarmCache(outDir);
        if (!warm && !(outZip.exists() && outZip.length() > 0)) {
            try (ZipFile apk = new ZipFile(info.sourceDir)) {
                ZipEntry entry = apk.getEntry("assets/" + DEXES_ASSET);
                if (entry != null) {
                    try (InputStream in = apk.getInputStream(entry);
                         FileOutputStream out = new FileOutputStream(outZip)) {
                        copy(in, out);
                    }
                } else {
                    try (InputStream in = context.getAssets().open(DEXES_ASSET);
                         FileOutputStream out = new FileOutputStream(outZip)) {
                        copy(in, out);
                    }
                }
            }
        }
        copyAsset(context, CODE_ASSET, new File(outDir, CODE_BIN));
        copyAsset(context, CONFIG_ASSET, new File(outDir, CONFIG_JSON));
        // Optional — only present when packer used --protect-so
        copyAsset(context, SOKEYS_ASSET, new File(outDir, SOKEYS_BIN));
        // Optional — Phase 3 NetGuard config
        copyAsset(context, NETGUARD_ASSET, new File(outDir, NETGUARD_JSON));
        // Optional — packer so_text_diag for runtime .text integrity (P3)
        copyAsset(context, SO_TEXT_DIAG_ASSET, new File(outDir, SO_TEXT_DIAG_JSON));
        writeStamp(outDir, new File(info.sourceDir));
        return outDir;
    }

    /** Clear cached protector assets when APK mtime/length changes. */
    static void invalidateIfApkChanged(File outDir, File apk) {
        if (apk == null || !apk.isFile()) return;
        String expected = apkStamp(apk);
        File stampFile = new File(outDir, STAMP_FILE);
        String actual = null;
        if (stampFile.isFile()) {
            try (FileInputStream in = new FileInputStream(stampFile)) {
                byte[] buf = new byte[128];
                int n = in.read(buf);
                if (n > 0) {
                    actual = new String(buf, 0, n, StandardCharsets.UTF_8).trim();
                }
            } catch (Exception ignored) {
            }
        }
        if (expected.equals(actual)) return;
        deleteQuietly(new File(outDir, DEXES_ZIP));
        deleteQuietly(new File(outDir, CODE_BIN));
        deleteQuietly(new File(outDir, CONFIG_JSON));
        deleteQuietly(new File(outDir, SOKEYS_BIN));
        deleteQuietly(new File(outDir, NETGUARD_JSON));
        deleteQuietly(new File(outDir, SO_TEXT_DIAG_JSON));
        // Extracted hollow dexes must not survive APK updates — DexMerger skips
        // rewrite when classes*.dex already exists with non-zero length.
        deleteExtractedDexes(outDir);
        deleteQuietly(new File(outDir, ".prepatched"));
        deleteQuietly(new File(new File(outDir, "so_plain"), "so_plain_ready"));
        deleteQuietly(new File(outDir, "dex_bundle.zip")); // legacy from brief experiment
        deleteDir(new File(outDir, "so_plain"));
        deleteDir(new File(outDir, "lib_mirror"));
        deleteDir(new File(outDir, "so_cipher"));
        deleteDir(new File(outDir, "so_warm"));
        deleteQuietly(stampFile);
        Log.i(TAG, "protector cache invalidated for new APK");
    }

    /** Remove leftover classes*.dex under the protector code-cache dir. */
    static void deleteExtractedDexes(File outDir) {
        if (outDir == null || !outDir.isDirectory()) return;
        File[] files = outDir.listFiles();
        if (files == null) return;
        for (File f : files) {
            if (f == null || !f.isFile()) continue;
            String n = f.getName();
            if (n.startsWith("classes") && n.endsWith(".dex")) {
                deleteQuietly(f);
            }
        }
    }

    private static void deleteDir(File dir) {
        if (dir == null || !dir.exists()) return;
        File[] files = dir.listFiles();
        if (files != null) {
            for (File f : files) {
                if (f == null) continue;
                if (f.isDirectory()) deleteDir(f);
                else deleteQuietly(f);
            }
        }
        deleteQuietly(dir);
    }

    static void writeStamp(File outDir, File apk) {
        if (apk == null || !apk.isFile()) return;
        try (FileOutputStream out = new FileOutputStream(new File(outDir, STAMP_FILE))) {
            out.write(apkStamp(apk).getBytes(StandardCharsets.UTF_8));
        } catch (Exception ignored) {
        }
    }

    static String apkStamp(File apk) {
        return apk.lastModified() + ":" + apk.length();
    }

    private static void deleteQuietly(File f) {
        if (f != null && f.exists()) {
            //noinspection ResultOfMethodCallIgnored
            f.delete();
        }
    }

    private static void copyAsset(Context context, String asset, File dest) {
        if (dest.exists() && dest.length() > 0) return;
        try (InputStream in = context.getAssets().open(asset);
             FileOutputStream out = new FileOutputStream(dest)) {
            copy(in, out);
        } catch (Exception e) {
            // sokeys.bin is optional unless packer set protect_so (native fail-closes).
            Log.w(TAG, "copyAsset failed: " + asset + " → " + dest.getName()
                    + " (" + e.getClass().getSimpleName() + ")");
        }
    }

    private static void copy(InputStream in, FileOutputStream out) throws Exception {
        byte[] buf = new byte[256 * 1024];
        int n;
        while ((n = in.read(buf)) > 0) {
            out.write(buf, 0, n);
        }
        out.flush();
    }

    private static String safe(String s) {
        return s == null ? "" : s.trim();
    }
}

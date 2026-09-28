package com.yqsh.protector.shell;

import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.util.Log;

import androidx.annotation.Keep;

import java.io.File;
import java.lang.reflect.Array;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.List;

/**
 * Native lib path policy for protect-so.
 * <p>
 * <b>Do not</b> rewrite {@link ApplicationInfo#nativeLibraryDir} to
 * {@code lib_mirror}/{@code so_plain}. Hi-MC / Teigha / OSG path-sensitive
 * megacores ({@code libd3}, {@code libzhd3d}) require the stock packaged
 * extract path ({@code /data/app/.../lib/&lt;abi&gt;}) for
 * {@code ApplicationInfo}, {@code dladdr}, and {@code /proc/self/maps}
 * dirname semantics. Decrypt is proven bit-identical to the original SO;
 * wrong display was caused by path redirect, not RC4.
 * <p>
 * Keyed loads go through native dlopen hooks: L1 publish onto extract when
 * writable; path-sensitive megacores (large Teigha/OSG) map the packaged
 * extract inode and decrypt {@code .text} in memory; other keyed SOs use
 * helper-first {@code so_plain}/{@code lib_mirror} so {@code loadLibrary}
 * never maps packaged ciphertext (e.g. {@code libxcrash} SIGILL).
 * {@code lib_mirror} remains a helper tree but must not become
 * {@code nativeLibraryDir}.
 * <p>
 * ClassLoader searches the plaintext helper <b>first</b> so {@code loadLibrary}
 * never maps packaged ciphertext (aggressive encrypts industry libs such as
 * {@code libxcrash}; ART {@code LoadNativeLibrary} would SIGILL in
 * {@code JNI_OnLoad}). {@code lib_mirror}/{@code so_plain} first, packaged
 * extract as fallback. {@link ApplicationInfo#nativeLibraryDir} stays packaged.
 * <p>
 * APK-agnostic — no customer package names.
 */
@Keep
final class NativeLibDirRedirect {
    private static final String TAG = "protector.SoDir";

    private NativeLibDirRedirect() {
    }

    static void apply(Context context, File protectorDir) {
        if (context == null || protectorDir == null) return;
        ApplicationInfo ai = context.getApplicationInfo();
        File plain = apply(ai, protectorDir);
        if (plain == null) return;
        try {
            // Keep LoadedApk / ApplicationInfo on packaged extract.
            String packaged = ai != null ? ai.nativeLibraryDir : null;
            patchClassLoader(context.getClassLoader(), plain.getAbsolutePath(), packaged);
        } catch (Throwable t) {
            Log.w(TAG, "ClassLoader patch skipped", t);
        }
    }

    /**
     * Prefer {@code lib_mirror} when populated; else {@code so_plain}.
     * Used only as ClassLoader <b>fallback</b> after packaged extract.
     */
    static File resolveLibDir(File protectorDir) {
        if (protectorDir == null) return null;
        File mirror = new File(protectorDir, "lib_mirror");
        if (mirror.isDirectory()) {
            String[] kids = mirror.list();
            if (kids != null && kids.length > 0) return mirror;
        }
        File plain = new File(protectorDir, "so_plain");
        if (plain.isDirectory()) return plain;
        return null;
    }

    /**
     * Used from AppComponentFactory before a Context exists.
     * Callers must {@code setNativeLibraryDir(packaged)} before init.
     * <b>Does not</b> change {@code ai.nativeLibraryDir}.
     * @return plaintext helper dir for ClassLoader fallback, else null
     */
    static File apply(ApplicationInfo ai, File protectorDir) {
        if (ai == null || protectorDir == null) return null;
        File plain = resolveLibDir(protectorDir);
        if (plain == null) {
            return null;
        }
        String original = ai.nativeLibraryDir;
        Log.i(TAG, "nativeLibraryDir kept packaged=" + original
                + " (plaintext helper=" + plain.getName() + ", not redirected)");
        return plain;
    }

    /**
     * Plaintext helper first so {@code loadLibrary} never maps packaged
     * ciphertext. Packaged extract is fallback. {@link ApplicationInfo#nativeLibraryDir}
     * stays packaged (see {@link #apply}).
     */
    static void patchClassLoader(ClassLoader cl, String plainDir) {
        patchClassLoader(cl, plainDir, null);
    }

    static void patchClassLoader(ClassLoader cl, String plainDir, String packagedDir) {
        if (cl == null || plainDir == null || plainDir.isEmpty()) return;
        try {
            Object pathList = getField(cl, "pathList");
            if (pathList == null) return;

            // findLibrary() only walks nativeLibraryPathElements. Updating
            // nativeLibraryDirectories alone is a no-op on API 26+ if
            // makePathElements(List) is missing — ART then maps packaged
            // ciphertext (Hi-MC System.loadLibrary("cpbase") SIGILL).
            List<File> helpers = new ArrayList<>();
            File primary = new File(plainDir);
            helpers.add(primary);
            File parent = primary.getParentFile();
            if (parent != null) {
                File soPlain = new File(parent, "so_plain");
                if (soPlain.isDirectory() && !soPlain.equals(primary)) {
                    helpers.add(soPlain);
                }
            }

            Object dirsObj = getField(pathList, "nativeLibraryDirectories");
            if (dirsObj instanceof List) {
                @SuppressWarnings("unchecked")
                List<File> dirs = (List<File>) dirsObj;
                if (packagedDir != null && !packagedDir.isEmpty()) {
                    dirs.remove(new File(packagedDir));
                }
                for (int i = helpers.size() - 1; i >= 0; i--) {
                    File h = helpers.get(i);
                    dirs.remove(h);
                    dirs.add(0, h);
                }
                if (packagedDir != null && !packagedDir.isEmpty()) {
                    File packaged = new File(packagedDir);
                    dirs.remove(packaged);
                    int insert = Math.min(helpers.size(), dirs.size());
                    dirs.add(insert, packaged);
                }
            }

            boolean rebuilt = rebuildNativeLibraryPathElements(pathList, helpers);
            boolean prepended = prependNativeLibraryElements(pathList, helpers);
            boolean elementsOk = rebuilt || prepended;
            Log.i(TAG, "ClassLoader native lib path: helper first, packaged fallback; helper="
                    + plainDir + " pathElements=" + (elementsOk ? "ok" : "UNPATCHED"));
        } catch (Throwable t) {
            Log.w(TAG, "patchClassLoader failed", t);
        }
    }

    /** DexPathList.makePathElements(List) — static on AOSP, often absent/overloaded on OEM. */
    private static boolean rebuildNativeLibraryPathElements(Object pathList, List<File> helpers) {
        Object dirsObj = getField(pathList, "nativeLibraryDirectories");
        if (!(dirsObj instanceof List)) return false;
        Class<?> clz = pathList.getClass();
        while (clz != null) {
            for (String name : new String[]{"makePathElements", "makeNativePathElements"}) {
                try {
                    Method m = clz.getDeclaredMethod(name, List.class);
                    if (m.getReturnType().isArray()) {
                        m.setAccessible(true);
                        Object elements = m.invoke(null, dirsObj);
                        if (elements != null) {
                            setField(pathList, "nativeLibraryPathElements", elements);
                            return true;
                        }
                    }
                } catch (NoSuchMethodException ignored) {
                } catch (Throwable t) {
                    Log.w(TAG, "rebuild pathElements via " + name + " failed", t);
                }
            }
            clz = clz.getSuperclass();
        }
        return false;
    }

    /**
     * Prepend DexPathList$NativeLibraryElement(File) so findLibrary hits helper
     * dirs before the packaged extract, even when makePathElements is missing.
     */
    private static boolean prependNativeLibraryElements(Object pathList, List<File> helpers) {
        Object oldObj = getField(pathList, "nativeLibraryPathElements");
        if (oldObj == null || !oldObj.getClass().isArray() || helpers == null || helpers.isEmpty()) {
            return false;
        }
        Class<?> nle = oldObj.getClass().getComponentType();
        if (nle == null) return false;
        Constructor<?> ctor = null;
        for (Constructor<?> c : nle.getDeclaredConstructors()) {
            Class<?>[] pts = c.getParameterTypes();
            if (pts.length == 1 && pts[0] == File.class) {
                ctor = c;
                break;
            }
        }
        if (ctor == null) return false;
        ctor.setAccessible(true);
        try {
            int oldLen = Array.getLength(oldObj);
            List<Object> created = new ArrayList<>();
            for (File h : helpers) {
                created.add(ctor.newInstance(h));
            }
            Object neu = Array.newInstance(nle, created.size() + oldLen);
            int i = 0;
            for (Object el : created) {
                Array.set(neu, i++, el);
            }
            for (int j = 0; j < oldLen; j++) {
                Array.set(neu, i++, Array.get(oldObj, j));
            }
            setField(pathList, "nativeLibraryPathElements", neu);
            return true;
        } catch (Throwable t) {
            Log.w(TAG, "prepend NativeLibraryElement failed", t);
            return false;
        }
    }

    private static Object getField(Object obj, String name) {
        if (obj == null) return null;
        Class<?> c = obj.getClass();
        while (c != null) {
            try {
                Field f = c.getDeclaredField(name);
                f.setAccessible(true);
                return f.get(obj);
            } catch (NoSuchFieldException e) {
                c = c.getSuperclass();
            } catch (Throwable t) {
                return null;
            }
        }
        return null;
    }

    private static void setField(Object obj, String name, Object value) {
        Class<?> c = obj.getClass();
        while (c != null) {
            try {
                Field f = c.getDeclaredField(name);
                f.setAccessible(true);
                f.set(obj, value);
                return;
            } catch (NoSuchFieldException e) {
                c = c.getSuperclass();
            } catch (Throwable ignored) {
                return;
            }
        }
    }
}

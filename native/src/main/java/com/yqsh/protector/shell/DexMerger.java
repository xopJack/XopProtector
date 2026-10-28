package com.yqsh.protector.shell;

import android.os.Build;
import android.util.Log;

import androidx.annotation.Keep;

import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.lang.reflect.Array;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.Enumeration;
import java.util.List;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

@Keep
public final class DexMerger {
    private static final String TAG = "protector.DexMerger";
    private static final String PREPATCHED_MARK = ".prepatched";
    private static boolean merged;

    private DexMerger() {
    }

    /** True when previous launch left prepatched classes*.dex (skip zip extract/decrypt). */
    public static boolean hasWarmCache(File protectorDir) {
        if (protectorDir == null || !protectorDir.isDirectory()) {
            return false;
        }
        File mark = new File(protectorDir, PREPATCHED_MARK);
        return mark.isFile() && !listExistingDexes(protectorDir).isEmpty();
    }

    public static synchronized void merge(ClassLoader classLoader, File protectorDir) {
        if (merged || classLoader == null || protectorDir == null) {
            return;
        }
        try {
            File zip = new File(protectorDir, StrEnc.d(new byte[]{
                    0x3e, 0x24, 0x14, 0x6e, 0x45, (byte)0xf3, (byte)0x82, (byte)0x8e, (byte)0xf2
            }));
            File mark = new File(protectorDir, PREPATCHED_MARK);
            List<File> dexFiles = listExistingDexes(protectorDir);
            boolean warm = mark.isFile() && !dexFiles.isEmpty();

            if (warm) {
                Log.i(TAG, "warm start: reuse prepatched dexes count=" + dexFiles.size());
            } else if (!dexFiles.isEmpty()) {
                // Native decrypt_and_extract already wrote classes*.dex (no plaintext zip).
                Log.i(TAG, "cold: use native-extracted dexes count=" + dexFiles.size());
                long t0 = System.currentTimeMillis();
                try {
                    JniBridge.prepatchExtractedDexes(protectorDir.getAbsolutePath());
                    Log.i(TAG, "prepatch done in " + (System.currentTimeMillis() - t0) + "ms");
                    writeMark(mark);
                } catch (Throwable t) {
                    Log.e(TAG, "prepatch failed (DefineClass path still works)", t);
                }
            } else {
                if (!zip.isFile()) {
                    Log.e(TAG, "dexes.zip missing and no warm cache");
                    return;
                }
                long tUnzip = System.currentTimeMillis();
                dexFiles = extractDexes(zip, protectorDir);
                Log.i(TAG, "unzip dexes done in " + (System.currentTimeMillis() - tUnzip)
                        + "ms count=" + dexFiles.size());
                if (dexFiles.isEmpty()) {
                    Log.i(TAG, "no dex in dexes.zip — using base.apk multidex only");
                    merged = true;
                    if (zip.isFile() && zip.delete()) {
                        Log.i(TAG, "deleted plaintext dexes.zip after merge");
                    }
                    return;
                }
                long t0 = System.currentTimeMillis();
                try {
                    JniBridge.prepatchExtractedDexes(protectorDir.getAbsolutePath());
                    Log.i(TAG, "prepatch done in " + (System.currentTimeMillis() - t0) + "ms");
                    writeMark(mark);
                } catch (Throwable t) {
                    Log.e(TAG, "prepatch failed (DefineClass path still works)", t);
                }
            }

            for (File dex : dexFiles) {
                // Android 14+: loading a writable DEX throws SecurityException.
                if (!dex.setReadOnly()) {
                    Log.w(TAG, "setReadOnly failed: " + dex.getAbsolutePath());
                }
            }
            File oatDir = new File(protectorDir, "oat");
            // API≤24: dex2oat(speed) on protector secondary dex → ART AllocObject
            // SIGSEGV after makeApplication on x86_64. Load without optimized dir.
            if (Build.VERSION.SDK_INT <= 24) {
                oatDir = null;
                Log.i(TAG, "skip oat dir on API " + Build.VERSION.SDK_INT);
            } else if (!oatDir.exists() && !oatDir.mkdirs()) {
                Log.w(TAG, "cannot create oat dir: " + oatDir.getAbsolutePath());
                oatDir = null;
            }
            long tLoad = System.currentTimeMillis();
            Object[] extra = makePathElements(dexFiles, oatDir);
            Log.i(TAG, "makePathElements done in " + (System.currentTimeMillis() - tLoad)
                    + "ms extra=" + extra.length);
            Object pathList = getField(classLoader, "pathList");
            Object[] origin = (Object[]) getField(pathList, "dexElements");
            Object[] combined = (Object[]) Array.newInstance(
                    origin.getClass().getComponentType(), origin.length + extra.length);
            System.arraycopy(extra, 0, combined, 0, extra.length);
            System.arraycopy(origin, 0, combined, extra.length, origin.length);
            setField(pathList, "dexElements", combined);
            merged = true;
            Log.i(TAG, "merged dexElements origin=" + origin.length + " extra=" + extra.length);
            if (zip.isFile() && zip.delete()) {
                Log.i(TAG, "deleted plaintext dexes.zip after merge");
            }
            // After ClassLoader sees business DEX: enable DexFile(APK) class-name scan compat.
            try {
                DexScanCompat.install(protectorDir);
            } catch (Throwable t) {
                Log.w(TAG, "DexScanCompat skipped", t);
            }
        } catch (Throwable t) {
            Log.e(TAG, "merge failed", t);
        }
    }

    private static void writeMark(File mark) {
        try (FileOutputStream fos = new FileOutputStream(mark)) {
            fos.write('1');
        } catch (Throwable t) {
            Log.w(TAG, "write prepatched mark failed", t);
        }
    }

    /** Package-visible for {@link DexScanCompat} (same early-CL constraints). */
    static List<File> listExistingDexes(File outDir) {
        // No lambdas/method-refs: shell runs before full multidex on API 23; R8
        // ExternalSyntheticLambda* may be missing from the early ClassLoader path.
        File[] files = outDir.listFiles(new java.io.FilenameFilter() {
            @Override
            public boolean accept(File dir, String name) {
                return name.startsWith("classes") && name.endsWith(".dex");
            }
        });
        if (files == null || files.length == 0) {
            return new ArrayList<>();
        }
        Arrays.sort(files, new Comparator<File>() {
            @Override
            public int compare(File a, File b) {
                return a.getName().compareTo(b.getName());
            }
        });
        List<File> result = new ArrayList<>();
        for (File f : files) {
            if (f.isFile() && f.length() > 0) {
                result.add(f);
            }
        }
        return result;
    }

    private static List<File> extractDexes(File zip, File outDir) throws Exception {
        List<File> result = new ArrayList<>();
        try (ZipFile zf = new ZipFile(zip)) {
            Enumeration<? extends ZipEntry> en = zf.entries();
            while (en.hasMoreElements()) {
                ZipEntry e = en.nextElement();
                if (e.isDirectory()) continue;
                String name = e.getName();
                int slash = Math.max(name.lastIndexOf('/'), name.lastIndexOf('\\'));
                String base = slash >= 0 ? name.substring(slash + 1) : name;
                if (!base.endsWith(".dex")) continue;
                File out = new File(outDir, base);
                if (out.exists()) {
                    //noinspection ResultOfMethodCallIgnored
                    out.setWritable(true);
                }
                try (InputStream in = zf.getInputStream(e);
                     FileOutputStream fos = new FileOutputStream(out)) {
                    byte[] buf = new byte[256 * 1024];
                    int n;
                    while ((n = in.read(buf)) > 0) {
                        fos.write(buf, 0, n);
                    }
                }
                result.add(out);
                Log.i(TAG, "dex: " + out.getAbsolutePath());
            }
        }
        return result;
    }

    @SuppressWarnings({"unchecked", "rawtypes"})
    private static Object[] makePathElements(List<File> dexFiles, File optimizedDirectory)
            throws Exception {
        ArrayList suppressed = new ArrayList();
        Class<?> dpl = Class.forName("dalvik.system.DexPathList");
        Method make;
        try {
            make = dpl.getDeclaredMethod("makePathElements", List.class, File.class, List.class);
        } catch (NoSuchMethodException e) {
            make = dpl.getDeclaredMethod("makeDexElements", ArrayList.class, File.class, ArrayList.class);
        }
        make.setAccessible(true);
        return (Object[]) make.invoke(null, dexFiles, optimizedDirectory, suppressed);
    }

    private static Object getField(Object obj, String name) throws Exception {
        Class<?> c = obj.getClass();
        while (c != null) {
            try {
                Field f = c.getDeclaredField(name);
                f.setAccessible(true);
                return f.get(obj);
            } catch (NoSuchFieldException ignored) {
                c = c.getSuperclass();
            }
        }
        throw new NoSuchFieldException(name);
    }

    private static void setField(Object obj, String name, Object value) throws Exception {
        Class<?> c = obj.getClass();
        while (c != null) {
            try {
                Field f = c.getDeclaredField(name);
                f.setAccessible(true);
                f.set(obj, value);
                return;
            } catch (NoSuchFieldException ignored) {
                c = c.getSuperclass();
            }
        }
        throw new NoSuchFieldException(name);
    }
}

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
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

@Keep
public final class DexMerger {
    private static final String TAG = "protector.DexMerger";
    private static final String PREPATCHED_MARK = ".prepatched";

    /**
     * API≤27: skip oat dir. API 24 had ART AllocObject SIGSEGV with secondary-dex
     * dex2oat; API 26–27 (8.0/8.1) often hit empty/failing dex2oat + Permission denied
     * on protector oat paths. Parallel load only helps when oatDir is used (API 28+).
     */
    private static final int OAT_DIR_MIN_API = 28;

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
            if (Build.VERSION.SDK_INT < OAT_DIR_MIN_API) {
                oatDir = null;
                Log.i(TAG, "skip oat dir on API " + Build.VERSION.SDK_INT
                        + " (minOatApi=" + OAT_DIR_MIN_API + ")");
            } else if (!oatDir.exists() && !oatDir.mkdirs()) {
                Log.w(TAG, "cannot create oat dir: " + oatDir.getAbsolutePath());
                oatDir = null;
            }
            // Overlap multi-MB scan_facade.zip IO with parallel dex2oat.
            try {
                DexScanCompat.prefetchFacadeAsync(protectorDir);
            } catch (Throwable t) {
                Log.w(TAG, "DexScanCompat prefetch skipped", t);
            }
            long tLoad = System.currentTimeMillis();
            Object[] extra = loadDexElements(dexFiles, oatDir, warm);
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

    /**
     * oatDir + multi-dex → parallel system makePathElements(one file) with ordered
     * concat. Each parallel worker uses {@code oat/p{i}/} so cold/warm CLC stays
     * stable across launches and workers never share one oat directory.
     * ≤1 dex / no oat / timeout / any worker error → serial into {@code oat/serial/}
     * (never the same dir as in-flight parallel dex2oat; never a partial Element[]).
     */
    private static Object[] loadDexElements(List<File> dexFiles, File oatDir, boolean warm)
            throws Exception {
        if (!shouldParallelLoad(dexFiles, oatDir)) {
            return makePathElementsSerial(dexFiles, oatDir);
        }
        Object[] parallel = makePathElementsParallel(dexFiles, oatDir);
        if (parallel != null) {
            Log.i(TAG, "parallel load ok warm=" + warm + " files=" + dexFiles.size()
                    + " elements=" + parallel.length);
            return parallel;
        }
        File serialOat = ensureOatSubdir(oatDir, "serial");
        Log.w(TAG, "parallel load incomplete — serial fallback files=" + dexFiles.size()
                + " oat=" + (serialOat != null ? serialOat.getName() : "null"));
        return makePathElementsSerial(dexFiles, serialOat != null ? serialOat : oatDir);
    }

    private static boolean shouldParallelLoad(List<File> dexFiles, File oatDir) {
        return oatDir != null
                && dexFiles != null
                && dexFiles.size() >= 2;
    }

    /**
     * Wall-clock budget for parallel join. Floor 20s; scales with dex count so large
     * multidex does not false-timeout. On expiry: discard all parallel parts → serial.
     */
    private static long parallelTimeoutMs(int dexCount) {
        return Math.max(20_000L, 8_000L * (long) dexCount);
    }

    /**
     * @return concatenated Elements in input order, or {@code null} to force serial
     *         fallback (timeout / worker throwable / empty aggregate).
     */
    private static Object[] makePathElementsParallel(List<File> dexFiles,
                                                     File optimizedDirectory) {
        final int n = dexFiles.size();
        int workers = Math.min(n, Math.max(1, Runtime.getRuntime().availableProcessors()));
        ExecutorService pool = Executors.newFixedThreadPool(workers);
        final Object[][] parts = new Object[n][];
        final Throwable[] errors = new Throwable[n];
        final CountDownLatch done = new CountDownLatch(n);
        try {
            for (int i = 0; i < n; i++) {
                final int idx = i;
                final File dex = dexFiles.get(i);
                pool.execute(new Runnable() {
                    @Override
                    public void run() {
                        try {
                            // Per-index oat subdir: no cross-worker dex2oat races; stable CLC.
                            File workerOat = ensureOatSubdir(optimizedDirectory, "p" + idx);
                            ArrayList<File> one = new ArrayList<>(1);
                            one.add(dex);
                            Object[] el = makePathElementsSerial(one,
                                    workerOat != null ? workerOat : optimizedDirectory);
                            parts[idx] = el;
                        } catch (Throwable t) {
                            errors[idx] = t;
                        } finally {
                            done.countDown();
                        }
                    }
                });
            }
            long timeoutMs = parallelTimeoutMs(n);
            boolean finished;
            try {
                finished = done.await(timeoutMs, TimeUnit.MILLISECONDS);
            } catch (InterruptedException ie) {
                Thread.currentThread().interrupt();
                Log.w(TAG, "parallel load interrupted — serial fallback");
                return null;
            }
            if (!finished) {
                Log.w(TAG, "parallel load timeout " + timeoutMs + "ms — serial fallback");
                return null;
            }
            for (int i = 0; i < n; i++) {
                if (errors[i] != null) {
                    Log.w(TAG, "parallel load error on " + dexFiles.get(i).getName()
                            + " — serial fallback", errors[i]);
                    return null;
                }
                if (parts[i] == null) {
                    Log.w(TAG, "parallel load null part on " + dexFiles.get(i).getName()
                            + " — serial fallback");
                    return null;
                }
            }
            return concatElementsInOrder(parts);
        } finally {
            // Interrupt stragglers; brief wait so serial fallback is less likely to
            // overlap Java-side work (native dex2oat may still finish into p{i}/ only).
            pool.shutdownNow();
            try {
                if (!pool.awaitTermination(2, TimeUnit.SECONDS)) {
                    Log.w(TAG, "parallel pool still busy after shutdownNow (oat/p* isolated)");
                }
            } catch (InterruptedException ie) {
                Thread.currentThread().interrupt();
            }
        }
    }

    /** {@code parent/name}; {@code null} if mkdir fails (caller falls back to parent). */
    private static File ensureOatSubdir(File parent, String name) {
        if (parent == null || name == null || name.isEmpty()) {
            return parent;
        }
        File sub = new File(parent, name);
        if (sub.isDirectory() || sub.mkdirs()) {
            return sub;
        }
        Log.w(TAG, "cannot create oat subdir: " + sub.getAbsolutePath());
        return null;
    }

    /** Preserve dex file order; skip empty Element arrays (per-file suppress like AOSP). */
    private static Object[] concatElementsInOrder(Object[][] parts) {
        int total = 0;
        Class<?> elemType = null;
        for (int i = 0; i < parts.length; i++) {
            Object[] p = parts[i];
            if (p == null || p.length == 0) {
                continue;
            }
            if (elemType == null) {
                elemType = p.getClass().getComponentType();
            }
            total += p.length;
        }
        if (elemType == null || total == 0) {
            // All files suppressed/empty — treat as incomplete so caller can serial-retry.
            return null;
        }
        Object[] combined = (Object[]) Array.newInstance(elemType, total);
        int pos = 0;
        for (int i = 0; i < parts.length; i++) {
            Object[] p = parts[i];
            if (p == null || p.length == 0) {
                continue;
            }
            System.arraycopy(p, 0, combined, pos, p.length);
            pos += p.length;
        }
        return combined;
    }

    /**
     * Always pass {@link ArrayList} so both {@code makePathElements(List,…)} and
     * {@code makeDexElements(ArrayList,…)} resolve. Each call owns its suppressed list.
     */
    @SuppressWarnings({"unchecked", "rawtypes"})
    private static Object[] makePathElementsSerial(List<File> dexFiles, File optimizedDirectory)
            throws Exception {
        ArrayList suppressed = new ArrayList();
        ArrayList<File> files = (dexFiles instanceof ArrayList)
                ? (ArrayList<File>) dexFiles
                : new ArrayList<>(dexFiles);
        Class<?> dpl = Class.forName("dalvik.system.DexPathList");
        Method make;
        try {
            make = dpl.getDeclaredMethod("makePathElements", List.class, File.class, List.class);
        } catch (NoSuchMethodException e) {
            make = dpl.getDeclaredMethod(
                    "makeDexElements", ArrayList.class, File.class, ArrayList.class);
        }
        make.setAccessible(true);
        Object[] elements = (Object[]) make.invoke(null, files, optimizedDirectory, suppressed);
        if (elements == null) {
            return new Object[0];
        }
        return elements;
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

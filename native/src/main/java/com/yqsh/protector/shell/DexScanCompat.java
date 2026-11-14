package com.yqsh.protector.shell;

import android.util.Log;

import androidx.annotation.Keep;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.zip.Deflater;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

/**
 * Makes {@code DexFile(ApplicationInfo.sourceDir).entries()} see business classes
 * after encrypt-first packing (business DEX only in dexes.zip).
 *
 * <p>Builds a scan facade zip from decrypted {@code classes*.dex}, then asks native
 * to redirect {@code DexFile.openDexFileNative} when the path is this app's APK and
 * the call looks like a class-name scan ({@code outputName == null},
 * {@code ClassLoader == null}). Fail-open on any error.
 *
 * <p>Cold start: {@link #prefetchFacadeAsync} runs beside parallel dex2oat so the
 * multi‑MB zip copy overlaps oat work; {@link #install} joins then hooks.
 * Zip uses {@link Deflater#NO_COMPRESSION} (STORED-like) to avoid deflate CPU.
 *
 * <p>No lambdas / anonymous classes beyond a named {@link Runnable}: shell may run
 * before full multidex; R8 synthetics have caused {@code NoSuchMethodError} on the
 * early ClassLoader path.
 */
@Keep
public final class DexScanCompat {
    private static final String TAG = "protector.DexScan";
    static final String FACADE_ZIP = "scan_facade.zip";
    private static final String FACADE_STAMP = "scan_facade.stamp";
    private static final long PREFETCH_JOIN_MS = 90_000L;

    private static boolean installed;
    private static final Object PREFETCH_LOCK = new Object();
    private static Thread prefetchThread;
    private static File prefetchDir;

    private DexScanCompat() {
    }

    /**
     * Kick facade zip build on a background thread (no-op when stamp is warm).
     * Call after dexes are on disk / read-only and <b>before</b> slow
     * {@code makePathElements}, so IO overlaps dex2oat.
     */
    public static void prefetchFacadeAsync(File protectorDir) {
        if (protectorDir == null) {
            return;
        }
        try {
            if (!JniBridge.dexScanCompatEnabled()) {
                return;
            }
            List<File> dexes = DexMerger.listExistingDexes(protectorDir);
            if (dexes.isEmpty()) {
                return;
            }
            if (facadeUpToDate(protectorDir, dexes)) {
                Log.i(TAG, "prefetch skip — facade warm");
                return;
            }
            synchronized (PREFETCH_LOCK) {
                if (prefetchThread != null && prefetchThread.isAlive()
                        && protectorDir.equals(prefetchDir)) {
                    return;
                }
                prefetchDir = protectorDir;
                PrefetchRunnable task = new PrefetchRunnable(protectorDir);
                Thread t = new Thread(task, "protector-dexscan-facade");
                t.setPriority(Thread.NORM_PRIORITY - 1);
                prefetchThread = t;
                t.start();
                Log.i(TAG, "prefetch facade started dexes=" + dexes.size());
            }
        } catch (Throwable t) {
            Log.w(TAG, "prefetchFacadeAsync skipped", t);
        }
    }

    /** Call after a successful {@link DexMerger#merge}. Fail-open. */
    public static void install(File protectorDir) {
        if (installed || protectorDir == null) {
            return;
        }
        try {
            if (!JniBridge.dexScanCompatEnabled()) {
                Log.i(TAG, "disabled by config");
                installed = true;
                return;
            }
            joinPrefetch(protectorDir);
            List<File> dexes = DexMerger.listExistingDexes(protectorDir);
            if (dexes.isEmpty()) {
                Log.i(TAG, "no business dex — skip");
                installed = true;
                return;
            }
            File facade = ensureFacade(protectorDir, dexes);
            if (facade == null || !facade.isFile() || facade.length() == 0) {
                Log.w(TAG, "facade missing — skip");
                return;
            }
            boolean hooked = JniBridge.installDexScanCompat(facade.getAbsolutePath());
            installed = true;
            if (hooked) {
                Log.i(TAG, "hook ok facade=" + facade.getAbsolutePath()
                        + " dexes=" + dexes.size());
            } else {
                Log.w(TAG, "hook failed (fail-open) facade=" + facade.getAbsolutePath()
                        + " dexes=" + dexes.size());
            }
        } catch (Throwable t) {
            Log.w(TAG, "install skipped (fail-open)", t);
        }
    }

    private static void joinPrefetch(File protectorDir) {
        Thread t;
        synchronized (PREFETCH_LOCK) {
            t = prefetchThread;
            if (t == null || prefetchDir == null || !protectorDir.equals(prefetchDir)) {
                return;
            }
        }
        if (!t.isAlive()) {
            return;
        }
        long t0 = System.currentTimeMillis();
        try {
            t.join(PREFETCH_JOIN_MS);
        } catch (InterruptedException ie) {
            Thread.currentThread().interrupt();
            Log.w(TAG, "prefetch join interrupted");
            return;
        }
        if (t.isAlive()) {
            Log.w(TAG, "prefetch join timeout " + PREFETCH_JOIN_MS + "ms — build sync");
        } else {
            Log.i(TAG, "prefetch join waited " + (System.currentTimeMillis() - t0) + "ms");
        }
    }

    private static boolean facadeUpToDate(File protectorDir, List<File> dexes) {
        File facade = new File(protectorDir, FACADE_ZIP);
        File stampFile = new File(protectorDir, FACADE_STAMP);
        if (!facade.isFile() || facade.length() == 0 || !stampFile.isFile()) {
            return false;
        }
        return buildStamp(dexes).equals(readStamp(stampFile));
    }

    private static File ensureFacade(File protectorDir, List<File> dexes) throws Exception {
        synchronized (PREFETCH_LOCK) {
            return ensureFacadeLocked(protectorDir, dexes);
        }
    }

    private static File ensureFacadeLocked(File protectorDir, List<File> dexes) throws Exception {
        File facade = new File(protectorDir, FACADE_ZIP);
        File stampFile = new File(protectorDir, FACADE_STAMP);
        String stamp = buildStamp(dexes);
        if (facade.isFile() && facade.length() > 0 && stampFile.isFile()) {
            String prev = readStamp(stampFile);
            if (stamp.equals(prev)) {
                return facade;
            }
        }
        File tmp = new File(protectorDir, FACADE_ZIP + ".tmp");
        if (tmp.exists() && !tmp.delete()) {
            Log.w(TAG, "cannot clear tmp facade");
        }
        long t0 = System.currentTimeMillis();
        FileOutputStream fos = new FileOutputStream(tmp);
        try {
            ZipOutputStream zos = new ZipOutputStream(new BufferedOutputStream(fos, 512 * 1024));
            try {
                // Level 0 ≈ store: avoids multi‑MB deflate on cold start (was ~15s).
                zos.setLevel(Deflater.NO_COMPRESSION);
                byte[] buf = new byte[512 * 1024];
                for (int i = 0; i < dexes.size(); i++) {
                    File dex = dexes.get(i);
                    ZipEntry entry = new ZipEntry(dex.getName());
                    zos.putNextEntry(entry);
                    FileInputStream fin = new FileInputStream(dex);
                    try {
                        BufferedInputStream in = new BufferedInputStream(fin, 512 * 1024);
                        try {
                            int n;
                            while ((n = in.read(buf)) > 0) {
                                zos.write(buf, 0, n);
                            }
                        } finally {
                            in.close();
                        }
                    } finally {
                        fin.close();
                    }
                    zos.closeEntry();
                }
            } finally {
                zos.close();
            }
        } finally {
            fos.close();
        }
        if (facade.exists() && !facade.delete()) {
            Log.w(TAG, "cannot replace old facade");
        }
        if (!tmp.renameTo(facade)) {
            copyFile(tmp, facade);
            //noinspection ResultOfMethodCallIgnored
            tmp.delete();
        }
        writeStamp(stampFile, stamp);
        if (!facade.setReadOnly()) {
            Log.w(TAG, "setReadOnly failed on facade");
        }
        Log.i(TAG, "facade built in " + (System.currentTimeMillis() - t0)
                + "ms size=" + facade.length());
        return facade;
    }

    private static void copyFile(File from, File to) throws Exception {
        FileInputStream in = new FileInputStream(from);
        try {
            OutputStream out = new FileOutputStream(to);
            try {
                byte[] buf = new byte[512 * 1024];
                int n;
                while ((n = in.read(buf)) > 0) {
                    out.write(buf, 0, n);
                }
            } finally {
                out.close();
            }
        } finally {
            in.close();
        }
    }

    private static String buildStamp(List<File> dexes) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < dexes.size(); i++) {
            File f = dexes.get(i);
            sb.append(f.getName()).append(':')
                    .append(f.length()).append(':')
                    .append(f.lastModified()).append('\n');
        }
        return sb.toString();
    }

    private static String readStamp(File stampFile) {
        try {
            FileInputStream in = new FileInputStream(stampFile);
            try {
                byte[] buf = new byte[4096];
                int n = in.read(buf);
                if (n <= 0) {
                    return "";
                }
                return new String(buf, 0, n, StandardCharsets.UTF_8);
            } finally {
                in.close();
            }
        } catch (Exception e) {
            return "";
        }
    }

    private static void writeStamp(File stampFile, String stamp) {
        try {
            FileOutputStream out = new FileOutputStream(stampFile);
            try {
                out.write(stamp.getBytes(StandardCharsets.UTF_8));
            } finally {
                out.close();
            }
        } catch (Exception ignored) {
        }
    }

    /** Named Runnable — avoids R8 ExternalSyntheticLambda on early CL. */
    private static final class PrefetchRunnable implements Runnable {
        private final File dir;

        PrefetchRunnable(File dir) {
            this.dir = dir;
        }

        @Override
        public void run() {
            try {
                List<File> dexes = DexMerger.listExistingDexes(dir);
                if (dexes.isEmpty()) {
                    return;
                }
                ensureFacade(dir, dexes);
            } catch (Throwable t) {
                Log.w(TAG, "prefetch facade failed", t);
            }
        }
    }
}

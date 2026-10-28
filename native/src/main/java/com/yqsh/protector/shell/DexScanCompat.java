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
 * <p>No lambdas / anonymous classes: shell may run before full multidex; R8
 * synthetics have caused {@code NoSuchMethodError} on the early ClassLoader path.
 */
@Keep
public final class DexScanCompat {
    private static final String TAG = "protector.DexScan";
    static final String FACADE_ZIP = "scan_facade.zip";
    private static final String FACADE_STAMP = "scan_facade.stamp";
    private static boolean installed;

    private DexScanCompat() {
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

    private static File ensureFacade(File protectorDir, List<File> dexes) throws Exception {
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
            ZipOutputStream zos = new ZipOutputStream(new BufferedOutputStream(fos));
            try {
                byte[] buf = new byte[256 * 1024];
                for (int i = 0; i < dexes.size(); i++) {
                    File dex = dexes.get(i);
                    ZipEntry entry = new ZipEntry(dex.getName());
                    zos.putNextEntry(entry);
                    FileInputStream fin = new FileInputStream(dex);
                    try {
                        BufferedInputStream in = new BufferedInputStream(fin);
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
                byte[] buf = new byte[256 * 1024];
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
}

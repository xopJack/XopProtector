package com.yqsh.protector.packer;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.android.tools.smali.dexlib2.Opcodes;
import com.android.tools.smali.dexlib2.dexbacked.DexBackedDexFile;
import com.android.tools.smali.dexlib2.iface.ClassDef;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/**
 * P2 offline scan: real APKs → class-split modes (skips missing paths).
 * Run: {@code gradlew :packer:test --tests com.yqsh.protector.packer.ApkClassSplitScanTest}
 */
class ApkClassSplitScanTest {

    private static final Object[][] SAMPLES = {
            {"E:\\Android\\github\\APK\\oppo__1.7.2.apk", "com.ideack.notes"},
            {"E:\\Android\\github\\APK\\C_managed_versionCode10_versionName2.3_release.apk",
                    "com.terminalv3.managed"},
            {"E:\\Android\\github\\APK\\HeYuan_1.0.8.apk", "com.ksxx.heyuanforest"},
            {"E:\\Android\\github\\APK\\competition-v5-release.apk",
                    "com.torhang.flight.competition.v5"},
            {"E:\\Android\\github\\APK\\app-debug.apk", "com.demo.xopprotector"},
    };

    @TempDir
    Path tmp;

    @Test
    void scanAvailableApks_printSplitSummary() throws Exception {
        int scanned = 0;
        for (Object[] row : SAMPLES) {
            File apk = new File((String) row[0]);
            if (!apk.isFile()) {
                System.out.println("[skip] missing " + apk.getName());
                continue;
            }
            scanned++;
            String applicationId = (String) row[1];
            DexLayout.Context rules = new DexLayout.Context();
            rules.appPackagePrefix = ProtectPolicy.toDescriptorPrefix(applicationId);
            rules.paymentAutoVmp = true;
            rules.industryAutoVmp = false;

            Path work = tmp.resolve(apk.getName().replace('.', '_'));
            Files.createDirectories(work);
            List<File> dexes = extractDexes(apk, work.resolve("in").toFile());
            DexClassSplit.Bundle bundle = DexClassSplit.splitAll(dexes, rules, work.resolve("out").toFile());

            System.out.println("=== " + apk.getName() + " pkg=" + applicationId
                    + " dexes=" + dexes.size()
                    + " plain=" + bundle.plainDexes.size()
                    + " business=" + bundle.businessDexes.size()
                    + " unprotected=" + bundle.unprotectedPlainSources.size()
                    + " biz_classes=" + bundle.totalBusinessClasses
                    + " plain_classes=" + bundle.totalPlainClasses);

            for (DexClassSplit.FileResult d : bundle.details) {
                if (d.plainMode == DexClassSplit.PlainMode.STRIPPED) {
                    assertNoBusiness(d.plainDex, rules, d.sourceName);
                }
                if (d.plainMode == DexClassSplit.PlainMode.KEEP_FULL_UNPROTECTED) {
                    assertTrue(d.businessClasses > 0, d.sourceName + " KEEP_FULL without business?");
                }
                if (d.plainMode == DexClassSplit.PlainMode.NONE) {
                    assertTrue(d.plainDex == null);
                    assertTrue(d.businessClasses > 0);
                }
            }
            // Root gate for non-KEEP_FULL plains
            for (DexClassSplit.FileResult d : bundle.details) {
                if (d.plainDex == null || d.isPlainUnprotected()) {
                    continue;
                }
                assertNoBusiness(d.plainDex, rules, d.sourceName + "/" + d.plainMode);
            }
        }
        assertTrue(scanned > 0, "no sample APKs found on disk");
        System.out.println("ApkClassSplitScan scanned=" + scanned);
    }

    private static List<File> extractDexes(File apk, File outDir) throws Exception {
        if (!outDir.mkdirs() && !outDir.isDirectory()) {
            throw new IllegalStateException("mkdir " + outDir);
        }
        List<File> dexes = new ArrayList<>();
        try (ZipFile zf = new ZipFile(apk)) {
            var en = zf.entries();
            while (en.hasMoreElements()) {
                ZipEntry e = en.nextElement();
                if (e.isDirectory()) continue;
                String name = e.getName();
                if (name.contains("/")) continue;
                if (!name.startsWith("classes") || !name.endsWith(".dex")) continue;
                File out = new File(outDir, name);
                try (InputStream in = zf.getInputStream(e)) {
                    Files.copy(in, out.toPath(), StandardCopyOption.REPLACE_EXISTING);
                }
                dexes.add(out);
            }
        }
        dexes.sort(Comparator.comparingInt(f -> dexNumber(f.getName())));
        return dexes;
    }

    private static int dexNumber(String name) {
        if ("classes.dex".equals(name)) return 1;
        if (name.startsWith("classes") && name.endsWith(".dex")) {
            String mid = name.substring("classes".length(), name.length() - ".dex".length());
            if (mid.isEmpty()) return 1;
            try {
                return Integer.parseInt(mid);
            } catch (NumberFormatException ignored) {
                return 99;
            }
        }
        return 99;
    }

    private static void assertNoBusiness(File dex, DexLayout.Context rules, String label)
            throws Exception {
        try (BufferedInputStream in = new BufferedInputStream(new FileInputStream(dex))) {
            DexBackedDexFile df = DexBackedDexFile.fromInputStream(Opcodes.getDefault(), in);
            for (ClassDef c : df.getClasses()) {
                String type = c.getType();
                assertFalse(DexLayout.isBusinessType(type, rules),
                        () -> String.format(Locale.US, "%s still has business %s", label, type));
            }
        }
    }
}

package com.yqsh.protector.packer;

import com.android.tools.smali.dexlib2.Opcodes;
import com.android.tools.smali.dexlib2.dexbacked.DexBackedDexFile;
import com.android.tools.smali.dexlib2.iface.ClassDef;
import com.android.tools.smali.dexlib2.writer.io.FileDataStore;
import com.android.tools.smali.dexlib2.writer.pool.DexPool;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * Always-on class extract: pull {@linkplain DexLayout#isBusinessType business}
 * classes into a companion DEX (→ encrypted {@code dexes.zip}). Non-business
 * classes stay in the APK root for install-time AOT.
 *
 * <p>Plain side policy:
 * <ul>
 *   <li>No business classes → copy original bytes (no DexPool).</li>
 *   <li>Mixed, plain set has no DexPool-fragile packages → DexPool strip
 *       (business descriptors removed from root).</li>
 *   <li>Mixed, plain set contains Compose / known fragile packages →
 *       {@link PlainMode#KEEP_FULL_UNPROTECTED}: original bytes kept (may still
 *       contain business classes); never advertised as “extracted / thinned”.</li>
 * </ul>
 */
public final class DexClassSplit {

    /**
     * Packages that historically broke under DexPool rewrite
     * ({@code IncompatibleClassChangeError} on interface vs class).
     */
    static final String[] DEXPOOL_FRAGILE_PREFIXES = {
            "Landroidx/compose/",
    };

    public enum PlainMode {
        /** No root copy (all classes extracted). */
        NONE,
        /** Original bytes; no business classes in this DEX. */
        ORIGINAL_COPY,
        /** DexPool-written DEX with business classes removed. */
        STRIPPED,
        /**
         * Original bytes retained because stripping would DexPool-rewrite fragile
         * library classes. Root may still contain business types — not “protected”.
         */
        KEEP_FULL_UNPROTECTED
    }

    public static final class FileResult {
        /** Root DEX; null if every class was extracted. */
        public final File plainDex;
        /** Business DEX for encryption; null if nothing matched. */
        public final File businessDex;
        public final String sourceName;
        public final int plainClasses;
        public final int businessClasses;
        public final PlainMode plainMode;

        FileResult(File plainDex, File businessDex, String sourceName,
                   int plainClasses, int businessClasses, PlainMode plainMode) {
            this.plainDex = plainDex;
            this.businessDex = businessDex;
            this.sourceName = sourceName;
            this.plainClasses = plainClasses;
            this.businessClasses = businessClasses;
            this.plainMode = plainMode;
        }

        public boolean isPlainUnprotected() {
            return plainMode == PlainMode.KEEP_FULL_UNPROTECTED;
        }
    }

    public static final class Bundle {
        public final List<File> plainDexes = new ArrayList<>();
        public final List<File> businessDexes = new ArrayList<>();
        public final List<FileResult> details = new ArrayList<>();
        /** Source basenames that kept a full original plain (business may remain). */
        public final List<String> unprotectedPlainSources = new ArrayList<>();
        public int totalPlainClasses;
        public int totalBusinessClasses;
    }

    private DexClassSplit() {
    }

    /**
     * Split every {@code classes*.dex}. Business outputs keep the original
     * basename so {@code code.bin} dex indices stay aligned with runtime extract.
     */
    public static Bundle splitAll(List<File> dexFiles, DexLayout.Context rules, File workDir)
            throws IOException {
        if (rules == null
                || rules.appPackagePrefix == null
                || rules.appPackagePrefix.isEmpty()) {
            throw new IllegalArgumentException(
                    "class-split requires applicationId / app package prefix");
        }
        File plainDir = new File(workDir, "plain");
        File bizDir = new File(workDir, "business");
        if (!plainDir.mkdirs() && !plainDir.isDirectory()) {
            throw new IOException("cannot create " + plainDir);
        }
        if (!bizDir.mkdirs() && !bizDir.isDirectory()) {
            throw new IOException("cannot create " + bizDir);
        }

        Bundle bundle = new Bundle();
        System.out.println("Dex class-split: app_prefix=" + rules.appPackagePrefix
                + " business_prefixes=" + rules.businessPrefixes.size()
                + " (plain=strip business; fragile→KEEP_FULL_UNPROTECTED)");
        for (File dex : dexFiles) {
            FileResult r = splitOne(dex, rules, plainDir, bizDir);
            bundle.details.add(r);
            bundle.totalPlainClasses += r.plainClasses;
            bundle.totalBusinessClasses += r.businessClasses;
            System.out.println("[XOP-DEX-SPLIT] " + r.sourceName
                    + " plain=" + r.plainClasses
                    + " business=" + r.businessClasses
                    + " plain_mode=" + r.plainMode
                    + " plain_file=" + (r.plainDex != null ? r.plainDex.getName() : "-")
                    + " biz_file=" + (r.businessDex != null ? r.businessDex.getName() : "-"));
            if (r.plainDex != null) {
                bundle.plainDexes.add(r.plainDex);
            }
            if (r.businessDex != null) {
                bundle.businessDexes.add(r.businessDex);
            }
            if (r.isPlainUnprotected()) {
                bundle.unprotectedPlainSources.add(r.sourceName);
            }
        }
        System.out.println(String.format(Locale.US,
                "Dex class-split done: plain_dexes=%d business_dexes=%d plain_classes=%d business_classes=%d unprotected_plain=%d",
                bundle.plainDexes.size(), bundle.businessDexes.size(),
                bundle.totalPlainClasses, bundle.totalBusinessClasses,
                bundle.unprotectedPlainSources.size()));
        if (!bundle.unprotectedPlainSources.isEmpty()) {
            System.out.println("WARN: plain KEEP_FULL_UNPROTECTED (business may remain in root): "
                    + bundle.unprotectedPlainSources);
        }
        return bundle;
    }

    static FileResult splitOne(File input, DexLayout.Context rules,
                               File plainDir, File bizDir) throws IOException {
        String name = input.getName();
        DexBackedDexFile dex;
        try (BufferedInputStream in = new BufferedInputStream(new FileInputStream(input))) {
            dex = DexBackedDexFile.fromInputStream(Opcodes.getDefault(), in);
        }

        List<ClassDef> plainClasses = new ArrayList<>();
        List<ClassDef> businessClasses = new ArrayList<>();
        boolean plainHasFragile = false;
        for (ClassDef classDef : dex.getClasses()) {
            String type = classDef.getType();
            if (DexLayout.isBusinessType(type, rules)) {
                businessClasses.add(classDef);
            } else {
                plainClasses.add(classDef);
                if (isDexPoolFragileType(type)) {
                    plainHasFragile = true;
                }
            }
        }

        int plain = plainClasses.size();
        int business = businessClasses.size();
        File plainOut = null;
        File bizOut = null;
        PlainMode plainMode = PlainMode.NONE;

        if (business > 0) {
            DexPool bizPool = new DexPool(Opcodes.getDefault());
            for (ClassDef c : businessClasses) {
                bizPool.internClass(c);
            }
            bizOut = new File(bizDir, name);
            bizPool.writeTo(new FileDataStore(bizOut));
        }

        if (plain == 0) {
            // All-business: no root copy.
            return new FileResult(null, bizOut, name, plain, business, PlainMode.NONE);
        }

        if (business == 0) {
            // SDK / library only — keep original bytes (avoids DexPool on Compose-only DEX).
            plainOut = new File(plainDir, name);
            Files.copy(input.toPath(), plainOut.toPath(), StandardCopyOption.REPLACE_EXISTING);
            plainMode = PlainMode.ORIGINAL_COPY;
            return new FileResult(plainOut, null, name, plain, business, plainMode);
        }

        // Mixed: strip business from plain unless fragile libraries would be DexPool-rewritten.
        if (plainHasFragile) {
            plainOut = new File(plainDir, name);
            Files.copy(input.toPath(), plainOut.toPath(), StandardCopyOption.REPLACE_EXISTING);
            plainMode = PlainMode.KEEP_FULL_UNPROTECTED;
            return new FileResult(plainOut, bizOut, name, plain, business, plainMode);
        }

        DexPool plainPool = new DexPool(Opcodes.getDefault());
        for (ClassDef c : plainClasses) {
            plainPool.internClass(c);
        }
        plainOut = new File(plainDir, name);
        plainPool.writeTo(new FileDataStore(plainOut));
        assertNoBusinessInDex(plainOut, rules, name);
        plainMode = PlainMode.STRIPPED;
        return new FileResult(plainOut, bizOut, name, plain, business, plainMode);
    }

    /** @deprecated Use {@link DexLayout#isBusinessType}; kept for older call sites/tests. */
    @Deprecated
    static boolean isAppType(String typeDescriptor, String appPackagePrefix) {
        return typeDescriptor != null
                && appPackagePrefix != null
                && !appPackagePrefix.isEmpty()
                && typeDescriptor.startsWith(appPackagePrefix);
    }

    static boolean isDexPoolFragileType(String typeDescriptor) {
        if (typeDescriptor == null) {
            return false;
        }
        for (String p : DEXPOOL_FRAGILE_PREFIXES) {
            if (typeDescriptor.startsWith(p)) {
                return true;
            }
        }
        return false;
    }

    /** Gate: stripped plain must not retain business descriptors. */
    static void assertNoBusinessInDex(File dexFile, DexLayout.Context rules, String label)
            throws IOException {
        try (BufferedInputStream in = new BufferedInputStream(new FileInputStream(dexFile))) {
            DexBackedDexFile dex = DexBackedDexFile.fromInputStream(Opcodes.getDefault(), in);
            for (ClassDef c : dex.getClasses()) {
                String type = c.getType();
                if (DexLayout.isBusinessType(type, rules)) {
                    throw new IOException("class-split plain still contains business type in "
                            + label + ": " + type);
                }
            }
        }
    }
}

package com.yqsh.protector.packer;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.android.tools.smali.dexlib2.AccessFlags;
import com.android.tools.smali.dexlib2.Opcodes;
import com.android.tools.smali.dexlib2.dexbacked.DexBackedDexFile;
import com.android.tools.smali.dexlib2.immutable.ImmutableClassDef;
import com.android.tools.smali.dexlib2.immutable.ImmutableMethod;
import com.android.tools.smali.dexlib2.writer.io.FileDataStore;
import com.android.tools.smali.dexlib2.writer.pool.DexPool;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.nio.file.Path;
import java.util.Collections;

class DexClassSplitTest {

    @TempDir
    Path tmp;

    private static DexLayout.Context appRules() {
        DexLayout.Context ctx = new DexLayout.Context();
        ctx.appPackagePrefix = "Lcom/ideack/notes/";
        ctx.paymentAutoVmp = true;
        return ctx;
    }

    @Test
    void splitOne_mixed_stripsBusinessFromPlain() throws Exception {
        File input = tmp.resolve("classes.dex").toFile();
        writeDex(input,
                "Lcom/ideack/notes/App;",
                "Landroidx/appcompat/app/AppCompatActivity;");

        File plainDir = tmp.resolve("plain").toFile();
        File bizDir = tmp.resolve("biz").toFile();
        assertTrue(plainDir.mkdirs());
        assertTrue(bizDir.mkdirs());

        DexClassSplit.FileResult r = DexClassSplit.splitOne(input, appRules(), plainDir, bizDir);
        assertEquals(1, r.businessClasses);
        assertEquals(1, r.plainClasses);
        assertNotNull(r.plainDex);
        assertNotNull(r.businessDex);
        assertEquals(DexClassSplit.PlainMode.STRIPPED, r.plainMode);

        assertEquals(1, countClasses(r.businessDex));
        assertEquals(1, countClasses(r.plainDex));
        assertTrue(hasType(r.businessDex, "Lcom/ideack/notes/App;"));
        assertTrue(hasType(r.plainDex, "Landroidx/appcompat/app/AppCompatActivity;"));
        assertFalse(hasType(r.plainDex, "Lcom/ideack/notes/App;"));
    }

    @Test
    void splitOne_allBusiness_noPlainFile() throws Exception {
        File input = tmp.resolve("classes3.dex").toFile();
        writeDex(input, "Lcom/ideack/notes/MainActivity;", "Lcom/ideack/notes/Helper;");

        File plainDir = tmp.resolve("plain3").toFile();
        File bizDir = tmp.resolve("biz3").toFile();
        assertTrue(plainDir.mkdirs());
        assertTrue(bizDir.mkdirs());

        DexClassSplit.FileResult r = DexClassSplit.splitOne(input, appRules(), plainDir, bizDir);
        assertEquals(2, r.businessClasses);
        assertEquals(0, r.plainClasses);
        assertNull(r.plainDex);
        assertNotNull(r.businessDex);
        assertEquals(DexClassSplit.PlainMode.NONE, r.plainMode);
    }

    @Test
    void splitOne_allSdk_noBusinessFile() throws Exception {
        File input = tmp.resolve("classes2.dex").toFile();
        writeDex(input, "Landroidx/core/util/Pair;");

        File plainDir = tmp.resolve("plain2").toFile();
        File bizDir = tmp.resolve("biz2").toFile();
        assertTrue(plainDir.mkdirs());
        assertTrue(bizDir.mkdirs());

        DexClassSplit.FileResult r = DexClassSplit.splitOne(input, appRules(), plainDir, bizDir);
        assertEquals(0, r.businessClasses);
        assertEquals(1, r.plainClasses);
        assertNotNull(r.plainDex);
        assertNull(r.businessDex);
        assertEquals(DexClassSplit.PlainMode.ORIGINAL_COPY, r.plainMode);
    }

    @Test
    void splitOne_paymentPrefix_extractedEvenOutsideAppId() throws Exception {
        File input = tmp.resolve("classes4.dex").toFile();
        writeDex(input,
                "Lcom/alipay/sdk/m/u/e;",
                "Landroidx/core/util/Pair;");

        File plainDir = tmp.resolve("plain4").toFile();
        File bizDir = tmp.resolve("biz4").toFile();
        assertTrue(plainDir.mkdirs());
        assertTrue(bizDir.mkdirs());

        DexClassSplit.FileResult r = DexClassSplit.splitOne(input, appRules(), plainDir, bizDir);
        assertEquals(1, r.businessClasses);
        assertEquals(1, r.plainClasses);
        assertTrue(hasType(r.businessDex, "Lcom/alipay/sdk/m/u/e;"));
        assertFalse(hasType(r.plainDex, "Lcom/alipay/sdk/m/u/e;"));
        assertEquals(DexClassSplit.PlainMode.STRIPPED, r.plainMode);
    }

    @Test
    void splitOne_hollowPrefix_extracted() throws Exception {
        File input = tmp.resolve("classes5.dex").toFile();
        writeDex(input,
                "Lcom/third/party/Secret;",
                "Landroidx/core/util/Pair;");

        DexLayout.Context rules = appRules();
        rules.hollowPrefixes.add("Lcom/third/party/");

        File plainDir = tmp.resolve("plain5").toFile();
        File bizDir = tmp.resolve("biz5").toFile();
        assertTrue(plainDir.mkdirs());
        assertTrue(bizDir.mkdirs());

        DexClassSplit.FileResult r = DexClassSplit.splitOne(input, rules, plainDir, bizDir);
        assertEquals(1, r.businessClasses);
        assertTrue(hasType(r.businessDex, "Lcom/third/party/Secret;"));
        assertFalse(hasType(r.plainDex, "Lcom/third/party/Secret;"));
    }

    @Test
    void splitOne_composeFragile_keepFullUnprotected() throws Exception {
        File input = tmp.resolve("classes6.dex").toFile();
        writeDex(input,
                "Lcom/ideack/notes/App;",
                "Landroidx/compose/ui/graphics/drawscope/DrawScope;");

        File plainDir = tmp.resolve("plain6").toFile();
        File bizDir = tmp.resolve("biz6").toFile();
        assertTrue(plainDir.mkdirs());
        assertTrue(bizDir.mkdirs());

        DexClassSplit.FileResult r = DexClassSplit.splitOne(input, appRules(), plainDir, bizDir);
        assertEquals(DexClassSplit.PlainMode.KEEP_FULL_UNPROTECTED, r.plainMode);
        assertTrue(r.isPlainUnprotected());
        assertNotNull(r.businessDex);
        assertTrue(hasType(r.businessDex, "Lcom/ideack/notes/App;"));
        // Root keeps original (business still present) — honest unprotected path.
        assertTrue(hasType(r.plainDex, "Lcom/ideack/notes/App;"));
        assertTrue(hasType(r.plainDex, "Landroidx/compose/ui/graphics/drawscope/DrawScope;"));
    }

    private static void writeDex(File out, String... types) throws Exception {
        DexPool pool = new DexPool(Opcodes.getDefault());
        for (String type : types) {
            pool.internClass(emptyClass(type));
        }
        pool.writeTo(new FileDataStore(out));
    }

    private static ImmutableClassDef emptyClass(String type) {
        ImmutableMethod init = new ImmutableMethod(
                type, "<init>", Collections.emptyList(), "V",
                AccessFlags.PUBLIC.getValue() | AccessFlags.CONSTRUCTOR.getValue(),
                null, null, null);
        return new ImmutableClassDef(
                type,
                AccessFlags.PUBLIC.getValue(),
                "Ljava/lang/Object;",
                null,
                null,
                null,
                null,
                Collections.singletonList(init));
    }

    private static int countClasses(File dexFile) throws Exception {
        try (BufferedInputStream in = new BufferedInputStream(new FileInputStream(dexFile))) {
            DexBackedDexFile dex = DexBackedDexFile.fromInputStream(Opcodes.getDefault(), in);
            int n = 0;
            for (var ignored : dex.getClasses()) {
                n++;
            }
            return n;
        }
    }

    private static boolean hasType(File dexFile, String type) throws Exception {
        try (BufferedInputStream in = new BufferedInputStream(new FileInputStream(dexFile))) {
            DexBackedDexFile dex = DexBackedDexFile.fromInputStream(Opcodes.getDefault(), in);
            for (var c : dex.getClasses()) {
                if (type.equals(c.getType())) {
                    return true;
                }
            }
            return false;
        }
    }
}

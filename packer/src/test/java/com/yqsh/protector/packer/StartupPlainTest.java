package com.yqsh.protector.packer;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

import java.util.Collections;

class StartupPlainTest {

    @Test
    void isBusinessType_startupPlainWinsOverAppPrefix() {
        DexLayout.Context ctx = new DexLayout.Context();
        ctx.appPackagePrefix = "Lcom/ideack/notes/";
        ctx.paymentAutoVmp = false;
        ctx.startupPlainTypes.add("Lcom/ideack/notes/App;");
        ctx.startupPlainTypes.add("Lcom/ideack/notes/ui/activity/SplashActivity;");

        assertFalse(DexLayout.isBusinessType("Lcom/ideack/notes/App;", ctx));
        assertFalse(DexLayout.isBusinessType(
                "Lcom/ideack/notes/ui/activity/SplashActivity;", ctx));
        assertFalse(DexLayout.isBusinessType(
                "Lcom/ideack/notes/ui/activity/SplashActivity$1;", ctx));
        // Sibling business still encrypted.
        assertTrue(DexLayout.isBusinessType(
                "Lcom/ideack/notes/ui/activity/HomeActivity;", ctx));
        assertTrue(DexLayout.isBusinessType("Lcom/ideack/notes/util/X;", ctx));
    }

    @Test
    void isBusinessType_startupPlainPrefix() {
        DexLayout.Context ctx = new DexLayout.Context();
        ctx.appPackagePrefix = "Lcom/ideack/notes/";
        ctx.paymentAutoVmp = false;
        ctx.startupPlainPrefixes.add("Lcom/ideack/notes/ui/activity/");

        assertFalse(DexLayout.isBusinessType(
                "Lcom/ideack/notes/ui/activity/SplashActivity;", ctx));
        assertFalse(DexLayout.isBusinessType(
                "Lcom/ideack/notes/ui/activity/HomeActivity;", ctx));
        assertTrue(DexLayout.isBusinessType("Lcom/ideack/notes/util/X;", ctx));
        assertTrue(DexLayout.isBusinessType("Lcom/ideack/notes/App;", ctx));
    }

    @Test
    void parentPackagePrefix_fromType() {
        assertEquals("Lcom/ideack/notes/ui/activity/",
                StartupPlain.parentPackagePrefix(
                        "Lcom/ideack/notes/ui/activity/SplashActivity;"));
        // Lcom/a/b/ = 3 segments (com,a,b) — allowed; Lcom/a/ = 2 — rejected
        assertEquals("Lcom/a/b/",
                StartupPlain.parentPackagePrefix("Lcom/a/b/App;"));
        assertNull(StartupPlain.parentPackagePrefix("Lcom/a/App;"));
        assertNull(StartupPlain.parentPackagePrefix("Lcom/App;"));
        assertNull(StartupPlain.parentPackagePrefix(null));
    }

    @Test
    void apply_autoPrefixFromLauncherType() {
        DexLayout.Context ctx = new DexLayout.Context();
        ctx.appPackagePrefix = "Lcom/ideack/notes/";
        ctx.paymentAutoVmp = false;
        ctx.businessExactTypes.add("Lcom/ideack/notes/ui/activity/SplashActivity;");
        ctx.businessExactTypes.add("Lcom/ideack/notes/ui/activity/HomeActivity;");
        ctx.businessExactTypes.add("Lcom/ideack/notes/util/X;");
        // Simulate apply()'s launcher auto-prefix path without a real Manifest.
        ctx.startupPlainTypes.add("Lcom/ideack/notes/App;");
        ctx.startupPlainTypes.add("Lcom/ideack/notes/ui/activity/SplashActivity;");
        StartupPlain.applyPrefixes(ctx, Collections.singletonList(
                StartupPlain.parentPackagePrefix(
                        "Lcom/ideack/notes/ui/activity/SplashActivity;")));
        assertTrue(ctx.startupPlainPrefixes.contains("Lcom/ideack/notes/ui/activity/"));
        assertFalse(DexLayout.isBusinessType(
                "Lcom/ideack/notes/ui/activity/HomeActivity;", ctx));
        assertTrue(DexLayout.isBusinessType("Lcom/ideack/notes/util/X;", ctx));
    }

    @Test
    void normalizePrefix_dotAndDalvik() {
        assertEquals("Lcom/ideack/notes/ui/activity/",
                StartupPlain.normalizePrefix("Lcom/ideack/notes/ui/activity/"));
        assertEquals("Lcom/ideack/notes/ui/activity/",
                StartupPlain.normalizePrefix("com.ideack.notes.ui.activity"));
        assertNull(StartupPlain.normalizePrefix("Lcom/ideack/notes/App;"));
        // com/foo = 2 segments → too shallow; com/foo/bar = 3 → ok
        assertEquals(0, StartupPlain.applyPrefixes(new DexLayout.Context(),
                Collections.singletonList("Lcom/foo/")));
        assertEquals(1, StartupPlain.applyPrefixes(new DexLayout.Context(),
                Collections.singletonList("Lcom/foo/bar/")));
        assertEquals(1, StartupPlain.applyPrefixes(new DexLayout.Context(),
                Collections.singletonList("Lcom/foo/bar/ui/")));
    }

    @Test
    void applyPrefixes_stripsCoveredExact() {
        DexLayout.Context ctx = new DexLayout.Context();
        ctx.businessExactTypes.add("Lcom/ideack/notes/ui/activity/SplashActivity;");
        ctx.businessExactTypes.add("Lcom/ideack/notes/util/X;");
        StartupPlain.applyPrefixes(ctx,
                Collections.singletonList("Lcom/ideack/notes/ui/activity/"));
        assertTrue(ctx.startupPlainPrefixes.contains("Lcom/ideack/notes/ui/activity/"));
        assertFalse(ctx.businessExactTypes.contains(
                "Lcom/ideack/notes/ui/activity/SplashActivity;"));
        assertTrue(ctx.businessExactTypes.contains("Lcom/ideack/notes/util/X;"));
    }

    @Test
    void apply_stripsOverlappingExactTypes() {
        DexLayout.Context ctx = new DexLayout.Context();
        ctx.appPackagePrefix = "Lcom/a/b/";
        ctx.businessExactTypes.add("Lcom/c/d/MyApp;");
        ctx.businessExactTypes.add("Lcom/c/d/Other;");
        ctx.startupPlainTypes.clear();
        // Simulate collect: manually seed then strip via apply logic
        ctx.startupPlainTypes.add("Lcom/c/d/MyApp;");
        // Re-run strip path used by apply
        ctx.businessExactTypes.removeIf(exact ->
                exact != null && DexLayout.matchesExactType(exact, ctx.startupPlainTypes));
        assertFalse(ctx.businessExactTypes.contains("Lcom/c/d/MyApp;"));
        assertTrue(ctx.businessExactTypes.contains("Lcom/c/d/Other;"));
        assertFalse(DexLayout.isBusinessType("Lcom/c/d/MyApp;", ctx));
    }

    @Test
    void parseArgs_startupPlainAndLazyDefault() throws Exception {
        ProtectOptions def = PackerMain.parseArgs(new String[]{"in.apk"});
        assertFalse(def.startupPlain);
        assertEquals(ProtectOptions.SoDecryptMode.LAZY, def.soDecryptMode);
        assertNull(def.startupPlainAppLeaf);

        ProtectOptions on = PackerMain.parseArgs(new String[]{
                "in.apk",
                "--startup-plain",
                "--so-decrypt-mode", "eager",
                "--startup-plain-prefix", "Lcom/ideack/notes/ui/activity/",
                "--startup-plain-prefix", "com.ideack.notes.welcome"
        });
        assertTrue(on.startupPlain);
        assertEquals(ProtectOptions.SoDecryptMode.EAGER, on.soDecryptMode);
        assertEquals(2, on.startupPlainPrefixes.size());
        assertTrue(on.startupPlainPrefixes.contains("Lcom/ideack/notes/ui/activity/"));
        assertTrue(on.startupPlainPrefixes.contains("com.ideack.notes.welcome"));

        ProtectOptions off = PackerMain.parseArgs(new String[]{
                "in.apk", "--no-startup-plain"
        });
        assertFalse(off.startupPlain);
    }

    @Test
    void parseArgs_perfAndAppLeaf() throws Exception {
        ProtectOptions perf = PackerMain.parseArgs(new String[]{
                "in.apk", "--profile", "perf"
        });
        assertEquals(ProtectPolicy.Profile.PERF, perf.profile);
        assertNull(perf.startupPlainAppLeaf); // null → app-leaf OFF at buildDexLayout

        ProtectOptions on = PackerMain.parseArgs(new String[]{
                "in.apk", "--startup-plain-app-leaf"
        });
        assertEquals(Boolean.TRUE, on.startupPlainAppLeaf);

        ProtectOptions off = PackerMain.parseArgs(new String[]{
                "in.apk", "--profile", "perf", "--no-startup-plain-app-leaf"
        });
        assertEquals(Boolean.FALSE, off.startupPlainAppLeaf);
    }

    @Test
    void isBusinessType_perfNarrowSkipsAppAndCluster() {
        DexLayout.Context ctx = new DexLayout.Context();
        ctx.appPackagePrefix = "Lcom/ideack/notes/";
        ctx.businessPrefixes.add("Lcom/ideack/jar/");
        ctx.businessExactTypes.add("Lcom/ideack/notes/ui/OtherActivity;");
        ctx.paymentAutoVmp = true;
        ctx.matchAppPackagePrefix = false;
        ctx.matchBusinessPrefixes = false;

        assertFalse(DexLayout.isBusinessType("Lcom/ideack/notes/util/X;", ctx));
        assertFalse(DexLayout.isBusinessType("Lcom/ideack/jar/adv/Ad;", ctx));
        assertTrue(DexLayout.isBusinessType(
                "Lcom/ideack/notes/ui/OtherActivity;", ctx));
        // Payment markers still encrypt under narrow mode.
        assertTrue(DexLayout.isBusinessType(
                "Lcom/alipay/sdk/app/PayTask;", ctx));
    }
}

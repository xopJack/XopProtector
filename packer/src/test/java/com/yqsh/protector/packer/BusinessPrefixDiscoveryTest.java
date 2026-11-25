package com.yqsh.protector.packer;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

class BusinessPrefixDiscoveryTest {

    @Test
    void oneLevelParent_requiresFourSegments() {
        assertEquals("Lcom/foo/bar/",
                BusinessPrefixDiscovery.oneLevelParentPrefix("Lcom/foo/bar/app/"));
        assertNull(BusinessPrefixDiscovery.oneLevelParentPrefix("Lcom/foo/bar/"));
        assertNull(BusinessPrefixDiscovery.oneLevelParentPrefix("Lcom/foo/"));
        assertNull(BusinessPrefixDiscovery.oneLevelParentPrefix(null));
    }

    @Test
    void resolveManifestClassName_androidRules() {
        assertEquals("com.foo.bar.MainActivity",
                BusinessPrefixDiscovery.resolveManifestClassName(
                        "com.foo.bar", ".MainActivity"));
        assertEquals("com.foo.bar.MainActivity",
                BusinessPrefixDiscovery.resolveManifestClassName(
                        "com.foo.bar", "MainActivity"));
        assertEquals("com.other.LibActivity",
                BusinessPrefixDiscovery.resolveManifestClassName(
                        "com.foo.bar", "com.other.LibActivity"));
    }

    @Test
    void packagePrefixOfType() {
        assertEquals("Lcom/foo/bar/",
                BusinessPrefixDiscovery.packagePrefixOfType("Lcom/foo/bar/Baz$Q;"));
        assertNull(BusinessPrefixDiscovery.packagePrefixOfType("I"));
    }

    @Test
    void isBusinessType_usesBusinessPrefixes() {
        DexLayout.Context ctx = new DexLayout.Context();
        ctx.appPackagePrefix = "Lcom/foo/bar/app/";
        ctx.businessPrefixes.add("Lcom/foo/bar/");
        ctx.businessPrefixes.add("Lcom/foo/feature/");
        ctx.paymentAutoVmp = false;
        assertTrue(DexLayout.isBusinessType("Lcom/foo/bar/app/App;", ctx));
        assertTrue(DexLayout.isBusinessType("Lcom/foo/bar/util/Helper;", ctx));
        assertTrue(DexLayout.isBusinessType("Lcom/foo/feature/Ui;", ctx));
        assertFalse(DexLayout.isBusinessType("Lcom/foo/sdk/Lib;", ctx));
        assertFalse(DexLayout.isBusinessType("Lokhttp3/OkHttpClient;", ctx));
    }

    @Test
    void isBusinessType_usesBusinessExactTypes() {
        DexLayout.Context ctx = new DexLayout.Context();
        ctx.appPackagePrefix = "Lcom/a/b/";
        ctx.businessExactTypes.add("Lcom/c/d/MainActivity;");
        ctx.paymentAutoVmp = false;
        assertTrue(DexLayout.isBusinessType("Lcom/c/d/MainActivity;", ctx));
        assertTrue(DexLayout.isBusinessType("Lcom/c/d/MainActivity$1;", ctx));
        assertFalse(DexLayout.isBusinessType("Lcom/c/d/Helper;", ctx));
    }

    @Test
    void parseArgs_businessDiscoveryFlags() throws Exception {
        ProtectOptions o = PackerMain.parseArgs(new String[]{
                "in.apk",
                "--no-business-parent-prefix",
                "--no-business-auto-discover",
                "--business-discover-min-classes", "12",
                "--no-manifest-app-cross-vendor-leaf",
                "--no-manifest-business-exact",
                "--no-manifest-ambiguous-exact"
        });
        assertFalse(o.businessParentPrefix);
        assertFalse(o.businessAutoDiscover);
        assertEquals(12, o.businessDiscoverMinClasses);
        assertFalse(o.manifestAppCrossVendorLeaf);
        assertFalse(o.manifestBusinessExact);
        assertFalse(o.manifestAmbiguousExact);
    }

    @Test
    void toTypeDescriptor_andLeaf() {
        assertEquals("Lcom/c/d/MainActivity;",
                BusinessPrefixDiscovery.toTypeDescriptor("com.c.d.MainActivity"));
        assertEquals("Lcom/c/d/",
                BusinessPrefixDiscovery.leafPackagePrefixOfFqcn("com.c.d.MainActivity"));
        assertEquals(3, BusinessPrefixDiscovery.pathSegmentCount("Lcom/c/d/"));
        assertTrue(BusinessPrefixDiscovery.isFrameworkApplication(
                "android.app.Application"));
        assertFalse(BusinessPrefixDiscovery.isFrameworkApplication(
                "com.c.d.MyApp"));
    }

    @Test
    void enrich_parentOnly_noDex() {
        DexLayout.Context ctx = new DexLayout.Context();
        ctx.appPackagePrefix = "Lcom/acme/product/app/";
        BusinessPrefixDiscovery.Options opt = new BusinessPrefixDiscovery.Options();
        opt.parentPrefix = true;
        opt.autoDiscover = false;
        BusinessPrefixDiscovery.enrich(ctx, null, "com.acme.product.app",
                Collections.emptyList(), opt);
        assertTrue(ctx.businessPrefixes.contains("Lcom/acme/product/"));
    }

    @Test
    void vendorRoot_twoSegments() {
        assertEquals("Lcom/ideack/",
                BusinessPrefixDiscovery.vendorRootPrefix("Lcom/ideack/notes/"));
    }

    @Test
    void acceptDiscovered_rejectsAdsAndSdk() {
        String root = "Lcom/ideack/";
        assertTrue(BusinessPrefixDiscovery.acceptDiscoveredPrefix(
                "Lcom/ideack/jar/view/", root));
        assertFalse(BusinessPrefixDiscovery.acceptDiscoveredPrefix(
                "Lcom/bytedance/sdk/openadsdk/", root));
        assertFalse(BusinessPrefixDiscovery.acceptDiscoveredPrefix(
                "Lcom/byazt/gh/", root));
        assertFalse(BusinessPrefixDiscovery.acceptDiscoveredPrefix(
                "Landroidx/core/content/", root));
        assertFalse(BusinessPrefixDiscovery.acceptDiscoveredPrefix(
                "Lcom/other/company/", root));
    }

    @Test
    void enrich_renamedApplicationId_applicationDefinesRoot() {
        // applicationId=com.a.b, Application+Activity under com.c.d
        DexLayout.Context ctx = new DexLayout.Context();
        ctx.appPackagePrefix = "Lcom/a/b/";
        ctx.paymentAutoVmp = false;
        BusinessPrefixDiscovery.Options opt = new BusinessPrefixDiscovery.Options();
        opt.parentPrefix = false;
        opt.autoDiscover = false;
        opt.appCrossVendorLeaf = true;
        opt.businessExact = true;
        opt.ambiguousExact = true;
        opt.discoverMinClasses = 8; // Application leaf needs DEX count; Activity leaf does not
        List<String> components = Arrays.asList(
                "com.c.d.MyApp",
                "com.c.d.MainActivity",
                "com.c.d.ui.HomeActivity",
                "com.c.feature.OtherActivity",
                "com.bytedance.sdk.openadsdk.StubActivity",
                "com.other.vendor.WeirdActivity"
        );
        BusinessPrefixDiscovery.enrichWithComponents(ctx, "com.a.b",
                "com.c.d.MyApp", components, Collections.emptyList(), opt);

        // Application exact (leaf skipped: no DEX / thin)
        assertTrue(ctx.businessExactTypes.contains("Lcom/c/d/MyApp;"));
        // Under Application leaf (Lcom/c/d/) → package promotion
        assertTrue(ctx.businessPrefixes.contains("Lcom/c/d/"));
        assertTrue(ctx.businessPrefixes.contains("Lcom/c/d/ui/")
                || DexLayout.isBusinessType("Lcom/c/d/ui/HomeActivity;", ctx));
        assertTrue(DexLayout.isBusinessType("Lcom/c/d/MainActivity;", ctx));
        assertTrue(DexLayout.isBusinessType("Lcom/c/d/ui/HomeActivity;", ctx));
        // Sibling outside Application leaf → exact only, no package
        assertTrue(DexLayout.isBusinessType("Lcom/c/feature/OtherActivity;", ctx));
        assertFalse(ctx.businessPrefixes.contains("Lcom/c/feature/"));
        // Ads denied; other ambiguous exact-only
        assertFalse(ctx.businessPrefixes.stream()
                .anyMatch(p -> p.startsWith("Lcom/bytedance/")));
        assertFalse(ctx.businessExactTypes.contains(
                "Lcom/bytedance/sdk/openadsdk/StubActivity;"));
        assertTrue(DexLayout.isBusinessType(
                "Lcom/other/vendor/WeirdActivity;", ctx));
        assertFalse(ctx.businessPrefixes.contains("Lcom/other/vendor/"));
    }

    @Test
    void enrich_noApplication_crossPackage_exactOnly() {
        DexLayout.Context ctx = new DexLayout.Context();
        ctx.appPackagePrefix = "Lcom/a/b/";
        ctx.paymentAutoVmp = false;
        BusinessPrefixDiscovery.Options opt = new BusinessPrefixDiscovery.Options();
        opt.parentPrefix = false;
        opt.autoDiscover = false;
        opt.ambiguousExact = true;
        BusinessPrefixDiscovery.enrichWithComponents(ctx, "com.a.b",
                null,
                Arrays.asList(
                        "com.c.d.MainActivity",
                        "com.bytedance.sdk.openadsdk.StubActivity"),
                Collections.emptyList(), opt);
        assertTrue(ctx.businessExactTypes.contains("Lcom/c/d/MainActivity;"));
        assertTrue(DexLayout.isBusinessType("Lcom/c/d/MainActivity;", ctx));
        assertFalse(ctx.businessPrefixes.contains("Lcom/c/d/"));
        assertFalse(DexLayout.isBusinessType(
                "Lcom/bytedance/sdk/openadsdk/StubActivity;", ctx));
    }

    @Test
    void enrich_adApplication_denied_noSystemRoot() {
        DexLayout.Context ctx = new DexLayout.Context();
        ctx.appPackagePrefix = "Lcom/a/b/";
        ctx.paymentAutoVmp = false;
        BusinessPrefixDiscovery.Options opt = new BusinessPrefixDiscovery.Options();
        opt.parentPrefix = false;
        opt.autoDiscover = false;
        BusinessPrefixDiscovery.enrichWithComponents(ctx, "com.a.b",
                "com.bytedance.sdk.openadsdk.FakeApp",
                Collections.singletonList(
                        "com.bytedance.sdk.openadsdk.StubActivity"),
                Collections.emptyList(), opt);
        assertTrue(ctx.businessPrefixes.isEmpty());
        assertTrue(ctx.businessExactTypes.isEmpty());
    }

    @Test
    void enrich_ambiguousExact_optional() {
        DexLayout.Context ctx = new DexLayout.Context();
        ctx.appPackagePrefix = "Lcom/a/b/";
        ctx.paymentAutoVmp = false;
        BusinessPrefixDiscovery.Options opt = new BusinessPrefixDiscovery.Options();
        opt.parentPrefix = false;
        opt.autoDiscover = false;
        opt.ambiguousExact = true;
        BusinessPrefixDiscovery.enrichWithComponents(ctx, "com.a.b",
                null,
                Collections.singletonList("com.other.vendor.WeirdActivity"),
                Collections.emptyList(), opt);
        assertTrue(ctx.businessExactTypes.contains(
                "Lcom/other/vendor/WeirdActivity;"));
        assertFalse(ctx.businessPrefixes.contains("Lcom/other/vendor/"));
    }

    @Test
    void enrich_sameVendor_manifestPrefix() {
        DexLayout.Context ctx = new DexLayout.Context();
        ctx.appPackagePrefix = "Lcom/foo/bar/";
        ctx.paymentAutoVmp = false;
        BusinessPrefixDiscovery.Options opt = new BusinessPrefixDiscovery.Options();
        opt.parentPrefix = false;
        opt.autoDiscover = false;
        BusinessPrefixDiscovery.enrichWithComponents(ctx, "com.foo.bar",
                "com.foo.bar.App",
                Arrays.asList("com.foo.bar.App", "com.foo.bar.ui.MainActivity"),
                Collections.emptyList(), opt);
        assertTrue(ctx.businessPrefixes.contains("Lcom/foo/bar/ui/")
                || DexLayout.isBusinessType("Lcom/foo/bar/ui/MainActivity;", ctx));
        assertTrue(DexLayout.isBusinessType("Lcom/foo/bar/ui/MainActivity;", ctx));
    }
}

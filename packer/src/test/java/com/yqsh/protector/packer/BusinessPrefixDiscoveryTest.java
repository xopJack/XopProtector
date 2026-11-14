package com.yqsh.protector.packer;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

import java.util.Collections;

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
    void parseArgs_businessDiscoveryFlags() throws Exception {
        ProtectOptions o = PackerMain.parseArgs(new String[]{
                "in.apk",
                "--no-business-parent-prefix",
                "--no-business-auto-discover",
                "--business-discover-min-classes", "12"
        });
        assertFalse(o.businessParentPrefix);
        assertFalse(o.businessAutoDiscover);
        assertEquals(12, o.businessDiscoverMinClasses);
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
}

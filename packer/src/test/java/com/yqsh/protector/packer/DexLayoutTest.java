package com.yqsh.protector.packer;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

class DexLayoutTest {

    @Test
    void parseMode_aliasesMapToHybrid() {
        assertEquals(DexLayout.Mode.HYBRID, DexLayout.parseMode("hybrid"));
        assertEquals(DexLayout.Mode.HYBRID, DexLayout.parseMode("baidu"));
        assertEquals(DexLayout.Mode.HYBRID, DexLayout.parseMode("encrypt-all"));
        assertEquals(DexLayout.Mode.HYBRID, DexLayout.parseMode(""));
    }

    @Test
    void parseArgs_ignoresDeprecatedDexLayout() throws Exception {
        ProtectOptions o = PackerMain.parseArgs(new String[]{
                "in.apk",
                "--dex-layout", "encrypt-all"
        });
        assertEquals("in.apk", o.inputApk.getName());
    }

    @Test
    void decideHybrid_sdkOnly_keepPlain() {
        DexLayout.Context ctx = new DexLayout.Context();
        DexLayout.Result r = DexLayout.decideHybrid(0, 500, 0, ctx);
        assertEquals(DexLayout.Decision.KEEP_PLAIN, r.decision);
        assertTrue(r.reason.contains("sdk-only"));
    }

    @Test
    void decideHybrid_anyBusiness_encrypt() {
        DexLayout.Context ctx = new DexLayout.Context();
        DexLayout.Result r = DexLayout.decideHybrid(1, 9000, 0, ctx);
        assertEquals(DexLayout.Decision.ENCRYPT, r.decision);
        assertTrue(r.reason.contains("business"));
    }

    @Test
    void decideHybrid_greyOther_noBusiness_keepPlain() {
        DexLayout.Context ctx = new DexLayout.Context();
        DexLayout.Result r = DexLayout.decideHybrid(0, 100, 3, ctx);
        assertEquals(DexLayout.Decision.KEEP_PLAIN, r.decision);
        assertTrue(r.reason.contains("no-business"));
    }

    @Test
    void isBusinessType_appPrefixAndPayment() {
        DexLayout.Context ctx = new DexLayout.Context();
        ctx.appPackagePrefix = "Lcom/ideack/notes/";
        ctx.paymentAutoVmp = true;
        assertTrue(DexLayout.isBusinessType("Lcom/ideack/notes/App;", ctx));
        assertTrue(DexLayout.isBusinessType("Lcom/alipay/sdk/m/u/e;", ctx));
        assertFalse(DexLayout.isBusinessType(
                "Landroidx/appcompat/app/AppCompatActivity;", ctx));
        assertTrue(DexLayout.isSdkType("Landroidx/appcompat/app/AppCompatActivity;"));
    }
}

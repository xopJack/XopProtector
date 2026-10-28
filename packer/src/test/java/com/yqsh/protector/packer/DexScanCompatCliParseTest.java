package com.yqsh.protector.packer;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

class DexScanCompatCliParseTest {

    @Test
    void defaultIsOn() throws Exception {
        ProtectOptions o = PackerMain.parseArgs(new String[]{"in.apk"});
        assertTrue(o.dexScanCompat);
    }

    @Test
    void canDisable() throws Exception {
        ProtectOptions o = PackerMain.parseArgs(new String[]{
                "in.apk",
                "--no-dex-scan-compat"
        });
        assertFalse(o.dexScanCompat);
    }

    @Test
    void canEnableExplicitly() throws Exception {
        ProtectOptions o = PackerMain.parseArgs(new String[]{
                "in.apk",
                "--no-dex-scan-compat",
                "--dex-scan-compat"
        });
        assertTrue(o.dexScanCompat);
    }
}

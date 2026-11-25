package com.yqsh.protector.packer;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;

class SoDecryptModeCliParseTest {

    @Test
    void defaultIsLazy() throws Exception {
        ProtectOptions o = PackerMain.parseArgs(new String[]{"in.apk"});
        assertEquals(ProtectOptions.SoDecryptMode.LAZY, o.soDecryptMode);
    }

    @Test
    void parseLazy() throws Exception {
        ProtectOptions o = PackerMain.parseArgs(new String[]{
                "in.apk",
                "--so-decrypt-mode", "lazy"
        });
        assertEquals(ProtectOptions.SoDecryptMode.LAZY, o.soDecryptMode);
    }

    @Test
    void parseEagerCaseInsensitive() throws Exception {
        ProtectOptions o = PackerMain.parseArgs(new String[]{
                "in.apk",
                "--so-decrypt-mode", "EAGER"
        });
        assertEquals(ProtectOptions.SoDecryptMode.EAGER, o.soDecryptMode);
    }

    @Test
    void unknownModeThrows() {
        assertThrows(IllegalArgumentException.class, () ->
                PackerMain.parseArgs(new String[]{
                        "in.apk",
                        "--so-decrypt-mode", "async"
                }));
    }

    @Test
    void wireHelpers() {
        assertEquals("eager", ProtectOptions.soDecryptModeWire(
                ProtectOptions.SoDecryptMode.EAGER));
        assertEquals("lazy", ProtectOptions.soDecryptModeWire(
                ProtectOptions.SoDecryptMode.LAZY));
        assertEquals(ProtectOptions.SoDecryptMode.LAZY,
                ProtectOptions.parseSoDecryptMode("lazy"));
    }
}

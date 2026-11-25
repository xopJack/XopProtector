package com.yqsh.protector.packer;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

class BusinessSoSystemSonameTest {

    @Test
    void systemSonameMatchesCryptoAndSslPrefixes() {
        assertTrue(BusinessSoProtector.isSystemSonameSkip("libcrypto.so"));
        assertTrue(BusinessSoProtector.isSystemSonameSkip("libcryptoPrivate.so"));
        assertTrue(BusinessSoProtector.isSystemSonameSkip("libssl.so"));
        assertTrue(BusinessSoProtector.isSystemSonameSkip("libsslPrivate.so"));
        assertTrue(BusinessSoProtector.isSystemSonameSkip("libGLESv3.so"));
        assertTrue(BusinessSoProtector.isSystemSonameSkip("libc.so"));
    }

    @Test
    void systemSonameDoesNotMatchBusinessLibs() {
        assertFalse(BusinessSoProtector.isSystemSonameSkip("libcpbase.so"));
        assertFalse(BusinessSoProtector.isSystemSonameSkip("libd3.so"));
        assertFalse(BusinessSoProtector.isSystemSonameSkip("libBugly.so"));
    }

    @Test
    void industryStillSeparateFromSystem() {
        assertTrue(BusinessSoProtector.isIndustrySkip("libBugly.so"));
        assertTrue(BusinessSoProtector.isIndustrySkip("libsophix.so"));
        assertFalse(BusinessSoProtector.isSystemSonameSkip("libBugly.so"));
    }

    @Test
    void pangleCsjMaparmorSkippedInSafe() throws Exception {
        assertTrue(BusinessSoProtector.isIndustrySkip("libpanglearmor.so"));
        assertTrue(BusinessSoProtector.isIndustrySkip("libmaparmor.so"));
        assertTrue(BusinessSoProtector.isIndustrySkip("libMapArmor.so"));
        var m = BusinessSoProtector.class.getDeclaredMethod(
                "skipReason", String.class, BusinessSoProtector.Mode.class);
        m.setAccessible(true);
        assertEquals("industry/runtime",
                m.invoke(null, "libmaparmor.so", BusinessSoProtector.Mode.SAFE));
        assertEquals(null,
                m.invoke(null, "libmaparmor.so", BusinessSoProtector.Mode.AGGRESSIVE));
        // P0 EXACT uses category reason (see BusinessSoIndustryPolicyTest).
        assertEquals("industry/crash",
                m.invoke(null, "libcrashsdk.so", BusinessSoProtector.Mode.SAFE));
    }

    @Test
    void uniAppWeexRuntimeSkippedInAllModes() throws Exception {
        assertTrue(BusinessSoProtector.isUniAppRuntimeSkip("libweexjsb.so"));
        assertTrue(BusinessSoProtector.isUniAppRuntimeSkip("libweexjst.so"));
        assertTrue(BusinessSoProtector.isUniAppRuntimeSkip("libweexjss.so"));
        assertTrue(BusinessSoProtector.isUniAppRuntimeSkip("libweexcore.so"));
        assertTrue(BusinessSoProtector.isUniAppRuntimeSkip("libimagepipeline.so"));
        assertTrue(BusinessSoProtector.isUniAppRuntimeSkip("libdcblur.so"));
        assertFalse(BusinessSoProtector.isUniAppRuntimeSkip("libweex.so"));
        assertFalse(BusinessSoProtector.isUniAppRuntimeSkip("libcpbase.so"));

        var m = BusinessSoProtector.class.getDeclaredMethod(
                "skipReason", String.class, BusinessSoProtector.Mode.class);
        m.setAccessible(true);
        assertEquals("uniapp/runtime",
                m.invoke(null, "libweexjss.so", BusinessSoProtector.Mode.AGGRESSIVE));
        assertEquals("uniapp/runtime",
                m.invoke(null, "libweexcore.so", BusinessSoProtector.Mode.AGGRESSIVE));
        assertEquals("uniapp/runtime",
                m.invoke(null, "libimagepipeline.so", BusinessSoProtector.Mode.SAFE));
    }

    @Test
    void skipReasonAggressiveStillBlocksClassS() throws Exception {
        var m = BusinessSoProtector.class.getDeclaredMethod(
                "skipReason", String.class, BusinessSoProtector.Mode.class);
        m.setAccessible(true);
        assertEquals("system_soname",
                m.invoke(null, "libcrypto.so", BusinessSoProtector.Mode.AGGRESSIVE));
        assertEquals("system_soname",
                m.invoke(null, "libsslPrivate.so", BusinessSoProtector.Mode.MAX));
        // Industry only in SAFE/MAX
        assertEquals("industry/runtime",
                m.invoke(null, "libBugly.so", BusinessSoProtector.Mode.SAFE));
        assertEquals(null,
                m.invoke(null, "libBugly.so", BusinessSoProtector.Mode.AGGRESSIVE));
    }
}

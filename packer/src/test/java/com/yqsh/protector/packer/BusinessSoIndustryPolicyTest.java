package com.yqsh.protector.packer;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.reflect.Method;

import org.junit.jupiter.api.Test;

/**
 * P0 SO Industry Compatibility Policy — EXACT/PREFIX, SAFE/MAX only,
 * AGGRESSIVE isolated; P1 short prefixes must not match.
 */
class BusinessSoIndustryPolicyTest {

    private static String skipReason(String name, BusinessSoProtector.Mode mode)
            throws Exception {
        Method m = BusinessSoProtector.class.getDeclaredMethod(
                "skipReason", String.class, BusinessSoProtector.Mode.class);
        m.setAccessible(true);
        return (String) m.invoke(null, name, mode);
    }

    @Test
    void t01t02_exactCrashsdkSafeAndMax() throws Exception {
        assertEquals("industry/crash",
                skipReason("libcrashsdk.so", BusinessSoProtector.Mode.SAFE));
        assertEquals("industry/crash",
                skipReason("libcrashsdk.so", BusinessSoProtector.Mode.MAX));
        assertEquals("industry/crash",
                BusinessSoProtector.industryPolicyReason("libcrashsdk.so"));
    }

    @Test
    void t03t04_prefixOemPushSafeAndMax() throws Exception {
        assertEquals("industry/oem-push",
                skipReason("libhms_core.so", BusinessSoProtector.Mode.SAFE));
        assertEquals("industry/oem-push",
                skipReason("libmipush_sdk.so", BusinessSoProtector.Mode.MAX));
        assertEquals("industry/cloud-push",
                skipReason("libtpns_xxx.so", BusinessSoProtector.Mode.SAFE));
        assertEquals("industry/analytics",
                skipReason("libsensorsdata.so", BusinessSoProtector.Mode.MAX));
    }

    @Test
    void t05t06_skipMeansIndustryPolicyHit() {
        // Packer only emits sokeys for encrypted entries; policy hit ⇒ SKIP path.
        assertTrue(BusinessSoProtector.isIndustrySkip("libapssdk.so"));
        assertEquals("industry/analytics/ad-aux",
                BusinessSoProtector.industryPolicyReason("libapssdk.so"));
        assertEquals("industry/compliance/ad-aux",
                BusinessSoProtector.industryPolicyReason("libCtaApiLib.so"));
    }

    @Test
    void tpnsAndJcoreSampleExactSkip() throws Exception {
        assertEquals("industry/cloud-push",
                skipReason("libxgVipSecurity.so", BusinessSoProtector.Mode.SAFE));
        assertEquals("industry/cloud-push",
                skipReason("libxgVipSecurity.so", BusinessSoProtector.Mode.MAX));
        assertEquals("industry/jpush",
                skipReason("libjutils.so", BusinessSoProtector.Mode.SAFE));
        // Wide P1 prefixes still rejected; only the sample EXACT hits.
        assertNull(BusinessSoProtector.industryPolicyReason("libxg_other.so"));
        assertNull(skipReason("libxgVipSecurity.so", BusinessSoProtector.Mode.AGGRESSIVE));
        assertNull(skipReason("libjutils.so", BusinessSoProtector.Mode.AGGRESSIVE));
    }

    @Test
    void baiduLocationExactSkip() throws Exception {
        assertEquals("industry/location",
                skipReason("liblocSDK8b.so", BusinessSoProtector.Mode.SAFE));
        assertEquals("industry/location",
                skipReason("libindoor.so", BusinessSoProtector.Mode.MAX));
        assertEquals("industry/location",
                skipReason("libtiny_magic.so", BusinessSoProtector.Mode.SAFE));
        assertNull(BusinessSoProtector.industryPolicyReason("liblocsdk.so"));
        assertNull(BusinessSoProtector.industryPolicyReason("libindoorbase.so"));
        assertNull(BusinessSoProtector.industryPolicyReason("libtiny.so"));
        assertNull(skipReason("liblocSDK8b.so", BusinessSoProtector.Mode.AGGRESSIVE));
    }

    @Test
    void t07t08_aggressiveIgnoresIndustryPolicy() throws Exception {
        assertNull(skipReason("libcrashsdk.so", BusinessSoProtector.Mode.AGGRESSIVE));
        assertNull(skipReason("libhms_core.so", BusinessSoProtector.Mode.AGGRESSIVE));
        assertNull(skipReason("libsensors.so", BusinessSoProtector.Mode.AGGRESSIVE));
    }

    @Test
    void t09t10_businessSoNotMatchedByP0() throws Exception {
        assertNull(BusinessSoProtector.industryPolicyReason("libjl_crc.so"));
        assertNull(BusinessSoProtector.industryPolicyReason("libpldroid_encoder.so"));
        assertNull(skipReason("libjl_auth.so", BusinessSoProtector.Mode.SAFE));
        assertNull(skipReason("libpldroid_amix.so", BusinessSoProtector.Mode.MAX));
    }

    @Test
    void t11t12_p1ShortPrefixesNotInPolicy() throws Exception {
        assertNull(BusinessSoProtector.industryPolicyReason("libmcs_sdk.so"));
        assertNull(BusinessSoProtector.industryPolicyReason("libxg_push.so"));
        assertNull(BusinessSoProtector.industryPolicyReason("liboppo_push.so"));
        assertNull(BusinessSoProtector.industryPolicyReason("libvivo_utils.so"));
        assertNull(BusinessSoProtector.industryPolicyReason("libpushkit.so"));
        assertNull(skipReason("libmcs_sdk.so", BusinessSoProtector.Mode.SAFE));
        assertNull(skipReason("libxg_push.so", BusinessSoProtector.Mode.MAX));
    }

    @Test
    void t13_exactCaseNormalized() throws Exception {
        assertEquals("industry/compliance/ad-aux",
                skipReason("libCtaApiLib.so", BusinessSoProtector.Mode.SAFE));
        assertEquals("industry/crash",
                skipReason("LibCrashSdk.SO", BusinessSoProtector.Mode.MAX));
    }

    @Test
    void legacyRulesUnchangedCategoryRuntime() throws Exception {
        assertEquals("industry/runtime",
                skipReason("libmaparmor.so", BusinessSoProtector.Mode.SAFE));
        assertEquals("industry/runtime",
                skipReason("libBugly.so", BusinessSoProtector.Mode.MAX));
        assertEquals("industry/runtime",
                skipReason("libumeng-spy.so", BusinessSoProtector.Mode.SAFE));
        assertTrue(BusinessSoProtector.isIndustrySkip("libjpush.so"));
        assertTrue(BusinessSoProtector.isIndustrySkip("libgetui.so"));
    }

    @Test
    void vpushKeptOppoVivoWidePrefixesDeferred() {
        assertEquals("industry/oem-push",
                BusinessSoProtector.industryPolicyReason("libvpush_core.so"));
        assertNull(BusinessSoProtector.industryPolicyReason("libvivo_foo.so"));
        assertNull(BusinessSoProtector.industryPolicyReason("liboppo_bar.so"));
    }

    @Test
    void emptyNameStillTreatedAsSkipLikeLegacy() {
        assertTrue(BusinessSoProtector.isIndustrySkip(""));
        assertTrue(BusinessSoProtector.isIndustrySkip(null));
    }
}

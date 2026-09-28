package com.yqsh.protector.packer;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

class BusinessSoTextDiagTest {

    @Test
    void buildSoTextDiagJsonIncludesPlaintextShaAndPtLoad() {
        BusinessSoProtector.ProtectResult result =
                new BusinessSoProtector.ProtectResult(new java.util.ArrayList<>());
        result.mode = BusinessSoProtector.Mode.SAFE;
        BusinessSoProtector.TextDiag diag = new BusinessSoProtector.TextDiag(
                0x1000L, 0x200L, 0x401000L,
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                0L, 0L, 0x3000L, 0x3000L, 5 /* PF_R|PF_X */);
        result.encrypted.add(new BusinessSoProtector.SoDecision(
                "arm64-v8a", "libDJIProtobuf.so", 1_048_576L, 0x200L, 1000L,
                "encrypted", diag));

        String json = BusinessSoProtector.buildSoTextDiagJson(result);
        assertTrue(json.contains("\"version\": 2"));
        assertTrue(json.contains("\"mode\": \"safe\""));
        assertTrue(json.contains("libDJIProtobuf.so"));
        assertTrue(json.contains("\"text_offset\": 4096"));
        assertTrue(json.contains("\"text_size\": 512"));
        assertTrue(json.contains("\"text_sh_addr\": 4198400"));
        assertTrue(json.contains(
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"));
        assertTrue(json.contains("\"p_flags\": 5"));
        assertTrue(json.contains("\"l2e\": false"));
        assertFalse(json.contains("sokeys"));
    }

    @Test
    void soTextDiagJsonWritesL2eWhenPathSensitive() {
        BusinessSoProtector.ProtectResult result =
                new BusinessSoProtector.ProtectResult(new java.util.ArrayList<>());
        result.mode = BusinessSoProtector.Mode.AGGRESSIVE;
        BusinessSoProtector.TextDiag diag = new BusinessSoProtector.TextDiag(
                0x1000L, 5L * 1024 * 1024, 0x401000L,
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                0L, 0L, 0x3000L, 0x3000L, 5);
        result.encrypted.add(new BusinessSoProtector.SoDecision(
                "arm64-v8a", "libd3.so", 90_000_000L, 5L * 1024 * 1024, 1000L,
                "encrypted", diag, true));
        String json = BusinessSoProtector.buildSoTextDiagJson(result);
        assertTrue(json.contains("\"l2e\": true"));
        assertTrue(json.contains("libd3.so"));
    }

    @Test
    void sizeReportEncryptedIncludesTextMeta() {
        BusinessSoProtector.ProtectResult result =
                new BusinessSoProtector.ProtectResult(new java.util.ArrayList<>());
        result.mode = BusinessSoProtector.Mode.MAX;
        result.encrypted.add(new BusinessSoProtector.SoDecision(
                "armeabi-v7a", "libfoo.so", 4096L, 256L, 0L, "encrypted",
                new BusinessSoProtector.TextDiag(
                        0x200L, 256L, 0x8200L, "aa", 0L, 0L, 0x1000L, 0x1000L, 5)));

        String report = BusinessSoProtector.buildSizeReportJson(1000, 1100, result, true);
        assertTrue(report.contains("\"so_mode\": \"max\""));
        assertTrue(report.contains("\"text_offset\": 512"));
        assertTrue(report.contains("\"text_sha256\": \"aa\""));
    }
}

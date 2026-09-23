package com.yqsh.protector.packer;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;
import java.nio.file.Files;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** {@code --protect-so-include}: encrypt ONLY the listed basenames. */
class BusinessSoIncludeFilterTest {

    @TempDir
    File temp;

    @Test
    void includeOnlyKeepsListedBasenameAndSkipsOthers() throws Exception {
        File abi = new File(temp, "arm64-v8a");
        assertTrue(abi.mkdirs());
        for (String name : new String[] {
                "libsupercell_brawlstars.so",   // the one we want protected
                "libg.so",
                "libscid_sdk.so",
                "libc++_shared.so"
        }) {
            Files.write(new File(abi, name).toPath(), new byte[] {0x7f, 'E', 'L', 'F'});
        }

        BusinessSoProtector.Options opts = new BusinessSoProtector.Options();
        opts.mode = BusinessSoProtector.Mode.SAFE;
        opts.includeBasenames.add("libsupercell_brawlstars.so");

        BusinessSoProtector.ProtectResult result = BusinessSoProtector.protectAll(temp, opts);

        // The listed basename must not be skipped with the not_included reason.
        long listedSkipped = result.skippedPolicy.stream()
                .filter(d -> "libsupercell_brawlstars.so".equals(d.name))
                .filter(d -> "not_included".equals(d.reason) || "exclude".equals(d.reason))
                .count();
        assertEquals(0, listedSkipped, "included basename must be a protect candidate");

        // Everything else is skipped with the not_included reason.
        long notIncluded = result.skippedPolicy.stream()
                .filter(d -> "not_included".equals(d.reason))
                .count();
        assertEquals(3, notIncluded,
                "libg/libscid_sdk/libc++_shared should be skipped as not_included");
    }

    @Test
    void includeAndExcludeAreRejectedTogether() throws Exception {
        File abi = new File(temp, "arm64-v8a");
        assertTrue(abi.mkdirs());
        Files.write(new File(abi, "liba.so").toPath(), new byte[] {0x7f, 'E', 'L', 'F'});

        BusinessSoProtector.Options opts = new BusinessSoProtector.Options();
        opts.includeBasenames.add("liba.so");
        opts.excludeBasenames.add("libb.so");

        IllegalArgumentException e = assertThrows(
                IllegalArgumentException.class,
                () -> BusinessSoProtector.protectAll(temp, opts));
        assertTrue(e.getMessage().contains("mutually exclusive"));
    }
}
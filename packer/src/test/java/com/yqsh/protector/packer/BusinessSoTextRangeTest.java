package com.yqsh.protector.packer;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import java.io.File;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Files;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** .text that is not stored in the file must be skipped, not EOF the pack. */
class BusinessSoTextRangeTest {

    @TempDir
    File tmp;

    @Test
    void textPastEofAndNobitsAreSkipped() throws Exception {
        File past = new File(tmp, "past.so");
        Files.write(past.toPath(), elfWithText(1, 0x100, 0x1000));
        assertEquals(".text exceeds file", BusinessSoProtector.textRangeSkipReason(past));

        File nobits = new File(tmp, "nobits.so");
        Files.write(nobits.toPath(), elfWithText(8, 0, 0x20));
        assertEquals(".text not in file", BusinessSoProtector.textRangeSkipReason(nobits));

        File ok = new File(tmp, "ok.so");
        Files.write(ok.toPath(), elfWithText(1, 64, 16));
        assertNull(BusinessSoProtector.textRangeSkipReason(ok));
    }

    /** ELF64 AArch64 ET_DYN with null, .text, .shstrtab. */
    private static byte[] elfWithText(int textType, long textOff, long textSize) {
        byte[] str = new byte[] {
                0,
                '.', 't', 'e', 'x', 't', 0,
                '.', 's', 'h', 's', 't', 'r', 't', 'a', 'b', 0
        };
        int shOff = 64;
        int shEnt = 64;
        int shNum = 3;
        int strOff = shOff + shNum * shEnt;
        ByteBuffer b = ByteBuffer.allocate(strOff + str.length).order(ByteOrder.LITTLE_ENDIAN);
        b.put(new byte[] {0x7f, 'E', 'L', 'F', 2, 1, 1, 0});
        b.position(16);
        b.putShort((short) 3); // ET_DYN
        b.putShort((short) 183); // EM_AARCH64
        b.putInt(1);
        b.position(32);
        b.putLong(0); // phoff
        b.putLong(shOff);
        b.putInt(0); // flags
        b.putShort((short) 64);
        b.putShort((short) 0);
        b.putShort((short) 0);
        b.putShort((short) shEnt);
        b.putShort((short) shNum);
        b.putShort((short) 2); // shstrndx
        // sh 1 .text
        b.position(shOff + shEnt);
        b.putInt(1); // name
        b.putInt(textType);
        b.putLong(6);
        b.putLong(0);
        b.putLong(textOff);
        b.putLong(textSize);
        // sh 2 .shstrtab
        b.position(shOff + 2 * shEnt);
        b.putInt(7);
        b.putInt(3);
        b.putLong(0);
        b.putLong(0);
        b.putLong(strOff);
        b.putLong(str.length);
        b.position(strOff);
        b.put(str);
        return b.array();
    }
}

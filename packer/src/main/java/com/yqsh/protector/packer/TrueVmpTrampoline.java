package com.yqsh.protector.packer;

import com.android.tools.smali.dexlib2.AccessFlags;
import com.android.tools.smali.dexlib2.Opcode;
import com.android.tools.smali.dexlib2.Opcodes;
import com.android.tools.smali.dexlib2.builder.MutableMethodImplementation;
import com.android.tools.smali.dexlib2.builder.instruction.BuilderInstruction10x;
import com.android.tools.smali.dexlib2.builder.instruction.BuilderInstruction11x;
import com.android.tools.smali.dexlib2.builder.instruction.BuilderInstruction21c;
import com.android.tools.smali.dexlib2.builder.instruction.BuilderInstruction21s;
import com.android.tools.smali.dexlib2.builder.instruction.BuilderInstruction22c;
import com.android.tools.smali.dexlib2.builder.instruction.BuilderInstruction22x;
import com.android.tools.smali.dexlib2.builder.instruction.BuilderInstruction23x;
import com.android.tools.smali.dexlib2.builder.instruction.BuilderInstruction31i;
import com.android.tools.smali.dexlib2.builder.instruction.BuilderInstruction35c;
import com.android.tools.smali.dexlib2.dexbacked.DexBackedDexFile;
import com.android.tools.smali.dexlib2.iface.ClassDef;
import com.android.tools.smali.dexlib2.iface.Method;
import com.android.tools.smali.dexlib2.iface.MethodImplementation;
import com.android.tools.smali.dexlib2.immutable.ImmutableClassDef;
import com.android.tools.smali.dexlib2.immutable.ImmutableMethod;
import com.android.tools.smali.dexlib2.immutable.reference.ImmutableMethodReference;
import com.android.tools.smali.dexlib2.immutable.reference.ImmutableTypeReference;
import com.android.tools.smali.dexlib2.writer.io.FileDataStore;
import com.android.tools.smali.dexlib2.writer.pool.DexPool;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Rewrites TRUE_VMP methods so their DEX body only calls
 * {@code VmBridge.interpret(dexIndex, methodIdx, Object[] args)}.
 */
public final class TrueVmpTrampoline {
    private static final String BRIDGE = "Lcom/yqsh/protector/shell/VmBridge;";
    private static final List<String> INTERPRET_PARAMS = List.of("I", "I", "[Ljava/lang/Object;");

    public static final class Target {
        public final int methodIndex;
        public final int dexIndex;

        public Target(int methodIndex, int dexIndex) {
            this.methodIndex = methodIndex;
            this.dexIndex = dexIndex;
        }
    }

    private TrueVmpTrampoline() {
    }

    /** All primitive signatures including F/D are supported. */
    public static boolean supportsSignature(String returnType, String[] paramTypes) {
        return true;
    }

    /**
     * After DexPool rewrite + rematch of method indices, patch the
     * {@code const} immediates inside TRUE_VMP trampolines so they match
     * rematched code.bin keys (avoids collisions with hollow entries).
     */
    public static void rebindEmbeddedIndices(File dexFile, List<PackerMain.InsnRecord> records)
            throws IOException {
        List<PackerMain.InsnRecord> trueVmp = new ArrayList<>();
        for (PackerMain.InsnRecord r : records) {
            if (r != null && (r.flags & VmCodec.FLAG_TRUE_VMP) != 0) {
                trueVmp.add(r);
            }
        }
        if (trueVmp.isEmpty()) {
            return;
        }

        com.android.dex.Dex dex = new com.android.dex.Dex(Files.readAllBytes(dexFile.toPath()));
        Map<String, Integer> codeOffsets = indexCodeOffsets(dex);
        try (java.io.RandomAccessFile raf = new java.io.RandomAccessFile(dexFile, "rw")) {
            for (PackerMain.InsnRecord rec : trueVmp) {
                Integer codeOffBoxed = codeOffsets.get(PackerMain.methodKey(rec));
                int codeOff = codeOffBoxed == null ? -1 : codeOffBoxed;
                if (codeOff <= 0) {
                    throw new IOException("TRUE_VMP rebind: no code for "
                            + rec.definingClass + "->" + rec.methodName);
                }
                // code_item header is 16 bytes; trampoline starts with:
                //   const v1, dexIndex    (6 bytes)  opcode 0x14
                //   const v2, methodIdx   (6 bytes)  — immediate at +8
                raf.seek(codeOff + 16);
                byte[] head = new byte[12];
                raf.readFully(head);
                int op0 = head[0] & 0xff;
                int op1 = head[6] & 0xff;
                if (op0 == 0x14 && (head[1] & 0xff) == 1 && op1 == 0x14 && (head[7] & 0xff) == 2) {
                    head[8] = (byte) (rec.methodIndex & 0xff);
                    head[9] = (byte) ((rec.methodIndex >> 8) & 0xff);
                    head[10] = (byte) ((rec.methodIndex >> 16) & 0xff);
                    head[11] = (byte) ((rec.methodIndex >> 24) & 0xff);
                    raf.seek(codeOff + 16);
                    raf.write(head);
                } else if (op0 == 0x13 && op1 == 0x13) {
                    // Legacy trampoline (const/16) — only valid if index fits.
                    if (rec.methodIndex > Short.MAX_VALUE) {
                        throw new IOException("TRUE_VMP rebind: legacy const/16 cannot hold "
                                + rec.methodIndex);
                    }
                    head[6] = (byte) (rec.methodIndex & 0xff);
                    head[7] = (byte) ((rec.methodIndex >> 8) & 0xff);
                    raf.seek(codeOff + 16);
                    raf.write(head, 0, 8);
                } else {
                    throw new IOException("TRUE_VMP rebind: unexpected trampoline opcodes for "
                            + rec.methodName + " head="
                            + String.format("%02x %02x … %02x %02x",
                            head[0] & 0xff, head[1] & 0xff, head[6] & 0xff, head[7] & 0xff));
                }
            }
        }
        System.out.println("TRUE_VMP rebind methods=" + trueVmp.size());
    }

    /** Signature → code_item offset. Methods without code are omitted. First hit wins. */
    private static Map<String, Integer> indexCodeOffsets(com.android.dex.Dex dex) {
        Map<String, Integer> map = new HashMap<>();
        for (com.android.dex.ClassDef classDef : dex.classDefs()) {
            if (classDef.getClassDataOffset() == 0) {
                continue;
            }
            String definingClass = dex.typeNames().get(classDef.getTypeIndex());
            com.android.dex.ClassData classData = dex.readClassData(classDef);
            indexCodeOffsets(dex, map, definingClass, classData.getDirectMethods());
            indexCodeOffsets(dex, map, definingClass, classData.getVirtualMethods());
        }
        return map;
    }

    private static void indexCodeOffsets(com.android.dex.Dex dex, Map<String, Integer> map,
                                         String definingClass,
                                         com.android.dex.ClassData.Method[] methods) {
        for (com.android.dex.ClassData.Method method : methods) {
            if (method.getCodeOffset() == 0) {
                continue;
            }
            com.android.dex.MethodId mid = dex.methodIds().get(method.getMethodIndex());
            com.android.dex.ProtoId proto = dex.protoIds().get(mid.getProtoIndex());
            String[] params;
            int paramOff = proto.getParametersOffset();
            if (paramOff == 0) {
                params = new String[0];
            } else {
                short[] types = dex.readTypeList(paramOff).getTypes();
                params = new String[types.length];
                for (int i = 0; i < types.length; i++) {
                    params[i] = dex.typeNames().get(types[i] & 0xffff);
                }
            }
            map.putIfAbsent(PackerMain.methodKey(
                    definingClass,
                    dex.strings().get(mid.getNameIndex()),
                    params,
                    dex.typeNames().get(proto.getReturnTypeIndex())),
                    method.getCodeOffset());
        }
    }

    public static void rewrite(File dexFile, List<Target> targets) throws IOException {
        if (targets == null || targets.isEmpty()) {
            return;
        }
        Set<Integer> want = new HashSet<>();
        int dexIndex = targets.get(0).dexIndex;
        for (Target t : targets) {
            if (t.dexIndex != dexIndex) {
                throw new IOException("mixed dexIndex in trampoline rewrite");
            }
            want.add(t.methodIndex);
        }
        System.out.println("TRUE_VMP trampoline rewriting methods=" + want.size()
                + " dexIndex=" + dexIndex);

        DexBackedDexFile dex;
        try (BufferedInputStream in = new BufferedInputStream(new FileInputStream(dexFile))) {
            dex = DexBackedDexFile.fromInputStream(Opcodes.getDefault(), in);
        }
        Map<String, Integer> methodIndex = indexMethodSection(dex);

        List<ClassDef> outClasses = new ArrayList<>();
        int rewritten = 0;
        for (ClassDef cls : dex.getClasses()) {
            boolean touched = false;
            List<Method> directs = new ArrayList<>();
            List<Method> virtuals = new ArrayList<>();
            for (Method m : cls.getDirectMethods()) {
                Method r = maybeRewrite(m, methodIndex, want, dexIndex);
                if (r != m) {
                    rewritten++;
                    touched = true;
                }
                directs.add(r);
            }
            for (Method m : cls.getVirtualMethods()) {
                Method r = maybeRewrite(m, methodIndex, want, dexIndex);
                if (r != m) {
                    rewritten++;
                    touched = true;
                }
                virtuals.add(r);
            }
            if (!touched) {
                outClasses.add(cls);
                continue;
            }
            outClasses.add(new ImmutableClassDef(
                    cls.getType(),
                    cls.getAccessFlags(),
                    cls.getSuperclass(),
                    cls.getInterfaces(),
                    cls.getSourceFile(),
                    cls.getAnnotations(),
                    cls.getStaticFields(),
                    cls.getInstanceFields(),
                    directs,
                    virtuals));
        }

        if (rewritten != want.size()) {
            throw new IOException("TRUE_VMP trampoline rewrite mismatch: want="
                    + want.size() + " got=" + rewritten + " file=" + dexFile.getName());
        }

        File tmp = new File(dexFile.getParentFile(), dexFile.getName() + ".vmp.tmp");
        DexPool pool = new DexPool(Opcodes.getDefault());
        for (ClassDef c : outClasses) {
            pool.internClass(c);
        }
        pool.writeTo(new FileDataStore(tmp));
        Files.move(tmp.toPath(), dexFile.toPath(), StandardCopyOption.REPLACE_EXISTING);
        System.out.println("TRUE_VMP trampoline rewritten methods=" + rewritten
                + " dexIndex=" + dexIndex);
    }

    private static Method maybeRewrite(Method m, Map<String, Integer> methodIndex,
                                       Set<Integer> want, int dexIndex) throws IOException {
        Integer idx = methodIndex.get(signatureKey(m));
        if (idx == null || !want.contains(idx)) {
            return m;
        }
        if (!AccessFlags.STATIC.isSet(m.getAccessFlags())) {
            // Phase 2: instance methods allowed; trampoline boxes `this` as args[0].
        }
        MethodImplementation impl = buildTrampoline(m, dexIndex, idx);
        return new ImmutableMethod(
                m.getDefiningClass(),
                m.getName(),
                m.getParameters(),
                m.getReturnType(),
                m.getAccessFlags(),
                m.getAnnotations(),
                m.getHiddenApiRestrictions(),
                impl);
    }

    /** Signature → method_id index. First id wins, matching the old linear scan. */
    private static Map<String, Integer> indexMethodSection(DexBackedDexFile dex) {
        var section = dex.getMethodSection();
        Map<String, Integer> map = new HashMap<>(Math.max(16, section.size() * 2));
        for (int i = 0; i < section.size(); i++) {
            var mr = section.get(i);
            map.putIfAbsent(signatureKey(mr.getDefiningClass(), mr.getName(),
                    mr.getParameterTypes(), mr.getReturnType()), i);
        }
        return map;
    }

    private static String signatureKey(Method m) {
        return signatureKey(m.getDefiningClass(), m.getName(),
                m.getParameterTypes(), m.getReturnType());
    }

    private static String signatureKey(String definingClass, String name,
                                       List<? extends CharSequence> params, String returnType) {
        String[] arr;
        if (params == null || params.isEmpty()) {
            arr = new String[0];
        } else {
            arr = new String[params.size()];
            for (int i = 0; i < params.size(); i++) {
                arr[i] = params.get(i).toString();
            }
        }
        return PackerMain.methodKey(definingClass, name, arr, returnType);
    }

    private static MethodImplementation buildTrampoline(Method m, int dexIndex, int methodIdx) {
        List<? extends CharSequence> params = m.getParameterTypes();
        String ret = m.getReturnType();
        boolean isStatic = AccessFlags.STATIC.isSet(m.getAccessFlags());
        int paramRegs = isStatic ? 0 : 1; // `this`
        for (CharSequence p : params) {
            paramRegs += isWide(p.toString()) ? 2 : 1;
        }
        // v0=array, v1=dexIdx, v2=methodIdx, v3=boxed, v4=slot,
        // v5/v6=scratch for MOVE_*_FROM16 before invoke-* (nibble regs only).
        final int temps = 7;
        int regCount = temps + paramRegs;
        int paramBase = temps;

        if (dexIndex < 0 || methodIdx < 0) {
            throw new IllegalArgumentException("dex/method index negative");
        }

        int boxedArgCount = params.size() + (isStatic ? 0 : 1);

        MutableMethodImplementation impl = new MutableMethodImplementation(regCount);
        // Use 32-bit const — large multidex apps often have method_id > 32767.
        impl.addInstruction(new BuilderInstruction31i(Opcode.CONST, 1, dexIndex));
        impl.addInstruction(new BuilderInstruction31i(Opcode.CONST, 2, methodIdx));
        impl.addInstruction(new BuilderInstruction21s(Opcode.CONST_16, 4, (short) boxedArgCount));
        impl.addInstruction(new BuilderInstruction22c(
                Opcode.NEW_ARRAY, 0, 4, new ImmutableTypeReference("[Ljava/lang/Object;")));

        int reg = paramBase;
        int slot = 0;
        if (!isStatic) {
            impl.addInstruction(new BuilderInstruction21s(Opcode.CONST_16, 4, (short) slot++));
            impl.addInstruction(new BuilderInstruction22x(Opcode.MOVE_OBJECT_FROM16, 3, reg));
            impl.addInstruction(new BuilderInstruction23x(Opcode.APUT_OBJECT, 3, 0, 4));
            reg += 1;
        }
        for (int i = 0; i < params.size(); i++) {
            String pt = params.get(i).toString();
            impl.addInstruction(new BuilderInstruction21s(Opcode.CONST_16, 4, (short) slot++));
            switch (pt) {
                case "I":
                case "B":
                case "S":
                case "C":
                    invokeStatic1(impl, "Ljava/lang/Integer;", "valueOf", "I",
                            "Ljava/lang/Integer;", reg);
                    break;
                case "Z":
                    invokeStatic1(impl, "Ljava/lang/Boolean;", "valueOf", "Z",
                            "Ljava/lang/Boolean;", reg);
                    break;
                case "J":
                    invokeStaticWide(impl, "Ljava/lang/Long;", "valueOf", "J",
                            "Ljava/lang/Long;", reg);
                    break;
                case "F":
                    invokeStatic1(impl, "Ljava/lang/Float;", "valueOf", "F",
                            "Ljava/lang/Float;", reg);
                    break;
                case "D":
                    invokeStaticWide(impl, "Ljava/lang/Double;", "valueOf", "D",
                            "Ljava/lang/Double;", reg);
                    break;
                default:
                    if (!pt.startsWith("L") && !pt.startsWith("[")) {
                        throw new IllegalArgumentException("unsupported param " + pt);
                    }
                    impl.addInstruction(new BuilderInstruction22x(Opcode.MOVE_OBJECT_FROM16, 3, reg));
                    break;
            }
            impl.addInstruction(new BuilderInstruction23x(Opcode.APUT_OBJECT, 3, 0, 4));
            reg += isWide(pt) ? 2 : 1;
        }

        ImmutableMethodReference interpret = new ImmutableMethodReference(
                BRIDGE, "interpret", INTERPRET_PARAMS, "Ljava/lang/Object;");
        impl.addInstruction(new BuilderInstruction35c(
                Opcode.INVOKE_STATIC, 3, 1, 2, 0, 0, 0, interpret));
        impl.addInstruction(new BuilderInstruction11x(Opcode.MOVE_RESULT_OBJECT, 0));

        switch (ret) {
            case "V":
                impl.addInstruction(new BuilderInstruction10x(Opcode.RETURN_VOID));
                break;
            case "I":
            case "B":
            case "S":
            case "C":
                unboxInt(impl);
                break;
            case "Z":
                unboxBool(impl);
                break;
            case "J":
                unboxLong(impl);
                break;
            case "F":
                unboxFloat(impl);
                break;
            case "D":
                unboxDouble(impl);
                break;
            default:
                if (ret.startsWith("L") || ret.startsWith("[")) {
                    impl.addInstruction(new BuilderInstruction21c(
                            Opcode.CHECK_CAST, 0, new ImmutableTypeReference(ret)));
                    impl.addInstruction(new BuilderInstruction11x(Opcode.RETURN_OBJECT, 0));
                } else {
                    throw new IllegalArgumentException("unsupported return " + ret);
                }
                break;
        }
        return impl;
    }

    private static void invokeStatic1(MutableMethodImplementation impl,
                                      String owner, String name, String param, String ret, int reg) {
        // invoke-* /35c only accepts nibble registers (v0–v15).
        impl.addInstruction(new BuilderInstruction22x(Opcode.MOVE_FROM16, 5, reg));
        ImmutableMethodReference ref = new ImmutableMethodReference(
                owner, name, List.of(param), ret);
        impl.addInstruction(new BuilderInstruction35c(
                Opcode.INVOKE_STATIC, 1, 5, 0, 0, 0, 0, ref));
        impl.addInstruction(new BuilderInstruction11x(Opcode.MOVE_RESULT_OBJECT, 3));
    }

    private static void invokeStaticWide(MutableMethodImplementation impl,
                                         String owner, String name, String param, String ret, int reg) {
        impl.addInstruction(new BuilderInstruction22x(Opcode.MOVE_WIDE_FROM16, 5, reg));
        ImmutableMethodReference ref = new ImmutableMethodReference(
                owner, name, List.of(param), ret);
        impl.addInstruction(new BuilderInstruction35c(
                Opcode.INVOKE_STATIC, 2, 5, 6, 0, 0, 0, ref));
        impl.addInstruction(new BuilderInstruction11x(Opcode.MOVE_RESULT_OBJECT, 3));
    }

    private static void unboxInt(MutableMethodImplementation impl) {
        impl.addInstruction(new BuilderInstruction21c(
                Opcode.CHECK_CAST, 0, new ImmutableTypeReference("Ljava/lang/Integer;")));
        impl.addInstruction(new BuilderInstruction35c(
                Opcode.INVOKE_VIRTUAL, 1, 0, 0, 0, 0, 0,
                new ImmutableMethodReference("Ljava/lang/Integer;", "intValue", List.of(), "I")));
        impl.addInstruction(new BuilderInstruction11x(Opcode.MOVE_RESULT, 0));
        impl.addInstruction(new BuilderInstruction11x(Opcode.RETURN, 0));
    }

    private static void unboxBool(MutableMethodImplementation impl) {
        impl.addInstruction(new BuilderInstruction21c(
                Opcode.CHECK_CAST, 0, new ImmutableTypeReference("Ljava/lang/Boolean;")));
        impl.addInstruction(new BuilderInstruction35c(
                Opcode.INVOKE_VIRTUAL, 1, 0, 0, 0, 0, 0,
                new ImmutableMethodReference("Ljava/lang/Boolean;", "booleanValue", List.of(), "Z")));
        impl.addInstruction(new BuilderInstruction11x(Opcode.MOVE_RESULT, 0));
        impl.addInstruction(new BuilderInstruction11x(Opcode.RETURN, 0));
    }

    private static void unboxLong(MutableMethodImplementation impl) {
        impl.addInstruction(new BuilderInstruction21c(
                Opcode.CHECK_CAST, 0, new ImmutableTypeReference("Ljava/lang/Long;")));
        impl.addInstruction(new BuilderInstruction35c(
                Opcode.INVOKE_VIRTUAL, 1, 0, 0, 0, 0, 0,
                new ImmutableMethodReference("Ljava/lang/Long;", "longValue", List.of(), "J")));
        impl.addInstruction(new BuilderInstruction11x(Opcode.MOVE_RESULT_WIDE, 0));
        impl.addInstruction(new BuilderInstruction11x(Opcode.RETURN_WIDE, 0));
    }

    private static void unboxFloat(MutableMethodImplementation impl) {
        impl.addInstruction(new BuilderInstruction21c(
                Opcode.CHECK_CAST, 0, new ImmutableTypeReference("Ljava/lang/Float;")));
        impl.addInstruction(new BuilderInstruction35c(
                Opcode.INVOKE_VIRTUAL, 1, 0, 0, 0, 0, 0,
                new ImmutableMethodReference("Ljava/lang/Float;", "floatValue", List.of(), "F")));
        impl.addInstruction(new BuilderInstruction11x(Opcode.MOVE_RESULT, 0));
        impl.addInstruction(new BuilderInstruction11x(Opcode.RETURN, 0));
    }

    private static void unboxDouble(MutableMethodImplementation impl) {
        impl.addInstruction(new BuilderInstruction21c(
                Opcode.CHECK_CAST, 0, new ImmutableTypeReference("Ljava/lang/Double;")));
        impl.addInstruction(new BuilderInstruction35c(
                Opcode.INVOKE_VIRTUAL, 1, 0, 0, 0, 0, 0,
                new ImmutableMethodReference("Ljava/lang/Double;", "doubleValue", List.of(), "D")));
        impl.addInstruction(new BuilderInstruction11x(Opcode.MOVE_RESULT_WIDE, 0));
        impl.addInstruction(new BuilderInstruction11x(Opcode.RETURN_WIDE, 0));
    }

    private static boolean isWide(String type) {
        return "J".equals(type) || "D".equals(type);
    }
}

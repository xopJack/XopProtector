package com.yqsh.protector.packer;

import com.android.dex.ClassDef;
import com.android.dex.Dex;

import java.io.File;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * Helpers for DEX class density / legacy {@code --dex-layout} aliases.
 * Packing always uses {@link DexClassSplit}: {@link #isBusinessType} classes →
 * {@code dexes.zip}; non-business stay in the APK root (stripped when safe,
 * or KEEP_FULL_UNPROTECTED when DexPool would rewrite Compose-like packages).
 *
 * <p>{@link #classify} / {@link #decideHybrid} are deprecated whole-DEX
 * diagnostics only — packing uses {@link DexClassSplit} + {@link #isBusinessType}.
 */
public final class DexLayout {

    public enum Mode {
        /**
         * @deprecated Removed in 0.8.0; packing always class-splits. Kept so
         *             old CLI values parse without failing.
         */
        @Deprecated
        ENCRYPT_ALL,
        /** Per-class business extract + non-business root DEX (install AOT). */
        HYBRID
    }

    public enum Decision {
        ENCRYPT,
        KEEP_PLAIN
    }

    /** Inputs for hybrid classification (from packer options + manifest). */
    public static final class Context {
        public Mode mode = Mode.HYBRID;
        /** e.g. {@code Lcom/foo/bar/} from applicationId. */
        public String appPackagePrefix;
        /**
         * Extra class-split prefixes (Manifest components, parent of
         * applicationId, non-SDK DEX clusters). Not hollow allowlist — see
         * {@link #hollowPrefixes}.
         */
        public final List<String> businessPrefixes = new ArrayList<>();
        public final List<String> hollowPrefixes = new ArrayList<>();
        public final List<String> trueVmpPrefixes = new ArrayList<>();
        public boolean paymentAutoVmp = true;
        public boolean industryAutoVmp;

        /**
         * Soft ratio gate (default 0.01). With {@link #minBusinessCount}{@code 1},
         * any business class still encrypts; ratio is logged for diagnostics.
         */
        public double businessRatioThreshold = 0.01;
        /** Minimum business class count to force ENCRYPT (default 1). */
        public int minBusinessCount = 1;
    }

    public static final class Result {
        public final Decision decision;
        public final int totalClasses;
        public final int businessClasses;
        public final int sdkClasses;
        public final int otherClasses;
        public final String reason;

        Result(Decision decision, int business, int sdk, int other, String reason) {
            this.decision = decision;
            this.businessClasses = business;
            this.sdkClasses = sdk;
            this.otherClasses = other;
            this.totalClasses = business + sdk + other;
            this.reason = reason;
        }
    }

    private DexLayout() {
    }

    /** Always {@link Mode#HYBRID}; legacy encrypt-all aliases accepted as no-ops. */
    public static Mode parseMode(String raw) {
        if (raw == null || raw.isEmpty()) {
            return Mode.HYBRID;
        }
        switch (raw.trim().toLowerCase(Locale.ROOT)) {
            case "encrypt-all":
            case "encrypt_all":
            case "all":
            case "full":
            case "hybrid":
            case "baidu":
            case "sdk-plain":
            case "sdk_plain":
                return Mode.HYBRID;
            default:
                throw new IllegalArgumentException(
                        "unknown --dex-layout '" + raw + "' (deprecated; packing always class-splits)");
        }
    }

    public static String modeWire(Mode mode) {
        return "hybrid";
    }

    /**
     * Whole-DEX diagnostic only — packing uses {@link DexClassSplit} per class.
     *
     * @deprecated Not on the protect path since 0.8.0; kept for unit tests / tooling.
     */
    @Deprecated
    public static Result classify(File dexFile, Context ctx) throws Exception {
        if (ctx == null || ctx.mode == Mode.ENCRYPT_ALL) {
            return new Result(Decision.ENCRYPT, 0, 0, 0, "encrypt-all");
        }
        byte[] data = Files.readAllBytes(dexFile.toPath());
        Dex dex = new Dex(data);
        int business = 0;
        int sdk = 0;
        int other = 0;
        for (ClassDef classDef : dex.classDefs()) {
            String type = dex.typeNames().get(classDef.getTypeIndex());
            if (type == null || type.length() < 3) {
                continue;
            }
            if (isBusinessType(type, ctx)) {
                business++;
            } else if (isSdkType(type)) {
                sdk++;
            } else {
                other++;
            }
        }
        return decideHybrid(business, sdk, other, ctx);
    }

    /**
     * Whole-DEX diagnostic companion to {@link #classify}.
     *
     * @deprecated Not used by {@link DexClassSplit}; do not call from packing.
     */
    @Deprecated
    static Result decideHybrid(int business, int sdk, int other, Context ctx) {
        int minBiz = ctx != null && ctx.minBusinessCount > 0 ? ctx.minBusinessCount : 1;
        double threshold = ctx != null ? ctx.businessRatioThreshold : 0.01;
        int total = business + sdk + other;
        double ratio = total == 0 ? 0.0 : (double) business / (double) total;

        if (business >= minBiz || (business > 0 && ratio >= threshold)) {
            return new Result(Decision.ENCRYPT, business, sdk, other,
                    "business classes=" + business + " ratio="
                            + String.format(Locale.US, "%.4f", ratio));
        }
        if (business > 0) {
            // Below soft gates but still present — never leave business plaintext.
            return new Result(Decision.ENCRYPT, business, sdk, other,
                    "business classes=" + business + " (force)");
        }
        if (other > 0) {
            return new Result(Decision.KEEP_PLAIN, business, sdk, other,
                    "no-business other=" + other + " sdk=" + sdk);
        }
        return new Result(Decision.KEEP_PLAIN, business, sdk, other,
                "sdk-only classes=" + sdk);
    }

    /** Per-class extract rule shared with {@link DexClassSplit}. */
    public static boolean isBusinessType(String typeDescriptor, Context ctx) {
        if (typeDescriptor == null || ctx == null) {
            return false;
        }
        if (ctx.appPackagePrefix != null && !ctx.appPackagePrefix.isEmpty()
                && typeDescriptor.startsWith(ctx.appPackagePrefix)) {
            return true;
        }
        if (matchesPrefixList(typeDescriptor, ctx.businessPrefixes)) {
            return true;
        }
        if (matchesPrefixList(typeDescriptor, ctx.hollowPrefixes)) {
            return true;
        }
        if (matchesPrefixList(typeDescriptor, ctx.trueVmpPrefixes)) {
            return true;
        }
        if (ctx.paymentAutoVmp && PaymentVmpRules.matches(typeDescriptor)) {
            return true;
        }
        if (ctx.industryAutoVmp) {
            if (IndustryVmpRules.matches(typeDescriptor, ctx.appPackagePrefix)) {
                return true;
            }
            // Industry markers under Manifest / parent / cluster prefixes.
            if (ctx.businessPrefixes != null) {
                for (String p : ctx.businessPrefixes) {
                    if (IndustryVmpRules.matches(typeDescriptor, p)) {
                        return true;
                    }
                }
            }
        }
        return false;
    }

    static boolean isSdkType(String typeDescriptor) {
        return ProtectPolicy.isSdkOrFramework(typeDescriptor)
                || ProtectPolicy.isGeneratedNoise(typeDescriptor);
    }

    private static boolean matchesPrefixList(String type, List<String> prefixes) {
        if (prefixes == null || prefixes.isEmpty()) {
            return false;
        }
        for (String p : prefixes) {
            if (p != null && !p.isEmpty() && type.startsWith(p)) {
                return true;
            }
        }
        return false;
    }
}

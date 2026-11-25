package com.yqsh.protector.packer;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;

/**
 * Unified commercial hollow policy — same rules for every APK.
 *
 * <p>Explicit {@code --hollow-prefix} is an allowlist (customer scope). When empty,
 * the selected {@link Profile} decides what to hollow via shared skip lists
 * (framework / major SDKs / Android components). Never hard-codes a single app
 * package name.
 */
public final class ProtectPolicy {

    public enum Profile {
        /**
         * Default commercial (speed + static DEX encrypt): do <strong>not</strong>
         * hollow by package. Method deep-protect is auto True-VMP on
         * {@code alipay}/{@code wxapi} types (see {@link PaymentVmpRules}), plus
         * optional {@code --true-vmp-prefix} / {@code --hollow-prefix}.
         */
        BALANCED,
        /**
         * Industry / tools apps: same encrypt-first (no package-wide hollow) as
         * {@link #BALANCED}, plus <strong>default-on</strong> auto True-VMP via
         * {@link IndustryVmpRules} (override with {@code --no-industry-auto-vmp} —
         * see {@code doc/auto-true-vmp-contract.md}), and raised SO protect budgets
         * when unset (see {@link ProtectOptions}).
         */
        INDUSTRY,
        /**
         * Wider coverage: skip framework/major SDKs/components; hollow remaining
         * business types.
         */
        AGGRESSIVE,
        /**
         * Near max: only skip shell + {@code Landroid/} + {@code Landroidx/}.
         */
        MAX,
        /**
         * Speed-first: encrypt-first hollow (same as balanced) <strong>and</strong>
         * narrow class-split — no {@code applicationId} / cluster prefix encrypt;
         * only Manifest exact types, {@code --hollow-prefix}, payment/industry
         * True-VMP, and {@code --true-vmp-prefix}. Application leaf startup-plain
         * is opt-in via {@code --startup-plain-app-leaf} (default off).
         */
        PERF
    }

    /** Always skip (all profiles). */
    private static final String[] NEVER_PREFIXES = {
            "Lcom/yqsh/protector/",
            "Landroid/",
    };

    /** Aggressive still keeps AndroidX plaintext (startup / UI). */
    private static final String[] AGGRESSIVE_EXTRA_SKIP = {
            "Landroidx/",
    };

    /**
     * Framework + ubiquitous libraries — shared by balanced/perf.
     * Keep as type-descriptor prefixes (Dalvik form).
     */
    private static final String[] COMMON_SDK_SKIP = {
            "Landroidx/",
            "Lcom/google/",
            "Lcom/android/",
            "Ldalvik/",
            "Ljava/",
            "Ljavax/",
            "Lj$/",
            "Lkotlin/",
            "Lkotlinx/",
            "Lorg/jetbrains/",
            "Lorg/intellij/",
            "Lorg/apache/",
            "Lorg/json/",
            "Lorg/xmlpull/",
            "Lorg/xml/",
            "Lorg/w3c/",
            "Lokhttp3/",
            "Lokio/",
            "Lretrofit2/",
            "Lcom/squareup/",
            "Lio/reactivex/",
            "Lrx/",
            "Lcom/bumptech/glide/",
            "Lcom/facebook/",
            "Lcom/airbnb/",
            "Ldagger/",
            "Ljavax/inject/",
            "Lcom/google/gson/",
            "Lcom/google/protobuf/",
            "Lcom/google/zxing/",
            "Lcom/google/android/",
            "Lcom/alibaba/fastjson/",
            "Lcom/alibaba/android/",
            "Lcom/amazonaws/",
            "Lcom/taobao/",
            "Lcom/aliyun/",
            "Lio/dcloud/",
            "Lio/flutter/",
            "Lio/netty/",
            "Lorg/bouncycastle/",
            "Lorg/spongycastle/",
            "Lorg/slf4j/",
            "Ltimber/",
            "Lcom/tencent/mmkv/",
            "Lcom/tencent/bugly/",
            "Lcom/umeng/",
            "Lcom/bytedance/",
            "Lcom/sensorsdata/",
            "Lme/jessyan/autosize/",
            "Lcom/blankj/",
            "Lcom/scwang/smart/",
            "Lcom/gyf/immersionbar/",
            "Lcom/lxj/xpopup/",
            "Lcom/permissionx/",
            "Lcom/hjq/",
            "Lcom/chad/library/",
            "Lcom/github/",
            "Lorg/greenrobot/",
            "Lcom/jakewharton/",
            "Lbolt/",
            "Lshadow/",
    };

    /** Extra skips for {@link Profile#PERF} only. */
    private static final String[] PERF_EXTRA_SKIP = {
            "Lcom/tencent/",
            "Lcom/baidu/",
            "Lcom/amap/",
            "Lcom/huawei/",
            "Lcom/xiaomi/",
            "Lcom/netease/",
            "Lcom/qihoo/",
            "Lcn/jiguang/",
            "Lcn/jpush/",
            "Lcom/igexin/",
            "Lcom/getui/",
            "Lcom/alipay/",
            "Lcom/unionpay/",
            "Lcom/sina/",
            "Lcom/ss/android/",
            "Lio/dcloud/",
            "Lcom/orhanobut/",
            "Lcom/afollestad/",
            "Lcom/yanzhenjie/",
            "Lcom/zhy/",
            "Lorg/koin/",
            "Ltoothpick/",
            "Lbutterknife/",
            "Lp/q/",
    };

    private static final String[] COMPONENT_SUFFIXES = {
            "Activity",
            "Application",
            "Service",
            "Receiver",
            "Provider",
            "Fragment",
            "DialogFragment",
            "AppComponentFactory",
            "ContentProvider",
            "BroadcastReceiver",
            "IntentService",
            "JobService",
            "BackupAgent",
    };

    private final Profile profile;
    private final List<String> allowPrefixes;
    /** Dalvik prefix from manifest package, e.g. {@code Lcom/foo/bar/}. */
    private final String appPackagePrefix;

    public ProtectPolicy(Profile profile, List<String> allowPrefixes) {
        this(profile, allowPrefixes, null);
    }

    public ProtectPolicy(Profile profile, List<String> allowPrefixes, String applicationId) {
        this.profile = profile != null ? profile : Profile.BALANCED;
        if (allowPrefixes == null || allowPrefixes.isEmpty()) {
            this.allowPrefixes = Collections.emptyList();
        } else {
            this.allowPrefixes = Collections.unmodifiableList(new ArrayList<>(allowPrefixes));
        }
        this.appPackagePrefix = toDescriptorPrefix(applicationId);
    }

    /** {@code com.foo.bar} → {@code Lcom/foo/bar/}. */
    public static String toDescriptorPrefix(String applicationId) {
        if (applicationId == null) return null;
        String pkg = applicationId.trim();
        if (pkg.isEmpty()) return null;
        return "L" + pkg.replace('.', '/') + "/";
    }

    public Profile profile() {
        return profile;
    }

    /**
     * Dalvik type prefix for Manifest {@code package}, e.g. {@code Lcom/foo/bar/},
     * or {@code null} if unknown.
     */
    public String appPackagePrefix() {
        return appPackagePrefix;
    }

    public boolean hasAllowlist() {
        return !allowPrefixes.isEmpty();
    }

    public static Profile parseProfile(String raw) {
        if (raw == null || raw.isEmpty()) {
            return Profile.BALANCED;
        }
        switch (raw.trim().toLowerCase(Locale.ROOT)) {
            case "balanced":
            case "default":
                return Profile.BALANCED;
            case "industry":
            case "ind":
                return Profile.INDUSTRY;
            case "aggressive":
            case "wide":
                return Profile.AGGRESSIVE;
            case "max":
            case "all":
                return Profile.MAX;
            case "perf":
            case "performance":
            case "fast":
                return Profile.PERF;
            default:
                throw new IllegalArgumentException(
                        "unknown --profile '" + raw
                                + "' (balanced|industry|aggressive|max|perf)");
        }
    }

    public String describe() {
        String mode = hasAllowlist()
                ? ("allowlist=" + allowPrefixes.size() + " prefix(es)")
                : "auto";
        String scope = appPackagePrefix != null ? (" app=" + appPackagePrefix) : "";
        return "profile=" + profile.name().toLowerCase(Locale.ROOT) + " mode=" + mode + scope;
    }

    /**
     * @param typeDescriptor Dalvik type e.g. {@code Lcom/foo/Bar;}
     */
    public boolean shouldHollow(String typeDescriptor) {
        if (typeDescriptor == null || typeDescriptor.length() < 3) {
            return false;
        }
        if (startsWithAny(typeDescriptor, NEVER_PREFIXES)) {
            return false;
        }
        if (isGeneratedNoise(typeDescriptor)) {
            return false;
        }

        if (hasAllowlist()) {
            if (!matchesAllowlist(typeDescriptor)) {
                return false;
            }
            // Allowlist still respects component skip on balanced/perf (startup).
            if (profile != Profile.MAX && isAndroidComponent(typeDescriptor)) {
                return false;
            }
            if (profile == Profile.MAX && startsWithAny(typeDescriptor, AGGRESSIVE_EXTRA_SKIP)) {
                return false;
            }
            return true;
        }

        // Auto mode by profile
        switch (profile) {
            case MAX:
                if (startsWithAny(typeDescriptor, AGGRESSIVE_EXTRA_SKIP)) {
                    return false;
                }
                return true;
            case AGGRESSIVE:
                // Wide business hollow (legacy default).
                if (startsWithAny(typeDescriptor, COMMON_SDK_SKIP)) {
                    return false;
                }
                if (isAndroidComponent(typeDescriptor)) {
                    return false;
                }
                return true;
            case INDUSTRY:
            case PERF:
            case BALANCED:
            default:
                // Encrypt-first: no package-wide hollow.
                // True-VMP via PaymentVmpRules / IndustryVmpRules / --true-vmp-prefix.
                return false;
        }
    }

    /**
     * Framework / major SDK / shell types that industry auto-VMP must not touch.
     */
    public static boolean isSdkOrFramework(String typeDescriptor) {
        if (typeDescriptor == null || typeDescriptor.length() < 3) {
            return true;
        }
        return startsWithAny(typeDescriptor, NEVER_PREFIXES)
                || startsWithAny(typeDescriptor, COMMON_SDK_SKIP)
                || startsWithAny(typeDescriptor, PERF_EXTRA_SKIP);
    }

    private boolean matchesAllowlist(String typeDescriptor) {
        for (String prefix : allowPrefixes) {
            if (prefix != null && !prefix.isEmpty() && typeDescriptor.startsWith(prefix)) {
                return true;
            }
        }
        return false;
    }

    static boolean isGeneratedNoise(String typeDescriptor) {
        if (typeDescriptor.endsWith("/R;") || typeDescriptor.contains("/R$")) {
            return true;
        }
        if (typeDescriptor.endsWith("/BuildConfig;")) {
            return true;
        }
        if (typeDescriptor.contains("/databinding/") || typeDescriptor.contains("/DataBinding")) {
            return true;
        }
        // Kotlin file facade / synthetic lambdas often end with Kt or $
        return false;
    }

    static boolean isAndroidComponent(String typeDescriptor) {
        String simple = simpleName(typeDescriptor);
        if (simple.isEmpty()) {
            return false;
        }
        for (String suffix : COMPONENT_SUFFIXES) {
            if (simple.equals(suffix) || simple.endsWith(suffix)) {
                return true;
            }
        }
        return false;
    }

    /** Outer simple name: {@code Lcom/a/B$C;} → {@code B}. */
    static String simpleName(String typeDescriptor) {
        int start = typeDescriptor.lastIndexOf('/');
        int from = start >= 0 ? start + 1 : (typeDescriptor.startsWith("L") ? 1 : 0);
        int to = typeDescriptor.endsWith(";") ? typeDescriptor.length() - 1 : typeDescriptor.length();
        if (from >= to) {
            return "";
        }
        String name = typeDescriptor.substring(from, to);
        int dollar = name.indexOf('$');
        if (dollar >= 0) {
            name = name.substring(0, dollar);
        }
        return name;
    }

    private static boolean startsWithAny(String type, String[] prefixes) {
        for (String p : prefixes) {
            if (type.startsWith(p)) {
                return true;
            }
        }
        return false;
    }
}

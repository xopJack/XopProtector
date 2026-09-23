package com.yqsh.protector.packer;

import java.io.File;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Stable options for {@link Protector#protect(ProtectOptions, ProtectProgressListener)}.
 */
public final class ProtectOptions {
    /**
     * Three-state for auto True-VMP axes — see {@code doc/auto-true-vmp-contract.md}.
     * {@link #UNSET} keeps profile defaults (payment on; industry on iff profile INDUSTRY).
     */
    public enum AutoVmpMode {
        UNSET,
        OFF,
        ON
    }

    public File inputApk;
    public File outputApk;
    public File shellDir;

    public ProtectPolicy.Profile profile = ProtectPolicy.Profile.BALANCED;
    public final List<String> hollowPrefixes = new ArrayList<>();
    public final List<String> vmpPrefixes = new ArrayList<>();
    public final List<String> trueVmpPrefixes = new ArrayList<>();

    /**
     * Payment markers ({@link PaymentVmpRules}). CLI: {@code --payment-auto-vmp} /
     * {@code --no-payment-auto-vmp}. Default when unset: on.
     */
    public AutoVmpMode paymentAutoVmp = AutoVmpMode.UNSET;
    /**
     * Industry markers ({@link IndustryVmpRules}). CLI: {@code --industry-auto-vmp} /
     * {@code --no-industry-auto-vmp}. Default when unset: on iff {@link ProtectPolicy.Profile#INDUSTRY}.
     */
    public AutoVmpMode industryAutoVmp = AutoVmpMode.UNSET;

    public boolean protectSo = true;
    public BusinessSoProtector.Mode protectSoMode = BusinessSoProtector.Mode.SAFE;
    public double protectSoBudgetMb = 12.0;
    public double protectSoMaxFileMb = 8.0;
    public String protectSoAbi = "all";
    /**
     * Basenames never encrypted (e.g. {@code libd3.so}). CLI:
     * {@code --protect-so-exclude libd3.so,libzhd3d.so}.
     */
    public java.util.LinkedHashSet<String> protectSoExclude = new java.util.LinkedHashSet<>();
    /**
     * If non-empty, ONLY these basenames are encrypted (mutually exclusive with
     * {@link #protectSoExclude}; include wins). CLI: {@code --protect-so-include libx.so,liby.so}.
     */
    public java.util.LinkedHashSet<String> protectSoInclude = new java.util.LinkedHashSet<>();

    /**
     * Runtime SO decrypt timing (written to {@code config.json}).
     * {@link #EAGER} — full materialize + preload at cold start (default, compatible).
     * {@link #LAZY} — on-demand materialize + preload existing {@code so_plain};
     *               background fill this process (no {@code so_plain_ready} warm reuse).
     * CLI: {@code --so-decrypt-mode eager|lazy}.
     */
    public enum SoDecryptMode {
        EAGER,
        LAZY
    }

    /** Default {@link SoDecryptMode#EAGER} for backward-compatible cold-start behavior. */
    public SoDecryptMode soDecryptMode = SoDecryptMode.EAGER;

    /** Parse {@code eager|lazy} (case-insensitive). */
    public static SoDecryptMode parseSoDecryptMode(String raw) {
        if (raw == null || raw.isEmpty()) {
            throw new IllegalArgumentException("empty --so-decrypt-mode (eager|lazy)");
        }
        String m = raw.trim().toLowerCase(java.util.Locale.US);
        switch (m) {
            case "eager":
                return SoDecryptMode.EAGER;
            case "lazy":
                return SoDecryptMode.LAZY;
            default:
                throw new IllegalArgumentException(
                        "unknown --so-decrypt-mode '" + raw + "' (eager|lazy)");
        }
    }

    /** Wire value for config.json / logs. */
    public static String soDecryptModeWire(SoDecryptMode mode) {
        return mode == SoDecryptMode.LAZY ? "lazy" : "eager";
    }
    /**
     * When true, {@link ProtectPolicy.Profile#INDUSTRY} will not replace
     * {@link #protectSoBudgetMb} with the industry default (48).
     */
    public boolean protectSoBudgetExplicit;
    /**
     * When true, industry profile will not replace {@link #protectSoMaxFileMb}
     * with the industry default (24).
     */
    public boolean protectSoMaxFileExplicit;

    /** Industry profile SO budget defaults (MB). */
    public static final double INDUSTRY_SO_BUDGET_MB = 48.0;
    public static final double INDUSTRY_SO_MAX_FILE_MB = 24.0;

    public String applicationOverride;
    public String certSha256Override;

    /** Default: disable Root+Emulator (16|32). */
    public int riskFlags = 16 | 32;
    /** 0=alert, 1=degrade, 2=block. */
    public int raspAction = 2;
    public boolean reportEnabled = true;

    /** Null = leave output unsigned. */
    public PackerMain.SignConfig signConfig;

    /** Emit NDJSON progress events on stdout (for desktop UI). */
    public boolean jsonProgress;

    /**
     * Phase 2B — shorten {@code res/} file paths + rewrite {@code resources.arsc}
     * string pool (AndResGuard-style). Default off. CLI: {@code --enable-res-protect}.
     * Does not encrypt arsc (must stay STORED). Desktop UI hidden; use packer CLI.
     */
    public boolean enableResProtect;

    /**
     * Phase 2A — encrypt {@code assets/**} (excl. {@code assets/protector/**}).
     * Default off. CLI: {@code --encrypt-assets}.
     * App must use {@code ProtectorAssets} (no AssetManager hook). Desktop UI hidden.
     */
    public boolean encryptAssets;

    /**
     * Phase 3 — proxy/VPN detect + optional cert pin list.
     * CLI: {@code --detect-proxy} / {@code --pin-certs <file>}.
     * Desktop UI currently hidden; use packer CLI to enable.
     */
    public boolean detectProxy;

    /** Leaf cert SHA-256 hex pins (from {@code --pin-certs}); may be empty. */
    public final List<String> pinCertSha256 = new ArrayList<>();

    /**
     * Reserved Phase 6 — multi-channel APK marking via APK Signing Block.
     * Set automatically when {@link #channel} / {@link #channels} are used.
     */
    public boolean enableChannelMark;

    /**
     * Phase 6 — single channel stamped onto the signed primary output.
     * CLI: {@code --channel <name>} (requires {@link #signConfig}).
     */
    public String channel;

    /**
     * Phase 6 — batch channels → sibling {@code <out>-<channel>.apk}.
     * CLI: {@code --channels <file>} (requires {@link #signConfig}).
     */
    public final List<String> channels = new ArrayList<>();

    /**
     * @deprecated Prefer {@link #detectProxy}; kept as alias for roadmap flag.
     */
    public boolean enableNetGuard;

    public List<String> hollowPrefixesView() {
        return Collections.unmodifiableList(hollowPrefixes);
    }
}

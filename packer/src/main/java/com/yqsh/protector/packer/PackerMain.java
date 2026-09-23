package com.yqsh.protector.packer;

import com.android.apksigner.ApkSignerTool;
import com.iyxan23.zipalignjava.ZipAlign;
import com.wind.meditor.core.FileProcesser;
import com.wind.meditor.property.AttributeItem;
import com.wind.meditor.property.ModificationProperty;
import com.wind.meditor.utils.NodeValue;

import com.yqsh.protector.packer.util.CryptoUtils;

import net.lingala.zip4j.ZipFile;
import net.lingala.zip4j.model.ZipParameters;
import net.lingala.zip4j.model.enums.CompressionMethod;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import java.util.zip.ZipOutputStream;

/**
 * Minimal packer CLI:
 * extract method insns -> write code.bin -> hollow dexes into assets/protector/dexes.zip
 * replace Application with ProxyApplication -> embed shell dex + so ->
 * optional sign (default: leave unsigned for the caller to sign).
 */
public class PackerMain {

    private static final String PROXY_APP = "com.yqsh.protector.shell.ProxyApplication";
    private static final String PROXY_ACF = "com.yqsh.protector.shell.ProxyComponentFactory";

    private static final String HMAC_KEY_SPEC = "HmacSHA256";

    /**
     * Optional allowlist of type-descriptor prefixes ({@code --hollow-prefix}).
     * Empty = auto mode under {@link #protectPolicy} profile.
     */
    private final List<String> hollowPrefixes = new ArrayList<>();
    /** Type prefixes whose methods get VMP packing (PVM1) in addition to AES-GCM. */
    private final List<String> vmpPrefixes = new ArrayList<>();
    /** Type prefixes for true VMP (PVM2 interpreter; never restored to DEX). */
    private final List<String> trueVmpPrefixes = new ArrayList<>();
    /** Resolved auto True-VMP axes (see {@link AutoVmpPolicy}). */
    private boolean paymentAutoVmpEffective = true;
    private boolean industryAutoVmpEffective = false;
    private boolean paymentAutoVmpFromCli;
    private boolean industryAutoVmpFromCli;
    /**
     * Commercial hollow policy (default {@link ProtectPolicy.Profile#BALANCED}).
     * Same rules for every APK — not per-app hardcoding.
     */
    private ProtectPolicy protectPolicy = new ProtectPolicy(ProtectPolicy.Profile.BALANCED, null);
    /** Optional override for config application_name (skip Sophix stub etc.). */
    private String applicationOverride;
    /** Optional override for config app_sign_sha256 (hex). */
    private String certSha256Override;
    /**
     * risk_flags bitmask (see native risk.h). Default disables Root+Emulator.
     * FLAG_DISABLE_ROOT=16, FLAG_DISABLE_EMULATOR=32 → 48.
     */
    private int riskFlags = 16 | 32;
    /** rasp_action: 0=alert, 1=degrade, 2=block (default). */
    private int raspAction = 2;
    /** Write threats.log / ring buffer (default on). */
    private boolean reportEnabled = true;
    /** Encrypt business lib/*.so .text (default on; disable with --no-protect-so). */
    private boolean protectSo = true;
    /** Phase 2A: encrypt assets/** into protector/aenc (default off). */
    private boolean encryptAssets = false;
    /** Phase 2B: shorten res/ paths + rewrite resources.arsc (default off). */
    private boolean enableResProtect = false;
    /** Phase 3: proxy/VPN heuristics (default off). */
    private boolean detectProxy = false;
    /** Phase 3: leaf cert SHA-256 pins for NetGuard. */
    private final List<String> pinCertSha256 = new ArrayList<>();
    /** SO selection policy — default SAFE (industry skips + size budget). */
    private BusinessSoProtector.Mode protectSoMode = BusinessSoProtector.Mode.SAFE;
    /** SO protect extra APK size budget (MB). Ignored by mode=max. */
    private double protectSoBudgetMb = 12.0;
    /** Skip unpacked SO larger than this (MB). Ignored by mode=max. */
    private double protectSoMaxFileMb = 8.0;
    /** {@code all} or a single ABI (e.g. arm64-v8a). */
    private String protectSoAbi = "all";
    /** Exact SO basenames to skip (see {@code --protect-so-exclude}). */
    private final java.util.LinkedHashSet<String> protectSoExclude = new java.util.LinkedHashSet<>();
    /** If non-empty, only these SO basenames are encrypted (see {@code --protect-so-include}). */
    private final java.util.LinkedHashSet<String> protectSoInclude = new java.util.LinkedHashSet<>();
    /** Runtime SO decrypt timing — default eager (full materialize + preload). */
    private ProtectOptions.SoDecryptMode soDecryptMode = ProtectOptions.SoDecryptMode.EAGER;
    /** Per-APK PVM2 opcode morph (Phase 3); set in protect(). */
    private Pvm2Morph pvm2Morph;
    /** True-VMP compile telemetry (PR6). Does not change admission. */
    private final Pvm2Admission pvm2Admission = new Pvm2Admission();
    /** Per-APK HMAC key for config.json (HKDF {@code K_hmac}; not written into SO). */
    private byte[] hmacKey;
    /** Phase 6: single channel stamped onto signed output. */
    private String channel;
    /** Phase 6: extra channel ids → sibling APKs {@code name-<channel>.apk}. */
    private final List<String> channels = new ArrayList<>();
    /** Progress sink (library / desktop UI). */
    private ProtectProgressListener progress = ProtectProgressListener.NONE;

    void setProgressListener(ProtectProgressListener listener) {
        this.progress = listener != null ? listener : ProtectProgressListener.NONE;
    }

    void applyOptions(ProtectOptions options) {
        hollowPrefixes.clear();
        hollowPrefixes.addAll(options.hollowPrefixes);
        protectPolicy = new ProtectPolicy(options.profile, options.hollowPrefixes);
        vmpPrefixes.clear();
        vmpPrefixes.addAll(options.vmpPrefixes);
        trueVmpPrefixes.clear();
        trueVmpPrefixes.addAll(options.trueVmpPrefixes);
        AutoVmpPolicy.Resolved autoVmp = AutoVmpPolicy.resolve(
                options.paymentAutoVmp, options.industryAutoVmp, options.profile);
        paymentAutoVmpEffective = autoVmp.paymentEffective;
        industryAutoVmpEffective = autoVmp.industryEffective;
        paymentAutoVmpFromCli = autoVmp.paymentFromCli;
        industryAutoVmpFromCli = autoVmp.industryFromCli;
        protectSo = options.protectSo;
        encryptAssets = options.encryptAssets;
        enableResProtect = options.enableResProtect;
        detectProxy = options.detectProxy || options.enableNetGuard;
        pinCertSha256.clear();
        pinCertSha256.addAll(options.pinCertSha256);
        protectSoMode = options.protectSoMode;
        protectSoBudgetMb = options.protectSoBudgetMb;
        protectSoMaxFileMb = options.protectSoMaxFileMb;
        if (options.profile == ProtectPolicy.Profile.INDUSTRY) {
            if (!options.protectSoBudgetExplicit) {
                protectSoBudgetMb = ProtectOptions.INDUSTRY_SO_BUDGET_MB;
            }
            if (!options.protectSoMaxFileExplicit) {
                protectSoMaxFileMb = ProtectOptions.INDUSTRY_SO_MAX_FILE_MB;
            }
        }
        protectSoAbi = options.protectSoAbi;
        protectSoExclude.clear();
        if (options.protectSoExclude != null) {
            for (String e : options.protectSoExclude) {
                String n = BusinessSoProtector.normalizeSoBasename(e);
                if (!n.isEmpty()) protectSoExclude.add(n);
            }
        }
        protectSoInclude.clear();
        if (options.protectSoInclude != null) {
            for (String e : options.protectSoInclude) {
                String n = BusinessSoProtector.normalizeSoBasename(e);
                if (!n.isEmpty()) protectSoInclude.add(n);
            }
        }
        soDecryptMode = options.soDecryptMode != null
                ? options.soDecryptMode : ProtectOptions.SoDecryptMode.EAGER;
        applicationOverride = options.applicationOverride;
        certSha256Override = options.certSha256Override;
        riskFlags = options.riskFlags;
        raspAction = options.raspAction;
        reportEnabled = options.reportEnabled;
        channel = options.channel;
        channels.clear();
        channels.addAll(options.channels);
    }

    private void phase(String id, String message, int percent) {
        progress.onPhase(id, message, percent);
    }

    public static void main(String[] args) {
        if (args.length < 1) {
            printUsage();
            System.exit(1);
        }
        try {
            if ("channel".equals(args[0])) {
                runChannelCli(args);
                return;
            }
            ProtectOptions options = parseArgs(args);
            ProtectResult result = new Protector().protect(options);
            if (!options.jsonProgress) {
                System.out.println("Protected APK: " + result.outputApk.getAbsolutePath());
            }
        } catch (Exception e) {
            e.printStackTrace(System.err);
            System.exit(1);
        }
    }

    /**
     * Standalone channel tooling (works on any V2/V3-signed APK):
     * <pre>
     *   channel get &lt;apk&gt;
     *   channel put &lt;apk&gt; &lt;name&gt; [-o out.apk]
     *   channel batch &lt;apk&gt; &lt;channels.txt&gt; [-o-dir dir]
     * </pre>
     */
    private static void runChannelCli(String[] args) throws Exception {
        if (args.length < 2) {
            printChannelUsage();
            System.exit(1);
        }
        String sub = args[1];
        if ("get".equals(sub)) {
            if (args.length < 3) {
                printChannelUsage();
                System.exit(1);
            }
            File apk = new File(args[2]);
            String ch = ApkChannel.readChannel(apk);
            System.out.println(ch != null ? ch : "");
            return;
        }
        if ("put".equals(sub)) {
            if (args.length < 4) {
                printChannelUsage();
                System.exit(1);
            }
            File apk = new File(args[2]);
            String name = args[3];
            File out = apk;
            for (int i = 4; i < args.length; i++) {
                if ("-o".equals(args[i]) && i + 1 < args.length) {
                    out = new File(args[++i]);
                }
            }
            if (!out.equals(apk)) {
                Files.copy(apk.toPath(), out.toPath(), StandardCopyOption.REPLACE_EXISTING);
            }
            ApkChannel.writeChannel(out, out, name);
            System.out.println("channel=" + name + " -> " + out.getAbsolutePath());
            return;
        }
        if ("batch".equals(sub)) {
            if (args.length < 4) {
                printChannelUsage();
                System.exit(1);
            }
            File apk = new File(args[2]);
            File listFile = new File(args[3]);
            File outDir = apk.getParentFile() != null ? apk.getParentFile() : new File(".");
            for (int i = 4; i < args.length; i++) {
                if ("-o-dir".equals(args[i]) && i + 1 < args.length) {
                    outDir = new File(args[++i]);
                }
            }
            outDir.mkdirs();
            List<String> list = readChannelListFile(listFile);
            for (String ch : list) {
                File dest = channelSibling(apk, outDir, ch);
                Files.copy(apk.toPath(), dest.toPath(), StandardCopyOption.REPLACE_EXISTING);
                ApkChannel.writeChannel(dest, dest, ch);
                System.out.println("channel=" + ch + " -> " + dest.getAbsolutePath());
            }
            return;
        }
        printChannelUsage();
        System.exit(1);
    }

    private static void printChannelUsage() {
        System.err.println("Usage: java -jar protector-packer.jar channel get <apk>");
        System.err.println("       java -jar protector-packer.jar channel put <apk> <name> [-o out.apk]");
        System.err.println("       java -jar protector-packer.jar channel batch <apk> <channels.txt> [-o-dir dir]");
    }

    private static File channelSibling(File baseApk, File outDir, String channel) {
        String name = baseApk.getName();
        String stem = name.endsWith(".apk") ? name.substring(0, name.length() - 4) : name;
        return new File(outDir, stem + "-" + sanitizeChannelFileToken(channel) + ".apk");
    }

    private static String sanitizeChannelFileToken(String channel) {
        StringBuilder sb = new StringBuilder(channel.length());
        for (int i = 0; i < channel.length(); i++) {
            char c = channel.charAt(i);
            if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
                    || (c >= '0' && c <= '9') || c == '_' || c == '-' || c == '.') {
                sb.append(c);
            } else {
                sb.append('_');
            }
        }
        return sb.length() > 0 ? sb.toString() : "channel";
    }

    private static void printUsage() {
        System.err.println("Usage: java -jar protector-packer.jar <input.apk> [-o out.apk] "
                + "[--shell-dir <dir>] [--profile balanced|industry|aggressive|perf|max] "
                + "[--hollow-prefix Lcom/foo/]... "
                + "[--vmp-prefix Lcom/foo/]... [--true-vmp-prefix Lcom/foo/]... "
                + "[--payment-auto-vmp|--no-payment-auto-vmp] "
                + "[--industry-auto-vmp|--no-industry-auto-vmp] "
                + "[--auto-true-vmp payment|industry|both|off] "
                + "[--protect-so|--no-protect-so] "
                + "[--encrypt-assets|--no-encrypt-assets] "
                + "[--enable-res-protect|--no-res-protect] "
                + "[--detect-proxy] [--pin-certs <file>] "
                + "[--channel <name>] [--channels <file>] "
                + "[--protect-so-mode safe|aggressive|max] "
                + "[--protect-so-budget-mb <n>] [--protect-so-max-file-mb <n>] "
                + "[--protect-so-abi <abi>|all] "
                + "[--protect-so-exclude <liba.so,libb.so>] "
                + "[--protect-so-include <libx.so>] "
                + "[--so-decrypt-mode eager|lazy] "
                + "[--application <real.Application>] "
                + "[--cert-sha256 <hex>] "
                + "[--risk-flags <int>] [--rasp-action <0|1|2>] [--report-enabled <0|1>] "
                + "[--json-progress] "
                + "[--keystore <file> --alias <alias> --storepass <pass> [--keypass <pass>]]");
        System.err.println("  channel …        stamp/read signing-block channel (see: channel help)");
        System.err.println("  --profile          hollow / VMP intensity (default balanced)");
        System.err.println("                     balanced/perf=encrypt DEX; auto True-VMP on");
        System.err.println("                     /wxapi/ + all Alipay types (pay hot-path denylist empty)");
        System.err.println("                     industry=same + IndustryVmpRules default on;");
        System.err.println("                     SO budget defaults 48/24 MB unless overridden");
        System.err.println("                     aggressive=all non-SDK business types hollow");
        System.err.println("                     max=near hollow-all (skip Landroid/Landroidx)");
        System.err.println("  --hollow-prefix    allowlist type prefix (repeatable; enables hollow)");
        System.err.println("  --vmp-prefix       PVM1-pack methods (decode→DEX; not interpreter)");
        System.err.println("  --true-vmp-prefix  extra True-VMP prefixes (additive)");
        System.err.println("  --payment-auto-vmp / --no-payment-auto-vmp");
        System.err.println("                     force PaymentVmpRules on/off (default on when unset)");
        System.err.println("  --industry-auto-vmp / --no-industry-auto-vmp");
        System.err.println("                     force IndustryVmpRules on/off");
        System.err.println("                     (default on iff --profile industry)");
        System.err.println("  --auto-true-vmp    payment|industry|both|off (fine-grained flags override)");
        System.err.println("  --protect-so       RC4 .text of business SOs (default ON)");
        System.err.println("  --no-protect-so    disable business SO .text encryption");
        System.err.println("  --encrypt-assets   AES-GCM encrypt assets/** → protector/aenc (default OFF)");
        System.err.println("                     App must use ProtectorAssets (no AssetManager hook)");
        System.err.println("  --no-encrypt-assets disable assets encryption");
        System.err.println("  --enable-res-protect shorten res/ paths + rewrite resources.arsc (default OFF)");
        System.err.println("  --no-res-protect   disable res path obfuscation");
        System.err.println("  --detect-proxy     enable proxy/VPN heuristics (NetGuard; default OFF)");
        System.err.println("  --pin-certs <file> leaf cert SHA-256 hex pins (one per line) for NetGuard");
        System.err.println("  --channel <name>   stamp Walle-compatible channel after sign (needs --keystore)");
        System.err.println("  --channels <file>  batch stamp → <out>-<channel>.apk (needs --keystore)");
        System.err.println("  --protect-so-mode  safe (default)=common SO skips + size budget;");
        System.err.println("                     aggressive=shell+reloc only + soft budget;");
        System.err.println("                     max=common SO skips, no size budget");
        System.err.println("  --protect-so-budget-mb   SO size budget MB (default 12; profile industry 48;");
        System.err.println("                           --protect-so-mode max ignores)");
        System.err.println("  --protect-so-max-file-mb skip SO if unpacked >N MB (default 8; industry 24)");
        System.err.println("  --protect-so-abi   all (default) | arm64-v8a | …");
        System.err.println("  --protect-so-exclude  comma-separated basenames to never encrypt");
        System.err.println("                     (e.g. libd3.so,libzhd3d.so); repeatable");
        System.err.println("  --protect-so-include comma-separated basenames to encrypt ONLY");
        System.err.println("                     (mutually exclusive with --protect-so-exclude)");
        System.err.println("  --so-decrypt-mode  eager (default)=full materialize+preload at cold start;");
        System.err.println("                     lazy=on-demand + background fill (this process only)");
        System.err.println("                     Prefer loadLibrary after Application attach.");
        System.err.println("  --risk-flags      bitmask (default 48 = disable Root+Emulator)");
        System.err.println("  --rasp-action     0=alert 1=degrade 2=block (default 2)");
        System.err.println("  --report-enabled  threat log/ring (default 1)");
        System.err.println("  --json-progress   emit NDJSON progress events on stdout (desktop UI)");
        System.err.println("Default: output is aligned but UNSIGNED. Pass --keystore to sign.");
    }

    static ProtectOptions parseArgs(String[] args) throws Exception {
        File inputApk = new File(args[0]);
        File outputApk = null;
        File shellDir = null;
        File keystore = null;
        String storePass = null;
        String keyPass = null;
        String alias = null;
        String applicationOverride = null;
        String certSha256Override = null;
        Integer riskFlagsOverride = null;
        Integer raspActionOverride = null;
        Boolean reportEnabledOverride = null;
        boolean protectSo = true;
        boolean encryptAssetsFlag = false;
        boolean enableResProtectFlag = false;
        boolean detectProxyFlag = false;
        List<String> pinCerts = new ArrayList<>();
        String channelFlag = null;
        List<String> channelsFlag = new ArrayList<>();
        boolean jsonProgress = false;
        BusinessSoProtector.Mode protectSoMode = BusinessSoProtector.Mode.SAFE;
        double protectSoBudgetMb = 12.0;
        double protectSoMaxFileMb = 8.0;
        boolean protectSoBudgetExplicit = false;
        boolean protectSoMaxFileExplicit = false;
        String protectSoAbi = "all";
        java.util.LinkedHashSet<String> protectSoExclude = new java.util.LinkedHashSet<>();
        java.util.LinkedHashSet<String> protectSoInclude = new java.util.LinkedHashSet<>();
        ProtectOptions.SoDecryptMode soDecryptMode = ProtectOptions.SoDecryptMode.EAGER;
        ProtectPolicy.Profile profile = ProtectPolicy.Profile.BALANCED;
        List<String> hollowPrefixes = new ArrayList<>();
        List<String> vmpPrefixes = new ArrayList<>();
        List<String> trueVmpPrefixes = new ArrayList<>();
        ProtectOptions.AutoVmpMode paymentAutoVmp = ProtectOptions.AutoVmpMode.UNSET;
        ProtectOptions.AutoVmpMode industryAutoVmp = ProtectOptions.AutoVmpMode.UNSET;
        String autoTrueVmpAggregate = null;
        for (int i = 1; i < args.length; i++) {
            if ("-o".equals(args[i]) && i + 1 < args.length) {
                outputApk = new File(args[++i]);
            } else if ("--shell-dir".equals(args[i]) && i + 1 < args.length) {
                shellDir = new File(args[++i]);
            } else if ("--profile".equals(args[i]) && i + 1 < args.length) {
                profile = ProtectPolicy.parseProfile(args[++i]);
            } else if ("--hollow-prefix".equals(args[i]) && i + 1 < args.length) {
                hollowPrefixes.add(args[++i]);
            } else if ("--vmp-prefix".equals(args[i]) && i + 1 < args.length) {
                vmpPrefixes.add(args[++i]);
            } else if ("--true-vmp-prefix".equals(args[i]) && i + 1 < args.length) {
                trueVmpPrefixes.add(args[++i]);
            } else if ("--payment-auto-vmp".equals(args[i])) {
                paymentAutoVmp = AutoVmpPolicy.applyPairedFlag(
                        paymentAutoVmp, ProtectOptions.AutoVmpMode.ON, "payment");
            } else if ("--no-payment-auto-vmp".equals(args[i])) {
                paymentAutoVmp = AutoVmpPolicy.applyPairedFlag(
                        paymentAutoVmp, ProtectOptions.AutoVmpMode.OFF, "payment");
            } else if ("--industry-auto-vmp".equals(args[i])) {
                industryAutoVmp = AutoVmpPolicy.applyPairedFlag(
                        industryAutoVmp, ProtectOptions.AutoVmpMode.ON, "industry");
            } else if ("--no-industry-auto-vmp".equals(args[i])) {
                industryAutoVmp = AutoVmpPolicy.applyPairedFlag(
                        industryAutoVmp, ProtectOptions.AutoVmpMode.OFF, "industry");
            } else if ("--auto-true-vmp".equals(args[i]) && i + 1 < args.length) {
                autoTrueVmpAggregate = args[++i];
            } else if ("--protect-so".equals(args[i])) {
                protectSo = true;
            } else if ("--no-protect-so".equals(args[i])) {
                protectSo = false;
            } else if ("--encrypt-assets".equals(args[i])) {
                encryptAssetsFlag = true;
            } else if ("--no-encrypt-assets".equals(args[i])) {
                encryptAssetsFlag = false;
            } else if ("--enable-res-protect".equals(args[i]) || "--res-protect".equals(args[i])) {
                enableResProtectFlag = true;
            } else if ("--no-res-protect".equals(args[i])) {
                enableResProtectFlag = false;
            } else if ("--detect-proxy".equals(args[i])) {
                detectProxyFlag = true;
            } else if ("--pin-certs".equals(args[i]) && i + 1 < args.length) {
                pinCerts.addAll(readPinCertFile(new File(args[++i])));
            } else if ("--channel".equals(args[i]) && i + 1 < args.length) {
                channelFlag = args[++i].trim();
            } else if ("--channels".equals(args[i]) && i + 1 < args.length) {
                channelsFlag.addAll(readChannelListFile(new File(args[++i])));
            } else if ("--protect-so-mode".equals(args[i]) && i + 1 < args.length) {
                protectSoMode = BusinessSoProtector.parseMode(args[++i]);
            } else if ("--protect-so-budget-mb".equals(args[i]) && i + 1 < args.length) {
                protectSoBudgetMb = Double.parseDouble(args[++i]);
                protectSoBudgetExplicit = true;
            } else if ("--protect-so-max-file-mb".equals(args[i]) && i + 1 < args.length) {
                protectSoMaxFileMb = Double.parseDouble(args[++i]);
                protectSoMaxFileExplicit = true;
            } else if ("--protect-so-abi".equals(args[i]) && i + 1 < args.length) {
                protectSoAbi = args[++i].trim();
            } else if ("--protect-so-exclude".equals(args[i]) && i + 1 < args.length) {
                for (String part : args[++i].split(",")) {
                    String n = BusinessSoProtector.normalizeSoBasename(part);
                    if (!n.isEmpty()) protectSoExclude.add(n);
                }
            } else if ("--protect-so-include".equals(args[i]) && i + 1 < args.length) {
                for (String part : args[++i].split(",")) {
                    String n = BusinessSoProtector.normalizeSoBasename(part);
                    if (!n.isEmpty()) protectSoInclude.add(n);
                }
            } else if ("--so-decrypt-mode".equals(args[i]) && i + 1 < args.length) {
                soDecryptMode = ProtectOptions.parseSoDecryptMode(args[++i]);
            } else if ("--application".equals(args[i]) && i + 1 < args.length) {
                applicationOverride = args[++i];
            } else if ("--cert-sha256".equals(args[i]) && i + 1 < args.length) {
                certSha256Override = args[++i];
            } else if ("--risk-flags".equals(args[i]) && i + 1 < args.length) {
                riskFlagsOverride = Integer.decode(args[++i]);
            } else if ("--rasp-action".equals(args[i]) && i + 1 < args.length) {
                raspActionOverride = Integer.parseInt(args[++i]);
            } else if ("--report-enabled".equals(args[i]) && i + 1 < args.length) {
                reportEnabledOverride = !"0".equals(args[++i]) && !"false".equalsIgnoreCase(args[i]);
            } else if ("--json-progress".equals(args[i])) {
                jsonProgress = true;
            } else if ("--keystore".equals(args[i]) && i + 1 < args.length) {
                keystore = new File(args[++i]);
            } else if ("--storepass".equals(args[i]) && i + 1 < args.length) {
                storePass = args[++i];
            } else if ("--keypass".equals(args[i]) && i + 1 < args.length) {
                keyPass = args[++i];
            } else if ("--alias".equals(args[i]) && i + 1 < args.length) {
                alias = args[++i];
            }
        }
        if (outputApk == null) {
            String name = inputApk.getName().replace(".apk", "-protected.apk");
            outputApk = new File(inputApk.getParentFile(), name);
        }
        if (shellDir == null) {
            File jarDir = new File(PackerMain.class.getProtectionDomain()
                    .getCodeSource().getLocation().toURI()).getParentFile();
            shellDir = new File(jarDir, "shell-files");
            if (!shellDir.exists()) {
                shellDir = new File("native/build/intermediates");
            }
        }
        if (raspActionOverride != null && (raspActionOverride < 0 || raspActionOverride > 2)) {
            throw new IllegalArgumentException("--rasp-action must be 0, 1, or 2");
        }

        // Aggregate first; paired flags already applied (and override aggregate axes still UNSET).
        if (autoTrueVmpAggregate != null) {
            ProtectOptions.AutoVmpMode[] agg = AutoVmpPolicy.fromAggregate(autoTrueVmpAggregate);
            if (paymentAutoVmp == ProtectOptions.AutoVmpMode.UNSET) {
                paymentAutoVmp = agg[0];
            }
            if (industryAutoVmp == ProtectOptions.AutoVmpMode.UNSET) {
                industryAutoVmp = agg[1];
            }
        }

        ProtectOptions options = new ProtectOptions();
        options.inputApk = inputApk;
        options.outputApk = outputApk;
        options.shellDir = shellDir;
        options.profile = profile;
        options.hollowPrefixes.addAll(hollowPrefixes);
        options.vmpPrefixes.addAll(vmpPrefixes);
        options.trueVmpPrefixes.addAll(trueVmpPrefixes);
        options.paymentAutoVmp = paymentAutoVmp;
        options.industryAutoVmp = industryAutoVmp;
        options.protectSo = protectSo;
        options.encryptAssets = encryptAssetsFlag;
        options.enableResProtect = enableResProtectFlag;
        options.detectProxy = detectProxyFlag;
        options.enableNetGuard = detectProxyFlag || !pinCerts.isEmpty();
        options.pinCertSha256.addAll(pinCerts);
        if (channelFlag != null && !channelFlag.isEmpty()) {
            options.channel = channelFlag;
            options.enableChannelMark = true;
        }
        options.channels.addAll(channelsFlag);
        if (!channelsFlag.isEmpty()) {
            options.enableChannelMark = true;
        }
        options.protectSoMode = protectSoMode;
        options.protectSoBudgetMb = protectSoBudgetMb;
        options.protectSoMaxFileMb = protectSoMaxFileMb;
        options.protectSoBudgetExplicit = protectSoBudgetExplicit;
        options.protectSoMaxFileExplicit = protectSoMaxFileExplicit;
        options.protectSoAbi = protectSoAbi;
        options.protectSoExclude.clear();
        options.protectSoExclude.addAll(protectSoExclude);
        options.protectSoInclude.clear();
        options.protectSoInclude.addAll(protectSoInclude);
        options.soDecryptMode = soDecryptMode;
        options.applicationOverride = applicationOverride;
        options.certSha256Override = certSha256Override;
        if (riskFlagsOverride != null) {
            options.riskFlags = riskFlagsOverride;
        }
        if (raspActionOverride != null) {
            options.raspAction = raspActionOverride;
        }
        if (reportEnabledOverride != null) {
            options.reportEnabled = reportEnabledOverride;
        }
        options.signConfig = resolveSignConfig(keystore, storePass, keyPass, alias);
        options.jsonProgress = jsonProgress;
        return options;
    }

    /**
     * @return null when caller did not request signing (default).
     */
    private static SignConfig resolveSignConfig(File keystore, String storePass, String keyPass, String alias) {
        if (keystore == null) {
            return null;
        }
        if (!keystore.isFile()) {
            throw new IllegalArgumentException("keystore not found: " + keystore.getAbsolutePath());
        }
        if (alias == null || alias.isEmpty()) {
            throw new IllegalArgumentException("--alias is required when --keystore is set");
        }
        if (storePass == null) {
            throw new IllegalArgumentException("--storepass is required when --keystore is set");
        }
        if (keyPass == null) {
            keyPass = storePass;
        }
        return new SignConfig(keystore, alias, storePass, keyPass);
    }

    public ProtectResult protect(File inputApk, File outputApk, File shellHint) throws Exception {
        return protect(inputApk, outputApk, shellHint, null);
    }

    public ProtectResult protect(File inputApk, File outputApk, File shellHint, SignConfig signConfig)
            throws Exception {
        Path work = Files.createTempDirectory("protector-work-");
        long inputBytes = inputApk.length();
        BusinessSoProtector.ProtectResult soResult = null;
        File reportBeside = null;
        boolean signed = signConfig != null;
        try {
            // Fail fast on bad keystore/alias/password before expensive hollow/VMP work.
            if (signConfig != null) {
                phase("validate_sign", "Validating keystore", 2);
                String preview = computeCertSha256(
                        signConfig.keystore, signConfig.alias, signConfig.storePass);
                System.out.println("keystore ok alias=" + signConfig.alias
                        + " cert_sha256=" + preview.substring(0, 16) + "…");
            }

            phase("unzip", "Unpacking APK", 5);
            File unpack = work.resolve("apk").toFile();
            Map<String, Long> soCompressedSizes = new LinkedHashMap<>();
            Set<String> storeEntries = unzip(inputApk, unpack, soCompressedSizes);

            String originalApp = readApplicationName(new File(unpack, "AndroidManifest.xml"));
            System.out.println("Original Application: " + originalApp);
            if (applicationOverride != null && !applicationOverride.isEmpty()) {
                System.out.println("Application override: " + applicationOverride);
                originalApp = applicationOverride;
            }
            String packageName = ManifestHelperLocal.getPackageName(
                    new File(unpack, "AndroidManifest.xml"));
            System.out.println("Package: " + packageName);
            if (packageName == null || packageName.isEmpty()) {
                throw new IllegalStateException("Manifest package name required for key derivation");
            }
            // Rebuild policy with applicationId so balanced/perf scope is package-local.
            protectPolicy = new ProtectPolicy(protectPolicy.profile(), hollowPrefixes, packageName);
            System.out.println("Hollow policy: " + protectPolicy.describe());
            if (industryAutoVmpEffective
                    && (protectPolicy.appPackagePrefix() == null
                    || protectPolicy.appPackagePrefix().isEmpty())) {
                System.out.println("WARN: Industry auto True-VMP enabled but Manifest package "
                        + "missing — industry markers will match nothing "
                        + "(use --true-vmp-prefix for manual targets)");
            }
            AutoVmpPolicy.Resolved autoVmpLog = new AutoVmpPolicy.Resolved(
                    paymentAutoVmpEffective, industryAutoVmpEffective,
                    paymentAutoVmpFromCli, industryAutoVmpFromCli);
            System.out.println(AutoVmpPolicy.formatPolicyLine(
                    autoVmpLog, protectPolicy.profile(), trueVmpPrefixes.size(),
                    protectPolicy.appPackagePrefix()));
            if (protectPolicy.profile() == ProtectPolicy.Profile.INDUSTRY) {
                System.out.println("Industry defaults: IndustryVmpRules="
                        + (industryAutoVmpEffective ? "on" : "off")
                        + " so_budget_mb=" + protectSoBudgetMb
                        + " so_max_file_mb=" + protectSoMaxFileMb);
            }

            int xorKey = 0; // legacy field retained in config.json
            String appSignSha256 = resolveAppSignSha256(inputApk, signConfig);
            if (appSignSha256 == null || appSignSha256.isEmpty()) {
                throw new IllegalStateException(
                        "Failed to resolve app_sign_sha256. Provide --cert-sha256 <hex>, "
                                + "or --keystore (uses that cert), or a signed input APK.");
            }
            byte[] kMaster = new byte[KeyLadder.MASTER_LEN];
            new SecureRandom().nextBytes(kMaster);
            byte[] kWrap = new byte[KeyLadder.WRAP_LEN];
            new SecureRandom().nextBytes(kWrap);
            KeyLadder.Derived derived = KeyLadder.derive(
                    kMaster, KeyLadder.fromHex(appSignSha256), packageName);
            byte[] aesKey = derived.insn;
            byte[] dexAesKey = derived.dex;
            byte[] soAesKey = derived.so;
            hmacKey = derived.hmac;
            byte[] assetsAesKey = derived.assets;
            pvm2Morph = Pvm2Morph.random(new SecureRandom());
            pvm2Admission.reset();
            System.out.println("PVM2 morph isa_id=" + pvm2Morph.isaId
                    + " op_count=" + Pvm2Morph.OP_COUNT
                    + " imm_xor=on");

            File assetsProtector = new File(unpack, "assets/protector");
            assetsProtector.mkdirs();

            // Extract & hollow / True-VMP selected methods (default: payment auto-VMP only)
            phase("hollow", "Hollowing / VMP methods", 20);
            List<File> dexFiles = listDexFiles(unpack);
            Map<Integer, List<InsnRecord>> all = new HashMap<>();
            int autoVmpTypes = 0;
            int autoVmpMethods = 0;
            int autoIndustryTypes = 0;
            int autoIndustryMethods = 0;
            for (File dex : dexFiles) {
                int dexNo = dexNumber(dex.getName());
                File hollowed = new File(dex.getParent(), dex.getName() + ".hollow");
                HollowResult hr = hollowDex(dex, hollowed, aesKey, dexNo);
                all.put(dexNo, hr.records);
                autoVmpTypes += hr.autoPaymentTypes;
                autoVmpMethods += hr.autoPaymentMethods;
                autoIndustryTypes += hr.autoIndustryTypes;
                autoIndustryMethods += hr.autoIndustryMethods;
                Files.move(hollowed.toPath(), dex.toPath(), StandardCopyOption.REPLACE_EXISTING);
                System.out.println("Hollowed " + dex.getName() + " methods=" + hr.records.size());
            }
            System.out.println("Auto True-VMP (alipay|/wxapi/): types=" + autoVmpTypes
                    + " methods=" + autoVmpMethods);
            if (industryAutoVmpEffective) {
                System.out.println("Auto True-VMP (IndustryVmpRules): types=" + autoIndustryTypes
                        + " methods=" + autoIndustryMethods);
            }
            System.out.println(pvm2Admission.admissionLine());
            System.out.println(pvm2Admission.skipReasonsLine());
            System.out.println(pvm2Admission.unsupportedOpcodesLine());

            // Write code.bin (only DEXes that actually hollowed methods; may be empty)
            File codeBin = new File(assetsProtector, "code.bin");
            writeCodeBin(codeBin, all);

            // All business DEX go into encrypted dexes.zip — APK must not contain plaintext
            // business classesN.dex (shell + junk only after embed).
            File dexZip = new File(assetsProtector, "dexes.zip");
            if (dexFiles.isEmpty()) {
                throw new IllegalStateException("input APK has no classes*.dex");
            }
            zipDeflate(dexFiles, dexZip);
            for (File dex : dexFiles) {
                //noinspection ResultOfMethodCallIgnored
                dex.delete();
            }
            System.out.println("dexes.zip entries=" + dexFiles.size()
                    + " (all business DEX; no plaintext multidex in base.apk)");
            encryptDexesZipPdx1(dexZip, dexAesKey);
            String dexHmacHex = CryptoUtils.toHex(
                    CryptoUtils.hmacSha256(hmacKey, Files.readAllBytes(dexZip.toPath())));
            String codeHmacHex = CryptoUtils.toHex(
                    CryptoUtils.hmacSha256(hmacKey, Files.readAllBytes(codeBin.toPath())));
            String codeMethodsHmacHex = CodeMethodsIntegrity.hmacHex(hmacKey, all);

            boolean wroteSokeys = false;
            if (protectSo) {
                phase("protect_so", "Encrypting business SO .text", 45);
                BusinessSoProtector.Options soOpts = new BusinessSoProtector.Options();
                soOpts.mode = protectSoMode;
                soOpts.budgetMb = protectSoBudgetMb;
                soOpts.maxFileMb = protectSoMaxFileMb;
                soOpts.abiFilter = protectSoAbi;
                soOpts.excludeBasenames = new java.util.LinkedHashSet<>(protectSoExclude);
                soOpts.includeBasenames = new java.util.LinkedHashSet<>(protectSoInclude);
                soOpts.compressedSizes = soCompressedSizes;
                soOpts.storedEntries = storeEntries;
                soResult = BusinessSoProtector.protectAll(new File(unpack, "lib"), soOpts);
                List<BusinessSoProtector.Entry> soEntries = soResult.entries;
                if (!soEntries.isEmpty()) {
                    byte[] sokeys = BusinessSoProtector.buildSokeysBlob(soEntries, soAesKey);
                    Files.write(new File(assetsProtector, "sokeys.bin").toPath(), sokeys);
                    wroteSokeys = true;
                    System.out.println("Wrote sokeys.bin entries=" + soEntries.size()
                            + " size=" + sokeys.length);
                } else {
                    System.out.println("WARN: SO protect enabled but no encryptable business .so found");
                }
            }

            int assetsEncrypted = 0;
            if (encryptAssets) {
                phase("encrypt_assets", "Encrypting app assets", 55);
                AssetsEncryptor.Result ar = AssetsEncryptor.encryptAll(unpack, assetsAesKey);
                assetsEncrypted = ar.encrypted;
                System.out.println("Assets encrypt: files=" + ar.encrypted
                        + " skipped=" + ar.skipped);
            }

            // Embed shell before config.json so bitcode_hmac.<abi> can be HMAC-covered.
            phase("manifest", "Rewriting manifest / embedding shell", 60);
            writeApplicationName(new File(unpack, "AndroidManifest.xml"), PROXY_APP);
            tryWriteAppComponentFactory(new File(unpack, "AndroidManifest.xml"), PROXY_ACF);
            setExtractNativeLibs(new File(unpack, "AndroidManifest.xml"));

            Map<String, String> bitcodeHmac = embedShell(unpack, shellHint, kWrap, kMaster, hmacKey);
            Arrays.fill(kMaster, (byte) 0);
            Arrays.fill(kWrap, (byte) 0);

            // config.json — AES/HMAC keys are HKDF-derived at runtime, not stored here.
            // HMAC-SHA256 protects risk_flags / rasp_action / app_sign_sha256 / protect_so /
            // encrypt_assets / net_guard / so_decrypt_mode / package / vmp_lru /
            // dex_hmac / code_hmac / code_methods_hmac / bitcode_hmac.
            boolean netGuardOn = detectProxy || !pinCertSha256.isEmpty();
            if (netGuardOn) {
                writeNetGuardJson(assetsProtector, detectProxy, pinCertSha256);
            }
            String soDecryptWire = ProtectOptions.soDecryptModeWire(soDecryptMode);
            String bitcodeHmacJson = formatBitcodeHmacJson(bitcodeHmac);
            String configPayload = String.format(Locale.US,
                    "{\"application_name\":\"%s\",\"insns_xor_key\":%d,"
                            + "\"risk_flags\":%d,\"rasp_action\":%d,\"report_enabled\":%s,"
                            + "\"app_sign_sha256\":\"%s\",\"protect_so\":%s,\"encrypt_assets\":%s,"
                            + "\"detect_proxy\":%s,\"net_guard\":%s,\"so_decrypt_mode\":\"%s\","
                            + "\"package\":\"%s\",\"vmp_lru\":%d,\"dex_hmac\":\"%s\","
                            + "\"code_hmac\":\"%s\",\"code_methods_hmac\":\"%s\",\"bitcode_hmac\":%s",
                    escapeJson(originalApp == null ? "" : originalApp), xorKey,
                    riskFlags, raspAction, reportEnabled ? "true" : "false", appSignSha256,
                    wroteSokeys ? "true" : "false",
                    (assetsEncrypted > 0) ? "true" : "false",
                    detectProxy ? "true" : "false",
                    netGuardOn ? "true" : "false",
                    soDecryptWire,
                    escapeJson(packageName),
                    32,
                    dexHmacHex,
                    codeHmacHex,
                    codeMethodsHmacHex,
                    bitcodeHmacJson);
            String hmac = computeHmacHex(configPayload, hmacKey);
            String config = configPayload + ",\"_hmac\":\"" + hmac + "\"}\n";
            Files.writeString(new File(assetsProtector, "config.json").toPath(), config,
                    StandardCharsets.UTF_8);
            System.out.println("app_sign_sha256=" + appSignSha256
                    + " risk_flags=0x" + Integer.toHexString(riskFlags)
                    + " rasp_action=" + raspAction
                    + " report_enabled=" + reportEnabled
                    + " protect_so=" + wroteSokeys
                    + " so_decrypt_mode=" + soDecryptWire
                    + " vmp_lru=32"
                    + " dex_hmac=set"
                    + " code_hmac=set"
                    + " code_methods_hmac=set"
                    + " bitcode_hmac=" + bitcodeHmac.size()
                    + " encrypt_assets=" + (assetsEncrypted > 0)
                    + " res_protect=" + enableResProtect
                    + " detect_proxy=" + detectProxy
                    + " pin_certs=" + pinCertSha256.size());

            embedJunkCodeDex(unpack, work.toFile());

            // size_report placeholder (output_mb refined beside output after pack)
            String reportPlaceholder = BusinessSoProtector.buildSizeReportJson(
                    inputBytes, inputBytes, soResult, wroteSokeys);
            Files.writeString(new File(assetsProtector, "size_report.json").toPath(),
                    reportPlaceholder, StandardCharsets.UTF_8);

            if (enableResProtect) {
                phase("res_protect", "Obfuscating res/ paths", 78);
                ResPathObfuscator.Result rr = ResPathObfuscator.obfuscate(unpack);
                ResPathObfuscator.remapStoreEntries(storeEntries, rr.mapping);
            }

            // Repack unsigned
            phase("repack", "Repacking and aligning APK", 80);
            File unsigned = work.resolve("unsigned.apk").toFile();
            zipDir(unpack, unsigned, storeEntries);
            System.out.println("unsigned apk size=" + unsigned.length());
            if (unsigned.length() < 100) {
                throw new IllegalStateException("unsigned apk too small");
            }

            File aligned = work.resolve("aligned.apk").toFile();
            System.out.println("zipalign: starting");
            alignApk(unsigned, aligned);
            System.out.println("aligned apk size=" + aligned.length());
            if (!aligned.isFile() || aligned.length() < 100) {
                throw new IllegalStateException("aligned apk missing or too small");
            }

            outputApk.getParentFile().mkdirs();
            if (signConfig != null) {
                phase("sign", "Signing APK", 90);
                System.out.println("signing file size=" + aligned.length());
                sign(aligned, signConfig, outputApk);
                System.out.println("Signed OK size=" + outputApk.length());
            } else {
                Files.copy(aligned.toPath(), outputApk.toPath(), StandardCopyOption.REPLACE_EXISTING);
                System.out.println("Unsigned OK size=" + outputApk.length()
                        + " (pass --keystore to sign, or sign externally)");
            }

            applyChannelMarks(outputApk, signConfig != null);

            long outputBytes = outputApk.length();
            String sizeReport = BusinessSoProtector.buildSizeReportJson(
                    inputBytes, outputBytes, soResult, wroteSokeys);
            reportBeside = new File(outputApk.getParentFile(),
                    outputApk.getName().replace(".apk", "") + "-size_report.json");
            Files.writeString(reportBeside.toPath(), sizeReport, StandardCharsets.UTF_8);
            System.out.println("=== size_report ===");
            System.out.print(sizeReport);
            System.out.println("Wrote " + reportBeside.getAbsolutePath());
            if (soResult != null && soResult.budgetTruncated) {
                System.out.println("WARN: SO size-budget truncated — see so_skipped_budget in size_report");
                progress.onWarn("SO size-budget truncated — see so_skipped_budget in size_report");
            }
            return new ProtectResult(outputApk, reportBeside, signed);
        } finally {
            deleteRecursively(work.toFile());
        }
    }

    private Map<String, String> embedShell(File unpack, File shellHint, byte[] kWrap, byte[] kMaster,
                                           byte[] kHmac)
            throws Exception {
        File shellDex = findShellDex(shellHint);
        File shellLibs = findShellLibs(shellHint);
        if (shellDex == null || !shellDex.exists()) {
            throw new IllegalStateException(
                    "Cannot find shell classes.dex. Build :native and :demo first, or pass --shell-dir. hint=" + shellHint);
        }
        File targetDex = new File(unpack, "classes.dex");
        Files.copy(shellDex.toPath(), targetDex.toPath(), StandardCopyOption.REPLACE_EXISTING);
        System.out.println("Embedded shell dex: " + shellDex.getAbsolutePath());

        Map<String, String> bitcodeHmac = new TreeMap<>();
        if (shellLibs != null && shellLibs.isDirectory()) {
            File libRoot = new File(unpack, "lib");
            Set<String> targetAbis = listTargetAbis(libRoot);
            // No native libs in input: keep :native abiFilters defaults.
            if (targetAbis.isEmpty()) {
                targetAbis = Set.of("armeabi-v7a", "arm64-v8a");
                System.out.println("No lib/<abi> in input; embedding shell for " + targetAbis);
            } else {
                System.out.println("Embedding shell libs for input ABIs: " + targetAbis);
            }
            String[] knownAbis = {"armeabi-v7a", "arm64-v8a", "x86", "x86_64"};
            List<String> missingShellAbis = new ArrayList<>();
            for (String abi : knownAbis) {
                if (!targetAbis.contains(abi)) continue;
                File srcAbi = new File(shellLibs, abi);
                if (!srcAbi.isDirectory()) {
                    missingShellAbis.add(abi);
                    continue;
                }
                File dstAbi = new File(libRoot, abi);
                dstAbi.mkdirs();
                File[] sos = srcAbi.listFiles((d, n) -> n.endsWith(".so"));
                if (sos == null || sos.length == 0) {
                    missingShellAbis.add(abi);
                    continue;
                }
                boolean hasProtector = false;
                for (File so : sos) {
                    File dest = new File(dstAbi, so.getName());
                    Files.copy(so.toPath(), dest.toPath(), StandardCopyOption.REPLACE_EXISTING);
                    if ("libprotector.so".equals(so.getName()) && kWrap != null) {
                        String hmacHex = SoSectionEncryptor.encrypt(dest, kWrap, kMaster, kHmac);
                        bitcodeHmac.put(abi, hmacHex);
                        hasProtector = true;
                    }
                    System.out.println("Embedded " + abi + "/" + so.getName());
                }
                if (!hasProtector) {
                    missingShellAbis.add(abi);
                }
            }
            if (!missingShellAbis.isEmpty()) {
                throw new IllegalStateException(
                        "Input APK needs shell libs for ABI(s) " + missingShellAbis
                                + " but --shell-dir has none. Build :native for those ABIs "
                                + "or strip unsupported ABIs from the input APK. shell="
                                + shellLibs.getAbsolutePath());
            }
        } else {
            throw new IllegalStateException("shell libs not found under " + shellHint);
        }
        if (bitcodeHmac.isEmpty()) {
            throw new IllegalStateException("no libprotector.so embedded — cannot HMAC .bitcode");
        }
        return bitcodeHmac;
    }

    /** Compact JSON object for {@code bitcode_hmac}; keys sorted (TreeMap). */
    static String formatBitcodeHmacJson(Map<String, String> bitcodeHmac) {
        if (bitcodeHmac == null || bitcodeHmac.isEmpty()) {
            throw new IllegalArgumentException("bitcode_hmac required");
        }
        StringBuilder sb = new StringBuilder();
        sb.append('{');
        boolean first = true;
        for (Map.Entry<String, String> e : bitcodeHmac.entrySet()) {
            if (e.getKey() == null || e.getValue() == null || e.getValue().length() != 64) {
                throw new IllegalArgumentException("invalid bitcode_hmac entry for " + e.getKey());
            }
            if (!first) sb.append(',');
            first = false;
            sb.append('"').append(e.getKey()).append("\":\"").append(e.getValue()).append('"');
        }
        sb.append('}');
        return sb.toString();
    }

    /**
     * Replace plaintext dexes.zip with PDX1 || AES-GCM(zip).
     * Runtime decrypt_dexes_zip_file undoes this before DexMerger.
     */
    private static void encryptDexesZipPdx1(File dexZip, byte[] dexAesKey) throws Exception {
        byte[] plain = Files.readAllBytes(dexZip.toPath());
        if (plain.length < 4 || plain[0] != 'P' || plain[1] != 'K') {
            throw new IllegalStateException("dexes.zip is not a ZIP before PDX1 wrap");
        }
        byte[] enc = CryptoUtils.aesGcmEncrypt(dexAesKey, plain);
        // Wipe plaintext zip bytes from heap ASAP (best-effort).
        Arrays.fill(plain, (byte) 0);
        byte[] out = new byte[4 + enc.length];
        out[0] = 'P';
        out[1] = 'D';
        out[2] = 'X';
        out[3] = '1';
        System.arraycopy(enc, 0, out, 4, enc.length);
        Files.write(dexZip.toPath(), out);
        System.out.println("Encrypted dexes.zip as PDX1 size=" + out.length);
    }

    /** ABI dirs already present under unpack/lib (from the input APK). */
    private static Set<String> listTargetAbis(File libRoot) {
        Set<String> abis = new LinkedHashSet<>();
        if (libRoot == null || !libRoot.isDirectory()) {
            return abis;
        }
        File[] dirs = libRoot.listFiles(File::isDirectory);
        if (dirs == null) {
            return abis;
        }
        for (File d : dirs) {
            abis.add(d.getName());
        }
        return abis;
    }

    private void embedJunkCodeDex(File unpack, File workDir) throws Exception {
        File junkDex = new File(workDir, "junkcode.dex");
        JunkCodeGenerator.generateJunkCodeDex(junkDex);
        // After shell is classes.dex, junk is classes2.dex (business DEX are only in dexes.zip).
        File target = nextFreeClassesDex(unpack, null);
        Files.copy(junkDex.toPath(), target.toPath(), StandardCopyOption.REPLACE_EXISTING);
        System.out.println("Embedded junk dex as " + target.getName());
    }

    /**
     * First missing {@code classesN.dex} for N>=2 under unpack (classes.dex reserved for shell).
     * {@code reservedNames} optional basenames to skip.
     */
    private static File nextFreeClassesDex(File unpack, Set<String> reservedNames) {
        int n = 2;
        while (true) {
            File target = new File(unpack, "classes" + n + ".dex");
            boolean reserved = reservedNames != null && reservedNames.contains(target.getName());
            if (!target.exists() && !reserved) {
                return target;
            }
            n++;
        }
    }

    private String resolveAppSignSha256(File inputApk, SignConfig signConfig) throws Exception {
        if (certSha256Override != null && !certSha256Override.isEmpty()) {
            String hex = certSha256Override.trim().toLowerCase(Locale.US).replace(":", "");
            if (!hex.matches("[0-9a-f]{64}")) {
                throw new IllegalArgumentException(
                        "--cert-sha256 must be 64 hex chars (SHA-256), got: " + certSha256Override);
            }
            System.out.println("app_sign_sha256 from --cert-sha256");
            return hex;
        }
        if (signConfig != null) {
            System.out.println("app_sign_sha256 from --keystore");
            return computeCertSha256(signConfig.keystore, signConfig.alias, signConfig.storePass);
        }
        System.out.println("app_sign_sha256 from input APK signing cert");
        return computeApkCertSha256(inputApk);
    }

    private static String computeApkCertSha256(File apk) throws Exception {
        String hex = ApkSignerCert.sha256Hex(apk);
        if (hex == null || hex.isEmpty()) {
            throw new IllegalStateException(
                    "Input APK has no APK Signature Scheme v2/v3 certificate: "
                            + apk.getAbsolutePath()
                            + ". Pass --cert-sha256 <hex> for the final signing cert.");
        }
        return hex;
    }

    private static String computeCertSha256(File keystore, String alias, String password)
            throws Exception {
        KeyStore ks = loadKeyStore(keystore, password);
        Certificate cert = ks.getCertificate(alias);
        if (cert == null) {
            List<String> aliases = new ArrayList<>();
            Enumeration<String> en = ks.aliases();
            while (en.hasMoreElements()) {
                aliases.add(en.nextElement());
            }
            throw new IllegalStateException(
                    "certificate not found for alias \"" + alias + "\". available aliases: "
                            + (aliases.isEmpty() ? "(none)" : String.join(", ", aliases)));
        }
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] hash = md.digest(cert.getEncoded());
        return toHexLower(hash);
    }

    /** Load JKS or PKCS12; prefer type hinted by file magic. Surfaces password errors clearly. */
    static KeyStore loadKeyStore(File keystore, String password) throws Exception {
        if (keystore == null || !keystore.isFile()) {
            throw new IllegalStateException("keystore not found: "
                    + (keystore == null ? "(null)" : keystore.getAbsolutePath()));
        }
        char[] pwd = password == null ? new char[0] : password.toCharArray();
        List<String> types = detectKeyStoreTypes(keystore);
        Exception last = null;
        for (String type : types) {
            try {
                KeyStore candidate = KeyStore.getInstance(type);
                try (FileInputStream fis = new FileInputStream(keystore)) {
                    candidate.load(fis, pwd);
                }
                return candidate;
            } catch (Exception e) {
                last = e;
            }
        }
        String detail = last == null ? "unknown error" : rootMessage(last);
        String lower = detail.toLowerCase(Locale.US);
        if (lower.contains("password") || lower.contains("mac check")
                || lower.contains("pad block") || lower.contains("integrity check")) {
            throw new IllegalStateException(
                    "keystore password incorrect for " + keystore.getAbsolutePath()
                            + " (" + detail + ")", last);
        }
        throw new IllegalStateException(
                "failed to load keystore " + keystore.getAbsolutePath()
                        + " (tried " + String.join("/", types) + "): " + detail, last);
    }

    private static List<String> detectKeyStoreTypes(File keystore) {
        // PKCS12 = ASN.1 SEQUENCE (0x30); JKS magic = 0xFEEDFEED
        boolean pkcs12 = false;
        boolean jks = false;
        try (FileInputStream in = new FileInputStream(keystore)) {
            int b0 = in.read();
            int b1 = in.read();
            int b2 = in.read();
            int b3 = in.read();
            if (b0 == 0x30) {
                pkcs12 = true;
            }
            if (b0 == 0xFE && b1 == 0xED && b2 == 0xFE && b3 == 0xED) {
                jks = true;
            }
        } catch (Exception ignored) {
        }
        List<String> types = new ArrayList<>(2);
        if (pkcs12) {
            types.add("PKCS12");
            types.add("JKS");
        } else if (jks) {
            types.add("JKS");
            types.add("PKCS12");
        } else {
            // Android Studio often writes PKCS12 into a .jks filename.
            types.add("PKCS12");
            types.add("JKS");
        }
        return types;
    }

    private static String rootMessage(Throwable t) {
        Throwable cur = t;
        String last = t.getMessage();
        while (cur != null) {
            if (cur.getMessage() != null && !cur.getMessage().isEmpty()) {
                last = cur.getMessage();
            }
            cur = cur.getCause();
        }
        return last == null ? t.getClass().getSimpleName() : last;
    }

    private static String toHexLower(byte[] hash) {
        StringBuilder sb = new StringBuilder(hash.length * 2);
        for (byte b : hash) {
            sb.append(String.format(Locale.US, "%02x", b));
        }
        return sb.toString();
    }

    private File findShellDex(File hint) {
        List<File> candidates = new ArrayList<>();
        // Prefer packaged output from helper copy task
        candidates.add(new File("executable/shell-files/dex/classes.dex"));
        candidates.add(new File(hint, "dex/classes.dex"));
        candidates.add(new File(hint, "classes.dex"));
        // Gradle intermediates for :native (library) — use jar dex from demo merge is wrong;
        // we produce shell dex via :native jar -> d8 in a gradle task; fallback scan:
        collectFilesNamed(new File("native/build"), "classes.dex", candidates, 6);
        collectFilesNamed(new File("demo/build"), "classes.dex", candidates, 4);
        for (File f : candidates) {
            if (f != null && f.isFile() && f.length() > 0) {
                // Prefer native runtime dex if path contains protector shell markers — use first existing executable one
                if (f.getAbsolutePath().replace('\\', '/').contains("shell-files")) return f;
            }
        }
        for (File f : candidates) {
            if (f != null && f.isFile()) return f;
        }
        return null;
    }

    private File findShellLibs(File hint) {
        // Prefer "libs" — exportShellFiles writes here. Stale "lib/" must not win.
        File execLibs = new File("executable/shell-files/libs");
        if (execLibs.isDirectory()) return execLibs;
        File execLib = new File("executable/shell-files/lib");
        if (execLib.isDirectory()) return execLib;
        File h = new File(hint, "libs");
        if (h.isDirectory()) return h;
        h = new File(hint, "lib");
        if (h.isDirectory()) return h;
        // merged native libs from :native
        File merged = new File("native/build/intermediates/merged_native_libs/debug/out/lib");
        if (merged.isDirectory()) return merged;
        merged = new File("native/build/intermediates/merged_native_libs/release/out/lib");
        if (merged.isDirectory()) return merged;
        File jni = new File("native/build/intermediates/library_jni/debug/jni");
        if (jni.isDirectory()) return jni;
        return findFirstLibDir(new File("native/build/intermediates/merged_native_libs"));
    }

    private File findFirstLibDir(File root) {
        if (root == null || !root.exists()) return null;
        File[] children = root.listFiles();
        if (children == null) return null;
        for (File c : children) {
            File outLib = new File(c, "out/lib");
            if (outLib.isDirectory()) return outLib;
            File lib = new File(c, "lib");
            if (lib.isDirectory()) return lib;
            File nested = findFirstLibDir(c);
            if (nested != null) return nested;
        }
        return null;
    }

    private void collectFilesNamed(File dir, String name, List<File> out, int depth) {
        if (dir == null || !dir.exists() || depth < 0) return;
        File[] files = dir.listFiles();
        if (files == null) return;
        for (File f : files) {
            if (f.isDirectory()) collectFilesNamed(f, name, out, depth - 1);
            else if (name.equals(f.getName())) out.add(f);
        }
    }

    private void collectDirsNamed(File dir, String name, int depth) {
        // placeholder for future
    }

    private static final class HollowResult {
        final List<InsnRecord> records;
        final int autoPaymentTypes;
        final int autoPaymentMethods;
        final int autoIndustryTypes;
        final int autoIndustryMethods;

        HollowResult(List<InsnRecord> records, int autoPaymentTypes, int autoPaymentMethods,
                     int autoIndustryTypes, int autoIndustryMethods) {
            this.records = records;
            this.autoPaymentTypes = autoPaymentTypes;
            this.autoPaymentMethods = autoPaymentMethods;
            this.autoIndustryTypes = autoIndustryTypes;
            this.autoIndustryMethods = autoIndustryMethods;
        }
    }

    private HollowResult hollowDex(File inputDex, File outputDex, byte[] aesKey, int dexIndex)
            throws Exception {
        // Use dx Dex API via classpath dx.jar for precise code offsets
        byte[] data = Files.readAllBytes(inputDex.toPath());
        Files.write(outputDex.toPath(), data);

        List<InsnRecord> records = new ArrayList<>();
        List<TrueVmpTrampoline.Target> trueVmpTargets = new ArrayList<>();
        int autoPaymentTypes = 0;
        int autoPaymentMethods = 0;
        int autoIndustryTypes = 0;
        int autoIndustryMethods = 0;
        Set<String> trueVmpMethodKeys = new HashSet<>();

        // Phase 1: TRUE_VMP only. DexPool rebuilds the constant pool; any hollow
        // payload captured before that rewrite has stale string/type/method indices
        // and restores as VerifyError. So we trampoline first, then hollow.
        // Dex(File) rejects non-.dex extensions (output is *.hollow) — load from bytes.
        com.android.dex.Dex dex = new com.android.dex.Dex(Files.readAllBytes(outputDex.toPath()));
        try (RandomAccessFile raf = new RandomAccessFile(outputDex, "rw")) {
            int[] typeCounters = walkDexMethods(dex, raf, aesKey, ExtractPhase.TRUE_VMP_ONLY,
                    records, trueVmpTargets, trueVmpMethodKeys, dexIndex, null);
            autoPaymentTypes += typeCounters[0];
            autoIndustryTypes += typeCounters[1];
            autoPaymentMethods += typeCounters[2];
            autoIndustryMethods += typeCounters[3];
        }
        rewriteDexHashes(outputDex);

        if (!trueVmpTargets.isEmpty()) {
            TrueVmpTrampoline.rewrite(outputDex, trueVmpTargets);
            rewriteDexHashes(outputDex);
            rematchMethodIndices(outputDex, records);
            TrueVmpTrampoline.rebindEmbeddedIndices(outputDex, records);
            rewriteDexHashes(outputDex);
            System.out.println("TRUE_VMP DexPool done; hollowing against remapped pools");
        }

        // Phase 2: hollow / PVM1 against the post-DexPool dex (correct indices).
        dex = new com.android.dex.Dex(Files.readAllBytes(outputDex.toPath()));
        try (RandomAccessFile raf = new RandomAccessFile(outputDex, "rw")) {
            int[] typeCounters = walkDexMethods(dex, raf, aesKey, ExtractPhase.HOLLOW_OR_VMP,
                    records, trueVmpTargets, trueVmpMethodKeys, dexIndex, trueVmpMethodKeys);
            // Type counters already counted in phase 1 for overlapping types; only
            // add methods newly hollowed that are payment/industry (rare).
            autoPaymentMethods += typeCounters[2];
            autoIndustryMethods += typeCounters[3];
        }
        rewriteDexHashes(outputDex);

        return new HollowResult(records, autoPaymentTypes, autoPaymentMethods,
                autoIndustryTypes, autoIndustryMethods);
    }

    private enum ExtractPhase {
        TRUE_VMP_ONLY,
        HOLLOW_OR_VMP
    }

    /**
     * @return int[]{autoPayTypes, autoIndustryTypes, autoPayMethods, autoIndustryMethods}
     *         type counts are only filled on {@link ExtractPhase#TRUE_VMP_ONLY} (once).
     */
    private int[] walkDexMethods(com.android.dex.Dex dex, RandomAccessFile raf, byte[] aesKey,
                                 ExtractPhase phase, List<InsnRecord> records,
                                 List<TrueVmpTrampoline.Target> trueVmpTargets,
                                 Set<String> trueVmpMethodKeys, int dexIndex,
                                 Set<String> skipMethodKeys) throws Exception {
        int autoPayTypes = 0;
        int autoIndustryTypes = 0;
        int autoPayMethods = 0;
        int autoIndustryMethods = 0;
        for (com.android.dex.ClassDef classDef : dex.classDefs()) {
            if (classDef.getClassDataOffset() == 0) continue;
            String type = dex.typeNames().get(classDef.getTypeIndex());
            if (!shouldProcessType(type)) continue;
            boolean autoPay = paymentAutoVmpEffective && PaymentVmpRules.matches(type);
            boolean autoIndustry = !autoPay && industryAutoVmpEffective
                    && IndustryVmpRules.matches(type, protectPolicy.appPackagePrefix());
            if (phase == ExtractPhase.TRUE_VMP_ONLY) {
                if (autoPay) {
                    autoPayTypes++;
                }
                if (autoIndustry) {
                    autoIndustryTypes++;
                }
            }

            com.android.dex.ClassData classData = dex.readClassData(classDef);
            for (com.android.dex.ClassData.Method method : classData.getDirectMethods()) {
                InsnRecord rec = extractOne(dex, raf, method, aesKey, type, phase, skipMethodKeys);
                if (rec == null) {
                    continue;
                }
                records.add(rec);
                if ((rec.flags & VmCodec.FLAG_TRUE_VMP) != 0) {
                    trueVmpTargets.add(new TrueVmpTrampoline.Target(rec.methodIndex, dexIndex));
                    trueVmpMethodKeys.add(methodKey(rec));
                    if (autoPay) {
                        autoPayMethods++;
                    }
                    if (autoIndustry) {
                        autoIndustryMethods++;
                    }
                } else if (phase == ExtractPhase.HOLLOW_OR_VMP) {
                    if (autoPay && shouldTrueVmp(type)) {
                        // TRUE_VMP skip → hollow fallback still counts as payment protect.
                        autoPayMethods++;
                    }
                    if (autoIndustry && shouldTrueVmp(type)) {
                        autoIndustryMethods++;
                    }
                }
            }
            for (com.android.dex.ClassData.Method method : classData.getVirtualMethods()) {
                InsnRecord rec = extractOne(dex, raf, method, aesKey, type, phase, skipMethodKeys);
                if (rec == null) {
                    continue;
                }
                records.add(rec);
                if ((rec.flags & VmCodec.FLAG_TRUE_VMP) != 0) {
                    trueVmpTargets.add(new TrueVmpTrampoline.Target(rec.methodIndex, dexIndex));
                    trueVmpMethodKeys.add(methodKey(rec));
                    if (autoPay) {
                        autoPayMethods++;
                    }
                    if (autoIndustry) {
                        autoIndustryMethods++;
                    }
                } else if (phase == ExtractPhase.HOLLOW_OR_VMP) {
                    if (autoPay && shouldTrueVmp(type)) {
                        autoPayMethods++;
                    }
                    if (autoIndustry && shouldTrueVmp(type)) {
                        autoIndustryMethods++;
                    }
                }
            }
        }
        return new int[]{autoPayTypes, autoIndustryTypes, autoPayMethods, autoIndustryMethods};
    }

    private static String methodKey(InsnRecord rec) {
        return methodKey(rec.definingClass, rec.methodName, rec.paramTypes, rec.returnType);
    }

    private static String methodKey(String definingClass, String name, String[] params,
                                    String returnType) {
        StringBuilder sb = new StringBuilder();
        sb.append(definingClass).append('#').append(name).append('(');
        if (params != null) {
            for (String p : params) {
                sb.append(p);
            }
        }
        sb.append(')').append(returnType);
        return sb.toString();
    }

    /**
     * After dexlib2 rewrite, code.bin entries must use the new method_ids
     * index so DefineClass patching and TRUE_VMP interpret lookups agree.
     */
    private void rematchMethodIndices(File dexFile, List<InsnRecord> records) throws IOException {
        com.android.dex.Dex dex = new com.android.dex.Dex(Files.readAllBytes(dexFile.toPath()));
        for (InsnRecord rec : records) {
            if (rec.definingClass == null) {
                continue;
            }
            int idx = findMethodIndex(dex, rec.definingClass, rec.methodName,
                    rec.paramTypes, rec.returnType);
            if (idx < 0) {
                throw new IOException("rematch failed for " + rec.definingClass
                        + "->" + rec.methodName);
            }
            rec.methodIndex = idx;
        }
    }

    private static int findMethodIndex(com.android.dex.Dex dex, String definingClass,
                                       String name, String[] params, String returnType) {
        if (params == null) {
            params = new String[0];
        }
        List<com.android.dex.MethodId> methods = dex.methodIds();
        for (int i = 0; i < methods.size(); i++) {
            com.android.dex.MethodId mid = methods.get(i);
            if (!dex.typeNames().get(mid.getDeclaringClassIndex()).equals(definingClass)) {
                continue;
            }
            if (!dex.strings().get(mid.getNameIndex()).equals(name)) {
                continue;
            }
            com.android.dex.ProtoId proto = dex.protoIds().get(mid.getProtoIndex());
            if (!dex.typeNames().get(proto.getReturnTypeIndex()).equals(returnType)) {
                continue;
            }
            List<String> got = new ArrayList<>();
            int paramOff = proto.getParametersOffset();
            if (paramOff != 0) {
                com.android.dex.TypeList typeList = dex.readTypeList(paramOff);
                for (short t : typeList.getTypes()) {
                    got.add(dex.typeNames().get(t & 0xffff));
                }
            }
            if (got.size() != params.length) {
                continue;
            }
            boolean ok = true;
            for (int p = 0; p < params.length; p++) {
                if (!got.get(p).equals(params[p])) {
                    ok = false;
                    break;
                }
            }
            if (ok) {
                return i;
            }
        }
        return -1;
    }

    /** Hollow / VMP / auto payment True-VMP candidates. */
    private boolean shouldProcessType(String typeDescriptor) {
        if (shouldHollow(typeDescriptor)) {
            return true;
        }
        if (shouldTrueVmp(typeDescriptor) || shouldVmp(typeDescriptor)) {
            return true;
        }
        return false;
    }

    private static void writeNetGuardJson(File assetsProtector, boolean detectProxyFlag,
                                          List<String> pins) throws IOException {
        StringBuilder sb = new StringBuilder();
        sb.append("{\"detect_proxy\":").append(detectProxyFlag ? "true" : "false");
        sb.append(",\"detect_vpn\":").append(detectProxyFlag ? "true" : "false");
        sb.append(",\"pin_sha256\":[");
        for (int i = 0; i < pins.size(); i++) {
            if (i > 0) sb.append(',');
            sb.append('"').append(escapeJson(pins.get(i))).append('"');
        }
        sb.append("]}\n");
        Files.writeString(new File(assetsProtector, "netguard.json").toPath(), sb.toString(),
                StandardCharsets.UTF_8);
        System.out.println("Wrote netguard.json detect_proxy=" + detectProxyFlag
                + " pins=" + pins.size());
    }

    private static List<String> readPinCertFile(File file) throws IOException {
        if (file == null || !file.isFile()) {
            throw new IllegalArgumentException("--pin-certs file not found: " + file);
        }
        List<String> out = new ArrayList<>();
        for (String line : Files.readAllLines(file.toPath(), StandardCharsets.UTF_8)) {
            String t = line.trim();
            if (t.isEmpty() || t.startsWith("#")) continue;
            if (t.toLowerCase(Locale.US).startsWith("sha256/")) {
                t = t.substring(7);
            }
            StringBuilder hex = new StringBuilder();
            for (int i = 0; i < t.length(); i++) {
                char c = Character.toLowerCase(t.charAt(i));
                if ((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
                    hex.append(c);
                }
            }
            if (hex.length() != 64) {
                throw new IllegalArgumentException(
                        "--pin-certs bad SHA-256 line (want 64 hex): " + line);
            }
            out.add(hex.toString());
        }
        return out;
    }

    private static List<String> readChannelListFile(File file) throws IOException {
        if (file == null || !file.isFile()) {
            throw new IllegalArgumentException("--channels file not found: " + file);
        }
        List<String> out = new ArrayList<>();
        LinkedHashSet<String> seen = new LinkedHashSet<>();
        for (String line : Files.readAllLines(file.toPath(), StandardCharsets.UTF_8)) {
            String t = line.trim();
            if (t.isEmpty() || t.startsWith("#")) {
                continue;
            }
            if (seen.add(t)) {
                out.add(t);
            }
        }
        if (out.isEmpty()) {
            throw new IllegalArgumentException("--channels file has no channel names: " + file);
        }
        return out;
    }

    private void applyChannelMarks(File outputApk, boolean signed) throws Exception {
        boolean wantPrimary = channel != null && !channel.isEmpty();
        boolean wantBatch = !channels.isEmpty();
        if (!wantPrimary && !wantBatch) {
            return;
        }
        if (!signed) {
            throw new IllegalStateException(
                    "--channel/--channels require a V2/V3-signed APK (pass --keystore)");
        }
        phase("channel", "Stamping channel id(s)", 95);
        if (wantPrimary) {
            ApkChannel.writeChannel(outputApk, outputApk, channel);
            System.out.println("channel=" + channel + " -> " + outputApk.getAbsolutePath());
        }
        File outDir = outputApk.getParentFile() != null ? outputApk.getParentFile() : new File(".");
        for (String ch : channels) {
            if (wantPrimary && ch.equals(channel)) {
                continue; // already on primary
            }
            File dest = channelSibling(outputApk, outDir, ch);
            Files.copy(outputApk.toPath(), dest.toPath(), StandardCopyOption.REPLACE_EXISTING);
            ApkChannel.writeChannel(dest, dest, ch);
            System.out.println("channel=" + ch + " -> " + dest.getAbsolutePath());
        }
    }

    private boolean shouldHollow(String typeDescriptor) {
        return protectPolicy.shouldHollow(typeDescriptor);
    }

    private boolean shouldVmp(String typeDescriptor) {
        if (vmpPrefixes.isEmpty()) return false;
        for (String prefix : vmpPrefixes) {
            if (typeDescriptor.startsWith(prefix)) return true;
        }
        return false;
    }

    private boolean shouldTrueVmp(String typeDescriptor) {
        return AutoVmpPolicy.shouldTrueVmp(
                typeDescriptor,
                paymentAutoVmpEffective,
                industryAutoVmpEffective,
                trueVmpPrefixes,
                protectPolicy.appPackagePrefix());
    }

    private InsnRecord extractOne(com.android.dex.Dex dex, RandomAccessFile raf,
                                  com.android.dex.ClassData.Method method, byte[] aesKey,
                                  String typeDescriptor, ExtractPhase phase,
                                  Set<String> skipMethodKeys) throws Exception {
        if (method.getCodeOffset() == 0) return null;
        // Constructors/clinit must keep invokespecial/super; returning stubs fail ART verify.
        com.android.dex.MethodId methodId = dex.methodIds().get(method.getMethodIndex());
        String methodName = dex.strings().get(methodId.getNameIndex());
        if ("<init>".equals(methodName) || "<clinit>".equals(methodName)) {
            return null;
        }

        String returnType = dex.typeNames().get(
                dex.protoIds().get(dex.methodIds().get(method.getMethodIndex()).getProtoIndex())
                        .getReturnTypeIndex());
        com.android.dex.ProtoId proto =
                dex.protoIds().get(dex.methodIds().get(method.getMethodIndex()).getProtoIndex());
        String[] paramTypes;
        if (proto.getParametersOffset() == 0) {
            paramTypes = new String[0];
        } else {
            com.android.dex.TypeList tl = dex.readTypeList(proto.getParametersOffset());
            short[] types = tl.getTypes();
            paramTypes = new String[types.length];
            for (int i = 0; i < types.length; i++) {
                paramTypes[i] = dex.typeNames().get(types[i] & 0xffff);
            }
        }

        String key = methodKey(typeDescriptor, methodName, paramTypes, returnType);
        if (skipMethodKeys != null && skipMethodKeys.contains(key)) {
            return null;
        }

        if (phase == ExtractPhase.TRUE_VMP_ONLY && !shouldTrueVmp(typeDescriptor)) {
            return null;
        }
        if (phase == ExtractPhase.HOLLOW_OR_VMP
                && !shouldHollow(typeDescriptor) && !shouldVmp(typeDescriptor)) {
            return null;
        }

        com.android.dex.Code code = dex.readCode(method);
        short[] units = code.getInstructions();
        if (units.length == 0) {
            if (phase == ExtractPhase.TRUE_VMP_ONLY) {
                pvm2Admission.noteCandidate();
            }
            return null;
        }

        byte[] returnBytes = getReturnByteCodes(returnType);
        int byteSize = units.length * 2;
        if (byteSize < returnBytes.length) {
            if (phase == ExtractPhase.TRUE_VMP_ONLY) {
                pvm2Admission.noteCandidate();
            }
            return null;
        }

        int insnsOffset = method.getCodeOffset() + 16;
        byte[] original = new byte[byteSize];
        raf.seek(insnsOffset);
        raf.readFully(original);

        int flags = 0;
        byte[] toEncrypt = original;
        int plainSize = byteSize;
        boolean isStatic = (method.getAccessFlags() & 0x0008) != 0; // ACC_STATIC

        if (phase == ExtractPhase.TRUE_VMP_ONLY) {
            pvm2Admission.noteCandidate();
            Pvm2Compiler.Result compiled =
                    Pvm2Compiler.tryCompile(dex, code, returnType, isStatic, pvm2Morph);
            if (!compiled.isOk()) {
                pvm2Admission.noteFail(compiled.failReason);
                System.out.println("TRUE_VMP skip " + typeDescriptor + "->" + methodName
                        + ": " + compiled.failReason);
                return null;
            }
            // Stub until DexPool trampoline rewrite replaces the code item.
            writeReturnStub(raf, insnsOffset, returnBytes, byteSize);
            toEncrypt = compiled.image;
            plainSize = compiled.image.length;
            flags = VmCodec.FLAG_TRUE_VMP;
            Arrays.fill(original, (byte) 0);
            pvm2Admission.noteSuccess();
            System.out.println("TRUE_VMP " + typeDescriptor + "->" + methodName
                    + (isStatic ? " [static]" : " [instance]")
                    + " pvm2=" + plainSize + "B isa="
                    + (pvm2Morph != null ? pvm2Morph.isaId : -1));
        } else {
            writeReturnStub(raf, insnsOffset, returnBytes, byteSize);
            if (shouldVmp(typeDescriptor)) {
                byte[] pvm = VmCodec.encode(method.getMethodIndex(), original);
                if (pvm == null) {
                    throw new IOException("VMP encode failed");
                }
                toEncrypt = pvm;
                flags = VmCodec.FLAG_VMP;
                Arrays.fill(original, (byte) 0);
            } else if (!shouldHollow(typeDescriptor)) {
                raf.seek(insnsOffset);
                raf.write(original);
                return null;
            }
        }

        byte[] stored = CryptoUtils.aesGcmEncrypt(aesKey, toEncrypt);
        if (stored == null) {
            throw new IOException("AES-GCM encrypt insns failed");
        }
        if (toEncrypt != original) {
            Arrays.fill(toEncrypt, (byte) 0);
        }

        InsnRecord rec = new InsnRecord();
        rec.methodIndex = method.getMethodIndex();
        rec.plainInsnsSize = plainSize;
        rec.flags = flags;
        rec.insns = stored;
        rec.definingClass = typeDescriptor;
        rec.methodName = methodName;
        rec.paramTypes = paramTypes;
        rec.returnType = returnType;
        rec.registersSize = code.getRegistersSize();
        rec.insSize = code.getInsSize();
        rec.outsSize = code.getOutsSize();
        return rec;
    }

    private static void writeReturnStub(RandomAccessFile raf, int insnsOffset,
                                        byte[] returnBytes, int byteSize) throws IOException {
        raf.seek(insnsOffset);
        raf.write(returnBytes);
        int filled = returnBytes.length;
        while (filled + 2 <= byteSize) {
            raf.writeShort(0x000e);
            filled += 2;
        }
        if (filled < byteSize) {
            raf.write(0);
        }
    }

    /**
     * Placeholder bytecode matching return type so ART verification passes before restore.
     * Aligned with dpt-shell DexUtils.getReturnByteCodes.
     */
    static byte[] getReturnByteCodes(String typeName) {
        byte[] returnVoid = {(byte) 0x0e, (byte) 0x00};
        byte[] returnInt = {(byte) 0x12, (byte) 0x00, (byte) 0x0f, (byte) 0x00}; // const/4 v0,0 ; return v0
        byte[] returnWide = {(byte) 0x16, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x10, (byte) 0x00};
        byte[] returnObject = {(byte) 0x12, (byte) 0x00, (byte) 0x11, (byte) 0x00}; // const/4 v0,0 ; return-object v0
        if (typeName == null) return returnVoid;
        switch (typeName) {
            case "V":
                return returnVoid;
            case "B":
            case "C":
            case "F":
            case "I":
            case "S":
            case "Z":
                return returnInt;
            case "D":
            case "J":
                return returnWide;
            default:
                return returnObject;
        }
    }

    private void rewriteDexHashes(File dexFile) throws IOException {
        File tmp = new File(dexFile.getParent(), "hash_tmp.dex");
        try {
            Files.copy(dexFile.toPath(), tmp.toPath(), StandardCopyOption.REPLACE_EXISTING);
            com.android.dex.Dex dex = new com.android.dex.Dex(tmp);
            dex.writeHashes();
            try (FileOutputStream fos = new FileOutputStream(tmp)) {
                dex.writeTo(fos);
            }
            Files.move(tmp.toPath(), dexFile.toPath(), StandardCopyOption.REPLACE_EXISTING);
        } catch (Throwable t) {
            System.out.println("WARN: rewriteDexHashes: " + t.getMessage());
            //noinspection ResultOfMethodCallIgnored
            tmp.delete();
        }
    }

    private void writeCodeBin(File out, Map<Integer, List<InsnRecord>> map) throws IOException {
        List<Integer> dexIndexes = new ArrayList<>();
        for (Map.Entry<Integer, List<InsnRecord>> e : map.entrySet()) {
            List<InsnRecord> list = e.getValue();
            if (list != null && !list.isEmpty()) {
                dexIndexes.add(e.getKey());
            }
        }
        Collections.sort(dexIndexes);
        if (dexIndexes.isEmpty()) {
            // Encrypt-only / no hollow: runtime still needs a valid code.bin.
            try (FileOutputStream fos = new FileOutputStream(out)) {
                writeU16(fos, 4);
                writeU16(fos, 0);
            }
            System.out.println("Wrote empty code.bin v4 (0 hollow methods)");
            return;
        }

        // v4 header: version, count, offsets[]; each blob starts with dex_number.
        int headerSize = 2 + 2 + 4 * dexIndexes.size();
        int offset = headerSize;
        List<Integer> dexOffsets = new ArrayList<>();
        List<byte[]> dexBlobs = new ArrayList<>();

        for (Integer dexNo : dexIndexes) {
            List<InsnRecord> list = map.get(dexNo);
            dexOffsets.add(offset);
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            writeU32(bos, dexNo); // v4: real classesN ordinal (not slot index)
            writeU16(bos, list.size());
            for (InsnRecord r : list) {
                writeU32(bos, r.methodIndex);
                writeU32(bos, r.plainInsnsSize);
                writeU32(bos, r.insns.length);
                writeU32(bos, r.flags);
                bos.write(r.insns);
            }
            byte[] blob = bos.toByteArray();
            dexBlobs.add(blob);
            offset += blob.length;
        }

        try (FileOutputStream fos = new FileOutputStream(out)) {
            writeU16(fos, 4); // version 4: per-blob dex_number for non-contiguous multidex
            writeU16(fos, dexIndexes.size());
            for (Integer off : dexOffsets) writeU32(fos, off);
            for (byte[] blob : dexBlobs) fos.write(blob);
        }
        System.out.println("Wrote code.bin v4 size=" + out.length()
                + " dexes=" + dexIndexes);
    }

    private static void writeU16(java.io.OutputStream os, int v) throws IOException {
        os.write(v & 0xff);
        os.write((v >> 8) & 0xff);
    }

    private static void writeU32(java.io.OutputStream os, int v) throws IOException {
        os.write(v & 0xff);
        os.write((v >> 8) & 0xff);
        os.write((v >> 16) & 0xff);
        os.write((v >> 24) & 0xff);
    }

    private void zipDeflate(List<File> dexFiles, File outZip) throws IOException {
        ZipParameters params = new ZipParameters();
        params.setCompressionMethod(CompressionMethod.DEFLATE);
        try (ZipFile zf = new ZipFile(outZip)) {
            for (File dex : dexFiles) {
                zf.addFile(dex, params);
            }
        }
    }

    private String readApplicationName(File manifest) {
        return ManifestHelperLocal.getApplicationName(manifest);
    }

    private void writeApplicationName(File manifest, String name) {
        File tmp = new File(manifest.getParent(), "AndroidManifest_new.xml");
        ModificationProperty property = new ModificationProperty();
        property.addApplicationAttribute(new AttributeItem(NodeValue.Application.NAME, name));
        FileProcesser.processManifestFile(manifest.getAbsolutePath(), tmp.getAbsolutePath(), property);
        //noinspection ResultOfMethodCallIgnored
        manifest.delete();
        //noinspection ResultOfMethodCallIgnored
        tmp.renameTo(manifest);
    }

    private void tryWriteAppComponentFactory(File manifest, String name) {
        try {
            File tmp = new File(manifest.getParent(), "AndroidManifest_new.xml");
            ModificationProperty property = new ModificationProperty();
            property.addApplicationAttribute(new AttributeItem("appComponentFactory", name));
            FileProcesser.processManifestFile(manifest.getAbsolutePath(), tmp.getAbsolutePath(), property);
            manifest.delete();
            tmp.renameTo(manifest);
        } catch (Throwable t) {
            System.out.println("WARN: set appComponentFactory failed: " + t.getMessage());
        }
    }

    private void setExtractNativeLibs(File manifest) {
        try {
            File tmp = new File(manifest.getParent(), "AndroidManifest_new.xml");
            ModificationProperty property = new ModificationProperty();
            property.addApplicationAttribute(new AttributeItem(NodeValue.Application.EXTRACTNATIVELIBS, "true"));
            FileProcesser.processManifestFile(manifest.getAbsolutePath(), tmp.getAbsolutePath(), property);
            manifest.delete();
            tmp.renameTo(manifest);
        } catch (Throwable ignored) {
        }
    }

    private void sign(File input, SignConfig signConfig, File output) throws Exception {
        List<String> cmd = new ArrayList<>();
        cmd.add("sign");
        cmd.add("--ks");
        cmd.add(signConfig.keystore.getAbsolutePath());
        cmd.add("--ks-key-alias");
        cmd.add(signConfig.alias);
        cmd.add("--ks-pass");
        cmd.add("pass:" + signConfig.storePass);
        cmd.add("--key-pass");
        cmd.add("pass:" + signConfig.keyPass);
        cmd.add("--out");
        cmd.add(output.getAbsolutePath());
        cmd.add("--v1-signing-enabled");
        cmd.add("true");
        cmd.add("--v2-signing-enabled");
        cmd.add("true");
        cmd.add(input.getAbsolutePath());
        ApkSignerTool.main(cmd.toArray(new String[0]));
    }

    /** Optional APK signing credentials (null = leave unsigned). */
    public static final class SignConfig {
        public final File keystore;
        public final String alias;
        public final String storePass;
        public final String keyPass;

        public SignConfig(File keystore, String alias, String storePass, String keyPass) {
            this.keystore = keystore;
            this.alias = alias;
            this.storePass = storePass;
            this.keyPass = keyPass;
        }
    }

    private static List<File> listDexFiles(File apkDir) {
        List<File> list = new ArrayList<>();
        File[] files = apkDir.listFiles((d, n) -> n.startsWith("classes") && n.endsWith(".dex"));
        if (files != null) {
            for (File f : files) list.add(f);
        }
        list.sort(Comparator.comparing(File::getName));
        return list;
    }

    private static int dexNumber(String name) {
        if ("classes.dex".equals(name)) return 0;
        // classes2.dex -> 1
        String n = name.replace("classes", "").replace(".dex", "");
        if (n.isEmpty()) return 0;
        return Integer.parseInt(n) - 1;
    }

    private static Set<String> unzip(File zip, File dest) throws IOException {
        return unzip(zip, dest, null);
    }

    /**
     * Extract APK entries to disk. On Windows (case-insensitive FS), AGP's short
     * resource names like {@code res/hq.xml} vs {@code res/HQ.xml} would clobber
     * each other — store collisions under {@code .csstore/} and restore names in
     * {@link #zipDir}.
     *
     * @param soCompressedOut optional map filled with {@code lib/&lt;abi&gt;/*.so} → compressed size
     * @return entry names that were STORED (uncompressed) in the input APK —
     *         must stay STORED so SoundPool/openRawResourceFd keeps working
     */
    private static Set<String> unzip(File zip, File dest, Map<String, Long> soCompressedOut)
            throws IOException {
        if (!dest.exists() && !dest.mkdirs()) {
            throw new IOException("cannot create " + dest);
        }
        File csStore = new File(dest, ".csstore");
        Map<String, String> lowerToName = new HashMap<>();
        List<String> collisionLines = new ArrayList<>();
        int collisionSeq = 0;
        String destPath = dest.getCanonicalPath();
        Set<String> storeEntries = new HashSet<>();
        int fileEntryCount = 0;
        // Prefer ZipFile for compression method + compressed sizes.
        try (java.util.zip.ZipFile zf = new java.util.zip.ZipFile(zip)) {
            var en = zf.entries();
            while (en.hasMoreElements()) {
                ZipEntry e = en.nextElement();
                if (e.isDirectory()) {
                    continue;
                }
                String n = e.getName();
                if (n == null || n.isEmpty()) {
                    continue;
                }
                n = n.replace('\\', '/');
                fileEntryCount++;
                if (e.getMethod() == ZipEntry.STORED) {
                    storeEntries.add(n);
                }
                if (soCompressedOut != null
                        && n.startsWith("lib/")
                        && n.endsWith(".so")
                        && e.getCompressedSize() >= 0) {
                    soCompressedOut.put(n, e.getCompressedSize());
                }
            }
        }
        ProgressMilestones unzipProg = new ProgressMilestones("unzip", fileEntryCount);
        try (ZipInputStream zis = new ZipInputStream(new FileInputStream(zip))) {
            ZipEntry entry;
            while ((entry = zis.getNextEntry()) != null) {
                String name = entry.getName();
                if (name == null || name.isEmpty() || name.startsWith("/") || name.contains("..")) {
                    continue;
                }
                name = name.replace('\\', '/');
                if (entry.isDirectory()) {
                    File dir = new File(dest, name);
                    //noinspection ResultOfMethodCallIgnored
                    dir.mkdirs();
                    continue;
                }
                String lower = name.toLowerCase(Locale.ROOT);
                File out;
                if (lowerToName.containsKey(lower) && !name.equals(lowerToName.get(lower))) {
                    if (!csStore.exists() && !csStore.mkdirs()) {
                        throw new IOException("cannot create " + csStore);
                    }
                    String id = String.format(Locale.US, "c%d", collisionSeq++);
                    out = new File(csStore, id);
                    collisionLines.add(id + "\t" + name);
                } else {
                    lowerToName.put(lower, name);
                    out = new File(dest, name);
                }
                String outPath = out.getCanonicalPath();
                if (!outPath.startsWith(destPath + File.separator) && !outPath.equals(destPath)) {
                    unzipProg.tick();
                    continue;
                }
                File parent = out.getParentFile();
                if (parent != null) {
                    //noinspection ResultOfMethodCallIgnored
                    parent.mkdirs();
                }
                try (FileOutputStream fos = new FileOutputStream(out)) {
                    zis.transferTo(fos);
                }
                unzipProg.tick();
            }
        }
        unzipProg.finish();
        if (!collisionLines.isEmpty()) {
            Files.write(new File(csStore, "map.txt").toPath(), collisionLines, StandardCharsets.UTF_8);
            System.out.println("Preserved " + collisionLines.size()
                    + " case-colliding ZIP entries under .csstore/");
        }
        System.out.println("Preserved STORED entries from input: " + storeEntries.size());
        if (soCompressedOut != null && !soCompressedOut.isEmpty()) {
            System.out.println("SO compressed-size map entries=" + soCompressedOut.size());
        }
        return storeEntries;
    }

    /**
     * Media / resource types that need an uncompressed FD (SoundPool, openRawResourceFd).
     * Do NOT list .so/.dex/.zip here — inherit input STORED via storeEntries, else DEFLATE
     * (extractNativeLibs=true allows compressed native libs).
     */
    private static final String[] NO_COMPRESS_EXT = {
            ".jpg", ".jpeg", ".png", ".gif", ".webp", ".heic", ".heif",
            ".wav", ".mp2", ".mp3", ".ogg", ".aac", ".m4a",
            ".mpg", ".mpeg", ".mp4", ".m4v", ".3gp", ".3gpp", ".3g2", ".3gpp2", ".mkv", ".webm",
            ".mid", ".midi", ".smf", ".jet", ".rtttl", ".imy", ".xmf",
            ".arsc",
            ".sfb", ".matc",
    };

    private static boolean shouldStoreUncompressed(String entryName, Set<String> storeEntries) {
        if (entryName == null) {
            return false;
        }
        // resources.arsc must stay STORED for runtime mmap.
        if (entryName.equals("resources.arsc")) {
            return true;
        }
        // Preserve compression method from the input APK (uncompressed .so stay STORE).
        if (storeEntries != null && storeEntries.contains(entryName)) {
            return true;
        }
        String lower = entryName.toLowerCase(Locale.ROOT);
        for (String ext : NO_COMPRESS_EXT) {
            if (lower.endsWith(ext)) {
                return true;
            }
        }
        return false;
    }

    private static void zipDir(File sourceDir, File outZip, Set<String> storeEntries) throws IOException {
        if (outZip.exists()) {
            //noinspection ResultOfMethodCallIgnored
            outZip.delete();
        }
        Map<String, String> csMap = new HashMap<>(); // id -> zip entry name
        File csMapFile = new File(sourceDir, ".csstore/map.txt");
        if (csMapFile.isFile()) {
            for (String line : Files.readAllLines(csMapFile.toPath(), StandardCharsets.UTF_8)) {
                int tab = line.indexOf('\t');
                if (tab > 0) {
                    csMap.put(line.substring(0, tab), line.substring(tab + 1));
                }
            }
        }
        int storedCount = 0;
        Path base = sourceDir.toPath();
        List<Path> files;
        try (var walk = Files.walk(base)) {
            files = walk.filter(Files::isRegularFile)
                    .filter(path -> {
                        String rel = base.relativize(path).toString().replace('\\', '/');
                        return !rel.equals(".csstore/map.txt");
                    })
                    .collect(java.util.stream.Collectors.toList());
        }
        ProgressMilestones repackProg = new ProgressMilestones("repack", files.size());
        try (ZipFile zf = new ZipFile(outZip)) {
            for (Path path : files) {
                String rel = base.relativize(path).toString().replace('\\', '/');
                String entryName;
                if (rel.startsWith(".csstore/")) {
                    String id = rel.substring(".csstore/".length());
                    entryName = csMap.get(id);
                    if (entryName == null) {
                        throw new IOException("missing .csstore map for " + id);
                    }
                } else {
                    entryName = rel;
                }
                ZipParameters p = new ZipParameters();
                // STORE: arsc, input STORED entries, media noCompress; else DEFLATE
                if (shouldStoreUncompressed(entryName, storeEntries)) {
                    p.setCompressionMethod(CompressionMethod.STORE);
                } else {
                    p.setCompressionMethod(CompressionMethod.DEFLATE);
                }
                p.setFileNameInZip(entryName);
                zf.addFile(path.toFile(), p);
                repackProg.tick();
            }
        }
        repackProg.finish();
        // recount after zip (print via second pass on output)
        try (java.util.zip.ZipFile check = new java.util.zip.ZipFile(outZip)) {
            var en = check.entries();
            while (en.hasMoreElements()) {
                ZipEntry e = en.nextElement();
                if (e.getMethod() == ZipEntry.STORED) {
                    storedCount++;
                }
            }
        }
        System.out.println("Repacked APK STORED entries=" + storedCount);
        verifyResourcesArscStored(outZip);
    }

    /**
     * Align APK before signing. Prefer SDK {@code zipalign}; fall back to bundled
     * {@link ZipAlign}. Never silently emit an unaligned APK — Android 11+ rejects
     * targetSdk 30+ packages when {@code resources.arsc} is not STORED + 4-byte aligned.
     */
    private File alignApk(File input, File output) throws Exception {
        if (output.exists() && !output.delete()) {
            throw new IOException("cannot delete existing aligned apk: " + output);
        }

        File sdkZipalign = findSdkZipalign();
        if (sdkZipalign != null) {
            System.out.println("zipalign: using sdk " + sdkZipalign.getAbsolutePath());
            if (trySdkZipalign(sdkZipalign, input, output)) {
                verifyResourcesArscStored(output);
                return output;
            }
            System.out.println("zipalign: sdk failed, falling back to java ZipAlign");
            if (output.exists()) {
                //noinspection ResultOfMethodCallIgnored
                output.delete();
            }
        } else {
            System.out.println("zipalign: sdk not found, using java ZipAlign");
        }

        alignWithJava(input, output);
        verifyResourcesArscStored(output);
        return output;
    }

    private static void alignWithJava(File input, File output) throws Exception {
        try (RandomAccessFile raf = new RandomAccessFile(input, "r");
             FileOutputStream fos = new FileOutputStream(output)) {
            // 4-byte alignment for uncompressed entries (incl. resources.arsc).
            ZipAlign.alignZip(raf, fos, 4);
        }
        if (!output.isFile() || output.length() < 100) {
            throw new IllegalStateException("java ZipAlign produced empty output");
        }
        System.out.println("zipalign: java ZipAlign ok size=" + output.length());
    }

    private static boolean trySdkZipalign(File zipalign, File input, File output) {
        // Prefer -P 16 when build-tools supports it (16 KB page). Older tools
        // (e.g. 34.0.0) reject -P and print "ERROR: unknown flag" — probe first
        // so desktop logs do not look like a failed protect.
        List<String[]> argSets = new ArrayList<>();
        if (sdkZipalignSupportsPageSizeFlag(zipalign)) {
            argSets.add(new String[]{zipalign.getAbsolutePath(), "-P", "16", "-f", "4",
                    input.getAbsolutePath(), output.getAbsolutePath()});
        }
        argSets.add(new String[]{zipalign.getAbsolutePath(), "-f", "-p", "4",
                input.getAbsolutePath(), output.getAbsolutePath()});
        argSets.add(new String[]{zipalign.getAbsolutePath(), "-f", "4",
                input.getAbsolutePath(), output.getAbsolutePath()});
        for (String[] args : argSets) {
            try {
                ProcessBuilder pb = new ProcessBuilder(args);
                pb.redirectErrorStream(true);
                Process p = pb.start();
                String log = new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
                int code = p.waitFor();
                System.out.println("sdk zipalign rc=" + code
                        + " args=" + String.join(" ", Arrays.copyOfRange(args, 1, args.length - 2))
                        + (log.isBlank() ? "" : " " + log.trim()));
                if (code == 0 && output.isFile() && output.length() > 100) {
                    return true;
                }
            } catch (Exception ex) {
                System.out.println("sdk zipalign error: " + ex.getMessage());
            }
            if (output.exists()) {
                //noinspection ResultOfMethodCallIgnored
                output.delete();
            }
        }
        return false;
    }

    /** True if this zipalign binary documents the {@code -P} page-size option. */
    private static boolean sdkZipalignSupportsPageSizeFlag(File zipalign) {
        try {
            ProcessBuilder pb = new ProcessBuilder(zipalign.getAbsolutePath());
            pb.redirectErrorStream(true);
            Process p = pb.start();
            String help = new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
            p.waitFor();
            // Usage lines mention "-P" only on newer build-tools.
            return help.contains("-P") || help.contains("--page-size");
        } catch (Exception ignored) {
            return false;
        }
    }

    private static File findSdkZipalign() {
        for (String sdkDir : sdkRootCandidates()) {
            File buildTools = new File(sdkDir, "build-tools");
            File[] versions = buildTools.listFiles(File::isDirectory);
            if (versions == null || versions.length == 0) {
                continue;
            }
            File latest = versions[0];
            for (File v : versions) {
                if (v.getName().compareTo(latest.getName()) > 0) {
                    latest = v;
                }
            }
            File zipalign = new File(latest, isWindows() ? "zipalign.exe" : "zipalign");
            if (zipalign.isFile()) {
                return zipalign;
            }
        }
        return null;
    }

    private static List<String> sdkRootCandidates() {
        LinkedHashSet<String> roots = new LinkedHashSet<>();
        for (String key : new String[]{"ANDROID_HOME", "ANDROID_SDK_ROOT"}) {
            String v = System.getenv(key);
            if (v != null && !v.isBlank()) {
                roots.add(v.trim());
            }
        }
        // Walk up from CWD for local.properties (desktop engine cwd may be engine/).
        File dir = new File(System.getProperty("user.dir", ".")).getAbsoluteFile();
        for (int i = 0; i < 8 && dir != null; i++, dir = dir.getParentFile()) {
            File lp = new File(dir, "local.properties");
            if (!lp.isFile()) {
                continue;
            }
            try {
                for (String line : Files.readAllLines(lp.toPath(), StandardCharsets.UTF_8)) {
                    String t = line.trim();
                    if (t.startsWith("sdk.dir=")) {
                        String sdk = t.substring("sdk.dir=".length()).trim()
                                .replace("\\\\", "\\")
                                .replace("\\:", ":");
                        if (!sdk.isEmpty()) {
                            roots.add(sdk);
                        }
                    }
                }
            } catch (IOException ignored) {
                // try next parent
            }
        }
        String localApp = System.getenv("LOCALAPPDATA");
        if (localApp != null && !localApp.isBlank()) {
            roots.add(localApp + File.separator + "Android" + File.separator + "Sdk");
        }
        String home = System.getProperty("user.home");
        if (home != null && !home.isBlank()) {
            roots.add(home + File.separator + "AppData" + File.separator + "Local"
                    + File.separator + "Android" + File.separator + "Sdk");
            roots.add(home + File.separator + "Android" + File.separator + "Sdk");
        }
        return new ArrayList<>(roots);
    }

    /** Fail fast if resources.arsc is missing or compressed (Android R+ install -124). */
    private static void verifyResourcesArscStored(File apk) throws IOException {
        try (java.util.zip.ZipFile check = new java.util.zip.ZipFile(apk)) {
            ZipEntry e = check.getEntry("resources.arsc");
            if (e == null) {
                System.out.println("resources.arsc: absent (skip STORED check)");
                return;
            }
            if (e.getMethod() != ZipEntry.STORED) {
                throw new IllegalStateException(
                        "resources.arsc must be STORED (uncompressed) for Android 11+ install; "
                                + "method=" + e.getMethod() + " in " + apk.getAbsolutePath());
            }
            System.out.println("resources.arsc: STORED size=" + e.getSize());
        }
    }

    private static boolean isWindows() {
        return System.getProperty("os.name").toLowerCase(Locale.US).contains("win");
    }

    private static void deleteRecursively(File f) {
        if (f == null || !f.exists()) return;
        File[] children = f.listFiles();
        if (children != null) {
            for (File c : children) deleteRecursively(c);
        }
        //noinspection ResultOfMethodCallIgnored
        f.delete();
    }

    /** Compute HMAC-SHA256 hex string for config.json integrity protection.
     *  Must match the C++ implementation in crypto/sha256.h exactly. */
    private static String computeHmacHex(String payload, byte[] key) throws Exception {
        Mac mac = Mac.getInstance(HMAC_KEY_SPEC);
        mac.init(new SecretKeySpec(key, HMAC_KEY_SPEC));
        byte[] raw = mac.doFinal(payload.getBytes(StandardCharsets.UTF_8));
        StringBuilder sb = new StringBuilder(64);
        for (byte b : raw) {
            sb.append(String.format("%02x", b & 0xff));
        }
        return sb.toString();
    }

    private static String escapeJson(String s) {
        if (s == null) {
            return "";
        }
        StringBuilder out = new StringBuilder(s.length() + 8);
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '\\':
                    out.append("\\\\");
                    break;
                case '"':
                    out.append("\\\"");
                    break;
                case '\b':
                    out.append("\\b");
                    break;
                case '\f':
                    out.append("\\f");
                    break;
                case '\n':
                    out.append("\\n");
                    break;
                case '\r':
                    out.append("\\r");
                    break;
                case '\t':
                    out.append("\\t");
                    break;
                default:
                    if (c < 0x20) {
                        out.append(String.format(Locale.US, "\\u%04x", (int) c));
                    } else {
                        out.append(c);
                    }
                    break;
            }
        }
        return out.toString();
    }

    static class InsnRecord {
        int methodIndex;
        int plainInsnsSize;
        int flags; // bit0 = PVM1, bit1 = TRUE_VMP(PVM2)
        byte[] insns; // AES-GCM package
        String definingClass;
        String methodName;
        String[] paramTypes;
        String returnType;
        /** Original code_item header; required after DexPool outs_size recompute. */
        int registersSize;
        int insSize;
        int outsSize = -1;
    }
}

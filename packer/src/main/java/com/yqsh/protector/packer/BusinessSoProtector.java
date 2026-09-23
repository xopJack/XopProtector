package com.yqsh.protector.packer;

import com.yqsh.protector.packer.elf.ReadElf;
import com.yqsh.protector.packer.util.CryptoUtils;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.RandomAccessFile;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * Business-SO hardening: RC4-encrypt {@code .text} in place and emit
 * an AES-GCM wrapped key table ({@code sokeys.bin}) for runtime dlopen decrypt.
 * <p>
 * Selection is <strong>APK-agnostic</strong> (no customer package names):
 * shell libs, SOs with text relocs, and (in {@link Mode#SAFE}) industry-known
 * runtimes / system-shadow names are skipped. Same rules for every APK.
 * <p>
 * Commercial default ({@link Mode#SAFE}) also applies a size budget so large
 * engines (e.g. multi-10MB 3D libs) are skipped instead of inflating the APK.
 */
public final class BusinessSoProtector {

    /**
     * {@link #SAFE} — commercial default: industry skips + size budget.
     * {@link #AGGRESSIVE} — shell + text-reloc + <b>Class S</b> only; soft budget.
     * {@link #MAX} — same policy skips as SAFE industry set for stability, but
     *               <em>no</em> size budget (encrypt every eligible SO).
     */
    public enum Mode {
        SAFE,
        AGGRESSIVE,
        MAX
    }

    /** Always skip — shell / hook runtime shipped with the protector. */
    private static final String[] SHELL_SKIP = {
            "libprotector.so", "libshadowhook.so", "libshadowhook_nothing.so",
            "libc++_shared.so", "libdobby.so"
    };

    /**
     * Class S — Bionic/NDK / graphics stubs that must never be encrypted or live
     * under {@code so_plain} (hijacks linker search; breaks Conscrypt / GLES).
     * Applied in <b>all</b> modes including {@link Mode#AGGRESSIVE}.
     */
    private static final String[] SYSTEM_SONAME_EXACT = {
            "libc.so", "libm.so", "libdl.so", "liblog.so", "libz.so",
            "libc++.so", "libstdc++.so",
            "libandroid.so", "libjnigraphics.so",
            "libEGL.so", "libGLESv1_CM.so", "libGLESv2.so", "libGLESv3.so",
            "libOpenSLES.so", "libOpenMAXAL.so",
            "libvulkan.so", "libcamera2ndk.so",
    };

    /** Class S prefixes (after lowercasing). */
    private static final String[] SYSTEM_SONAME_PREFIX = {
            "libcrypto",
            "libssl",
            "libglesv", // libGLESv* after lowercasing
    };

    /**
     * UniApp / DCloud Weex + Fresco image pipeline — skip in <b>all</b> modes.
     * {@code .text} RC4 breaks Weex multi-process IPC ({@code spinWaitPeer timeout}).
     */
    private static final String[] UNIAPP_RUNTIME_EXACT_SKIP = {
            "libweexjsb.so",
            "libweexjst.so",
            "libweexjss.so",
            "libweexcore.so",
            "libimagepipeline.so",
            "libdcblur.so",
    };

    /**
     * Exact basenames for industry / early-load runtimes (SAFE/MAX only).
     * Encrypting these commonly yields SIGILL if decrypt is late.
     */
    private static final String[] INDUSTRY_EXACT_SKIP = {
            // Flutter AOT module — fixed industry name, not an app package id
            "libapp.so",
            "libflutter.so",
            "libflutter_linux_glfw.so",
    };

    /**
     * Basename prefixes (after lowercasing). Industry SDKs / engines — never
     * customer applicationId. Matched as {@code name.startsWith(prefix)}.
     * SAFE/MAX only (AGGRESSIVE may still encrypt these).
     */
    private static final String[] INDUSTRY_PREFIX_SKIP = {
            "libflutter",
            "libhermes",
            "libjsc",
            "libjscexecutor",
            "libreactnative",
            "libreact_",
            "libfbjni",
            "libfolly",
            "libglog",
            "libv8",
            "libsophix",
            "libbugly",
            "libmmkv",
            "libxcrash",
            "libbreakpad",
            "libcrashlytics",
            "libopencv",
            "libtbb",
            "libalipay",
            "libwechat",
            "libtencent",
            "libbaidu",
            "libamap",
            // Carrier / push / early ContentProvider SDKs (basename prefixes only)
            "libcmcc",
            "libunicom",
            "libct_",
            "libchinamobile",
            "libgetui",
            "libigexin",
            "libjpush",
            "libjcore",
            "libjiguang",
            "libmtgsig",
            "libsgmain",
            "libsgsecurity",
            "libmapbox",
            "libsqlite",
            "librealm",
            "libsqlcipher",
            "librive",
            "libskia",
            // PAG (libpag / liblibpag) — GLES megacore; ABI-asymmetric path_sensitive
            // previously encrypted only v7a while arm64 stayed plaintext → RC4 corrupt.
            "libpag",
            "liblibpag",
            "libicu",
            "libharfbuzz",
            "libfreetype",
            "libpng",
            "libjpeg",
            "libwebp",
            "libgif",
            "libffavc",
            "libavcodec",
            "libavformat",
            "libavutil",
            "libswscale",
            "libswresample",
            "libx264",
            "libx265",
            "libomp",
            "libopenblas",
            "libc++_shared", // already in SHELL; keep for aggressiveness of prefix checks
    };

    private static final int SHT_RELA = 4;
    private static final int SHT_REL = 9;

    /** Heuristic: encrypted .text worsens DEFLATE; ~0.35 of file size as APK delta. */
    private static final double SIMPLE_DELTA_RATIO = 0.35;
    /** When original compressed size is known: Δ ≈ compressed × (text/file) × k. */
    private static final double COMPRESSED_DELTA_K = 1.0;

    public static final class Entry {
        public final String name;
        public final byte[] key;

        public Entry(String name, byte[] key) {
            this.name = name;
            this.key = key;
        }
    }

    /** Tunables for SO selection (CLI / PackerMain). */
    public static final class Options {
        public Mode mode = Mode.SAFE;
        /** Soft/hard SO-protect extra APK size budget in MB. Ignored by {@link Mode#MAX}. */
        public double budgetMb = 12.0;
        /** Skip any single unpacked SO larger than this (MB). Ignored by {@link Mode#MAX}. */
        public double maxFileMb = 8.0;
        /**
         * {@code "all"} or a single ABI dir name (e.g. {@code arm64-v8a}).
         * When set to one ABI, only that directory is scanned for candidates;
         * selected basenames are still encrypted on <em>all</em> ABIs present
         * (sokeys is basename-keyed — partial ABI encrypt would corrupt the other).
         */
        public String abiFilter = "all";
        /**
         * Optional map from ZIP entry path {@code lib/&lt;abi&gt;/&lt;name&gt;} to
         * compressed size in the input APK (improves Δ estimate).
         */
        public Map<String, Long> compressedSizes;
        /** Entry paths that were STORED (uncompressed) in the input APK. */
        public java.util.Set<String> storedEntries;
        /**
         * Exact basenames to never encrypt (e.g. {@code libd3.so}).
         * Matched after normalizing to {@code lib*.so}. Reason in report: {@code exclude}.
         */
        public java.util.Set<String> excludeBasenames = new java.util.LinkedHashSet<>();
        /**
         * If non-empty, ONLY these basenames are candidates for encryption;
         * everything else is skipped with report reason {@code not_included}.
         * Mutually exclusive with {@code excludeBasenames} — one filter, not both.
         */
        public java.util.Set<String> includeBasenames = new java.util.LinkedHashSet<>();
    }

    /** Normalize user input to {@code libfoo.so} (accepts {@code foo}, {@code libfoo}, {@code libfoo.so}). */
    public static String normalizeSoBasename(String raw) {
        if (raw == null) return "";
        String n = raw.trim();
        if (n.isEmpty()) return "";
        int slash = Math.max(n.lastIndexOf('/'), n.lastIndexOf('\\'));
        if (slash >= 0) n = n.substring(slash + 1);
        if (!n.endsWith(".so")) n = n + ".so";
        if (!n.startsWith("lib")) n = "lib" + n;
        return n;
    }

    private static boolean isExcludedBasename(String name, java.util.Set<String> excludes) {
        if (excludes == null || excludes.isEmpty() || name == null) return false;
        String n = normalizeSoBasename(name);
        for (String e : excludes) {
            if (n.equals(normalizeSoBasename(e))) return true;
        }
        return false;
    }

    /** {@code true} when {@code includes} is empty (no filter) or {@code name} is in it. */
    private static boolean isIncludedBasename(String name, java.util.Set<String> includes) {
        if (includes == null || includes.isEmpty()) return true;
        if (name == null) return false;
        String n = normalizeSoBasename(name);
        for (String e : includes) {
            if (n.equals(normalizeSoBasename(e))) return true;
        }
        return false;
    }

    /** Result of {@link #protectAll(File, Options)}. */
    public static final class ProtectResult {
        public final List<Entry> entries;
        public final List<SoDecision> encrypted = new ArrayList<>();
        public final List<SoDecision> skippedBudget = new ArrayList<>();
        public final List<SoDecision> skippedPolicy = new ArrayList<>();
        public final List<SoDecision> skippedReloc = new ArrayList<>();
        public long estimatedDeltaBytes;
        public boolean budgetTruncated;

        public ProtectResult(List<Entry> entries) {
            this.entries = entries != null ? entries : new ArrayList<>();
        }
    }

    /** One SO file decision for size_report. */
    public static final class SoDecision {
        public final String abi;
        public final String name;
        public final long fileBytes;
        public final long textBytes;
        public final long estimatedDeltaBytes;
        public final String reason;

        public SoDecision(String abi, String name, long fileBytes, long textBytes,
                          long estimatedDeltaBytes, String reason) {
            this.abi = abi;
            this.name = name;
            this.fileBytes = fileBytes;
            this.textBytes = textBytes;
            this.estimatedDeltaBytes = estimatedDeltaBytes;
            this.reason = reason;
        }

        public String path() {
            return abi + "/" + name;
        }
    }

    private static final class Candidate {
        final File so;
        final String abi;
        final String name;
        final long fileBytes;
        final long textBytes;
        final long estimatedDeltaBytes;

        Candidate(File so, String abi, String name, long fileBytes, long textBytes,
                  long estimatedDeltaBytes) {
            this.so = so;
            this.abi = abi;
            this.name = name;
            this.fileBytes = fileBytes;
            this.textBytes = textBytes;
            this.estimatedDeltaBytes = estimatedDeltaBytes;
        }

        String path() {
            return abi + "/" + name;
        }
    }

    private static final class BasenameGroup {
        final String name;
        final List<Candidate> files = new ArrayList<>();
        long totalDelta;
        long maxFileBytes;

        BasenameGroup(String name) {
            this.name = name;
        }
    }

    private BusinessSoProtector() {
    }

    public static Mode parseMode(String raw) {
        if (raw == null || raw.isEmpty()) {
            return Mode.SAFE;
        }
        switch (raw.trim().toLowerCase(Locale.ROOT)) {
            case "safe":
            case "default":
            case "commercial":
                return Mode.SAFE;
            case "aggressive":
            case "wide":
                return Mode.AGGRESSIVE;
            case "max":
            case "full":
            case "all":
                return Mode.MAX;
            case "off":
            case "none":
            case "disable":
            case "disabled":
                throw new IllegalArgumentException(
                        "use --no-protect-so for off (not --protect-so-mode off)");
            default:
                throw new IllegalArgumentException(
                        "unknown --protect-so-mode '" + raw + "' (safe|aggressive|max)");
        }
    }

    /** Shell libs only (always). */
    static boolean isShellLib(String name) {
        if (name == null) return true;
        for (String s : SHELL_SKIP) {
            if (s.equals(name)) return true;
        }
        return false;
    }

    /**
     * Class S: system / reserved soname — never encrypt (all modes).
     * See docs/so-load-contract.md.
     */
    static boolean isSystemSonameSkip(String name) {
        if (name == null || name.isEmpty()) return true;
        String lower = name.toLowerCase(Locale.ROOT);
        for (String s : SYSTEM_SONAME_EXACT) {
            if (s.equals(lower)) return true;
        }
        for (String p : SYSTEM_SONAME_PREFIX) {
            if (lower.startsWith(p)) return true;
        }
        return false;
    }

    /**
     * Industry / early-load SDKs — SAFE and MAX only.
     * No applicationId or customer-specific basenames.
     */
    static boolean isUniAppRuntimeSkip(String name) {
        if (name == null || name.isEmpty()) return false;
        String lower = name.toLowerCase(Locale.ROOT);
        for (String s : UNIAPP_RUNTIME_EXACT_SKIP) {
            if (s.equals(lower)) return true;
        }
        return false;
    }

    static boolean isIndustrySkip(String name) {
        if (name == null || name.isEmpty()) return true;
        if (isUniAppRuntimeSkip(name)) return true;
        String lower = name.toLowerCase(Locale.ROOT);
        for (String s : INDUSTRY_EXACT_SKIP) {
            if (s.equals(lower)) return true;
        }
        for (String p : INDUSTRY_PREFIX_SKIP) {
            if (lower.startsWith(p.toLowerCase(Locale.ROOT))) return true;
        }
        return false;
    }

    /**
     * @deprecated use {@link #isSystemSonameSkip} / {@link #isIndustrySkip}
     */
    static boolean isSafeModeIndustrySkip(String name) {
        return isSystemSonameSkip(name) || isIndustrySkip(name);
    }

    private static String skipReason(String name, Mode mode) {
        if (isShellLib(name)) return "shell";
        // Class S: all modes (AGGRESSIVE included) — Conscrypt / GLES collision.
        if (isSystemSonameSkip(name)) return "system_soname";
        // UniApp / DCloud Weex: all modes — IPC breaks after .text RC4.
        if (isUniAppRuntimeSkip(name)) return "uniapp/runtime";
        // Industry SDKs: SAFE/MAX only.
        if (mode != Mode.AGGRESSIVE && isIndustrySkip(name)) return "industry/runtime";
        return null;
    }

    /**
     * Path-sensitive / dual-GL risk: large .text (or huge file) plus GLES stubs
     * or known engine markers. SAFE/MAX skip encrypt ({@code path_sensitive});
     * AGGRESSIVE may encrypt and rely on runtime L1/L2 extract-path load. See
     * docs/so-load-contract.md.
     */
    static boolean isPathSensitive(File soFile) {
        if (soFile == null || !soFile.isFile()) return false;
        long text = readTextSize(soFile);
        long fileSz = soFile.length();
        // libzhd3d-class OSG helpers often sit ~4–8MiB .text; mega cores >>16MiB.
        if (text < PATH_SENSITIVE_TEXT_MIN && fileSz < PATH_SENSITIVE_FILE_MIN) {
            return false;
        }
        return sectionAsciiHits(soFile, PATH_SENSITIVE_MARKERS);
    }

    private static final long PATH_SENSITIVE_TEXT_MIN = 4L * 1024L * 1024L;
    private static final long PATH_SENSITIVE_FILE_MIN = 16L * 1024L * 1024L;

    private static final String[] PATH_SENSITIVE_MARKERS = {
            "libGLESv3.so", "libGLESv2.so", "libGLESv1_CM.so", "libEGL.so",
            "osgDB", "osg::", "libosg", "ReaderWriter",
            "UnityEngine", "libil2cpp", "UE4Game", "libUE4",
            "cocos2d", "Cocos2d",
    };

    /** Scan .dynstr and a capped .rodata window for ASCII needles. */
    static boolean sectionAsciiHits(File soFile, String[] needles) {
        if (needles == null || needles.length == 0) return false;
        try (ReadElf elf = new ReadElf(soFile);
             RandomAccessFile raf = new RandomAccessFile(soFile, "r")) {
            for (ReadElf.SectionHeader sh : elf.getSectionHeaders()) {
                String sn = sh.getName();
                if (sn == null) continue;
                boolean dynstr = ".dynstr".equals(sn);
                boolean rodata = ".rodata".equals(sn);
                if (!dynstr && !rodata) continue;
                long size = sh.getSize();
                long off = sh.getOffset();
                if (size <= 0 || off < 0) continue;
                long cap = dynstr ? size : Math.min(size, 512L * 1024L);
                if (cap > 8L * 1024L * 1024L) cap = 8L * 1024L * 1024L;
                byte[] buf = new byte[(int) cap];
                raf.seek(off);
                int n = raf.read(buf);
                if (n <= 0) continue;
                for (String needle : needles) {
                    if (needle == null || needle.isEmpty()) continue;
                    byte[] nb = needle.getBytes(java.nio.charset.StandardCharsets.US_ASCII);
                    if (indexOf(buf, n, nb) >= 0) return true;
                }
            }
        } catch (Exception ignored) {
            return false;
        }
        return false;
    }

    private static int indexOf(byte[] hay, int hayLen, byte[] needle) {
        if (needle.length == 0 || hayLen < needle.length) return -1;
        outer:
        for (int i = 0; i <= hayLen - needle.length; i++) {
            for (int j = 0; j < needle.length; j++) {
                if (hay[i + j] != needle[j]) continue outer;
            }
            return i;
        }
        return -1;
    }

    private static boolean usesBudget(Mode mode) {
        return mode == Mode.SAFE || mode == Mode.AGGRESSIVE;
    }

    /**
     * Encrypt .text of lib/&lt;abi&gt;/*.so under default SAFE options.
     */
    public static List<Entry> protectAll(File unpackLibRoot) throws Exception {
        return protectAll(unpackLibRoot, Mode.SAFE);
    }

    public static List<Entry> protectAll(File unpackLibRoot, Mode mode) throws Exception {
        Options opts = new Options();
        opts.mode = mode != null ? mode : Mode.SAFE;
        return protectAll(unpackLibRoot, opts).entries;
    }

    /**
     * Two-phase SO protect: policy/reloc filter → size estimate → budget truncate → encrypt.
     */
    public static ProtectResult protectAll(File unpackLibRoot, Options options) throws Exception {
        Options opts = options != null ? options : new Options();
        Mode m = opts.mode != null ? opts.mode : Mode.SAFE;
        ProtectResult result = new ProtectResult(new ArrayList<>());
        if (unpackLibRoot == null || !unpackLibRoot.isDirectory()) return result;

        boolean hasInclude = opts.includeBasenames != null && !opts.includeBasenames.isEmpty();
        boolean hasExclude = opts.excludeBasenames != null && !opts.excludeBasenames.isEmpty();
        if (hasInclude && hasExclude) {
            throw new IllegalArgumentException(
                    "--protect-so-include and --protect-so-exclude are mutually exclusive: "
                            + "pass one filter, not both");
        }

        File[] abis = unpackLibRoot.listFiles(File::isDirectory);
        if (abis == null) return result;

        String abiFilter = opts.abiFilter == null || opts.abiFilter.isEmpty()
                ? "all" : opts.abiFilter.trim();
        boolean filterAbi = !"all".equalsIgnoreCase(abiFilter);

        long budgetBytes = usesBudget(m)
                ? Math.max(0L, Math.round(opts.budgetMb * 1024L * 1024L)) : Long.MAX_VALUE;
        long maxFileBytes = usesBudget(m)
                ? Math.max(0L, Math.round(opts.maxFileMb * 1024L * 1024L)) : Long.MAX_VALUE;

        // Phase 1: collect candidates (and all-ABI siblings for selected basenames later).
        Map<String, List<Candidate>> allByBasename = new LinkedHashMap<>();
        List<Candidate> primaryCandidates = new ArrayList<>();
        // Per-file skips that must block the whole basename: sokeys is basename-keyed;
        // encrypting only some ABIs RC4-corrupts plaintext siblings (SIGILL on load).
        Map<String, String> basenameAbiBlock = new LinkedHashMap<>();

        for (File abi : abis) {
            String abiName = abi.getName();
            File[] sos = abi.listFiles((d, n) -> n.endsWith(".so"));
            if (sos == null) continue;
            for (File so : sos) {
                String name = so.getName();
                if (isExcludedBasename(name, opts.excludeBasenames)) {
                    result.skippedPolicy.add(new SoDecision(
                            abiName, name, so.length(), 0, 0, "exclude"));
                    System.out.println("SKIP business SO (exclude): "
                            + abiName + "/" + name);
                    continue;
                }
                if (!isIncludedBasename(name, opts.includeBasenames)) {
                    result.skippedPolicy.add(new SoDecision(
                            abiName, name, so.length(), 0, 0, "not_included"));
                    System.out.println("SKIP business SO (not_included): "
                            + abiName + "/" + name);
                    continue;
                }
                String reason = skipReason(name, m);
                if (reason != null) {
                    result.skippedPolicy.add(new SoDecision(abiName, name, so.length(), 0, 0, reason));
                    System.out.println("SKIP business SO (" + reason + "): "
                            + abiName + "/" + name);
                    continue;
                }
                // SAFE/MAX: skip path-sensitive megacores (runtime L1/L2 may still
                // encrypt them under AGGRESSIVE). See docs/so-load-contract.md.
                if (m != Mode.AGGRESSIVE && isPathSensitive(so)) {
                    basenameAbiBlock.putIfAbsent(name, "path_sensitive");
                    result.skippedPolicy.add(new SoDecision(
                            abiName, name, so.length(), 0, 0, "path_sensitive"));
                    System.out.println("SKIP business SO (path_sensitive): "
                            + abiName + "/" + name);
                    continue;
                }
                if (hasUnsafeTextRelocs(so)) {
                    basenameAbiBlock.putIfAbsent(name, "relocs patch .text");
                    result.skippedReloc.add(new SoDecision(
                            abiName, name, so.length(), 0, 0, "relocs patch .text"));
                    System.out.println("SKIP business SO (relocs patch .text): "
                            + abiName + "/" + name);
                    continue;
                }
                long textSize = readTextSize(so);
                if (textSize <= 0) {
                    basenameAbiBlock.putIfAbsent(name, "no .text");
                    result.skippedPolicy.add(new SoDecision(
                            abiName, name, so.length(), 0, 0, "no .text"));
                    System.out.println("SKIP business SO (no .text): "
                            + abiName + "/" + name);
                    continue;
                }
                long delta = estimateDelta(abiName, name, so.length(), textSize,
                        opts.compressedSizes, opts.storedEntries);
                Candidate c = new Candidate(so, abiName, name, so.length(), textSize, delta);
                allByBasename.computeIfAbsent(name, k -> new ArrayList<>()).add(c);

                // abi filter: basename must appear under the selected ABI to be a
                // candidate; once selected, all ABI copies are encrypted (sokeys
                // is basename-keyed — encrypting only one ABI would corrupt the other).
                if (filterAbi && !abiName.equals(abiFilter)) {
                    continue;
                }
                primaryCandidates.add(c);
            }
        }

        // Drop candidates whose basename was blocked on any ABI (keep encrypt all-or-none).
        if (!basenameAbiBlock.isEmpty()) {
            for (Map.Entry<String, String> e : basenameAbiBlock.entrySet()) {
                String name = e.getKey();
                String blockReason = e.getValue();
                List<Candidate> siblings = allByBasename.remove(name);
                primaryCandidates.removeIf(c -> c.name.equals(name));
                if (siblings == null || siblings.isEmpty()) continue;
                String siblingReason = blockReason + "_abi";
                for (Candidate c : siblings) {
                    if ("relocs patch .text".equals(blockReason)) {
                        result.skippedReloc.add(new SoDecision(
                                c.abi, c.name, c.fileBytes, c.textBytes, 0, siblingReason));
                    } else {
                        result.skippedPolicy.add(new SoDecision(
                                c.abi, c.name, c.fileBytes, c.textBytes, 0, siblingReason));
                    }
                    System.out.println("SKIP business SO (" + siblingReason + "): "
                            + c.path() + " (basename blocked on another ABI)");
                }
            }
        }

        // Group by basename; budget is charged for ALL ABIs that will be encrypted
        // (same RC4 key across ABIs — partial encrypt would corrupt the other ABI).
        Map<String, BasenameGroup> groups = new LinkedHashMap<>();
        for (Candidate c : primaryCandidates) {
            BasenameGroup g = groups.computeIfAbsent(c.name, BasenameGroup::new);
            // Prefer full multi-ABI set for delta accounting.
            List<Candidate> siblings = allByBasename.get(c.name);
            if (siblings != null) {
                for (Candidate s : siblings) {
                    boolean exists = false;
                    for (Candidate e : g.files) {
                        if (e.abi.equals(s.abi)) {
                            exists = true;
                            break;
                        }
                    }
                    if (!exists) {
                        g.files.add(s);
                        g.totalDelta += s.estimatedDeltaBytes;
                        if (s.fileBytes > g.maxFileBytes) g.maxFileBytes = s.fileBytes;
                    }
                }
            }
        }

        List<BasenameGroup> ordered = new ArrayList<>(groups.values());
        ordered.sort(Comparator
                .comparingLong((BasenameGroup g) -> g.totalDelta)
                .thenComparingLong(g -> g.maxFileBytes)
                .thenComparing(g -> g.name));

        long usedBudget = 0;
        List<BasenameGroup> selected = new ArrayList<>();
        for (BasenameGroup g : ordered) {
            if (usesBudget(m) && g.maxFileBytes > maxFileBytes) {
                for (Candidate c : g.files) {
                    SoDecision d = new SoDecision(c.abi, c.name, c.fileBytes, c.textBytes,
                            c.estimatedDeltaBytes,
                            String.format(Locale.US, "size-budget max-file>%.1fMB", opts.maxFileMb));
                    result.skippedBudget.add(d);
                    System.out.println("SKIP business SO (size-budget): " + c.path()
                            + " file_mb=" + String.format(Locale.US, "%.2f", c.fileBytes / (1024.0 * 1024.0))
                            + " est_delta_mb=" + String.format(Locale.US, "%.2f",
                            c.estimatedDeltaBytes / (1024.0 * 1024.0)));
                }
                result.budgetTruncated = true;
                continue;
            }
            if (usesBudget(m) && usedBudget + g.totalDelta > budgetBytes && !selected.isEmpty()) {
                for (Candidate c : g.files) {
                    SoDecision d = new SoDecision(c.abi, c.name, c.fileBytes, c.textBytes,
                            c.estimatedDeltaBytes,
                            String.format(Locale.US, "size-budget total>%.1fMB", opts.budgetMb));
                    result.skippedBudget.add(d);
                    System.out.println("SKIP business SO (size-budget): " + c.path()
                            + " est_delta_mb=" + String.format(Locale.US, "%.2f",
                            c.estimatedDeltaBytes / (1024.0 * 1024.0)));
                }
                result.budgetTruncated = true;
                continue;
            }
            // First selection may exceed budget if a single small group still fits poorly —
            // allow one group only when selected is empty and group alone exceeds budget?
            // Commercial: still skip if alone exceeds budget (avoid encrypting one 50MB lib).
            if (usesBudget(m) && g.totalDelta > budgetBytes) {
                for (Candidate c : g.files) {
                    SoDecision d = new SoDecision(c.abi, c.name, c.fileBytes, c.textBytes,
                            c.estimatedDeltaBytes,
                            String.format(Locale.US, "size-budget alone>%.1fMB", opts.budgetMb));
                    result.skippedBudget.add(d);
                    System.out.println("SKIP business SO (size-budget): " + c.path()
                            + " est_delta_mb=" + String.format(Locale.US, "%.2f",
                            c.estimatedDeltaBytes / (1024.0 * 1024.0)));
                }
                result.budgetTruncated = true;
                continue;
            }
            selected.add(g);
            usedBudget += g.totalDelta;
        }

        if (result.budgetTruncated) {
            System.out.println("WARN: SO protect size-budget truncated"
                    + " mode=" + m.name().toLowerCase(Locale.ROOT)
                    + " budget_mb=" + opts.budgetMb
                    + " max_file_mb=" + opts.maxFileMb
                    + " selected_basenames=" + selected.size()
                    + " skipped_budget=" + result.skippedBudget.size());
        }

        // Phase 2: encrypt selected.
        Map<String, byte[]> keys = new LinkedHashMap<>();
        List<Entry> entries = new ArrayList<>();
        SecureRandom rng = new SecureRandom();
        for (BasenameGroup g : selected) {
            byte[] key = keys.get(g.name);
            if (key == null) {
                key = new byte[16];
                rng.nextBytes(key);
                keys.put(g.name, key);
                entries.add(new Entry(g.name, key));
            }
            for (Candidate c : g.files) {
                encryptText(c.so, key);
                SoDecision d = new SoDecision(c.abi, c.name, c.fileBytes, c.textBytes,
                        c.estimatedDeltaBytes, "encrypted");
                result.encrypted.add(d);
                result.estimatedDeltaBytes += c.estimatedDeltaBytes;
                System.out.println("Protected business SO .text: " + c.path()
                        + " est_delta_mb=" + String.format(Locale.US, "%.2f",
                        c.estimatedDeltaBytes / (1024.0 * 1024.0)));
            }
        }

        // Rebuild entries list into result (mutable list we created).
        result.entries.clear();
        result.entries.addAll(entries);

        System.out.println("SO protect mode=" + m.name().toLowerCase(Locale.ROOT)
                + " encrypted_basenames=" + entries.size()
                + " encrypted_files=" + result.encrypted.size()
                + " skipped_policy=" + result.skippedPolicy.size()
                + " skipped_reloc=" + result.skippedReloc.size()
                + " skipped_budget=" + result.skippedBudget.size()
                + " abi_filter=" + abiFilter
                + " est_so_delta_mb=" + String.format(Locale.US, "%.2f",
                result.estimatedDeltaBytes / (1024.0 * 1024.0)));
        return result;
    }

    /**
     * Estimate APK size increase from encrypting this SO's .text.
     * STORED entries: Δ≈0 (already uncompressed). Else prefer compressed×(text/file)×k,
     * fallback fileSize×0.35.
     */
    static long estimateDelta(String abi, String name, long fileBytes, long textBytes,
                              Map<String, Long> compressedSizes,
                              java.util.Set<String> storedEntries) {
        String entryPath = "lib/" + abi + "/" + name;
        if (storedEntries != null && storedEntries.contains(entryPath)) {
            return 0L;
        }
        if (fileBytes <= 0 || textBytes <= 0) {
            return Math.round(Math.max(0, fileBytes) * SIMPLE_DELTA_RATIO);
        }
        double textFrac = Math.min(1.0, (double) textBytes / (double) fileBytes);
        if (compressedSizes != null && compressedSizes.containsKey(entryPath)) {
            long compressed = compressedSizes.get(entryPath);
            if (compressed > 0 && compressed < fileBytes) {
                return Math.max(0L, Math.round(compressed * textFrac * COMPRESSED_DELTA_K));
            }
            // compressed == file → effectively stored/uncompressible already
            if (compressed >= fileBytes) {
                return 0L;
            }
        }
        return Math.max(0L, Math.round(fileBytes * SIMPLE_DELTA_RATIO));
    }

    static long readTextSize(File soFile) {
        try (ReadElf elf = new ReadElf(soFile)) {
            for (ReadElf.SectionHeader sh : elf.getSectionHeaders()) {
                if (".text".equals(sh.getName())) {
                    return sh.getSize();
                }
            }
        } catch (Exception ignored) {
            // fall through
        }
        return 0L;
    }

    /**
     * True if any SHT_REL / SHT_RELA entry's r_offset falls inside .text VMA.
     * Those SOs must not be .text-encrypted in-place.
     */
    static boolean hasUnsafeTextRelocs(File soFile) throws Exception {
        try {
            return hasUnsafeTextRelocs0(soFile);
        } catch (Exception ex) {
            System.out.println("SKIP business SO (reloc scan failed): " + soFile.getName()
                    + " (" + ex.getClass().getSimpleName() + ")");
            return true;
        }
    }

    private static boolean hasUnsafeTextRelocs0(File soFile) throws Exception {
        try (RandomAccessFile raf = new RandomAccessFile(soFile, "r")) {
            byte[] ident = new byte[16];
            raf.readFully(ident);
            if (ident[0] != 0x7f || ident[1] != 'E' || ident[2] != 'L' || ident[3] != 'F') {
                return true; // treat unknown as unsafe
            }
            boolean is64 = ident[4] == 2;
            boolean le = ident[5] == 1;
            ByteOrder order = le ? ByteOrder.LITTLE_ENDIAN : ByteOrder.BIG_ENDIAN;
            raf.seek(0);
            byte[] ehdr = new byte[is64 ? 64 : 52];
            raf.readFully(ehdr);
            ByteBuffer eb = ByteBuffer.wrap(ehdr).order(order);
            long shOff;
            int shEntSize;
            int shNum;
            int shStrNdx;
            if (is64) {
                eb.position(40);
                shOff = eb.getLong();
                eb.position(58);
                shEntSize = eb.getShort() & 0xffff;
                shNum = eb.getShort() & 0xffff;
                shStrNdx = eb.getShort() & 0xffff;
            } else {
                eb.position(32);
                shOff = eb.getInt() & 0xffffffffL;
                eb.position(46);
                shEntSize = eb.getShort() & 0xffff;
                shNum = eb.getShort() & 0xffff;
                shStrNdx = eb.getShort() & 0xffff;
            }
            if (shOff == 0 || shNum == 0 || shEntSize == 0) return true;

            byte[] shdrs = new byte[shNum * shEntSize];
            raf.seek(shOff);
            raf.readFully(shdrs);

            long textAddr = -1;
            long textSize = 0;
            {
                int o = shStrNdx * shEntSize;
                if (o < 0 || o + shEntSize > shdrs.length) return true;
                ByteBuffer sh = ByteBuffer.wrap(shdrs).order(order);
                sh.position(o + (is64 ? 24 : 16));
                long shstrOff = is64 ? sh.getLong() : (sh.getInt() & 0xffffffffL);
                long shstrSize = is64 ? sh.getLong() : (sh.getInt() & 0xffffffffL);
                if (shstrSize <= 0 || shstrSize > 1024 * 1024) return true;
                byte[] shstr = new byte[(int) shstrSize];
                raf.seek(shstrOff);
                raf.readFully(shstr);

                List<int[]> relocSections = new ArrayList<>();
                for (int i = 0; i < shNum; i++) {
                    int base = i * shEntSize;
                    if (base + shEntSize > shdrs.length) return true;
                    ByteBuffer sec = ByteBuffer.wrap(shdrs).order(order);
                    sec.position(base);
                    int nameOff = sec.getInt();
                    int type = sec.getInt();
                    long addr;
                    long offset;
                    long size;
                    long entsize;
                    if (is64) {
                        sec.getLong(); // flags
                        addr = sec.getLong();
                        offset = sec.getLong();
                        size = sec.getLong();
                        sec.getInt(); // link
                        sec.getInt(); // info
                        sec.getLong(); // addralign
                        entsize = sec.getLong();
                    } else {
                        sec.getInt(); // flags
                        addr = sec.getInt() & 0xffffffffL;
                        offset = sec.getInt() & 0xffffffffL;
                        size = sec.getInt() & 0xffffffffL;
                        sec.getInt(); // link
                        sec.getInt(); // info
                        sec.getInt(); // addralign
                        entsize = sec.getInt() & 0xffffffffL;
                    }
                    String name = cString(shstr, nameOff);
                    if (".text".equals(name)) {
                        textAddr = addr;
                        textSize = size;
                    }
                    if (type == SHT_RELA || type == SHT_REL) {
                        if (entsize > 0 && size > 0 && offset >= 0 && size <= Integer.MAX_VALUE) {
                            relocSections.add(new int[]{
                                    (int) offset, (int) size, (int) entsize
                            });
                        }
                    }
                }
                if (textAddr < 0 || textSize <= 0) return true;
                long textEnd = textAddr + textSize;

                for (int[] rs : relocSections) {
                    int fileOff = rs[0];
                    int size = rs[1];
                    int entsize = rs[2];
                    if (fileOff < 0 || size <= 0 || entsize <= 0) continue;
                    if ((long) fileOff + size > raf.length()) continue;
                    byte[] blob = new byte[size];
                    raf.seek(fileOff);
                    raf.readFully(blob);
                    ByteBuffer bb = ByteBuffer.wrap(blob).order(order);
                    for (int off = 0; off + entsize <= size; off += entsize) {
                        bb.position(off);
                        if (is64) {
                            if (off + 8 > size) break;
                            long rOffset = bb.getLong();
                            if (rOffset >= textAddr && rOffset < textEnd) {
                                return true;
                            }
                        } else {
                            if (off + 4 > size) break;
                            long rOffset = bb.getInt() & 0xffffffffL;
                            if (rOffset >= textAddr && rOffset < textEnd) {
                                return true;
                            }
                        }
                    }
                }
                return false;
            }
        }
    }

    private static String cString(byte[] tab, int off) {
        if (off < 0 || off >= tab.length) return "";
        int end = off;
        while (end < tab.length && tab[end] != 0) end++;
        return new String(tab, off, end - off, StandardCharsets.US_ASCII);
    }

    /** Build plaintext key table then AES-GCM wrap with {@code K_so} → PSOK file bytes. */
    public static byte[] buildSokeysBlob(List<Entry> entries, byte[] soWrapKey) throws Exception {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        writeU32(bos, entries.size());
        for (Entry e : entries) {
            byte[] name = e.name.getBytes(StandardCharsets.UTF_8);
            writeU16(bos, name.length);
            bos.write(name);
            bos.write(e.key);
        }
        byte[] plain = bos.toByteArray();
        byte[] enc = CryptoUtils.aesGcmEncrypt(soWrapKey, plain);
        byte[] out = new byte[4 + enc.length];
        out[0] = 'P';
        out[1] = 'S';
        out[2] = 'O';
        out[3] = 'K';
        System.arraycopy(enc, 0, out, 4, enc.length);
        return out;
    }

    /**
     * JSON size report for assets/protector/size_report.json and stdout.
     */
    public static String buildSizeReportJson(long inputBytes, long outputBytes,
                                            ProtectResult so,
                                            boolean protectSoEnabled) {
        double inMb = inputBytes / (1024.0 * 1024.0);
        double outMb = outputBytes / (1024.0 * 1024.0);
        double deltaMb = (outputBytes - inputBytes) / (1024.0 * 1024.0);
        double deltaPct = inputBytes > 0
                ? 100.0 * (outputBytes - inputBytes) / (double) inputBytes : 0.0;
        StringBuilder sb = new StringBuilder(2048);
        sb.append("{\n");
        sb.append(String.format(Locale.US, "  \"input_mb\": %.3f,\n", inMb));
        sb.append(String.format(Locale.US, "  \"output_mb\": %.3f,\n", outMb));
        sb.append(String.format(Locale.US, "  \"delta_mb\": %.3f,\n", deltaMb));
        sb.append(String.format(Locale.US, "  \"delta_pct\": %.2f,\n", deltaPct));
        sb.append("  \"protect_so\": ").append(protectSoEnabled).append(",\n");
        if (so != null) {
            sb.append(String.format(Locale.US,
                    "  \"est_so_delta_mb\": %.3f,\n", so.estimatedDeltaBytes / (1024.0 * 1024.0)));
            sb.append("  \"budget_truncated\": ").append(so.budgetTruncated).append(",\n");
            appendDecisionArray(sb, "so_encrypted", so.encrypted, true);
            appendDecisionArray(sb, "so_skipped_budget", so.skippedBudget, true);
            appendDecisionArray(sb, "so_skipped_policy", so.skippedPolicy, true);
            appendDecisionArray(sb, "so_skipped_reloc", so.skippedReloc, true);
            appendDecisionArray(sb, "top_delta_contributors", topDelta(so), false);
        } else {
            sb.append("  \"est_so_delta_mb\": 0,\n");
            sb.append("  \"budget_truncated\": false,\n");
            sb.append("  \"so_encrypted\": [],\n");
            sb.append("  \"so_skipped_budget\": [],\n");
            sb.append("  \"so_skipped_policy\": [],\n");
            sb.append("  \"so_skipped_reloc\": [],\n");
            sb.append("  \"top_delta_contributors\": []\n");
        }
        sb.append("}\n");
        return sb.toString();
    }

    private static List<SoDecision> topDelta(ProtectResult so) {
        List<SoDecision> all = new ArrayList<>();
        all.addAll(so.encrypted);
        all.addAll(so.skippedBudget);
        all.sort(Comparator.comparingLong((SoDecision d) -> d.estimatedDeltaBytes).reversed());
        if (all.size() > 15) {
            return new ArrayList<>(all.subList(0, 15));
        }
        return all;
    }

    private static void appendDecisionArray(StringBuilder sb, String key, List<SoDecision> list,
                                            boolean trailingComma) {
        sb.append("  \"").append(key).append("\": [");
        if (list == null || list.isEmpty()) {
            sb.append("]");
            if (trailingComma) sb.append(",");
            sb.append("\n");
            return;
        }
        sb.append("\n");
        for (int i = 0; i < list.size(); i++) {
            SoDecision d = list.get(i);
            sb.append(String.format(Locale.US,
                    "    {\"path\": \"%s\", \"file_mb\": %.3f, \"est_delta_mb\": %.3f, \"reason\": \"%s\"}",
                    escapeJson(d.path()),
                    d.fileBytes / (1024.0 * 1024.0),
                    d.estimatedDeltaBytes / (1024.0 * 1024.0),
                    escapeJson(d.reason != null ? d.reason : "")));
            if (i + 1 < list.size()) sb.append(",");
            sb.append("\n");
        }
        sb.append("  ]");
        if (trailingComma) sb.append(",");
        sb.append("\n");
    }

    private static String escapeJson(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\").replace("\"", "\\\"");
    }

    private static void encryptText(File soFile, byte[] key) throws Exception {
        try (ReadElf elf = new ReadElf(soFile)) {
            for (ReadElf.SectionHeader sh : elf.getSectionHeaders()) {
                if (!".text".equals(sh.getName())) continue;
                long offset = sh.getOffset();
                int size = (int) sh.getSize();
                if (size <= 0) throw new IllegalStateException("empty .text in " + soFile.getName());
                byte[] plain = readAt(soFile, offset, size);
                byte[] enc = CryptoUtils.rc4Crypt(key, plain);
                writeAt(soFile, offset, enc);
                System.out.println(String.format(Locale.US,
                        "  RC4 .text offset=0x%x size=%d", offset, size));
                return;
            }
        }
        throw new IllegalStateException("no .text in " + soFile.getName());
    }

    private static void writeU16(ByteArrayOutputStream bos, int v) {
        bos.write(v & 0xff);
        bos.write((v >> 8) & 0xff);
    }

    private static void writeU32(ByteArrayOutputStream bos, int v) {
        bos.write(v & 0xff);
        bos.write((v >> 8) & 0xff);
        bos.write((v >> 16) & 0xff);
        bos.write((v >> 24) & 0xff);
    }

    private static byte[] readAt(File file, long offset, int len) throws Exception {
        byte[] buf = new byte[len];
        try (RandomAccessFile raf = new RandomAccessFile(file, "r")) {
            raf.seek(offset);
            raf.readFully(buf);
        }
        return buf;
    }

    private static void writeAt(File file, long offset, byte[] data) throws Exception {
        try (RandomAccessFile raf = new RandomAccessFile(file, "rw")) {
            raf.seek(offset);
            raf.write(data);
        }
    }
}

package com.yqsh.protector.packer;

import com.android.tools.smali.dexlib2.Opcodes;
import com.android.tools.smali.dexlib2.dexbacked.DexBackedDexFile;
import com.android.tools.smali.dexlib2.iface.ClassDef;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * Expands {@linkplain DexLayout.Context#businessPrefixes class-split business
 * prefixes} beyond Manifest {@code applicationId}:
 * <ul>
 *   <li>Activity / Service / Receiver / Provider / Application class packages</li>
 *   <li>Optional one-level parent of applicationId (e.g. {@code com.foo.bar.app}
 *       → also {@code Lcom/foo/bar/}; never company-root {@code Lcom/foo/})</li>
 *   <li>Optional non-SDK DEX package clustering (candidate app modules)</li>
 * </ul>
 */
public final class BusinessPrefixDiscovery {

    /** Default min class count for a non-SDK package prefix to auto-include. */
    public static final int DEFAULT_DISCOVER_MIN_CLASSES = 8;
    /** Cap auto-discovered cluster prefixes to keep split predictable. */
    public static final int MAX_CLUSTER_PREFIXES = 48;

    private BusinessPrefixDiscovery() {
    }

    public static final class Options {
        /** Default on: {@code com.a.b.c} → also protect {@code Lcom/a/b/}. */
        public boolean parentPrefix = true;
        /** Default on: cluster non-SDK packages from DEX. */
        public boolean autoDiscover = true;
        public int discoverMinClasses = DEFAULT_DISCOVER_MIN_CLASSES;
    }

    /**
     * Mutates {@code ctx.businessPrefixes}. Logs what was added.
     *
     * @param packageName Manifest {@code package} / applicationId (dot form)
     */
    public static void enrich(DexLayout.Context ctx, File manifest, String packageName,
                              List<File> dexFiles, Options opt) {
        if (ctx == null) {
            return;
        }
        Options o = opt != null ? opt : new Options();
        Set<String> already = new LinkedHashSet<>();
        if (ctx.appPackagePrefix != null && !ctx.appPackagePrefix.isEmpty()) {
            already.add(ctx.appPackagePrefix);
        }
        already.addAll(normalizeAll(ctx.hollowPrefixes));
        already.addAll(normalizeAll(ctx.trueVmpPrefixes));
        already.addAll(normalizeAll(ctx.businessPrefixes));

        List<String> added = new ArrayList<>();
        // Scope Manifest/cluster extras to the app vendor root (first 2 segments),
        // e.g. com.ideack.notes → Lcom/ideack/. Prevents ad/SDK Activities
        // (bytedance / byazt / androidx …) from being class-split as "business".
        String vendorRoot = vendorRootPrefix(ctx.appPackagePrefix);
        if (vendorRoot != null) {
            System.out.println("Business prefix vendor_root=" + vendorRoot);
        }

        // 1) Manifest components (app-vendor only; skip SDK / ads)
        List<String> fromManifest = prefixesFromManifest(manifest, packageName);
        for (String p : fromManifest) {
            if (!acceptDiscoveredPrefix(p, vendorRoot)) {
                continue;
            }
            if (addIfNew(ctx, already, p)) {
                added.add("manifest:" + p);
            }
        }

        // 2) One-level parent of applicationId (not company root)
        if (o.parentPrefix) {
            String parent = oneLevelParentPrefix(ctx.appPackagePrefix);
            if (parent != null && addIfNew(ctx, already, parent)) {
                added.add("parent:" + parent);
            }
        }

        // 3) Non-SDK package clusters from DEX (same vendor-root gate)
        if (o.autoDiscover && dexFiles != null && !dexFiles.isEmpty()) {
            int min = o.discoverMinClasses > 0
                    ? o.discoverMinClasses : DEFAULT_DISCOVER_MIN_CLASSES;
            List<String> clusters = prefixesFromDexClusters(
                    dexFiles, already, min, vendorRoot);
            int n = 0;
            for (String p : clusters) {
                if (n >= MAX_CLUSTER_PREFIXES) {
                    System.out.println("WARN: business auto-discover capped at "
                            + MAX_CLUSTER_PREFIXES + " prefixes");
                    break;
                }
                if (addIfNew(ctx, already, p)) {
                    added.add("cluster:" + p);
                    n++;
                }
            }
        }

        if (added.isEmpty()) {
            System.out.println("Business prefixes: no extras beyond app_prefix="
                    + ctx.appPackagePrefix);
        } else {
            System.out.println("Business prefixes added (" + added.size() + "):");
            for (String line : added) {
                System.out.println("  + " + line);
            }
        }
    }

    /**
     * {@code Lcom/foo/bar/app/} → {@code Lcom/foo/bar/}.
     * Requires ≥4 path segments so parent keeps ≥3 ({@code com.foo.bar}), never
     * company-root {@code Lcom/foo/}.
     */
    public static String oneLevelParentPrefix(String dalvikPrefix) {
        if (dalvikPrefix == null || dalvikPrefix.length() < 5) {
            return null;
        }
        String p = dalvikPrefix;
        if (!p.startsWith("L")) {
            return null;
        }
        if (!p.endsWith("/")) {
            p = p + "/";
        }
        // Strip trailing slash for segment count, then drop last segment.
        String body = p.substring(1, p.length() - 1); // foo/bar/app
        String[] segs = body.split("/");
        if (segs.length < 4) {
            return null;
        }
        StringBuilder sb = new StringBuilder("L");
        for (int i = 0; i < segs.length - 1; i++) {
            if (segs[i].isEmpty()) {
                return null;
            }
            sb.append(segs[i]).append('/');
        }
        return sb.toString();
    }

    /** Package prefixes from component {@code android:name} values. */
    public static List<String> prefixesFromManifest(File manifest, String packageName) {
        LinkedHashSet<String> out = new LinkedHashSet<>();
        if (manifest == null || !manifest.isFile()) {
            return new ArrayList<>();
        }
        List<String> names = ManifestHelperLocal.listComponentClassNames(manifest);
        for (String raw : names) {
            String fqcn = resolveManifestClassName(packageName, raw);
            if (fqcn == null || fqcn.isEmpty()) {
                continue;
            }
            String pkg = javaPackageOf(fqcn);
            String prefix = ProtectPolicy.toDescriptorPrefix(pkg);
            if (prefix != null && !prefix.isEmpty()) {
                out.add(prefix);
            }
        }
        return new ArrayList<>(out);
    }

    /**
     * Android rules: {@code .Foo} / {@code Foo} → {@code pkg.Foo}; dotted name
     * unchanged.
     */
    public static String resolveManifestClassName(String packageName, String androidName) {
        if (androidName == null) {
            return null;
        }
        String name = androidName.trim();
        if (name.isEmpty()) {
            return null;
        }
        if (name.charAt(0) == '.') {
            if (packageName == null || packageName.isEmpty()) {
                return null;
            }
            return packageName + name;
        }
        if (name.indexOf('.') >= 0) {
            return name;
        }
        if (packageName == null || packageName.isEmpty()) {
            return name;
        }
        return packageName + '.' + name;
    }

    static String javaPackageOf(String fqcn) {
        if (fqcn == null) {
            return null;
        }
        int dot = fqcn.lastIndexOf('.');
        if (dot <= 0) {
            return null;
        }
        return fqcn.substring(0, dot);
    }

    /**
     * First two path segments of applicationId as vendor root.
     * {@code Lcom/ideack/notes/} → {@code Lcom/ideack/}.
     */
    public static String vendorRootPrefix(String appPackagePrefix) {
        if (appPackagePrefix == null || appPackagePrefix.length() < 5
                || !appPackagePrefix.startsWith("L")) {
            return null;
        }
        String p = appPackagePrefix.endsWith("/")
                ? appPackagePrefix : appPackagePrefix + "/";
        String body = p.substring(1, p.length() - 1);
        String[] segs = body.split("/");
        if (segs.length < 2 || segs[0].isEmpty() || segs[1].isEmpty()) {
            return null;
        }
        return "L" + segs[0] + "/" + segs[1] + "/";
    }

    /**
     * Accept Manifest/cluster prefixes only when under the app vendor root and
     * not an SDK / known ad obfuscation package.
     */
    public static boolean acceptDiscoveredPrefix(String prefix, String vendorRoot) {
        String p = normalizePrefix(prefix);
        if (p == null) {
            return false;
        }
        // Synthetic type for SDK table / noise checks.
        if (DexLayout.isSdkType(p + "X;")) {
            return false;
        }
        if (isDeniedDiscoveryPrefix(p)) {
            return false;
        }
        if (vendorRoot == null || vendorRoot.isEmpty()) {
            // No vendor root → only keep non-SDK (legacy-safe fallback).
            return true;
        }
        return p.startsWith(vendorRoot);
    }

    /**
     * Ad / plugin obfuscation namespaces that are not in the static SDK skip
     * table but must never be class-split as app business.
     */
    private static final String[] DISCOVERY_DENY_PREFIXES = {
            "Lcom/byazt/",
            "Lcom/byted/",
            "Lcom/bytedance/",
            "Lcom/ss/android/",
            "Lcom/qq/e/",
            "Lms/bz/",
            "Lcom/huawei/openalliance/",
            "Lcom/kwad/",
            "Lcom/sigmob/",
            "Lcom/baidu/mobads/",
            "Lcom/unity3d/ads/",
            "Lcom/mbridge/",
            "Lcom/applovin/",
            "Lcom/vungle/",
            "Lcom/chartboost/",
            "Lcom/ironsource/",
            "Lcom/google/android/gms/ads/",
            "Lcom/google/ads/",
    };

    static boolean isDeniedDiscoveryPrefix(String prefix) {
        if (prefix == null) {
            return false;
        }
        for (String d : DISCOVERY_DENY_PREFIXES) {
            if (prefix.startsWith(d)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Cluster non-{@link DexLayout#isSdkType} class packages; keep prefixes with
     * at least {@code minClasses} types that are not already covered and lie
     * under the app {@code vendorRoot}.
     */
    public static List<String> prefixesFromDexClusters(List<File> dexFiles,
                                                       Collection<String> already,
                                                       int minClasses) {
        return prefixesFromDexClusters(dexFiles, already, minClasses, null);
    }

    public static List<String> prefixesFromDexClusters(List<File> dexFiles,
                                                       Collection<String> already,
                                                       int minClasses,
                                                       String vendorRoot) {
        Map<String, Integer> counts = new LinkedHashMap<>();
        for (File dex : dexFiles) {
            if (dex == null || !dex.isFile()) {
                continue;
            }
            try (BufferedInputStream in = new BufferedInputStream(new FileInputStream(dex))) {
                DexBackedDexFile df = DexBackedDexFile.fromInputStream(Opcodes.getDefault(), in);
                for (ClassDef cd : df.getClasses()) {
                    String type = cd.getType();
                    if (type == null || DexLayout.isSdkType(type)) {
                        continue;
                    }
                    String prefix = packagePrefixOfType(type);
                    if (prefix == null || coveredBy(prefix, already)) {
                        continue;
                    }
                    if (!acceptDiscoveredPrefix(prefix, vendorRoot)) {
                        continue;
                    }
                    Integer n = counts.get(prefix);
                    counts.put(prefix, n == null ? 1 : n + 1);
                }
            } catch (Exception e) {
                System.out.println("WARN: business auto-discover skip " + dex.getName()
                        + ": " + e.getMessage());
            }
        }
        List<Map.Entry<String, Integer>> ranked = new ArrayList<>(counts.entrySet());
        ranked.sort((a, b) -> {
            int c = Integer.compare(b.getValue(), a.getValue());
            if (c != 0) {
                return c;
            }
            return a.getKey().compareTo(b.getKey());
        });
        List<String> out = new ArrayList<>();
        for (Map.Entry<String, Integer> e : ranked) {
            if (e.getValue() < minClasses) {
                continue;
            }
            out.add(e.getKey());
        }
        return out;
    }

    /** {@code Lcom/foo/Bar$Q;} → {@code Lcom/foo/}. */
    public static String packagePrefixOfType(String typeDescriptor) {
        if (typeDescriptor == null || typeDescriptor.length() < 4
                || typeDescriptor.charAt(0) != 'L') {
            return null;
        }
        int slash = typeDescriptor.lastIndexOf('/');
        if (slash <= 0) {
            return null;
        }
        return typeDescriptor.substring(0, slash + 1);
    }

    private static boolean addIfNew(DexLayout.Context ctx, Set<String> already, String prefix) {
        String p = normalizePrefix(prefix);
        if (p == null || coveredBy(p, already)) {
            return false;
        }
        ctx.businessPrefixes.add(p);
        already.add(p);
        return true;
    }

    private static boolean coveredBy(String prefix, Collection<String> already) {
        if (prefix == null || already == null) {
            return false;
        }
        for (String a : already) {
            if (a != null && !a.isEmpty() && prefix.startsWith(a)) {
                return true;
            }
        }
        return false;
    }

    private static List<String> normalizeAll(List<String> in) {
        List<String> out = new ArrayList<>();
        if (in == null) {
            return out;
        }
        for (String s : in) {
            String n = normalizePrefix(s);
            if (n != null) {
                out.add(n);
            }
        }
        return out;
    }

    private static String normalizePrefix(String prefix) {
        if (prefix == null) {
            return null;
        }
        String p = prefix.trim();
        if (p.isEmpty()) {
            return null;
        }
        if (!p.startsWith("L")) {
            // Allow dot-form accidentally passed in.
            if (p.indexOf('.') >= 0 && p.indexOf('/') < 0) {
                p = ProtectPolicy.toDescriptorPrefix(p);
            }
        }
        if (p == null || p.isEmpty() || !p.startsWith("L")) {
            return null;
        }
        if (!p.endsWith("/")) {
            p = p + "/";
        }
        return p;
    }

    static String describeOptions(Options o) {
        if (o == null) {
            o = new Options();
        }
        return String.format(Locale.US,
                "parent_prefix=%s auto_discover=%s min_classes=%d",
                o.parentPrefix ? "on" : "off",
                o.autoDiscover ? "on" : "off",
                o.discoverMinClasses);
    }
}

package com.yqsh.protector.packer;

import com.android.tools.smali.dexlib2.Opcodes;
import com.android.tools.smali.dexlib2.dexbacked.DexBackedDexFile;
import com.android.tools.smali.dexlib2.iface.ClassDef;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * Expands {@linkplain DexLayout.Context#businessPrefixes class-split business
 * prefixes} (and optional {@linkplain DexLayout.Context#businessExactTypes
 * exact types}) beyond Manifest {@code applicationId}:
 * <ul>
 *   <li>Application class: leaf package (incl. cross-vendor when gated)</li>
 *   <li>Activity / Service / Receiver / Provider under applicationId vendor
 *       or Application <em>leaf</em> package: exact type + leaf package</li>
 *   <li>Known ad/SDK Manifest components: skipped entirely</li>
 *   <li>Ambiguous cross-package components: never package prefix; exact by
 *       default ({@code ambiguousExact})</li>
 *   <li>Optional one-level parent of applicationId</li>
 *   <li>Optional non-SDK DEX clustering (still gated by applicationId
 *       vendor root)</li>
 * </ul>
 */
public final class BusinessPrefixDiscovery {

    /** Default min class count for a non-SDK package prefix to auto-include. */
    public static final int DEFAULT_DISCOVER_MIN_CLASSES = 8;
    /** Cap auto-discovered cluster prefixes to keep split predictable. */
    public static final int MAX_CLUSTER_PREFIXES = 48;
    /** Cap cross-vendor Application / business leaf promotions. */
    public static final int MAX_CROSS_VENDOR_LEAVES = 16;

    private BusinessPrefixDiscovery() {
    }

    public static final class Options {
        /** Default on: {@code com.a.b.c} → also protect {@code Lcom/a/b/}. */
        public boolean parentPrefix = true;
        /** Default on: cluster non-SDK packages from DEX. */
        public boolean autoDiscover = true;
        public int discoverMinClasses = DEFAULT_DISCOVER_MIN_CLASSES;
        /**
         * Default on: when Manifest Application is outside applicationId
         * vendor root, promote its leaf package (deny/SDK/minClasses gated).
         */
        public boolean appCrossVendorLeaf = true;
        /**
         * Default on: add exact type descriptors for trusted Manifest
         * components (Application + same-vendor / same-Application-system).
         */
        public boolean businessExact = true;
        /**
         * Default on: add exact types for ambiguous cross-package Manifest
         * components (never their package prefixes). Covers rename cases with
         * no custom Application, and sibling modules outside Application leaf.
         */
        public boolean ambiguousExact = true;
    }

    /**
     * Mutates {@code ctx.businessPrefixes} / {@code businessExactTypes}.
     * Logs what was added.
     *
     * @param packageName Manifest {@code package} / applicationId (dot form)
     */
    public static void enrich(DexLayout.Context ctx, File manifest, String packageName,
                              List<File> dexFiles, Options opt) {
        String appRaw = null;
        List<String> componentNames = Collections.emptyList();
        if (manifest != null && manifest.isFile()) {
            appRaw = ManifestHelperLocal.getApplicationName(manifest);
            componentNames = ManifestHelperLocal.listComponentClassNames(manifest);
        }
        enrichWithComponents(ctx, packageName, appRaw, componentNames, dexFiles, opt);
    }

    /**
     * Test / tooling entry: same rules as {@link #enrich} with pre-resolved
     * Manifest {@code android:name} values (no binary AXML required).
     */
    public static void enrichWithComponents(DexLayout.Context ctx, String packageName,
                                            String applicationNameRaw,
                                            List<String> componentNames,
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

        Set<String> exactAlready = new LinkedHashSet<>();
        if (ctx.businessExactTypes != null) {
            exactAlready.addAll(ctx.businessExactTypes);
        }

        List<String> added = new ArrayList<>();
        List<String> skipped = new ArrayList<>();
        // applicationId vendor root — DEX cluster + same-id Manifest stay here.
        String vendorRoot = vendorRootPrefix(ctx.appPackagePrefix);
        if (vendorRoot != null) {
            System.out.println("Business prefix vendor_root=" + vendorRoot);
        }

        int min = o.discoverMinClasses > 0
                ? o.discoverMinClasses : DEFAULT_DISCOVER_MIN_CLASSES;
        int crossLeafCount = 0;

        // --- Application defines business root (may be cross-vendor) ---
        // Narrow trust to Application leaf (Lcom/c/d/), not company vendor (Lcom/c/).
        String appLeafRoot = null;
        String appFqcn = resolveManifestClassName(packageName, applicationNameRaw);
        if (appFqcn != null && !isFrameworkApplication(appFqcn)) {
            String appType = toTypeDescriptor(appFqcn);
            String appLeaf = leafPackagePrefixOfFqcn(appFqcn);
            if (isDeniedOrSdkPrefix(appLeaf)) {
                skipped.add("manifest-skip-deny:application:" + appFqcn);
            } else {
                appLeafRoot = appLeaf;
                // Exact first so thin cross-vendor Application still protects the class.
                if (o.businessExact && addExactIfNew(ctx, exactAlready, appType)) {
                    added.add("manifest-exact:" + appType);
                }
                boolean sameVendor = vendorRoot != null && appLeaf != null
                        && appLeaf.startsWith(vendorRoot);
                if (sameVendor) {
                    if (addIfNew(ctx, already, appLeaf)) {
                        added.add("manifest-app-leaf:" + appLeaf);
                    }
                } else if (o.appCrossVendorLeaf) {
                    // Require com.x.y (3 path segments); never company-root Lcom/x/.
                    if (pathSegmentCount(appLeaf) < 3) {
                        skipped.add("manifest-skip-shallow:application:" + appLeaf);
                    } else {
                        int n = countClassesUnderPrefix(dexFiles, appLeaf);
                        if (n < min) {
                            skipped.add("manifest-skip-thin:application:" + appLeaf
                                    + " (classes=" + n + " < " + min + ")");
                        } else if (crossLeafCount >= MAX_CROSS_VENDOR_LEAVES) {
                            skipped.add("manifest-skip-cap:application:" + appLeaf);
                        } else if (addIfNew(ctx, already, appLeaf)) {
                            added.add("manifest-app-leaf:" + appLeaf
                                    + " (cross-vendor classes=" + n + ")");
                            crossLeafCount++;
                        }
                    }
                }
            }
        }

        // --- Other Manifest components ---
        if (componentNames != null) {
            for (String raw : componentNames) {
                String fqcn = resolveManifestClassName(packageName, raw);
                if (fqcn == null || fqcn.isEmpty()) {
                    continue;
                }
                // Application already handled.
                if (appFqcn != null && fqcn.equals(appFqcn)) {
                    continue;
                }
                String type = toTypeDescriptor(fqcn);
                String leaf = leafPackagePrefixOfFqcn(fqcn);
                if (leaf == null || type == null) {
                    continue;
                }
                if (isDeniedOrSdkPrefix(leaf)) {
                    skipped.add("manifest-skip-deny:" + fqcn);
                    continue;
                }

                boolean underAppId = vendorRoot != null && leaf.startsWith(vendorRoot);
                boolean underAppLeaf = appLeafRoot != null
                        && leaf.startsWith(appLeafRoot);

                if (underAppId || underAppLeaf) {
                    // Leaf first — exact becomes redundant when prefix covers it.
                    boolean mayPromoteLeaf = underAppId
                            || crossLeafCount < MAX_CROSS_VENDOR_LEAVES;
                    if (!mayPromoteLeaf) {
                        skipped.add("manifest-skip-cap:" + fqcn);
                    } else if (addIfNew(ctx, already, leaf)) {
                        String tag = underAppId ? "manifest:" : "manifest-leaf:";
                        added.add(tag + leaf);
                        if (!underAppId) {
                            crossLeafCount++;
                        }
                    }
                    if (o.businessExact && addExactIfNew(ctx, exactAlready, type)) {
                        added.add("manifest-exact:" + type);
                    }
                } else {
                    // Ambiguous cross-package: never package prefix; exact by default.
                    skipped.add("manifest-skip-ambiguous:" + fqcn);
                    if (o.ambiguousExact && addExactIfNew(ctx, exactAlready, type)) {
                        added.add("manifest-exact-ambiguous:" + type);
                    }
                }
            }
        }

        // Parent of applicationId (not company root)
        if (o.parentPrefix) {
            String parent = oneLevelParentPrefix(ctx.appPackagePrefix);
            if (parent != null && addIfNew(ctx, already, parent)) {
                added.add("parent:" + parent);
            }
        }

        // Non-SDK package clusters from DEX (applicationId vendor-root only)
        if (o.autoDiscover && dexFiles != null && !dexFiles.isEmpty()) {
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
        if (!skipped.isEmpty()) {
            System.out.println("Business prefix skips (" + skipped.size() + "):");
            for (String line : skipped) {
                System.out.println("  - " + line);
            }
            boolean anyAmbiguous = false;
            for (String s : skipped) {
                if (s.startsWith("manifest-skip-ambiguous:")) {
                    anyAmbiguous = true;
                    break;
                }
            }
            if (anyAmbiguous) {
                System.out.println("WARN: ambiguous Manifest components skipped; "
                        + "add --hollow-prefix for real app packages if needed");
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

    /** {@code com.foo.Bar} → {@code Lcom/foo/Bar;}. */
    public static String toTypeDescriptor(String fqcn) {
        if (fqcn == null) {
            return null;
        }
        String n = fqcn.trim();
        if (n.isEmpty() || n.indexOf('.') < 0) {
            return null;
        }
        return "L" + n.replace('.', '/') + ";";
    }

    /** {@code com.foo.Bar} → {@code Lcom/foo/}. */
    public static String leafPackagePrefixOfFqcn(String fqcn) {
        String pkg = javaPackageOf(fqcn);
        return ProtectPolicy.toDescriptorPrefix(pkg);
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

    /** Path segments inside a Dalvik package prefix ({@code Lcom/a/b/} → 2). */
    public static int pathSegmentCount(String prefix) {
        String p = normalizePrefix(prefix);
        if (p == null) {
            return 0;
        }
        String body = p.substring(1, p.length() - 1);
        if (body.isEmpty()) {
            return 0;
        }
        String[] segs = body.split("/");
        int n = 0;
        for (String s : segs) {
            if (!s.isEmpty()) {
                n++;
            }
        }
        return n;
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
        if (isDeniedOrSdkPrefix(p)) {
            return false;
        }
        if (vendorRoot == null || vendorRoot.isEmpty()) {
            // No vendor root → only keep non-SDK (legacy-safe fallback).
            return true;
        }
        return p.startsWith(vendorRoot);
    }

    public static boolean isDeniedOrSdkPrefix(String prefix) {
        String p = normalizePrefix(prefix);
        if (p == null) {
            return true;
        }
        if (DexLayout.isSdkType(p + "X;")) {
            return true;
        }
        return isDeniedDiscoveryPrefix(p);
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

    static boolean isFrameworkApplication(String fqcn) {
        if (fqcn == null) {
            return true;
        }
        String n = fqcn.trim();
        return n.isEmpty()
                || "android.app.Application".equals(n)
                || "androidx.multidex.MultiDexApplication".equals(n)
                || "android.support.multidex.MultiDexApplication".equals(n);
    }

    /**
     * Count non-{@link DexLayout#isSdkType} classes under {@code prefix}.
     */
    public static int countClassesUnderPrefix(List<File> dexFiles, String prefix) {
        String p = normalizePrefix(prefix);
        if (p == null || dexFiles == null || dexFiles.isEmpty()) {
            return 0;
        }
        int count = 0;
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
                    if (type.startsWith(p)) {
                        count++;
                    }
                }
            } catch (Exception e) {
                System.out.println("WARN: count classes skip " + dex.getName()
                        + ": " + e.getMessage());
            }
        }
        return count;
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

    private static boolean addExactIfNew(DexLayout.Context ctx, Set<String> exactAlready,
                                         String typeDescriptor) {
        if (typeDescriptor == null || typeDescriptor.isEmpty()) {
            return false;
        }
        if (exactAlready.contains(typeDescriptor)) {
            return false;
        }
        // Already covered by a broader package prefix → still record exact for
        // clarity/logs? Prefer skip duplicate extract work — prefix already hits.
        for (String p : ctx.businessPrefixes) {
            if (p != null && !p.isEmpty() && typeDescriptor.startsWith(p)) {
                exactAlready.add(typeDescriptor);
                return false;
            }
        }
        if (ctx.appPackagePrefix != null && !ctx.appPackagePrefix.isEmpty()
                && typeDescriptor.startsWith(ctx.appPackagePrefix)) {
            exactAlready.add(typeDescriptor);
            return false;
        }
        ctx.businessExactTypes.add(typeDescriptor);
        exactAlready.add(typeDescriptor);
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
                "parent_prefix=%s auto_discover=%s min_classes=%d "
                        + "app_cross_vendor_leaf=%s business_exact=%s ambiguous_exact=%s",
                o.parentPrefix ? "on" : "off",
                o.autoDiscover ? "on" : "off",
                o.discoverMinClasses,
                o.appCrossVendorLeaf ? "on" : "off",
                o.businessExact ? "on" : "off",
                o.ambiguousExact ? "on" : "off");
    }
}

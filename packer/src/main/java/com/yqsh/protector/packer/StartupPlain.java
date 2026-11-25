package com.yqsh.protector.packer;

import java.io.File;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * Startup-plain: keep Manifest {@code Application}, MAIN/LAUNCHER activities,
 * and optional prefixes in the APK-root (install-AOT) DEX instead of encrypted
 * {@code dexes.zip}. Checked first in {@link DexLayout#isBusinessType}.
 */
public final class StartupPlain {

    private StartupPlain() {
    }

    /**
     * Resolve Application + launcher component FQCNs to type descriptors and
     * install them on {@code ctx}. Also auto-adds the <b>parent package</b>
     * of each LAUNCHER activity as a startup-plain prefix (≥3 path segments),
     * so splash/welcome siblings stay install-AOT without encrypting the whole
     * app. Removes overlapping {@link DexLayout.Context#businessExactTypes}.
     *
     * @return number of startup-plain types recorded
     */
    public static int apply(DexLayout.Context ctx, File manifest, String packageName) {
        if (ctx == null) {
            return 0;
        }
        String appType = collectApplicationType(manifest, packageName);
        List<String> launcherTypes = collectLauncherTypes(manifest, packageName);
        List<String> types = new ArrayList<>();
        if (appType != null) {
            types.add(appType);
        }
        for (String t : launcherTypes) {
            if (t != null && !t.isEmpty() && !types.contains(t)) {
                types.add(t);
            }
        }
        if (types.isEmpty()) {
            System.out.println("Startup-plain: none (no Application / LAUNCHER found)");
            return 0;
        }
        Set<String> already = new LinkedHashSet<>(ctx.startupPlainTypes);
        List<String> added = new ArrayList<>();
        for (String t : types) {
            if (t == null || t.isEmpty() || already.contains(t)) {
                continue;
            }
            ctx.startupPlainTypes.add(t);
            already.add(t);
            added.add(t);
        }
        stripOverlappingExactTypes(ctx);
        System.out.println("Startup-plain types (" + added.size() + "):");
        for (String t : added) {
            System.out.println("  plain:" + t);
        }
        // Auto leaf-prefix from LAUNCHER only (not Application — too broad;
        // use {@link #applyAppLeaf} / --startup-plain-app-leaf for that).
        List<String> autoPrefixes = new ArrayList<>();
        for (String t : launcherTypes) {
            String p = parentPackagePrefix(t);
            if (p != null && pathSegmentCount(p) >= 3) {
                autoPrefixes.add(p);
            }
        }
        if (!autoPrefixes.isEmpty()) {
            applyPrefixes(ctx, autoPrefixes);
        }
        return added.size();
    }

    /**
     * Keep the Manifest {@code Application} <b>leaf package</b> plain
     * ({@code Lcom/a/b/c/App;} → {@code Lcom/a/b/c/}). Same ≥3-segment gate as
     * {@link #applyPrefixes}. Used by {@code --startup-plain-app-leaf} / PERF.
     *
     * @return 1 if a new prefix was added, else 0
     */
    public static int applyAppLeaf(DexLayout.Context ctx, File manifest, String packageName) {
        if (ctx == null) {
            return 0;
        }
        String appType = collectApplicationType(manifest, packageName);
        String leaf = parentPackagePrefix(appType);
        if (leaf == null) {
            System.out.println("Startup-plain app-leaf: none (no Application or too shallow)");
            return 0;
        }
        int n = applyPrefixes(ctx, java.util.Collections.singletonList(leaf));
        if (n > 0) {
            System.out.println("Startup-plain app-leaf: " + leaf);
        }
        return n;
    }

    /**
     * P1: add explicit startup-plain prefixes (Dalvik or dot form).
     * Applied even when auto Application/LAUNCHER is disabled, so CLI intent wins.
     *
     * @return number of new prefixes recorded
     */
    public static int applyPrefixes(DexLayout.Context ctx, Collection<String> rawPrefixes) {
        if (ctx == null || rawPrefixes == null || rawPrefixes.isEmpty()) {
            return 0;
        }
        Set<String> already = new LinkedHashSet<>();
        for (String p : ctx.startupPlainPrefixes) {
            String n = normalizePrefix(p);
            if (n != null) {
                already.add(n);
            }
        }
        List<String> added = new ArrayList<>();
        for (String raw : rawPrefixes) {
            String p = normalizePrefix(raw);
            if (p == null || already.contains(p)) {
                continue;
            }
            // Require com.x.y (≥3 path segments); never company-root Lcom/x/ or Lcom/x/y/.
            if (pathSegmentCount(p) < 3) {
                System.out.println("WARN: startup-plain-prefix too shallow, skipped: " + raw);
                continue;
            }
            ctx.startupPlainPrefixes.add(p);
            already.add(p);
            added.add(p);
        }
        if (!added.isEmpty()) {
            stripExactCoveredByPrefixes(ctx);
            System.out.println("Startup-plain prefixes (" + added.size() + "):");
            for (String p : added) {
                System.out.println("  plain-prefix:" + p);
            }
        }
        return added.size();
    }

    /**
     * Application + MAIN/LAUNCHER activity (and activity-alias
     * {@code targetActivity}) as Dalvik type descriptors.
     */
    public static List<String> collectTypeDescriptors(File manifest, String packageName) {
        LinkedHashSet<String> out = new LinkedHashSet<>();
        String app = collectApplicationType(manifest, packageName);
        if (app != null) {
            out.add(app);
        }
        out.addAll(collectLauncherTypes(manifest, packageName));
        return new ArrayList<>(out);
    }

    static String collectApplicationType(File manifest, String packageName) {
        if (manifest == null || !manifest.isFile()) {
            return null;
        }
        String appRaw = ManifestHelperLocal.getApplicationName(manifest);
        String appFqcn = BusinessPrefixDiscovery.resolveManifestClassName(packageName, appRaw);
        if (appFqcn != null && !BusinessPrefixDiscovery.isFrameworkApplication(appFqcn)) {
            return BusinessPrefixDiscovery.toTypeDescriptor(appFqcn);
        }
        return null;
    }

    static List<String> collectLauncherTypes(File manifest, String packageName) {
        LinkedHashSet<String> out = new LinkedHashSet<>();
        if (manifest == null || !manifest.isFile()) {
            return new ArrayList<>();
        }
        for (String raw : ManifestHelperLocal.listLauncherComponentNames(manifest)) {
            String fqcn = BusinessPrefixDiscovery.resolveManifestClassName(packageName, raw);
            String type = BusinessPrefixDiscovery.toTypeDescriptor(fqcn);
            if (type != null) {
                out.add(type);
            }
        }
        return new ArrayList<>(out);
    }

    /**
     * {@code Lcom/a/b/c/SplashActivity;} → {@code Lcom/a/b/c/}.
     * Null when missing or resulting prefix has &lt;3 path segments
     * (same shallow gate as {@link #applyPrefixes}).
     */
    static String parentPackagePrefix(String typeDescriptor) {
        if (typeDescriptor == null || !typeDescriptor.startsWith("L")
                || !typeDescriptor.endsWith(";")) {
            return null;
        }
        String body = typeDescriptor.substring(1, typeDescriptor.length() - 1);
        int slash = body.lastIndexOf('/');
        if (slash <= 0) {
            return null;
        }
        String prefix = "L" + body.substring(0, slash + 1);
        if (pathSegmentCount(prefix) < 3) {
            return null;
        }
        return prefix;
    }

    /** {@code Lcom/foo/bar/} or {@code com.foo.bar} → normalized Dalvik prefix. */
    public static String normalizePrefix(String raw) {
        if (raw == null) {
            return null;
        }
        String p = raw.trim();
        if (p.isEmpty()) {
            return null;
        }
        if (!p.startsWith("L")) {
            if (p.indexOf('.') >= 0 && p.indexOf('/') < 0) {
                p = ProtectPolicy.toDescriptorPrefix(p);
            } else if (!p.startsWith("L")) {
                // Allow "com/foo/bar/" without leading L.
                if (p.indexOf('/') >= 0) {
                    if (!p.endsWith("/")) {
                        p = p + "/";
                    }
                    p = "L" + p;
                } else {
                    return null;
                }
            }
        }
        if (p == null || p.isEmpty() || !p.startsWith("L")) {
            return null;
        }
        if (!p.endsWith("/")) {
            // Type descriptor mistaken as prefix — reject exact types here.
            if (p.endsWith(";")) {
                return null;
            }
            p = p + "/";
        }
        return p;
    }

    static int pathSegmentCount(String prefix) {
        String p = normalizePrefix(prefix);
        if (p == null) {
            return 0;
        }
        String body = p.substring(1, p.length() - 1);
        if (body.isEmpty()) {
            return 0;
        }
        int n = 0;
        for (String s : body.split("/")) {
            if (!s.isEmpty()) {
                n++;
            }
        }
        return n;
    }

    private static void stripOverlappingExactTypes(DexLayout.Context ctx) {
        if (ctx.businessExactTypes == null || ctx.businessExactTypes.isEmpty()) {
            return;
        }
        Iterator<String> it = ctx.businessExactTypes.iterator();
        while (it.hasNext()) {
            String exact = it.next();
            if (exact != null && DexLayout.matchesExactType(exact, ctx.startupPlainTypes)) {
                it.remove();
            }
        }
    }

    private static void stripExactCoveredByPrefixes(DexLayout.Context ctx) {
        if (ctx.businessExactTypes == null || ctx.businessExactTypes.isEmpty()) {
            return;
        }
        Iterator<String> it = ctx.businessExactTypes.iterator();
        while (it.hasNext()) {
            String exact = it.next();
            if (exact == null) {
                continue;
            }
            for (String p : ctx.startupPlainPrefixes) {
                if (p != null && !p.isEmpty() && exact.startsWith(p)) {
                    it.remove();
                    break;
                }
            }
        }
    }
}

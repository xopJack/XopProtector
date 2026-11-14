package com.yqsh.protector.packer;

import pxb.android.axml.AxmlParser;

import java.io.File;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

final class ManifestHelperLocal {
    private static final Set<String> COMPONENT_TAGS = new LinkedHashSet<>();

    static {
        COMPONENT_TAGS.add("application");
        COMPONENT_TAGS.add("activity");
        COMPONENT_TAGS.add("activity-alias");
        COMPONENT_TAGS.add("service");
        COMPONENT_TAGS.add("receiver");
        COMPONENT_TAGS.add("provider");
    }

    private ManifestHelperLocal() {}

    static String getApplicationName(File manifest) {
        try {
            byte[] data = Files.readAllBytes(manifest.toPath());
            AxmlParser parser = new AxmlParser(data);
            while (parser.next() != AxmlParser.END_FILE) {
                if (parser.getAttrCount() == 0) continue;
                if (!"application".equals(parser.getName())) continue;
                for (int i = 0; i < parser.getAttrCount(); i++) {
                    if ("name".equals(parser.getAttrName(i))) {
                        Object v = parser.getAttrValue(i);
                        return v == null ? null : String.valueOf(v);
                    }
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    /** Manifest {@code package} / applicationId (e.g. {@code com.foo.bar}). */
    static String getPackageName(File manifest) {
        try {
            byte[] data = Files.readAllBytes(manifest.toPath());
            AxmlParser parser = new AxmlParser(data);
            while (parser.next() != AxmlParser.END_FILE) {
                if (parser.getAttrCount() == 0) continue;
                if (!"manifest".equals(parser.getName())) continue;
                for (int i = 0; i < parser.getAttrCount(); i++) {
                    if ("package".equals(parser.getAttrName(i))) {
                        Object v = parser.getAttrValue(i);
                        return v == null ? null : String.valueOf(v);
                    }
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * Raw {@code android:name} values from Application / Activity / Service /
     * Receiver / Provider (and activity-alias). Relative names are not resolved
     * here — see {@link BusinessPrefixDiscovery#resolveManifestClassName}.
     */
    static List<String> listComponentClassNames(File manifest) {
        LinkedHashSet<String> names = new LinkedHashSet<>();
        if (manifest == null || !manifest.isFile()) {
            return new ArrayList<>();
        }
        try {
            byte[] data = Files.readAllBytes(manifest.toPath());
            AxmlParser parser = new AxmlParser(data);
            while (parser.next() != AxmlParser.END_FILE) {
                if (parser.getAttrCount() == 0) {
                    continue;
                }
                String tag = parser.getName();
                if (tag == null) {
                    continue;
                }
                String lower = tag.toLowerCase(Locale.ROOT);
                if (!COMPONENT_TAGS.contains(lower)) {
                    continue;
                }
                for (int i = 0; i < parser.getAttrCount(); i++) {
                    if ("name".equals(parser.getAttrName(i))) {
                        Object v = parser.getAttrValue(i);
                        if (v != null) {
                            String s = String.valueOf(v).trim();
                            if (!s.isEmpty()) {
                                names.add(s);
                            }
                        }
                        break;
                    }
                }
            }
        } catch (Exception e) {
            System.out.println("WARN: manifest component scan failed: " + e.getMessage());
        }
        return new ArrayList<>(names);
    }
}

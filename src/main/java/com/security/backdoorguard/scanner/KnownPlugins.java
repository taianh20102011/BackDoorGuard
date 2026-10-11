package com.security.backdoorguard.scanner;

import java.util.List;
import java.util.Locale;
import java.util.Map;

/** Conservative built-in checks for JARs impersonating well-known plugins. */
final class KnownPlugins {
    private static final Map<String, List<String>> EXPECTED = Map.ofEntries(
            Map.entry("vault", List.of("net/milkbowl/vault/")),
            Map.entry("essentials", List.of("com/earth2me/essentials/")),
            Map.entry("worldedit", List.of("com/sk89q/worldedit/")),
            Map.entry("worldguard", List.of("com/sk89q/worldguard/")),
            Map.entry("luckperms", List.of("me/lucko/luckperms/")),
            Map.entry("protocollib", List.of("com/comphenix/protocol/")),
            Map.entry("placeholderapi", List.of("me/clip/placeholderapi/")),
            Map.entry("coreprotect", List.of("net/coreprotect/")),
            Map.entry("viaversion", List.of("com/viaversion/viaversion/")),
            Map.entry("citizens", List.of("net/citizensnpcs/")),
            Map.entry("authme", List.of("fr/xephi/authme/")),
            Map.entry("spark", List.of("me/lucko/spark/")),
            Map.entry("multiverse-core", List.of("com/onarandombox/", "org/mvplugins/")),
            Map.entry("geyser-spigot", List.of("org/geysermc/"))
    );

    private KnownPlugins() {}

    static String impersonated(String pluginName, String mainClass) {
        if (pluginName == null || mainClass == null) return null;
        List<String> prefixes = EXPECTED.get(pluginName.trim().toLowerCase(Locale.ROOT));
        if (prefixes == null || prefixes.isEmpty()) return null;
        String internal = mainClass.replace('.', '/');
        for (String prefix : prefixes) {
            if (internal.startsWith(prefix)) return null;
        }
        return pluginName;
    }

    static String expectedPackage(String pluginName) {
        if (pluginName == null) return null;
        List<String> prefixes = EXPECTED.get(pluginName.trim().toLowerCase(Locale.ROOT));
        return prefixes == null ? null : String.join(" or ", prefixes).replace('/', '.');
    }
}

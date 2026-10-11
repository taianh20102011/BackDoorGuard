package com.security.backdoorguard.i18n;

import org.bukkit.ChatColor;
import org.bukkit.configuration.file.YamlConfiguration;
import org.bukkit.plugin.java.JavaPlugin;
import org.bukkit.entity.Player;

import java.io.File;
import java.util.Locale;
import java.util.HashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Editable YAML-based localization with English fallback. */
public final class LanguageManager {
    private static final Pattern PLACEHOLDER = Pattern.compile("\\{([^{}]+)}");
    public static final String[] SUPPORTED = {"en", "vi", "es", "zh_CN", "fr", "de", "pt_BR", "ru", "ja", "ko"};

    private final JavaPlugin plugin;
    private volatile YamlConfiguration selected = new YamlConfiguration();
    private volatile YamlConfiguration fallback = new YamlConfiguration();
    private volatile Map<String, YamlConfiguration> translations = Map.of();
    private volatile String language = "en";

    public LanguageManager(JavaPlugin plugin) {
        this.plugin = plugin;
    }

    public void reload() {
        File directory = new File(plugin.getDataFolder(), "lang");
        if (!directory.exists() && !directory.mkdirs()) {
            plugin.getLogger().warning("Could not create language directory; bundled defaults will be used.");
        }
        for (String code : SUPPORTED) {
            String resource = "lang/" + code + ".yml";
            File destination = new File(directory, code + ".yml");
            if (!destination.exists()) {
                try {
                    plugin.saveResource(resource, false);
                } catch (IllegalArgumentException ex) {
                    plugin.getLogger().warning("Missing bundled language resource: " + resource);
                }
            }
        }

        Map<String, YamlConfiguration> loaded = new HashMap<>();
        for (String code : SUPPORTED) loaded.put(code, load(new File(directory, code + ".yml")));
        translations = Map.copyOf(loaded);
        fallback = translations.getOrDefault("en", new YamlConfiguration());
        language = normalize(plugin.getConfig().getString("language", "vi"));
        if (!SUPPORTED_AS_NORMALIZED.contains(language)) language = "en";
        selected = translations.getOrDefault(language, fallback);
    }

    private YamlConfiguration load(File file) {
        return YamlConfiguration.loadConfiguration(file);
    }

    private static final java.util.Set<String> SUPPORTED_AS_NORMALIZED = java.util.Arrays.stream(SUPPORTED)
            .map(LanguageManager::normalize).collect(java.util.stream.Collectors.toUnmodifiableSet());

    private static String normalize(String input) {
        if (input == null || input.isBlank()) return "en";
        String value = input.trim().replace('-', '_');
        if (value.equalsIgnoreCase("zh_cn")) return "zh_CN";
        if (value.equalsIgnoreCase("pt_br")) return "pt_BR";
        if (value.equalsIgnoreCase("en")) return "en";
        if (value.equalsIgnoreCase("vi")) return "vi";
        if (value.equalsIgnoreCase("es")) return "es";
        if (value.equalsIgnoreCase("fr")) return "fr";
        if (value.equalsIgnoreCase("de")) return "de";
        if (value.equalsIgnoreCase("ru")) return "ru";
        if (value.equalsIgnoreCase("ja")) return "ja";
        if (value.equalsIgnoreCase("ko")) return "ko";
        return value;
    }

    public String getLanguage() {
        return language;
    }

    public boolean isSupported(String code) {
        if (code == null) return false;
        String normalized = normalize(code);
        return SUPPORTED_AS_NORMALIZED.contains(normalized);
    }

    public void setLanguage(String code) {
        if (!isSupported(code)) throw new IllegalArgumentException("Unsupported language: " + code);
        plugin.getConfig().set("language", normalize(code));
        plugin.saveConfig();
        reload();
    }

    public String get(String key, Object... replacements) {
        return format(selected, key, replacements);
    }

    /** Resolve a user's locale to one of the bundled translations, with configured-language fallback. */
    public String getForLocale(String playerLocale, String key, Object... replacements) {
        String resolved = resolvePlayerLanguage(playerLocale);
        YamlConfiguration preferred = translations.getOrDefault(resolved, selected);
        return format(preferred, key, replacements);
    }

    /** Locale access is reflective to tolerate Paper/Bukkit API differences between builds. */
    public String getForPlayer(Player player, String key, Object... replacements) {
        return getForLocale(readPlayerLocale(player), key, replacements);
    }

    private String format(YamlConfiguration preferred, String key, Object... replacements) {
        String template = preferred.getString(key);
        if (template == null) template = fallback.getString(key, "[" + key + "]");

        Map<String, String> values = new HashMap<>();
        for (int i = 0; i + 1 < replacements.length; i += 2) {
            // Interpolated file names, plugin metadata and command labels are data, not
            // color-format strings. Strip section signs so untrusted values cannot forge alerts.
            values.put(String.valueOf(replacements[i]), String.valueOf(replacements[i + 1]).replace("\u00a7", ""));
        }
        String coloredTemplate = ChatColor.translateAlternateColorCodes('&', template);
        Matcher matcher = PLACEHOLDER.matcher(coloredTemplate);
        StringBuffer out = new StringBuffer(coloredTemplate.length() + 32);
        while (matcher.find()) {
            String replacement = values.get(matcher.group(1));
            if (replacement == null) replacement = matcher.group();
            matcher.appendReplacement(out, Matcher.quoteReplacement(replacement));
        }
        matcher.appendTail(out);
        return out.toString();
    }

    private String resolvePlayerLanguage(String playerLocale) {
        if (playerLocale == null || playerLocale.isBlank()) return language;
        String normalized = normalize(playerLocale);
        if (translations.containsKey(normalized)) return normalized;
        String shortCode = normalized.split("[_-]", 2)[0].toLowerCase(Locale.ROOT);
        if (shortCode.equals("zh")) return "zh_CN";
        if (shortCode.equals("pt")) return "pt_BR";
        if (SUPPORTED_AS_NORMALIZED.contains(shortCode)) return shortCode;
        return language;
    }

    private static String readPlayerLocale(Player player) {
        if (player == null) return "";
        for (String methodName : new String[] {"locale", "getLocale"}) {
            try {
                Object result = player.getClass().getMethod(methodName).invoke(player);
                if (result instanceof java.util.Locale locale) return locale.toLanguageTag();
                if (result instanceof String text && !text.isBlank()) return text;
            } catch (ReflectiveOperationException | RuntimeException ignored) { }
        }
        return "";
    }


    public String plain(String key, Object... replacements) {
        return ChatColor.stripColor(get(key, replacements));
    }
}
